const std = @import("std");
const sig = @import("../sig.zig");
const trace = @import("lib.zig");
const tracy = @import("tracy");

const logfmt = trace.logfmt;

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const Channel = sig.sync.Channel;
const RecycleFBA = sig.utils.allocators.RecycleFBA;

const Filters = trace.level.Filters;
const Level = trace.level.Level;
const NewEntry = trace.entry.NewEntry;

pub fn Logger(comptime scope: []const u8) type {
    return struct {
        impl: union(enum) {
            channel_print: *ChannelPrintLogger,
            direct_print,
            test_logger: *TestLogger,
            noop: void,
        },
        max_level: Level,
        filters: Filters,

        const Self = @This();

        /// Can be used in tests to minimize the amount of logging while still
        /// allowing warn and error messages to be printed in case something
        /// went wrong.
        pub const FOR_TESTS: Self = .{
            .impl = .direct_print,
            .max_level = .warn,
            .filters = .warn,
        };

        pub const noop: Self = .{
            .impl = .noop,
            .max_level = .err,
            .filters = .err,
        };

        pub fn withScope(self: Self, comptime new_scope: []const u8) Logger(new_scope) {
            return .{
                .impl = switch (self.impl) {
                    .channel_print => |logger| .{ .channel_print = logger },
                    .direct_print => |logger| .{ .direct_print = logger },
                    .test_logger => |logger| .{ .test_logger = logger },
                    .noop => .noop,
                },
                .max_level = self.filters.level(new_scope),
                .filters = self.filters,
            };
        }

        pub fn from(logger: anytype) Logger(scope) {
            return logger.withScope(scope);
        }

        pub fn deinit(self: *const Self) void {
            switch (self.impl) {
                .channel_print => |logger| logger.deinit(),
                .test_logger => |logger| logger.deinit(),
                .direct_print, .noop => {},
            }
        }

        pub fn err(self: Self) NewEntry(scope) {
            return self.entry(.err);
        }

        pub fn warn(self: Self) NewEntry(scope) {
            return self.entry(.warn);
        }

        pub fn info(self: Self) NewEntry(scope) {
            return self.entry(.info);
        }

        pub fn debug(self: Self) NewEntry(scope) {
            return self.entry(.debug);
        }

        pub fn trace(self: Self) NewEntry(scope) {
            return self.entry(.trace);
        }

        pub fn entry(self: Self, level: Level) NewEntry(scope) {
            const logger = if (@intFromEnum(self.max_level) < @intFromEnum(level)) noop else self;
            return .{ .logger = logger, .level = level, .fields = .{} };
        }

        pub fn log(self: Self, level: Level, comptime message: []const u8) void {
            self.private_log(level, .{}, message, .{});
        }

        pub fn logf(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            self.private_log(level, .{}, fmt, args);
        }

        /// Only intended for use within trace module.
        ///
        /// Passthrough to the logger implementation
        pub fn private_log(
            self: Self,
            level: Level,
            fields: anytype,
            comptime fmt: []const u8,
            args: anytype,
        ) void {
            if (@intFromEnum(self.max_level) < @intFromEnum(level)) return;
            switch (self.impl) {
                .noop => {},
                .direct_print => {
                    tracy.print(fmt, args);
                    direct_print.log(scope, level, fields, fmt, args);
                },
                inline else => |impl| {
                    tracy.print(fmt, args);
                    impl.log(scope, level, fields, fmt, args);
                },
            }
        }
    };
}

/// An instance of `Logger` that logs via the channel.
pub const ChannelPrintLogger = struct {
    exit: std.atomic.Value(bool),
    allocator: Allocator,
    log_allocator: Allocator,
    log_allocator_state: *RecycleFBA(.{}),
    max_buffer: u64,
    channel: Channel([]const u8),
    handle: ?std.Thread,
    write_stderr: bool,

    pub const Config = struct {
        allocator: std.mem.Allocator,
        /// Maximum memory that logger can use.
        max_buffer: u64,
        write_stderr: bool = true,
    };

    pub fn init(config: Config, maybe_writer: anytype) !*ChannelPrintLogger {
        const max_buffer = config.max_buffer;
        const recycle_fba = try config.allocator.create(RecycleFBA(.{}));
        errdefer config.allocator.destroy(recycle_fba);
        recycle_fba.* = try RecycleFBA(.{}).init(.{
            .records_allocator = config.allocator,
            .bytes_allocator = config.allocator,
        }, max_buffer);
        errdefer recycle_fba.deinit();

        const self = try config.allocator.create(ChannelPrintLogger);
        errdefer config.allocator.destroy(self);
        self.* = .{
            .allocator = config.allocator,
            .log_allocator = recycle_fba.allocator(),
            .log_allocator_state = recycle_fba,
            .max_buffer = max_buffer,
            .exit = AtomicBool.init(false),
            .handle = null,
            .channel = try Channel([]const u8).init(config.allocator),
            .write_stderr = config.write_stderr,
        };

        self.handle = try std.Thread.spawn(.{}, run, .{ self, maybe_writer });
        errdefer comptime unreachable;

        return self;
    }

    pub fn deinit(self: *ChannelPrintLogger) void {
        if (self.handle) |handle| {
            std.Thread.sleep(std.time.ns_per_ms * 5);
            self.exit.store(true, .seq_cst);
            handle.join();
        }

        self.channel.deinit();
        self.log_allocator_state.deinit();
        self.allocator.destroy(self.log_allocator_state);
        self.allocator.destroy(self);
    }

    pub fn logger(
        self: *ChannelPrintLogger,
        comptime scope: []const u8,
        filters: Filters,
    ) Logger(scope) {
        return .{
            .impl = .{ .channel_print = self },
            .max_level = filters.level(scope),
            .filters = filters,
        };
    }

    pub fn run(self: *ChannelPrintLogger, maybe_writer: anytype) void {
        const stderr_writer = std.io.getStdErr().writer();
        while (true) {
            self.channel.waitToReceive(.{ .unordered = &self.exit }) catch break;

            while (self.channel.tryReceive()) |message| {
                defer self.log_allocator.free(message);
                if (self.write_stderr) {
                    std.debug.lockStdErr();
                    defer std.debug.unlockStdErr();
                    stderr_writer.writeAll(message) catch {};
                }
                if (sig.utils.types.toOptional(maybe_writer)) |writer| {
                    writer.writeAll(message) catch {};
                }
            }
        }
    }

    pub fn log(
        self: *ChannelPrintLogger,
        comptime scope: ?[]const u8,
        level: Level,
        fields: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        const size = logfmt.countLog(scope, level, fields, fmt, args);
        const msg_buf = self.log_allocator.alloc(u8, size) catch |err| {
            std.debug.lockStdErr();
            defer std.debug.unlockStdErr();
            const stderr = std.io.getStdErr().writer();
            const err_msg = "failed to allocate {} bytes for log message - {}";
            logfmt.writeLog(stderr, "logger", .err, .{}, err_msg, .{ size, err }) catch {};
            logfmt.writeLog(stderr, scope, level, fields, fmt, args) catch {};
            return;
        };

        var stream = std.io.fixedBufferStream(msg_buf);
        logfmt.writeLog(stream.writer(), scope, level, fields, fmt, args) catch |err| {
            std.debug.print("writeLog failed with err: {any}", .{err});
            self.log_allocator.free(msg_buf);
            return;
        };
        std.debug.assert(size == stream.pos);

        self.channel.send(msg_buf) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            self.log_allocator.free(msg_buf);
            return;
        };
    }
};

/// Directly prints instead of running in a separate thread. This handles issues during tests
/// where some log messages never get logged because the logger is deinitialized before the
/// logging thread picks up the log message.
pub const direct_print = struct {
    pub fn logger(comptime scope: []const u8, filters: Filters) Logger(scope) {
        return .{
            .impl = .direct_print,
            .max_level = filters.level(scope),
            .filters = filters,
        };
    }

    pub fn log(
        comptime scope: ?[]const u8,
        level: Level,
        fields: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        const writer = std.io.getStdErr().writer();
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        logfmt.writeLog(writer, scope, level, fields, fmt, args) catch {};
    }
};

/// for use in tests where we want to capture and assert that messages were logged.
pub const TestLogger = struct {
    allocator: std.mem.Allocator,
    messages: std.ArrayListUnmanaged(Message),

    pub const Message = struct {
        level: Level,
        scope: []const u8,
        content: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) TestLogger {
        return .{
            .allocator = allocator,
            .messages = .empty,
        };
    }

    pub fn deinit(self: *TestLogger) void {
        for (self.messages.items) |msg| self.allocator.free(msg.content);
        self.messages.deinit(self.allocator);
    }

    pub fn logger(self: *TestLogger, comptime scope: []const u8, max_level: Level) Logger(scope) {
        return .{
            .impl = .{ .test_logger = self },
            .max_level = max_level,
            .filters = .{ .root = max_level },
        };
    }

    pub fn log(
        self: *TestLogger,
        comptime scope: ?[]const u8,
        level: Level,
        fields: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        _ = fields; // we haven't needed to validate this in any tests yet.
        const string = std.fmt.allocPrint(self.allocator, fmt, args) catch
            @panic("allocation failed in test logger");
        self.messages.append(self.allocator, .{
            .level = level,
            .scope = scope orelse "",
            .content = string,
        }) catch @panic("allocation failed in test logger");
    }
};

/// change this locally for temporary visibility into tests.
/// normally this should be err since we don't want any output from well-behaved passing tests.
const test_filters: Filters = .err;

test "direct" {
    const allocator = std.testing.allocator;
    const std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger("test", test_filters);
    logger.log(.warn, "warn");
    logger.log(.info, "info");
    logger.log(.debug, "debug");

    logger.logf(.warn, "{s}", .{"warn"});
    logger.logf(.info, "{s}", .{"info"});
    logger.logf(.debug, "{s}", .{"debug"});
}

test "trace_ngswitch" {
    const StuffChild = struct {
        const StuffChild = @This();
        logger: Logger(@typeName(StuffChild)),

        pub fn init(logger: anytype) StuffChild {
            return .{ .logger = logger.withScope(@typeName(StuffChild)) };
        }

        pub fn doStuffDetails(self: *StuffChild) void {
            self.logger.info().log("doing stuff child");
        }
    };

    const Stuff = struct {
        const Stuff = @This();
        logger: Logger(@typeName(Stuff)),

        pub fn init(logger: anytype) Stuff {
            return .{ .logger = logger.withScope(@typeName(Stuff)) };
        }

        pub fn doStuff(self: *Stuff) void {
            self.logger.info().log("doing stuff parent");
            const logger = self.logger.withScope("unscoped");
            var child = StuffChild.init(&logger);
            child.doStuffDetails();
        }
    };

    const allocator = std.testing.allocator;

    const std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger("test", test_filters);

    // Below logs out the following:
    // trace_ng.log.test.trace_ng: scope switch.Stuff] time=2024-09-11T06:49:02Z level=info doing stuff parent
    // [trace_ng.log.test.trace_ng: scope switch.StuffChild] time=2024-09-11T06:49:02Z level=info doing stuff child
    // time=2024-09-11T06:49:02Z level=info Log from main
    var stuff = Stuff.init(logger);
    stuff.doStuff();
}

test "reclaim" {
    const allocator = std.testing.allocator;

    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 4048,
    }, null);

    defer std_logger.deinit();

    const logger = std_logger.logger("test", test_filters);

    // Ensure memory can be continously requested from recycle_fba without getting stuck.
    for (0..25) |_| {
        logger.info()
            .field("f_agent", "Firefox")
            .field("f_version", 2.0)
            .log("Logging with logWithFields");
    }
}

test "level" {
    const allocator = std.testing.allocator;

    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 1 << 20,
    }, null);

    defer std_logger.deinit();

    const logger = std_logger.logger("test", test_filters);

    //None should log as they are higher than set max_log.
    logger
        .warn()
        .log("Logging with log");

    logger
        .info()
        .logf(
        "{s}",
        .{"Logging with logf"},
    );

    logger.info()
        .field("f_agent", "Firefox")
        .field("f_version", "2.0")
        .field("f_version_other", "3.0")
        .log("Logging with logWithFields");

    logger.trace()
        .field("f_agent", "Firefox")
        .field("f_version", 120)
        .field("f_local", "en")
        .field("f_stock", "nvidia")
        .logf("{s}", .{"Logging with logfWithFields"});
}

test "test_logger" {
    // TODO Replace this with a logger that is configurable with a writer
    // That way, the logger can be configured to write to a file, stdout or an array list.

    const logger = direct_print.logger("test", test_filters);

    logger.log(.info, "Logging with log");
}

test "channel logger" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);

    const logger = try ChannelPrintLogger.init(.{
        .allocator = std.testing.allocator,
        .write_stderr = false,
        .max_buffer = 512,
    }, stream.writer());

    logger.logger("test", .{ .root = .info }).log(.info, "hello world");
    std.Thread.sleep(10 * std.time.ns_per_ms);
    logger.deinit();

    const actual = stream.getWritten();
    try std.testing.expectEqualSlices(
        u8,
        "level=info scope=test message=\"hello world\"\n",
        actual[30..],
    );
}
