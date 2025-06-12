const std = @import("std");
const sig = @import("../sig.zig");
const trace = @import("lib.zig");
const tracy = @import("tracy");

const logfmt = trace.logfmt;

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const Channel = sig.sync.Channel;
const RecycleFBA = sig.utils.allocators.RecycleFBA;

const Level = trace.level.Level;
const NewEntry = trace.entry.NewEntry;

pub fn ScopedLogger(comptime scope: ?[]const u8) type {
    return union(enum) {
        channel_print: *ChannelPrintLogger,
        direct_print: DirectPrintLogger,
        noop: void,

        const Self = @This();

        /// Can be used in tests to minimize the amount of logging during tests.
        pub const TEST_DEFAULT_LEVEL: Level = .warn;

        pub fn unscoped(self: Self) Logger {
            return self.withScope(null);
        }

        pub fn withScope(self: Self, comptime new_scope: ?[]const u8) ScopedLogger(new_scope) {
            return switch (self) {
                .channel_print => |logger| .{ .channel_print = logger },
                .direct_print => |logger| .{ .direct_print = logger },
                .noop => .noop,
            };
        }

        pub fn from(logger: anytype) ScopedLogger(scope) {
            return logger.withScope(scope);
        }

        pub fn deinit(self: *const Self) void {
            switch (self.*) {
                .channel_print => |logger| logger.deinit(),
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

        fn entry(self: Self, level: Level) NewEntry(scope) {
            const logger = switch (self) {
                .noop => .noop,
                inline else => |impl| if (@intFromEnum(impl.max_level) >= @intFromEnum(level))
                    self
                else
                    .noop,
            };
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
            switch (self) {
                .noop => {},
                inline else => |impl| {
                    tracy.print(fmt, args);
                    impl.log(scope, level, fields, fmt, args);
                },
            }
        }
    };
}

pub const Logger = ScopedLogger(null);

/// An instance of `ScopedLogger` that logs via the channel.
pub const ChannelPrintLogger = struct {
    max_level: Level,
    exit: std.atomic.Value(bool),
    allocator: Allocator,
    log_allocator: Allocator,
    log_allocator_state: *RecycleFBA(.{}),
    max_buffer: u64,
    channel: Channel([]const u8),
    handle: ?std.Thread,
    write_stderr: bool,

    const Self = @This();

    pub const Config = struct {
        max_level: Level = Level.debug,
        allocator: std.mem.Allocator,
        /// Maximum memory that logger can use.
        max_buffer: u64,
        write_stderr: bool = true,
    };

    pub fn init(config: Config, maybe_writer: anytype) !*Self {
        const max_buffer = config.max_buffer;
        const recycle_fba = try config.allocator.create(RecycleFBA(.{}));
        errdefer config.allocator.destroy(recycle_fba);
        recycle_fba.* = try RecycleFBA(.{}).init(.{
            .records_allocator = config.allocator,
            .bytes_allocator = config.allocator,
        }, max_buffer);
        errdefer recycle_fba.deinit();

        const self = try config.allocator.create(Self);
        errdefer config.allocator.destroy(self);
        self.* = .{
            .allocator = config.allocator,
            .log_allocator = recycle_fba.allocator(),
            .log_allocator_state = recycle_fba,
            .max_buffer = max_buffer,
            .exit = AtomicBool.init(false),
            .max_level = config.max_level,
            .handle = null,
            .channel = try Channel([]const u8).init(config.allocator),
            .write_stderr = config.write_stderr,
        };

        self.handle = try std.Thread.spawn(.{}, run, .{ self, maybe_writer });
        errdefer comptime unreachable;

        return self;
    }

    pub fn deinit(self: *Self) void {
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

    pub fn logger(self: *Self) Logger {
        return .{ .channel_print = self };
    }

    pub fn scopedLogger(self: *Self, comptime new_scope: anytype) ScopedLogger(new_scope) {
        return .{ .channel_print = self };
    }

    pub fn run(self: *Self, maybe_writer: anytype) void {
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
        self: *Self,
        comptime scope: ?[]const u8,
        level: Level,
        fields: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(self.max_level) < @intFromEnum(level)) return;
        const size = logfmt.countLog(scope, level, fields, fmt, args);
        const msg_buf = self.allocBuf(size) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
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

    // Utility function for allocating memory from RecycleFBA for part of the log message.
    fn allocBuf(self: *const Self, size: u64) ![]u8 {
        for (0..100) |_| {
            return self.log_allocator.alloc(u8, size) catch {
                std.Thread.sleep(std.time.ns_per_ms);
                if (self.exit.load(.monotonic)) {
                    return error.MemoryBlockedWithExitSignaled;
                }
                continue;
            };
        }
        return error.OutOfMemory;
    }
};

/// Directly prints instead of running in a separate thread. This handles issues during tests
/// where some log messages never get logged because the logger is deinitialized before the
/// logging thread picks up the log message.
pub const DirectPrintLogger = struct {
    max_level: Level,

    const Self = @This();

    pub fn init(_: std.mem.Allocator, max_level: Level) Self {
        return .{ .max_level = max_level };
    }

    pub fn logger(self: Self) Logger {
        return .{ .direct_print = self };
    }

    pub fn scopedLogger(self: Self, comptime new_scope: anytype) ScopedLogger(new_scope) {
        return .{ .direct_print = self };
    }

    pub fn log(
        self: Self,
        comptime scope: ?[]const u8,
        level: Level,
        fields: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(self.max_level) < @intFromEnum(level)) return;
        const writer = std.io.getStdErr().writer();
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();
        logfmt.writeLog(writer, scope, level, fields, fmt, args) catch {};
    }
};

/// change this locally for temporary visibility into tests.
/// normally this should be err since we don't want any output from well-behaved passing tests.
const test_level = Level.err;

test "direct" {
    const allocator = std.testing.allocator;
    const std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = test_level,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger();
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
        logger: ScopedLogger(@typeName(StuffChild)),

        pub fn init(logger: *const Logger) StuffChild {
            return .{ .logger = logger.withScope(@typeName(StuffChild)) };
        }

        pub fn doStuffDetails(self: *StuffChild) void {
            self.logger.info().log("doing stuff child");
        }
    };

    const Stuff = struct {
        const Stuff = @This();
        logger: ScopedLogger(@typeName(Stuff)),

        pub fn init(logger: Logger) Stuff {
            return .{ .logger = logger.withScope(@typeName(Stuff)) };
        }

        pub fn doStuff(self: *Stuff) void {
            self.logger.info().log("doing stuff parent");
            const logger = self.logger.unscoped();
            var child = StuffChild.init(&logger);
            child.doStuffDetails();
        }
    };

    const allocator = std.testing.allocator;

    const std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = test_level,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger();

    // Below logs out the following:
    // trace_ng.log.test.trace_ng: scope switch.Stuff] time=2024-09-11T06:49:02Z level=info doing stuff parent
    // [trace_ng.log.test.trace_ng: scope switch.StuffChild] time=2024-09-11T06:49:02Z level=info doing stuff child
    // time=2024-09-11T06:49:02Z level=info Log from main
    var stuff = Stuff.init(logger);
    stuff.doStuff();
    // Log using the concrete instance also works.
    std_logger.log(null, .info, .{}, "Log from main", .{});
}

test "reclaim" {
    const allocator = std.testing.allocator;

    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = test_level,
        .max_buffer = 4048,
    }, null);

    defer std_logger.deinit();

    const logger = std_logger.logger();

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
        .max_level = test_level,
        .max_buffer = 1 << 20,
    }, null);

    defer std_logger.deinit();

    const logger = std_logger.logger();

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
    const allocator = std.testing.allocator;

    var test_logger = DirectPrintLogger.init(allocator, Level.warn);

    const logger = test_logger.logger();

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

    logger.logger().log(.info, "hello world");
    std.Thread.sleep(10 * std.time.ns_per_ms);
    logger.deinit();

    const actual = stream.getWritten();
    try std.testing.expectEqualSlices(u8, "level=info message=\"hello world\"\n", actual[30..]);
}
