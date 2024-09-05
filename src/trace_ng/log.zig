const std = @import("std");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const sig = @import("../sig.zig");
// TODO Improve import.
const Channel = @import("../sync/channel.zig").Channel;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const RecycleFBA = sig.utils.allocators.RecycleFBA;

pub const Config = struct {
    max_level: Level = Level.debug,
    allocator: std.mem.Allocator,
    /// Maximum memory that logger can use.
    max_buffer: u64,
    exit_sig: *std.atomic.Value(bool),
    kind: LogKind = LogKind.standard,
};

const INITIAL_LOG_CHANNEL_SIZE: usize = 1024;

const LogKind = enum {
    standard,
    testing,
    noop,
};

const Logger = ScoppedLogger(null);
pub fn ScoppedLogger(comptime scope: ?[]const u8) type {
    const StanardErrLogger = struct {
        const Self = @This();
        max_level: Level,
        exit_sig: *std.atomic.Value(bool),
        allocator: Allocator,
        log_allocator: Allocator,
        log_allocator_state: *RecycleFBA(.{}),
        max_buffer: u64,
        channel: *Channel(logfmt.LogMsg),
        handle: ?std.Thread,

        pub fn init(config: Config) *Self {
            const recycle_fba = config.allocator.create(RecycleFBA(.{})) catch @panic("could not allocate mem for RecycleFBA");
            recycle_fba.* = RecycleFBA(.{}).init(config.allocator, config.max_buffer) catch @panic("could not init RecycleFBA");
            const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
            self.* = .{
                .allocator = config.allocator,
                .log_allocator = recycle_fba.allocator(),
                .log_allocator_state = recycle_fba,
                .max_buffer = config.max_buffer,
                .max_level = config.max_level,
                .exit_sig = config.exit_sig,
                .channel = Channel(logfmt.LogMsg).init(config.allocator, INITIAL_LOG_CHANNEL_SIZE),
                .handle = std.Thread.spawn(.{}, Self.run, .{self}) catch @panic("could not spawn Logger"),
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            if (self.handle) |*handle| {
                self.exit_sig.store(true, .seq_cst);
                handle.join();
            }
            self.channel.close();
            self.channel.deinit();
            self.log_allocator_state.deinit();
            self.allocator.destroy(self.log_allocator_state);
            self.allocator.destroy(self);
        }

        pub fn unscoped(self: Self) Logger {
            return .{
                .allocator = self.allocator,
                .recycle_fba = self.log_allocator_state,
                .max_buffer = self.max_buffer,
                .max_level = self.max_level,
                .exit_sig = self.exit_sig,
                .channel = self.channel,
                .handle = self.handle,
            };
        }

        pub fn withScope(self: Self, comptime new_scope: anytype) ScoppedLogger(new_scope) {
            return .{
                .allocator = self.allocator,
                .recycle_fba = self.log_allocator_state,
                .max_buffer = self.max_buffer,
                .max_level = self.max_level,
                .exit_sig = self.exit_sig,
                .channel = self.channel,
                .handle = self.handle,
            };
        }

        pub fn run(self: *Self) void {
            while (!self.exit_sig.load(.seq_cst)) {
                std.time.sleep(std.time.ns_per_ms * 5);
                const messages = self.channel.drain() orelse {
                    // channel is closed
                    return;
                };
                defer self.channel.allocator.free(messages);

                for (messages) |message| {
                    const writer = std.io.getStdErr().writer();
                    logfmt.writeLog(writer, message) catch {};
                    if (message.maybe_fields) |fields| {
                        self.log_allocator.free(fields);
                    }
                    if (message.maybe_fmt) |fmt_msg| {
                        self.log_allocator.free(fmt_msg);
                    }
                }
            }
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            const maybe_scope = if (scope) |s| s else null;
            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = message,
                .maybe_fields = null,
                .maybe_fmt = null,
            };

            self.channel.send(log_msg) catch {};
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            const maybe_scope = if (scope) |s| s else null;

            // Format fields.
            const buf = self.allocBuf(512) catch {
                // Ignore error
                return;
            };
            var fmt_fields = std.io.fixedBufferStream(buf);
            logfmt.fmtField(fmt_fields.writer(), fields);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = message,
                .maybe_fields = fmt_fields.getWritten(),
                .maybe_fmt = null,
            };

            self.channel.send(log_msg) catch {
                // Ignore error
                return;
            };
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = if (scope) |s| s else null;

            // Format message.
            const buf = self.allocBuf(std.fmt.count(fmt, args)) catch {
                // Ignore error
                return;
            };
            var fmt_message = std.io.fixedBufferStream(buf);
            logfmt.fmtMsg(fmt_message.writer(), fmt, args);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = null,
                .maybe_fields = null,
                .maybe_fmt = fmt_message.getWritten(),
            };

            self.channel.send(log_msg) catch {
                // Ignore error
                return;
            };
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = if (scope) |s| s else null;

            // Format fields.
            const fields_buf = self.allocBuf(512) catch {
                // Ignore error
                return;
            };
            var fmt_fields = std.io.fixedBufferStream(fields_buf);
            logfmt.fmtField(fmt_fields.writer(), fields);

            // Format message.
            const msg_buf = self.allocBuf(std.fmt.count(fmt, args)) catch {
                // Ignore error
                return;
            };
            var fmt_message = std.io.fixedBufferStream(msg_buf);
            logfmt.fmtMsg(fmt_message.writer(), fmt, args);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = null,
                .maybe_fields = null,
                .maybe_fmt = fmt_message.getWritten(),
            };
            self.channel.send(log_msg) catch {
                // Ignore error
                return;
            };
        }

        // Utility function for allocating memory from RecycleFBA for part of the log message.
        fn allocBuf(self: *Self, size: u64) ![]u8 {
            const buf = blk: while (true) {
                const buf = self.log_allocator.alloc(u8, size) catch {
                    std.time.sleep(std.time.ns_per_ms);
                    if (self.exit_sig.load(.unordered)) {
                        return error.MemoryBlockedWithExitSignaled;
                    }
                    continue;
                };
                break :blk buf;
            };
            errdefer {
                self.log_allocator.free(buf);
            }
            return buf;
        }
    };

    const TestingLogger = struct {
        const Self = @This();
        max_level: Level,
        allocator: Allocator,
        max_buffer: u64,
        log_msg: ?std.ArrayList(u8),

        pub fn init(config: Config) *Self {
            const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
            self.* = .{
                .max_level = config.max_level,
                .allocator = config.allocator,
                .max_buffer = config.max_buffer,
                .log_msg = std.ArrayList(u8).init(config.allocator),
            };
            return self;
        }

        pub fn unscoped(self: *Self) Logger {
            return .{
                .allocator = self.allocator,
                .recycle_fba = self.recycle_fba,
                .max_buffer = self.max_buffer,
                .max_level = self.max_level,
                .exit_sig = self.exit_sig,
                .channel = self.channel,
                .handle = self.handle,
            };
        }

        pub fn withScope(self: *Self, comptime new_scope: anytype) ScoppedLogger(new_scope) {
            return .{
                .allocator = self.allocator,
                .recycle_fba = self.recycle_fba,
                .max_buffer = self.max_buffer,
                .max_level = self.max_level,
                .exit_sig = self.exit_sig,
                .channel = self.channel,
                .handle = self.handle,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.log_msg) |log_msg| {
                log_msg.deinit();
            }
            self.allocator.destroy(self);
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = message,
                .maybe_fields = null,
                .maybe_fmt = null,
            };

            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;

            // Format fields.
            var fmt_fields = std.ArrayList(u8).initCapacity(self.allocator, 256) catch @panic("could not initCapacity for message");
            defer fmt_fields.deinit();
            logfmt.fmtField(fmt_fields.writer(), fields);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = message,
                .maybe_fields = fmt_fields.items,
                .maybe_fmt = null,
            };

            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;

            // Format message.
            var fmt_msg = std.ArrayList(u8).initCapacity(self.allocator, 256) catch @panic("could not initCapacity for message");
            defer fmt_msg.deinit();
            logfmt.fmtMsg(fmt_msg.writer(), fmt, args);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = null,
                .maybe_fields = null,
                .maybe_fmt = fmt_msg.items,
            };

            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;

            // Format fields.
            var fmt_fields = std.ArrayList(u8).initCapacity(self.allocator, 256) catch @panic("could not initCapacity for message");
            defer fmt_fields.deinit();
            logfmt.fmtField(fmt_fields.writer(), fields);

            // Format message.
            var fmt_msg = std.ArrayList(u8).initCapacity(self.allocator, 256) catch @panic("could not initCapacity for message");
            defer fmt_msg.deinit();
            logfmt.fmtMsg(fmt_msg.writer(), fmt, args);

            const log_msg = logfmt.LogMsg{
                .level = level,
                .maybe_scope = maybe_scope,
                .maybe_msg = null,
                .maybe_fields = fmt_fields.items,
                .maybe_fmt = fmt_msg.items,
            };

            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_msg) catch @panic("Failed to write log");
        }
    };

    return union(LogKind) {
        const Self = @This();
        standard: *StanardErrLogger,
        testing: *TestingLogger,
        noop: void,
        pub fn init(config: Config) Self {
            switch (config.kind) {
                .standard => {
                    return .{ .standard = StanardErrLogger.init(.{
                        .allocator = config.allocator,
                        .exit_sig = config.exit_sig,
                        .max_level = config.max_level,
                        .max_buffer = config.max_buffer,
                    }) };
                },
                .testing, .noop => {
                    return .{ .testing = TestingLogger.init(.{
                        .allocator = config.allocator,
                        .exit_sig = config.exit_sig,
                        .max_level = config.max_level,
                        .max_buffer = config.max_buffer,
                    }) };
                },
            }
        }

        pub fn deinit(self: *Self) void {
            switch (self.*) {
                .standard => |logger| {
                    var standard = logger;
                    standard.deinit();
                },
                .testing => |logger| {
                    var test_logger = logger;
                    test_logger.deinit();
                },
                .noop => {},
            }
        }

        pub fn unscoped(self: *Self) *Logger {
            return @ptrCast(self);
        }

        pub fn withScope(self: *Self, comptime new_scope: []const u8) *ScoppedLogger(new_scope) {
            return @ptrCast(self);
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            switch (self.*) {
                .noop => {},
                inline else => |impl| impl.log(level, message),
            }
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            switch (self.*) {
                .noop => {},
                inline else => |impl| impl.logf(level, fmt, args),
            }
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            switch (self.*) {
                .noop => {},
                inline else => |impl| impl.logWithFields(level, message, fields),
            }
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            switch (self.*) {
                .noop => {},
                inline else => |impl| impl.logfWithFields(level, fmt, args, fields),
            }
        }
    };
}

test "trace_ng: scope switch" {
    const StuffChild = struct {
        const StuffChild = @This();
        logger: *ScoppedLogger(@typeName(StuffChild)),

        pub fn init(logger: *Logger) StuffChild {
            return .{ .logger = logger.withScope(@typeName(StuffChild)) };
        }

        pub fn doStuffDetails(self: *StuffChild) void {
            self.logger.log(.info, "doing stuff details");
        }
    };

    const Stuff = struct {
        const Stuff = @This();
        logger: *ScoppedLogger(@typeName(Stuff)),

        pub fn init(logger: *Logger) Stuff {
            return .{ .logger = logger.withScope(@typeName(Stuff)) };
        }

        pub fn doStuff(self: *Stuff) void {
            self.logger.log(.info, "doing stuff");
            var child = StuffChild.init(self.logger.unscoped());
            child.doStuffDetails();
        }
    };

    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = Logger.init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.info,
        .max_buffer = 2048,
    });
    defer logger.deinit();

    var stuff = Stuff.init(&logger);
    stuff.doStuff();
}

test "trace_ng: all" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = Logger.init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.info,
        .max_buffer = 2048,
    });

    defer logger.deinit();

    logger.log(.info, "Logging with log");
    logger.logf(
        .info,
        "{s}",
        .{"Logging with logf"},
    );
    logger.logWithFields(
        .info,
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logfWithFields(
        .info,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );
}

test "trace_ng: reclaim" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = Logger.init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.info,
        .max_buffer = 2048,
    });

    defer logger.deinit();

    // Ensure memory can be continously requested from recycle_fba without getting stuck.
    for (0..25) |_| {
        logger.logWithFields(
            .info,
            "Logging with logWithFields",
            .{
                .f_agent = "Firefox",
                .f_version = "2.0",
            },
        );
    }
}

test "trace_ng: level" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = Logger.init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.err,
        .max_buffer = 2048,
    });

    defer logger.deinit();

    // None should log as they are higher than set max_log.
    logger.log(.warn, "Logging with log");
    logger.logf(
        .info,
        "{s}",
        .{"Logging with logf"},
    );
    logger.logWithFields(
        .debug,
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );
    logger.logfWithFields(
        .debug,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );
}

test "trace_ng: format" {
    const allocator = std.testing.allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    var logger = Logger.init(.{
        .allocator = allocator,
        .exit_sig = exit,
        .max_level = Level.debug,
        .max_buffer = 2048,
        .kind = LogKind.testing,
    });

    defer logger.deinit();

    logger.log(.err, "Logging with log");
    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=error Logging with log\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.logf(
        .warn,
        "Log message: {s}",
        .{"Logging with logf"},
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=warning Log message: Logging with logf\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.logWithFields(
        .info,
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=info f_agent=Firefox f_version=2.0 Logging with logWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.logfWithFields(
        .debug,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=debug f_agent=Firefox f_version=120 f_local=en f_stock=nvidia Logging with logfWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    // Add scope.
    const scoped_logger = logger.withScope(@typeName(@This()));
    scoped_logger.logfWithFields(
        .debug,
        "{s}",
        .{"Logging with logfWithFields"},
        .{
            .f_agent = "Firefox",
            .f_version = 120,
            .f_local = "en",
            .f_stock = "nvidia",
        },
    );

    if (scoped_logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=debug f_agent=Firefox f_version=120 f_local=en f_stock=nvidia Logging with logfWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "[trace_ng.log] time="));
    }
}
