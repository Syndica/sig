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
        recycle_fba: RecycleFBA,
        max_buffer: u64,
        channel: *Channel(logfmt.LogMsg),
        handle: ?std.Thread,

        pub fn init(config: Config) *Self {
            const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
            self.* = .{
                .allocator = config.allocator,
                .recycle_fba = RecycleFBA.init(config.allocator, config.max_buffer) catch @panic("could not create RecycleFBA"),
                .max_buffer = config.max_buffer,
                .max_level = config.max_level,
                .exit_sig = config.exit_sig,
                .channel = Channel(logfmt.LogMsg).init(config.allocator, INITIAL_LOG_CHANNEL_SIZE),
                .handle = null,
            };
            return self;
        }

        pub fn unscoped(self: Self) Logger {
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

        pub fn withScope(self: Self, comptime new_scope: anytype) ScoppedLogger(new_scope) {
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

        pub fn spawn(self: *Self) void {
            self.handle = std.Thread.spawn(.{}, Self.run, .{self}) catch @panic("could not spawn Logger");
        }

        pub fn deinit(self: *Self) void {
            if (self.handle) |*handle| {
                self.exit_sig.store(true, .seq_cst);
                handle.join();
            }
            self.channel.close();
            self.channel.deinit();
            self.recycle_fba.deinit();
            self.allocator.destroy(self);
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
                    logfmt.writeLog(writer, message) catch @panic("logging failed");
                }
                self.recycle_fba.mux.lock();
                self.recycle_fba.alloc_allocator.reset();
                self.recycle_fba.mux.unlock();
            }
        }

        pub fn log(self: *Self, level: Level, message: []const u8) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            const maybe_scope = if (scope) |s| s else null;
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                message,
                null,
                null,
                null,
            );
            self.channel.send(log_message) catch @panic("could not send to channel");
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            const maybe_scope = if (scope) |s| s else null;
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                message,
                fields,
                null,
                null,
            );
            self.channel.send(log_message) catch @panic("could not send to channel");
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = if (scope) |s| s else null;

            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                null,
                null,
                fmt,
                args,
            );
            self.channel.send(log_message) catch @panic("could not send to channel");
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            const maybe_scope = if (scope) |s| s else null;

            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                null,
                fields,
                fmt,
                args,
            );
            self.channel.send(log_message) catch @panic("could not send to channel");
        }
    };

    const TestingLogger = struct {
        const Self = @This();
        max_level: Level,
        allocator: Allocator,
        recycle_fba: RecycleFBA,
        max_buffer: u64,
        log_msg: ?std.ArrayList(u8),

        pub fn init(config: Config) *Self {
            const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
            self.* = .{
                .max_level = config.max_level,
                .allocator = config.allocator,
                .recycle_fba = RecycleFBA.init(config.allocator, 2048) catch @panic("could not create RecycleFBA"),
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
            self.recycle_fba.deinit();
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
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                message,
                null,
                null,
                null,
            );
            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_message) catch @panic("Failed to write log");
        }

        pub fn logWithFields(self: *Self, level: Level, message: []const u8, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                message,
                fields,
                null,
                null,
            );
            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_message) catch @panic("Failed to write log");
        }

        pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }
            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                null,
                null,
                fmt,
                args,
            );
            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_message) catch @panic("Failed to write log");
        }

        pub fn logfWithFields(self: *Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
                // noop
                return;
            }

            self.log_msg.?.clearAndFree();
            const maybe_scope = if (scope) |s| s else null;
            const log_message = logfmt.createLogMessage(
                &self.recycle_fba,
                self.max_buffer,
                level,
                maybe_scope,
                null,
                fields,
                fmt,
                args,
            );
            const writer = self.log_msg.?.writer();
            logfmt.writeLog(writer, log_message) catch @panic("Failed to write log");
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

        pub fn spawn(self: Self) void {
            switch (self) {
                .standard => |logger| {
                    logger.spawn();
                },
                .noop, .testing => {},
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
    logger.spawn();

    var stuff = Stuff.init(&logger);
    stuff.doStuff();
}

test "trace_ng: testing.allocator" {
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
    logger.spawn();

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
    logger.spawn();

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
