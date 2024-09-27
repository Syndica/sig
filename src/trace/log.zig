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
    max_buffer: ?u64 = null,
};

const INITIAL_LOG_CHANNEL_SIZE: usize = 1024;

const LogKind = enum {
    standard,
    testing,
    noop,
};

/// A ScopedLogger could either be:
/// - A StandardErrLogger
/// - A TestingLogger
pub fn ScopedLogger(comptime scope: ?[]const u8) type {
    return union(LogKind) {
        const Self = @This();
        standard: *StandardErrLogger,
        testing: *TestingLogger,
        noop: void,

        pub fn unscoped(self: Self) Logger {
            return switch (self) {
                .standard => |logger| .{ .standard = logger },
                .testing => |logger| .{ .testing = logger },
                .noop => .noop,
            };
        }

        pub fn withScope(self: Self, comptime new_scope: []const u8) ScopedLogger(new_scope) {
            return switch (self) {
                .standard => |logger| .{ .standard = logger },
                .testing => |logger| .{ .testing = logger },
                .noop => .noop,
            };
        }

        pub fn deinit(self: *const Self) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.*.deinit();
                },
                .testing => |*logger| {
                    logger.*.deinit();
                },
                .noop => {},
            }
        }

        pub fn err(self: Self, message: []const u8) void {
            self.log(.err, message);
        }

        pub fn errf(self: Self, comptime fmt: []const u8, args: anytype) void {
            self.logf(.err, fmt, args);
        }

        pub fn errWithFields(self: Self, message: []const u8, fields: anytype) void {
            self.logWithFields(.err, message, fields);
        }

        pub fn errfWithFields(self: Self, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            self.logfWithFields(.err, fmt, args, fields);
        }

        pub fn warn(self: Self, message: []const u8) void {
            self.log(.warn, message);
        }

        pub fn warnf(self: Self, comptime fmt: []const u8, args: anytype) void {
            self.logf(.warn, fmt, args);
        }

        pub fn warnWithFields(self: Self, message: []const u8, fields: anytype) void {
            self.logWithFields(.warn, message, fields);
        }

        pub fn warnfWithFields(self: Self, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            self.logfWithFields(.warn, fmt, args, fields);
        }

        pub fn info(self: Self, message: []const u8) void {
            self.log(.info, message);
        }

        pub fn infof(self: Self, comptime fmt: []const u8, args: anytype) void {
            self.logf(.info, fmt, args);
        }

        pub fn infoWithFields(self: Self, message: []const u8, fields: anytype) void {
            self.logWithFields(.info, message, fields);
        }

        pub fn infofWithFields(self: Self, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            self.logfWithFields(.info, fmt, args, fields);
        }

        pub fn debug(self: Self, message: []const u8) void {
            self.log(.debug, message);
        }

        pub fn debugf(self: Self, comptime fmt: []const u8, args: anytype) void {
            self.logf(.debug, fmt, args);
        }

        pub fn debugWithFields(self: Self, message: []const u8, fields: anytype) void {
            self.logWithFields(.debug, message, fields);
        }

        pub fn debugfWithFields(self: Self, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            self.logfWithFields(.debug, fmt, args, fields);
        }

        pub fn log(self: Self, level: Level, message: []const u8) void {
            switch (self) {
                .noop => {},
                inline else => |*impl| impl.*.log(scope, level, message),
            }
        }

        pub fn logf(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
            switch (self) {
                .noop => {},
                inline else => |impl| impl.logf(scope, level, fmt, args),
            }
        }

        pub fn logWithFields(self: Self, level: Level, message: []const u8, fields: anytype) void {
            switch (self) {
                .noop => {},
                inline else => |impl| impl.logWithFields(scope, level, message, fields),
            }
        }

        pub fn logfWithFields(self: Self, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
            switch (self) {
                .noop => {},
                inline else => |impl| impl.logfWithFields(scope, level, fmt, args, fields),
            }
        }
    };
}

pub const Logger = ScopedLogger(null);

/// An instance of `ScopedLogger` that logs to the standard err.
pub const StandardErrLogger = struct {
    const Self = @This();
    max_level: Level,
    exit_sig: std.atomic.Value(bool),
    allocator: Allocator,
    log_allocator: Allocator,
    log_allocator_state: *RecycleFBA(.{}),
    max_buffer: u64,
    channel: *Channel(logfmt.LogMsg),
    handle: ?std.Thread,

    pub fn init(config: Config) !*Self {
        const recycle_fba = try config.allocator.create(RecycleFBA(.{}));
        const max_buffer = config.max_buffer orelse return error.MaxBufferNotSet;
        recycle_fba.* = try RecycleFBA(.{}).init(config.allocator, max_buffer);
        const self = try config.allocator.create(Self);
        self.* = .{
            .allocator = config.allocator,
            .log_allocator = recycle_fba.allocator(),
            .log_allocator_state = recycle_fba,
            .max_buffer = max_buffer,
            .exit_sig = AtomicBool.init(false),
            .max_level = config.max_level,
            .channel = Channel(logfmt.LogMsg).init(config.allocator, INITIAL_LOG_CHANNEL_SIZE),
            .handle = try std.Thread.spawn(.{}, run, .{self}),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.channel.close();
        if (self.handle) |*handle| {
            std.time.sleep(std.time.ns_per_ms * 5);
            self.exit_sig.store(true, .seq_cst);
            handle.join();
        }
        self.channel.deinit();
        self.log_allocator_state.deinit();
        self.allocator.destroy(self.log_allocator_state);
        self.allocator.destroy(self);
    }

    pub fn logger(self: *Self) Logger {
        return .{ .standard = self };
    }

    pub fn scopedLogger(self: *Self, comptime new_scope: anytype) ScopedLogger(new_scope) {
        return .{ .standard = self };
    }

    pub fn run(self: *Self) void {
        while (!self.exit_sig.load(.seq_cst)) {
            const messages = self.channel.drain() orelse {
                // channel is closed
                return;
            };
            defer self.channel.allocator.free(messages);
            const writer = std.io.getStdErr().writer();
            for (messages) |message| {
                { // Scope to limit the span of the lock on std err.
                    std.debug.lockStdErr();
                    defer std.debug.unlockStdErr();
                    logfmt.writeLog(writer, message) catch {};
                }
                if (message.maybe_fields) |fields| {
                    self.log_allocator.free(fields);
                }
                if (message.maybe_fmt) |fmt_msg| {
                    self.log_allocator.free(fmt_msg);
                }
            }
        }
    }

    pub fn log(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8) void {
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

        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            return;
        };
    }

    pub fn logWithFields(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8, fields: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
            // noop
            return;
        }

        const maybe_scope = if (scope) |s| s else null;

        // Format fields.
        const buf = self.allocBuf(self.estimateFieldSize(fields)) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
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

        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            return;
        };
    }

    pub fn logf(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
            // noop
            return;
        }
        const maybe_scope = if (scope) |s| s else null;

        // Format message.
        const buf = self.allocBuf(std.fmt.count(fmt, args)) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
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

        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
            return;
        };
    }

    pub fn logfWithFields(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
            // noop
            return;
        }
        const maybe_scope = if (scope) |s| s else null;

        // Format fields.
        const fields_buf = self.allocBuf(self.estimateFieldSize(fields)) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
            return;
        };
        var fmt_fields = std.io.fixedBufferStream(fields_buf);
        logfmt.fmtField(fmt_fields.writer(), fields);

        // Format message.
        const msg_buf = self.allocBuf(std.fmt.count(fmt, args)) catch |err| {
            std.debug.print("allocBuff failed with err: {any}", .{err});
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
        self.channel.send(log_msg) catch |err| {
            std.debug.print("Send msg through channel failed with err: {any}", .{err});
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

    // Utility fuction for getting the size of the struct when formated as k0=v0 k1=v2.
    // It uses `any` as the formatter hence it would slighly report more for string values.
    fn estimateFieldSize(_: *Self, input: anytype) usize {
        const info = @typeInfo(@TypeOf(input));
        var size: usize = 0;

        switch (info) {
            .Struct => |struct_info| {
                // Iterate through each field
                inline for (struct_info.fields) |field| {
                    // Add size for the key (field name)
                    size += field.name.len;
                    size += 1; // For '=' symbol
                    const field_value = @field(input, field.name);
                    const val_size = std.fmt.count("{any} ", .{field_value});
                    size += val_size;
                }
            },
            else => std.debug.panic("Expected a struct type"),
        }

        return size;
    }
};

/// An instance of `ScopedLogger` that logs to an internal array
/// that allows asserting the log message in tests.
pub const TestingLogger = struct {
    const builtin = @import("builtin");

    const Self = @This();
    max_level: Level,
    allocator: Allocator,
    log_msg: ?std.ArrayList(u8),
    pub fn init(config: Config) *Self {
        std.debug.assert(builtin.is_test);
        const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
        self.* = .{
            .max_level = config.max_level,
            .allocator = config.allocator,
            .log_msg = std.ArrayList(u8).init(config.allocator),
        };
        return self;
    }

    pub fn logger(self: *Self) Logger {
        return .{ .testing = self };
    }

    pub fn scopedLogger(self: *Self, comptime new_scope: anytype) ScopedLogger(new_scope) {
        return .{ .testing = self };
    }

    pub fn deinit(self: *const Self) void {
        if (self.log_msg) |log_msg| {
            log_msg.deinit();
        }
        self.allocator.destroy(self);
    }

    pub fn log(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8) void {
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

    pub fn logWithFields(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8, fields: anytype) void {
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

    pub fn logf(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) > @intFromEnum(self.max_level)) {
            // noop
            return;
        }
        self.log_msg.?.clearAndFree();
        const maybe_scope = if (scope) |s| s else null;

        // Format message.
        var fmt_msg = std.ArrayList(u8).initCapacity(self.allocator, 512) catch @panic("could not initCapacity for message");
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

    pub fn logfWithFields(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype, fields: anytype) void {
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

test "trace_ng: scope switch" {
    const StuffChild = struct {
        const StuffChild = @This();
        logger: ScopedLogger(@typeName(StuffChild)),

        pub fn init(logger: *const Logger) StuffChild {
            return .{ .logger = logger.withScope(@typeName(StuffChild)) };
        }

        pub fn doStuffDetails(self: *StuffChild) void {
            self.logger.log(.info, "doing stuff child");
        }
    };

    const Stuff = struct {
        const Stuff = @This();
        logger: ScopedLogger(@typeName(Stuff)),

        pub fn init(logger: Logger) Stuff {
            return .{ .logger = logger.withScope(@typeName(Stuff)) };
        }

        pub fn doStuff(self: *Stuff) void {
            self.logger.log(.info, "doing stuff parent");
            const logger = self.logger.unscoped();
            var child = StuffChild.init(&logger);
            child.doStuffDetails();
        }
    };

    const allocator = std.testing.allocator;

    const std_logger = StandardErrLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");
    defer std_logger.deinit();

    const logger = std_logger.logger();

    // Below logs out the following:
    // trace_ng.log.test.trace_ng: scope switch.Stuff] time=2024-09-11T06:49:02Z level=info doing stuff parent
    // [trace_ng.log.test.trace_ng: scope switch.StuffChild] time=2024-09-11T06:49:02Z level=info doing stuff child
    // time=2024-09-11T06:49:02Z level=info Log from main
    var stuff = Stuff.init(logger);
    stuff.doStuff();
    // Log using the concrete instance also works.
    std_logger.log(null, Level.info, "Log from main");
}

test "trace_ng: all" {
    const allocator = std.testing.allocator;

    var std_logger = StandardErrLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");
    defer std_logger.deinit();

    const logger = std_logger.logger();

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

    var std_logger = StandardErrLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");

    defer std_logger.deinit();

    const logger = std_logger.logger();

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

    var std_logger = StandardErrLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");

    defer std_logger.deinit();

    const logger = std_logger.logger();

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

    var test_logger = TestingLogger.init(.{
        .allocator = allocator,
        .max_level = Level.debug,
        .max_buffer = 2048,
    });

    defer test_logger.deinit();

    const logger = test_logger.logger();

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
        std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=info f_agent=Firefox f_version=2.0 Logging with logWithFields\n")) catch |err| std.debug.print("xxx{}", .{err});
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
    var scoped_logger = logger.withScope(@typeName(@This()));
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
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "[trace.log] time="));
    }
}

test "trace_ng: format.methods" {
    const allocator = std.testing.allocator;

    const test_logger = TestingLogger.init(.{
        .allocator = allocator,
        .max_level = Level.debug,
    });
    defer test_logger.deinit();

    const logger = test_logger.logger();

    // ERROR
    logger.err("Logging with log");
    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=error Logging with log\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.errf(
        "Log message: {s}",
        .{"Logging with logf"},
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=error Log message: Logging with logf\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.errWithFields(
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=error f_agent=Firefox f_version=2.0 Logging with logWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.errfWithFields(
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
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=error f_agent=Firefox f_version=120 f_local=en f_stock=nvidia Logging with logfWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    // WARN
    logger.warn("Logging with log");
    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=warning Logging with log\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.warnf(
        "Log message: {s}",
        .{"Logging with logf"},
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=warning Log message: Logging with logf\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.warnWithFields(
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=warning f_agent=Firefox f_version=2.0 Logging with logWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.warnfWithFields(
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
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=warning f_agent=Firefox f_version=120 f_local=en f_stock=nvidia Logging with logfWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    // INFO
    logger.info("Logging with log");
    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=info Logging with log\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.infof(
        "Log message: {s}",
        .{"Logging with logf"},
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=info Log message: Logging with logf\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.infoWithFields(
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

    logger.infofWithFields(
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
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=info f_agent=Firefox f_version=120 f_local=en f_stock=nvidia Logging with logfWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    // DEBUG
    logger.debug("Logging with log");
    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=debug Logging with log\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.debugf(
        "Log message: {s}",
        .{"Logging with logf"},
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=debug Log message: Logging with logf\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.debugWithFields(
        "Logging with logWithFields",
        .{
            .f_agent = "Firefox",
            .f_version = "2.0",
        },
    );

    if (logger.testing.log_msg) |log_msg| {
        try std.testing.expect(std.mem.endsWith(u8, log_msg.items, "level=debug f_agent=Firefox f_version=2.0 Logging with logWithFields\n"));
        try std.testing.expect(std.mem.startsWith(u8, log_msg.items, "time="));
    }

    logger.debugfWithFields(
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
}
