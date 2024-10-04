const std = @import("std");
const Level = @import("level.zig").Level;
const Entry = @import("entry.zig").Entry;
const StdEntry = @import("entry.zig").ChannelEntry;
const StdErrEntry = @import("entry.zig").StdErrEntry;
const logfmt = @import("logfmt.zig");
const sig = @import("../sig.zig");
// TODO Improve import.
const Channel = @import("../sync/channel.zig").Channel;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const RecycleFBA = sig.utils.allocators.RecycleFBA;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var gpa_allocator = gpa.allocator();

pub const Config = struct {
    max_level: Level = Level.debug,
    allocator: std.mem.Allocator,
    /// Maximum memory that logger can use.
    max_buffer: ?u64 = null,
};

const LogKind = enum {
    standard,
    test_logger,
    noop,
};

/// A ScopedLogger could either be:
/// - A StandardErrLogger
/// - A TestingLogger
pub fn ScopedLogger(comptime scope: ?[]const u8) type {
    return union(LogKind) {
        const Self = @This();
        standard: *ChannelPrintLogger,
        test_logger: *DirectPrintLogger,
        noop: void,

        /// Can be used in tests to minimize the amount of logging during tests.
        pub const TEST_DEFAULT_LEVEL: Level = .warn;

        pub fn unscoped(self: Self) Logger {
            return switch (self) {
                .standard => |logger| .{ .standard = logger },
                .test_logger => |logger| .{ .test_logger = logger },
                .noop => .noop,
            };
        }
        pub fn withScope(self: Self, comptime new_scope: []const u8) ScopedLogger(new_scope) {
            return switch (self) {
                .standard => |logger| .{ .standard = logger },
                .test_logger => |logger| .{ .test_logger = logger },
                .noop => .noop,
            };
        }

        pub fn deinit(self: *const Self) void {
            switch (self.*) {
                .standard => |*logger| {
                    logger.*.deinit();
                },
                .test_logger => |*logger| {
                    logger.*.deinit();
                },
                .noop => {},
            }
        }

        pub fn err(self: *const Self) Entry {
            return switch (self.*) {
                .noop => Entry{ .noop = {} },
                inline else => |impl| impl.err(scope),
            };
        }

        pub fn warn(self: *const Self) Entry {
            return switch (self.*) {
                .noop => Entry{ .noop = {} },
                inline else => |impl| impl.err(scope),
            };
        }

        pub fn info(self: *const Self) Entry {
            return switch (self.*) {
                .noop => Entry{ .noop = {} },
                inline else => |impl| impl.info(scope),
            };
        }

        pub fn debug(self: *const Self) Entry {
            return switch (self.*) {
                .noop => Entry{ .noop = {} },
                inline else => |impl| impl.debug(scope),
            };
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
                inline else => |*impl| impl.*.logf(scope, level, fmt, args),
            }
        }
    };
}

pub const Logger = ScopedLogger(null);

/// An instance of `ScopedLogger` that logs via the channel.
pub const ChannelPrintLogger = struct {
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
        const max_buffer = config.max_buffer orelse return error.MaxBufferNotSet;
        const recycle_fba = try config.allocator.create(RecycleFBA(.{}));
        recycle_fba.* = try RecycleFBA(.{}).init(config.allocator, max_buffer);
        const self = try config.allocator.create(Self);
        self.* = .{
            .allocator = config.allocator,
            .log_allocator = recycle_fba.allocator(),
            .log_allocator_state = recycle_fba,
            .max_buffer = max_buffer,
            .exit_sig = AtomicBool.init(false),
            .max_level = config.max_level,
            .handle = try std.Thread.spawn(.{}, run, .{self}),
            .channel = Channel(logfmt.LogMsg).create(config.allocator) catch
                @panic("could not allocate LogMsg channel"),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.handle) |*handle| {
            std.time.sleep(std.time.ns_per_ms * 5);
            self.exit_sig.store(true, .seq_cst);
            handle.join();
        }
        self.channel.deinit();
        self.log_allocator_state.deinit();
        self.allocator.destroy(self.channel);
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
        while (!self.exit_sig.load(.acquire)) {
            // while (self.channel.receive()) |message| {
            //     const writer = std.io.getStdErr().writer();
            //     { // Scope to limit the span of the lock on std err.
            //         std.debug.lockStdErr();
            //         defer std.debug.unlockStdErr();
            //         logfmt.writeLog(writer, message) catch {};
            //     }
            //     if (message.maybe_fields) |fields| {
            //         self.log_allocator.free(fields);
            //     }
            //     if (message.maybe_fmt) |fmt_msg| {
            //         self.log_allocator.free(fmt_msg);
            //     }
            // }
        }
    }

    pub fn err(self: *Self, comptime maybe_scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.err)) {
            return Entry{ .standard = StdEntry.init(self.log_allocator, maybe_scope, self.channel, Level.err) };
        }
        return Entry{ .noop = {} };
    }

    pub fn warn(self: *Self, comptime maybe_scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.warn)) {
            return Entry{ .standard = StdEntry.init(self.log_allocator, maybe_scope, self.channel, Level.warn) };
        }
        return Entry{ .noop = {} };
    }

    pub fn info(self: *Self, comptime maybe_scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.info)) {
            return Entry{ .standard = StdEntry.init(self.log_allocator, maybe_scope, self.channel, Level.info) };
        }
        return Entry{ .noop = {} };
    }

    pub fn debug(self: *Self, comptime maybe_scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.debug)) {
            return Entry{ .standard = StdEntry.init(self.log_allocator, maybe_scope, self.channel, Level.debug) };
        }
        return Entry{ .noop = {} };
    }

    pub fn log(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            switch (level) {
                .err => self.err(scope).log(message),
                .warn => self.warn(scope).log(message),
                .info => self.info(scope).log(message),
                .debug => self.debug(scope).log(message),
            }
        }
    }

    pub fn logf(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            switch (level) {
                .err => self.err(scope).logf(fmt, args),
                .warn => self.warn(scope).logf(fmt, args),
                .info => self.info(scope).logf(fmt, args),
                .debug => self.debug(scope).logf(fmt, args),
            }
        }
    }
};

/// Directly prints instead of running in a separate thread. This handles issues during tests
/// where some log messages never get logged because the logger is deinitialized before the
/// logging thread picks up the log message.
pub const DirectPrintLogger = struct {
    const builtin = @import("builtin");

    const Self = @This();
    max_level: Level,
    allocator: Allocator,
    pub fn init(config: Config) *Self {
        std.debug.assert(builtin.is_test);
        const self = config.allocator.create(Self) catch @panic("could not allocator.create Logger");
        self.* = .{
            .max_level = config.max_level,
            .allocator = config.allocator,
        };
        return self;
    }

    pub fn logger(self: *Self) Logger {
        return .{ .test_logger = self };
    }

    pub fn scopedLogger(self: *Self, comptime new_scope: anytype) ScopedLogger(new_scope) {
        return .{ .testing = self };
    }

    pub fn deinit(self: *const Self) void {
        self.allocator.destroy(self);
    }

    pub fn err(self: *Self, comptime scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.err)) {
            return Entry{ .testing = StdErrEntry.init(self.allocator, scope, Level.err) };
        }
        return Entry{ .noop = {} };
    }

    pub fn warn(self: *Self, comptime scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.warn)) {
            return Entry{ .testing = StdErrEntry.init(self.allocator, scope, Level.warn) };
        }
        return Entry{ .noop = {} };
    }

    pub fn info(self: *Self, comptime scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.info)) {
            return Entry{ .testing = StdErrEntry.init(self.allocator, scope, Level.info) };
        }
        return Entry{ .noop = {} };
    }

    pub fn debug(self: *Self, comptime scope: ?[]const u8) Entry {
        if (@intFromEnum(self.max_level) >= @intFromEnum(Level.debug)) {
            return Entry{ .testing = StdErrEntry.init(self.allocator, scope, Level.debug) };
        }
        return Entry{ .noop = {} };
    }

    pub fn log(self: *Self, comptime scope: ?[]const u8, level: Level, message: []const u8) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            switch (level) {
                .err => self.err(scope).log(message),
                .warn => self.warn(scope).log(message),
                .info => self.info(scope).log(message),
                .debug => self.debug(scope).log(message),
            }
        }
    }

    pub fn logf(self: *Self, comptime scope: ?[]const u8, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            switch (level) {
                .err => self.err(scope).logf(fmt, args),
                .warn => self.warn(scope).logf(fmt, args),
                .info => self.info(scope).logf(fmt, args),
                .debug => self.debug(scope).logf(fmt, args),
            }
        }
    }
};

test "trace_ng: direct" {
    const allocator = std.testing.allocator;
    const std_logger = ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");
    defer std_logger.deinit();

    const logger = std_logger.logger();
    logger.log(.err, "err");
    logger.log(.warn, "warn");
    logger.log(.info, "info");
    logger.log(.debug, "debug");

    logger.logf(.err, "{s}", .{"err"});
    logger.logf(.warn, "{s}", .{"warn"});
    logger.logf(.info, "{s}", .{"info"});
    logger.logf(.debug, "{s}", .{"debug"});
}

test "trace_ng: scope switch" {
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

    const std_logger = ChannelPrintLogger.init(.{
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
    std_logger.info(null).log("Log from main");
}

test "trace_ng: reclaim" {
    const allocator = std.testing.allocator;

    var std_logger = ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 4048,
    }) catch @panic("Logger init failed");

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

test "trace_ng: level" {
    const allocator = std.testing.allocator;

    var std_logger = ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
        .max_buffer = 2048,
    }) catch @panic("Logger init failed");

    defer std_logger.deinit();

    const logger = std_logger.logger();

    // None should log as they are higher than set max_log.
    logger
        .warn()
        .log("Logging with log");

    logger
        .info()
        .logf(
        "{s}",
        .{"Logging with logf"},
    );

    logger.debug()
        .field("f_agent", "Firefox")
        .field("f_version", "2.0")
        .log("Logging with logWithFields");

    logger.debug()
        .field("f_agent", "Firefox")
        .field("f_version", 120)
        .field("f_local", "en")
        .field("f_stock", "nvidia")
        .logf("{s}", .{"Logging with logfWithFields"});
}

test "trace_ng: test_logger" {
    // TODO Replace this with a logger that is configurable with a writer
    // That way, the logger can be configured to write to a file, stdout or an array list.
    const allocator = std.testing.allocator;

    var test_logger = DirectPrintLogger.init(.{
        .allocator = allocator,
        .max_level = Level.info,
    });
    defer test_logger.deinit();

    const logger = test_logger.logger();

    logger.log(.info, "Logging with log");
}
