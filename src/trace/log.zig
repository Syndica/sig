const std = @import("std");
const entry = @import("entry.zig");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const Entry = entry.Entry;
const StandardEntry = entry.StandardEntry;
const testing = std.testing;
const AtomicBool = std.atomic.Value(bool);
const Channel = @import("../sync/channel.zig").Channel;
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var gpa_allocator = gpa.allocator();

const INITIAL_ENTRIES_CHANNEL_SIZE: usize = 1024;

pub const default_logger: *Logger = &global;
var global: Logger = .{ .standard = undefined };

pub const Logger = union(enum) {
    standard: *StandardErrLogger,
    test_logger: TestLogger,
    noop,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_level: Level) Self {
        return .{ .standard = StandardErrLogger.init(allocator, max_level) };
    }

    pub fn spawn(self: Self) void {
        switch (self) {
            .standard => |logger| {
                logger.spawn();
            },
            .noop, .test_logger => {},
        }
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .standard => |logger| {
                logger.deinit();
            },
            .noop, .test_logger => {},
        }
    }

    pub fn field(self: Self, name: []const u8, value: anytype) Entry {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                return logger.field(name, value);
            },
            .noop => {
                return .noop;
            },
        }
    }

    pub fn infof(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.infof(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn debugf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.debugf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn warnf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.warnf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn errf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.errf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn logf(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.logf(level, fmt, args);
            },
            .noop => {},
        }
    }

    pub fn info(self: Self, msg: []const u8) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.info(msg);
            },
            .noop => {},
        }
    }

    pub fn debug(self: Self, msg: []const u8) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.debug(msg);
            },
            .noop => {},
        }
    }

    pub fn warn(self: Self, msg: []const u8) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.warn(msg);
            },
            .noop => {},
        }
    }

    pub fn err(self: Self, msg: []const u8) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.err(msg);
            },
            .noop => {},
        }
    }

    pub fn log(self: Self, level: Level, msg: []const u8) void {
        switch (self) {
            inline .standard, .test_logger => |logger| {
                logger.log(level, msg);
            },
            .noop => {},
        }
    }

    /// Can be used in tests to minimize the amount of logging during tests.
    pub const TEST_DEFAULT_LEVEL: Level = .warn;
};

pub const StandardErrLogger = struct {
    allocator: std.mem.Allocator,
    /// Messages more granular than this will not be logged
    max_level: Level,
    exit_sig: AtomicBool,
    handle: ?std.Thread,
    channel: *Channel(*StandardEntry),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, max_level: Level) *Self {
        const self = allocator.create(Self) catch @panic("could not allocator.create Logger");
        self.* = .{
            .allocator = allocator,
            .max_level = max_level,
            .exit_sig = AtomicBool.init(false),
            .handle = null,
            .channel = Channel(*StandardEntry).init(allocator, INITIAL_ENTRIES_CHANNEL_SIZE),
        };
        return self;
    }

    pub fn spawn(self: *Self) void {
        self.handle = std.Thread.spawn(.{}, StandardErrLogger.run, .{self}) catch @panic("could not spawn Logger");
    }

    pub fn deinit(self: *Self) void {
        self.channel.close();
        if (self.handle) |handle| {
            self.exit_sig.store(true, .seq_cst);
            handle.join();
        }
        self.channel.deinit();
        self.allocator.destroy(self);
    }

    fn run(self: *Self) void {
        const sink = StdErrSink{};

        while (!self.exit_sig.load(.seq_cst)) {
            std.time.sleep(std.time.ns_per_ms * 5);

            const entries = self.channel.drain() orelse {
                // channel is closed
                return;
            };
            defer self.channel.allocator.free(entries);

            sink.consumeEntries(entries);

            // deinit entries
            for (entries) |e| {
                e.deinit();
            }
        }
    }

    pub fn field(self: *Self, name: []const u8, value: anytype) Entry {
        var e = Entry.init(self.allocator, self.channel, self.max_level);
        return e.field(name, value);
    }

    pub fn info(self: *Self, msg: []const u8) void {
        self.log(.info, msg);
    }

    pub fn debug(self: *Self, msg: []const u8) void {
        self.log(.debug, msg);
    }

    pub fn warn(self: *Self, msg: []const u8) void {
        self.log(.warn, msg);
    }

    pub fn err(self: *Self, msg: []const u8) void {
        self.log(.err, msg);
    }

    pub fn infof(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.info, fmt, args);
    }

    pub fn debugf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.debug, fmt, args);
    }

    pub fn warnf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.warn, fmt, args);
    }

    pub fn errf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.err, fmt, args);
    }

    pub fn log(self: *Self, level: Level, msg: []const u8) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            var e = Entry.init(self.allocator, self.channel, self.max_level);
            e.log(level, msg);
        }
    }

    pub fn logf(self: *Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            var e = Entry.init(self.allocator, self.channel, self.max_level);
            e.logf(level, fmt, args);
        }
    }
};

/// Directly prints instead of running in a separate thread. This handles issues during tests
/// where some log messages never get logged because the logger is deinitialized before the
/// logging thread picks up the log message.
pub const TestLogger = struct {
    max_level: Level = .warn,

    const Self = @This();

    pub const default = TestLogger{};

    pub fn logger(self: Self) Logger {
        return .{ .test_logger = self };
    }

    pub fn field(_: Self, _: []const u8, _: anytype) Entry {
        @panic("`Logger.field` not supported");
    }

    pub fn info(self: Self, msg: []const u8) void {
        self.log(.info, msg);
    }

    pub fn debug(self: Self, msg: []const u8) void {
        self.log(.debug, msg);
    }

    pub fn warn(self: Self, msg: []const u8) void {
        self.log(.warn, msg);
    }

    pub fn err(self: Self, msg: []const u8) void {
        self.log(.err, msg);
    }

    pub fn infof(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.info, fmt, args);
    }

    pub fn debugf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.debug, fmt, args);
    }

    pub fn warnf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.warn, fmt, args);
    }

    pub fn errf(self: Self, comptime fmt: []const u8, args: anytype) void {
        self.logf(.err, fmt, args);
    }

    pub fn log(self: Self, level: Level, msg: []const u8) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            std.debug.print("{s}\n", .{msg});
        }
    }

    pub fn logf(self: Self, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(self.max_level) >= @intFromEnum(level)) {
            std.debug.print(fmt ++ "\n", args);
        }
    }
};

pub const StdErrSink = struct {
    const Self = @This();

    pub fn consumeEntries(_: Self, entries: []const *StandardEntry) void {
        const std_err_writer = std.io.getStdErr().writer();
        std.debug.lockStdErr();
        defer std.debug.unlockStdErr();

        for (entries) |e| {
            logfmt.formatter(e, std_err_writer) catch unreachable;
        }
    }
};

test "trace.logger: works" {
    var logger: Logger = .noop; // uncomment below to run visual test
    // var logger = Logger.init(testing.allocator, .info);
    logger.spawn();
    defer logger.deinit();

    logger.field("elapsed", 4245).debugf("request with id {s} succeeded", .{"abcd1234"});

    logger.field("kind", .some_enum_kind).infof("operation was done", .{});
    logger.field("authorized", false).warnf("api call received at {d} not authorized", .{10004});
    logger.field("error", "IOError").errf("api call received at {d} broke the system!", .{10005});

    std.time.sleep(std.time.ns_per_ms * 100);

    logger.field("elapsed", 4245).debug("request with id succeeded");
    logger.field("kind", .some_enum_kind).info("operation was done");
    logger.field("authorized", false).warn("api call received at not authorized");
    logger.field("error", "IOError").err("api call received broke the system!");

    const s: []const u8 = "t12312";
    logger
        .field("tmp1", 123)
        .field("tmp2", 456)
        .field("tmp2", s)
        .info("new push message");

    std.time.sleep(std.time.ns_per_ms * 100);
}

test "trace.logger: Logger is noop when configured as such" {
    var logger: Logger = .noop;
    defer logger.deinit();
    logger.spawn();

    logger.info("should not log");
    logger.field("key", "value").info("not logging");
    logger.err("should not log also");

    std.time.sleep(std.time.ms_per_s * 1);
}
