const std = @import("std");
const entry = @import("entry.zig");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const Entry = entry.Entry;
const StandardEntry = entry.StandardEntry;
const testing = std.testing;
const Mutex = std.Thread.Mutex;
const AtomicBool = std.atomic.Atomic(bool);
const Channel = @import("../sync/channel.zig").Channel;

const INITIAL_ENTRIES_CHANNEL_SIZE: usize = 1024;

pub const Logger = union(enum) {
    standard: *StandardErrLogger,
    noop,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, default_level: Level) Self {
        return .{ .standard = StandardErrLogger.init(allocator, default_level) };
    }

    pub fn spawn(self: Self) void {
        switch (self) {
            .standard => |logger| {
                logger.spawn();
            },
            .noop => {},
        }
    }

    pub fn deinit(self: Self) void {
        switch (self) {
            .standard => |logger| {
                logger.deinit();
            },
            .noop => {},
        }
    }

    pub fn field(self: Self, name: []const u8, value: anytype) Entry {
        switch (self) {
            .standard => |logger| {
                return logger.field(name, value);
            },
            .noop => {
                return .noop;
            },
        }
    }

    pub fn infof(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .standard => |logger| {
                logger.infof(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn debugf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .standard => |logger| {
                logger.debugf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn warnf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .standard => |logger| {
                logger.warnf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn errf(self: Self, comptime fmt: []const u8, args: anytype) void {
        switch (self) {
            .standard => |logger| {
                logger.errf(fmt, args);
            },
            .noop => {},
        }
    }

    pub fn info(self: Self, msg: []const u8) void {
        switch (self) {
            .standard => |logger| {
                logger.info(msg);
            },
            .noop => {},
        }
    }

    pub fn debug(self: Self, msg: []const u8) void {
        switch (self) {
            .standard => |logger| {
                logger.debug(msg);
            },
            .noop => {},
        }
    }

    pub fn warn(self: Self, msg: []const u8) void {
        switch (self) {
            .standard => |logger| {
                logger.warn(msg);
            },
            .noop => {},
        }
    }

    pub fn err(self: Self, msg: []const u8) void {
        switch (self) {
            .standard => |logger| {
                logger.err(msg);
            },
            .noop => {},
        }
    }
};

pub const StandardErrLogger = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    default_level: Level,
    exit_sig: AtomicBool,
    handle: ?std.Thread,
    channel: *Channel(*StandardEntry),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, default_level: Level) *Self {
        var self = allocator.create(Self) catch @panic("could not allocator.create Logger");
        var arena = std.heap.ArenaAllocator.init(allocator);

        self.* = .{
            .allocator = allocator,
            .arena = arena,
            .default_level = default_level,
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
            self.exit_sig.store(true, .SeqCst);
            handle.join();
        }
        self.channel.deinit();
        self.arena.deinit();
        self.allocator.destroy(self);
    }

    fn run(self: *Self) void {
        const sink = StdErrSink{};

        while (!self.exit_sig.load(.SeqCst)) {
            std.time.sleep(std.time.ns_per_ms * 5);

            var entries = self.channel.drain() orelse {
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
        var e = Entry.init(self.arena.allocator(), self.channel);
        return e.field(name, value);
    }

    pub fn info(self: *Self, msg: []const u8) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.info(msg);
    }

    pub fn debug(self: *Self, msg: []const u8) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.debug(msg);
    }

    pub fn warn(self: *Self, msg: []const u8) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.warn(msg);
    }

    pub fn err(self: *Self, msg: []const u8) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.err(msg);
    }

    pub fn infof(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.infof(fmt, args);
    }

    pub fn debugf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.debugf(fmt, args);
    }

    pub fn warnf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.warnf(fmt, args);
    }

    pub fn errf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        var e = Entry.init(self.arena.allocator(), self.channel);
        e.errf(fmt, args);
    }
};

pub const StdErrSink = struct {
    const Self = @This();

    pub fn consumeEntries(_: Self, entries: []*StandardEntry) void {
        var std_err_writer = std.io.getStdErr().writer();
        var std_err_mux = std.debug.getStderrMutex();
        std_err_mux.lock();
        defer std_err_mux.unlock();

        for (entries) |e| {
            logfmt.formatter(e, std_err_writer) catch unreachable;
        }
    }
};

test "trace.logger: works" {
    var logger = Logger.init(testing.allocator, .info);
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
