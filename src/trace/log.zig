const std = @import("std");
const entry = @import("entry.zig");
const Level = @import("level.zig").Level;
const logfmt = @import("logfmt.zig");
const Entry = entry.Entry;
const testing = std.testing;
const Mutex = std.Thread.Mutex;

pub const Logger = struct {
    allocator: std.mem.Allocator,
    pending_entries: std.ArrayList(*Entry),
    default_level: Level,
    mux: Mutex,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, default_level: Level) *Self {
        var self = allocator.create(Self) catch @panic("could not allocator.create Logger");
        self.* = .{
            .allocator = allocator,
            .pending_entries = std.ArrayList(*Entry).initCapacity(allocator, 1024) catch @panic("could not init ArrayList(FinalizedEntry)"),
            .default_level = default_level,
            .mux = Mutex{},
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.pending_entries.items) |p| {
            p.deinit();
        }
        self.pending_entries.deinit();
        self.allocator.destroy(self);
    }

    pub fn spawn(self: *Self) void {
        var handle = std.Thread.spawn(.{}, Logger.run, .{self}) catch @panic("could not spawn Logger");
        handle.detach();
    }

    fn run(self: *Self) void {
        var stdErrConsumer = BasicStdErrSink{};
        var runs: u8 = 0;
        while (runs < 5) : (runs += 1) {
            self.mux.lock();
            var i: usize = 0;

            while (i < self.pending_entries.items.len) : (i += 1) {
                var e = self.pending_entries.items[i];
                stdErrConsumer.consumeEntry(e);
                e.deinit();
            }
            self.pending_entries.shrinkRetainingCapacity(0);
            self.mux.unlock();

            std.time.sleep(std.time.ns_per_ms * 50);
        }
    }

    pub fn field(self: *Self, name: []const u8, value: anytype) *Entry {
        return Entry.init(self.allocator, self).field(name, value);
    }

    pub fn info(self: *Self, comptime msg: []const u8) void {
        Entry.init(self.allocator, self).infof(msg, .{});
    }

    pub fn debug(self: *Self, comptime msg: []const u8) void {
        Entry.init(self.allocator, self).debugf(msg, .{});
    }

    pub fn warn(self: *Self, comptime msg: []const u8) void {
        Entry.init(self.allocator, self).warn(msg, .{});
    }

    pub fn err(self: *Self, comptime msg: []const u8) void {
        Entry.init(self.allocator, self).err(msg, .{});
    }

    pub fn infof(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).infof(fmt, args);
    }

    pub fn debugf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).debugf(fmt, args);
    }

    pub fn warnf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).warn(fmt, args);
    }

    pub fn errf(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).err(fmt, args);
    }

    pub fn appendEntry(self: *Self, e: *Entry) void {
        self.mux.lock();
        defer self.mux.unlock();
        self.pending_entries.append(e) catch @panic("could not append to pending_entries");
    }
};

const BasicStdErrSink = struct {
    const Self = @This();

    pub fn consumeEntries(_: Self, entries: []*Entry) void {
        var std_err_writer = std.io.getStdErr().writer();
        var std_err_mux = std.debug.getStderrMutex();
        std_err_mux.lock();
        defer std_err_mux.unlock();

        for (entries) |e| {
            logfmt.formatter(e, std_err_writer) catch unreachable;
        }
    }

    pub fn consumeEntry(_: Self, e: *Entry) void {
        var std_err_writer = std.io.getStdErr().writer();
        var std_err_mux = std.debug.getStderrMutex();
        std_err_mux.lock();
        defer std_err_mux.unlock();

        logfmt.formatter(e, std_err_writer) catch unreachable;
    }
};

test "trace.logger: works" {
    var logger = Logger.init(testing.allocator, .info);
    defer logger.deinit();

    logger.spawn();

    logger.field("elapsed", 4245).debugf("request with id {s} succeeded", .{"abcd1234"});
    logger.field("kind", .some_enum_kind).infof("operation was done", .{});
    logger.field("authorized", false).warnf("api call received at {d} not authorized", .{10004});
    logger.field("error", "IOError").errf("api call received at {d} broke the system!", .{10005});

    std.time.sleep(std.time.ns_per_ms * 100);

    try testing.expect(logger.pending_entries.items.len == 0);

    logger.field("elapsed", 4245).debug("request with id succeeded");
    logger.field("kind", .some_enum_kind).info("operation was done");
    logger.field("authorized", false).warn("api call received at not authorized");
    logger.field("error", "IOError").err("api call received broke the system!");

    std.time.sleep(std.time.ns_per_ms * 100);
}
