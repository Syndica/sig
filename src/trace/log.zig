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
        var stdErrConsumer = BasicSink(std.io.getStdErr().writer()){};
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

    pub fn info(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).info(fmt, args);
    }

    pub fn debug(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).debug(fmt, args);
    }

    pub fn warn(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).warn(fmt, args);
    }

    pub fn err(self: *Self, comptime fmt: []const u8, args: anytype) void {
        Entry.init(self.allocator, self).err(fmt, args);
    }

    pub fn appendEntry(self: *Self, e: *Entry) void {
        self.mux.lock();
        defer self.mux.unlock();
        self.pending_entries.append(e) catch @panic("could not append to pending_entries");
    }
};

fn BasicSink(comptime writer: anytype) type {
    return struct {
        const Self = @This();

        pub fn consumeEntries(self: Self, entries: []*Entry) void {
            _ = self;
            for (entries) |e| {
                logfmt.formatter(e, writer) catch unreachable;
            }
        }

        pub fn consumeEntry(self: Self, e: *Entry) void {
            _ = self;
            logfmt.formatter(e, writer) catch unreachable;
        }
    };
}

test "trace.logger: works" {
    var logger = Logger.init(testing.allocator, .info);
    defer logger.deinit();

    logger.spawn();

    logger.field("elapsed", 4245).debug("request with id {s} succeeded", .{"abcd1234"});
    logger.field("kind", .some_enum_kind).info("operation was done", .{});
    logger.field("authorized", false).warn("api call received at {d} not authorized", .{10004});
    logger.field("error", "IOError").err("api call received at {d} broke the system!", .{10005});

    std.time.sleep(std.time.ns_per_ms * 100);

    try testing.expect(logger.pending_entries.items.len == 0);

    logger.field("elapsed", 4245).debug("request with id {s} succeeded", .{"abcd1234"});
    logger.field("kind", .some_enum_kind).info("operation was done", .{});
    logger.field("authorized", false).warn("api call received at {d} not authorized", .{10004});
    logger.field("error", "IOError").err("api call received at {d} broke the system!", .{10005});

    std.time.sleep(std.time.ns_per_ms * 100);
}
