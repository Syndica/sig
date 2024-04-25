const std = @import("std");
const mem = std.mem;
const testing = std.testing;

const Metric = @import("metric.zig").Metric;

pub const Counter = struct {
    const Self = @This();

    metric: Metric = Metric{ .getResultFn = getResult },
    value: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn inc(self: *Self) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn add(self: *Self, value: anytype) void {
        switch (@typeInfo(@TypeOf(value))) {
            .Int, .Float, .ComptimeInt, .ComptimeFloat => {},
            else => @compileError("can't add a non-number"),
        }

        _ = self.value.fetchAdd(@intCast(value), .monotonic);
    }

    pub fn get(self: *const Self) u64 {
        return self.value.load(.monotonic);
    }

    pub fn reset(self: *Self) void {
        _ = self.value.store(0, .monotonic);
    }

    pub fn set(self: *Self, value: anytype) void {
        switch (@typeInfo(@TypeOf(value))) {
            .Int, .Float, .ComptimeInt, .ComptimeFloat => {},
            else => @compileError("can't set a non-number"),
        }
        self.value.store(@intCast(value), .monotonic);
    }

    fn getResult(metric: *Metric, _: mem.Allocator) Metric.Error!Metric.Result {
        const self: *Self = @fieldParentPtr("metric", metric);
        return Metric.Result{ .counter = self.get() };
    }
};

test "prometheus.counter: inc/add/dec/set/get" {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    var counter = Counter{};

    try testing.expectEqual(@as(u64, 0), counter.get());

    counter.inc();
    try testing.expectEqual(@as(u64, 1), counter.get());

    counter.add(200);
    try testing.expectEqual(@as(u64, 201), counter.get());
}

test "prometheus.counter: concurrent" {
    var counter = Counter{};

    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(
            .{},
            struct {
                fn run(c: *Counter) void {
                    var i: usize = 0;
                    while (i < 20) : (i += 1) {
                        c.inc();
                    }
                }
            }.run,
            .{&counter},
        );
    }

    for (&threads) |*thread| thread.join();

    try testing.expectEqual(@as(u64, 80), counter.get());
}

test "prometheus.counter: write" {
    var counter = Counter{ .value = .{ .value = 340 } };

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    var metric = &counter.metric;
    try metric.write(testing.allocator, buffer.writer(), "mycounter");

    try testing.expectEqualStrings("mycounter 340\n", buffer.items);
}
