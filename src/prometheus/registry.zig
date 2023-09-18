const std = @import("std");
const fmt = std.fmt;
const hash_map = std.hash_map;
const heap = std.heap;
const mem = std.mem;
const testing = std.testing;
const Metric = @import("metric.zig").Metric;
const Counter = @import("counter.zig").Counter;
const Gauge = @import("gauge.zig").Gauge;
const Histogram = @import("histogram.zig").Histogram;
const GaugeCallFnType = @import("gauge.zig").GaugeCallFnType;

pub const GetMetricError = error{
    // Returned when trying to add a metric to an already full registry.
    TooManyMetrics,
    // Returned when the name of name is bigger than the configured max_name_len.
    NameTooLong,

    OutOfMemory,
};

const RegistryOptions = struct {
    max_metrics: comptime_int = 8192,
    max_name_len: comptime_int = 1024,
};

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
pub var registry: *Registry(.{}) = undefined;

pub fn init() error{OutOfMemory}!void {
    registry = try Registry(.{}).init(gpa_allocator);
}

pub fn deinit() void {
    registry.deinit();
}

pub fn Registry(comptime options: RegistryOptions) type {
    return struct {
        const Self = @This();
        const MetricMap = hash_map.StringHashMapUnmanaged(*Metric);

        root_allocator: mem.Allocator,
        arena_state: heap.ArenaAllocator,
        mutex: std.Thread.Mutex,
        metrics: MetricMap,

        pub fn init(alloc: mem.Allocator) error{OutOfMemory}!*Self {
            const self = try alloc.create(Self);

            self.* = .{
                .root_allocator = alloc,
                .arena_state = heap.ArenaAllocator.init(alloc),
                .mutex = .{},
                .metrics = MetricMap{},
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.arena_state.deinit();
            self.root_allocator.destroy(self);
        }

        fn nbMetrics(self: *const Self) usize {
            return self.metrics.count();
        }

        pub fn getOrCreateCounter(self: *Self, name: []const u8) GetMetricError!*Counter {
            if (self.nbMetrics() >= options.max_metrics) return error.TooManyMetrics;
            if (name.len > options.max_name_len) return error.NameTooLong;

            var allocator = self.arena_state.allocator();

            const duped_name = try allocator.dupe(u8, name);

            self.mutex.lock();
            defer self.mutex.unlock();

            var gop = try self.metrics.getOrPut(allocator, duped_name);
            if (!gop.found_existing) {
                var real_metric = try Counter.init(allocator);
                gop.value_ptr.* = &real_metric.metric;
            }

            return @fieldParentPtr(Counter, "metric", gop.value_ptr.*);
        }

        pub fn getOrCreateHistogram(self: *Self, name: []const u8) GetMetricError!*Histogram {
            if (self.nbMetrics() >= options.max_metrics) return error.TooManyMetrics;
            if (name.len > options.max_name_len) return error.NameTooLong;

            var allocator = self.arena_state.allocator();

            const duped_name = try allocator.dupe(u8, name);

            self.mutex.lock();
            defer self.mutex.unlock();

            var gop = try self.metrics.getOrPut(allocator, duped_name);
            if (!gop.found_existing) {
                var real_metric = try Histogram.init(allocator);
                gop.value_ptr.* = &real_metric.metric;
            }

            return @fieldParentPtr(Histogram, "metric", gop.value_ptr.*);
        }

        pub fn getOrCreateGauge(
            self: *Self,
            name: []const u8,
            state: anytype,
            callFn: GaugeCallFnType(@TypeOf(state), f64),
        ) GetMetricError!*Gauge(@TypeOf(state), f64) {
            if (self.nbMetrics() >= options.max_metrics) return error.TooManyMetrics;
            if (name.len > options.max_name_len) return error.NameTooLong;

            var allocator = self.arena_state.allocator();

            const duped_name = try allocator.dupe(u8, name);

            self.mutex.lock();
            defer self.mutex.unlock();

            var gop = try self.metrics.getOrPut(allocator, duped_name);
            if (!gop.found_existing) {
                var real_metric = try Gauge(@TypeOf(state), f64).init(allocator, callFn, state);
                gop.value_ptr.* = &real_metric.metric;
            }

            return @fieldParentPtr(Gauge(@TypeOf(state), f64), "metric", gop.value_ptr.*);
        }

        pub fn getOrCreateGaugeInt(
            self: *Self,
            name: []const u8,
            state: anytype,
            callFn: GaugeCallFnType(@TypeOf(state), u64),
        ) GetMetricError!*Gauge(@TypeOf(state), u64) {
            if (self.nbMetrics() >= options.max_metrics) return error.TooManyMetrics;
            if (name.len > options.max_name_len) return error.NameTooLong;

            var allocator = self.arena_state.allocator();

            const duped_name = try allocator.dupe(u8, name);

            self.mutex.lock();
            defer self.mutex.unlock();

            var gop = try self.metrics.getOrPut(allocator, duped_name);
            if (!gop.found_existing) {
                var real_metric = try Gauge(@TypeOf(state), u64).init(allocator, callFn, state);
                gop.value_ptr.* = &real_metric.metric;
            }

            return @fieldParentPtr(Gauge(@TypeOf(state), u64), "metric", gop.value_ptr.*);
        }

        pub fn write(self: *Self, allocator: mem.Allocator, writer: anytype) !void {
            var arena_state = heap.ArenaAllocator.init(allocator);
            defer arena_state.deinit();

            self.mutex.lock();
            defer self.mutex.unlock();

            try writeMetrics(arena_state.allocator(), self.metrics, writer);
        }

        fn writeMetrics(allocator: mem.Allocator, map: MetricMap, writer: anytype) !void {
            // Get the keys, sorted
            const keys = blk: {
                var key_list = try std.ArrayList([]const u8).initCapacity(allocator, map.count());

                var key_iter = map.keyIterator();
                while (key_iter.next()) |key| {
                    key_list.appendAssumeCapacity(key.*);
                }

                break :blk key_list.items;
            };
            defer allocator.free(keys);

            std.mem.sort([]const u8, keys, {}, stringLessThan);

            // Write each metric in key order
            for (keys) |key| {
                var metric = map.get(key) orelse unreachable;
                try metric.write(allocator, writer, key);
            }
        }
    };
}

fn stringLessThan(context: void, lhs: []const u8, rhs: []const u8) bool {
    _ = context;
    return mem.lessThan(u8, lhs, rhs);
}

test "registry getOrCreateCounter" {
    var reg = try Registry(.{}).create(testing.allocator);
    defer reg.destroy();

    const name = try fmt.allocPrint(testing.allocator, "http_requests{{status=\"{d}\"}}", .{500});
    defer testing.allocator.free(name);

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var counter = try reg.getOrCreateCounter(name);
        counter.inc();
    }

    var counter = try reg.getOrCreateCounter(name);
    try testing.expectEqual(@as(u64, 10), counter.get());
}

test "registry write" {
    const TestCase = struct {
        counter_name: []const u8,
        gauge_name: []const u8,
        histogram_name: []const u8,
        exp: []const u8,
    };

    const exp1 =
        \\http_conn_pool_size 4.000000
        \\http_request_size_bucket{vmrange="1.292e+02...1.468e+02"} 1
        \\http_request_size_bucket{vmrange="4.642e+02...5.275e+02"} 1
        \\http_request_size_bucket{vmrange="1.136e+03...1.292e+03"} 1
        \\http_request_size_sum 1870.360000
        \\http_request_size_count 3
        \\http_requests 2
        \\
    ;

    const exp2 =
        \\http_conn_pool_size{route="/api/v2/users"} 4.000000
        \\http_request_size_bucket{route="/api/v2/users",vmrange="1.292e+02...1.468e+02"} 1
        \\http_request_size_bucket{route="/api/v2/users",vmrange="4.642e+02...5.275e+02"} 1
        \\http_request_size_bucket{route="/api/v2/users",vmrange="1.136e+03...1.292e+03"} 1
        \\http_request_size_sum{route="/api/v2/users"} 1870.360000
        \\http_request_size_count{route="/api/v2/users"} 3
        \\http_requests{route="/api/v2/users"} 2
        \\
    ;

    const test_cases = &[_]TestCase{
        .{
            .counter_name = "http_requests",
            .gauge_name = "http_conn_pool_size",
            .histogram_name = "http_request_size",
            .exp = exp1,
        },
        .{
            .counter_name = "http_requests{route=\"/api/v2/users\"}",
            .gauge_name = "http_conn_pool_size{route=\"/api/v2/users\"}",
            .histogram_name = "http_request_size{route=\"/api/v2/users\"}",
            .exp = exp2,
        },
    };

    inline for (test_cases) |tc| {
        var reg = try Registry(.{}).create(testing.allocator);
        defer reg.destroy();

        // Add some counters
        {
            var counter = try reg.getOrCreateCounter(tc.counter_name);
            counter.set(2);
        }

        // Add some gauges
        {
            _ = try reg.getOrCreateGauge(
                tc.gauge_name,
                @as(f64, 4.0),
                struct {
                    fn get(s: *f64) f64 {
                        return s.*;
                    }
                }.get,
            );
        }

        // Add an histogram
        {
            var histogram = try reg.getOrCreateHistogram(tc.histogram_name);

            histogram.update(500.12);
            histogram.update(1230.240);
            histogram.update(140);
        }

        // Write to a buffer
        {
            var buffer = std.ArrayList(u8).init(testing.allocator);
            defer buffer.deinit();

            try reg.write(testing.allocator, buffer.writer());

            try testing.expectEqualStrings(tc.exp, buffer.items);
        }

        // Write to  a file
        {
            const filename = "prometheus_metrics.txt";
            var file = try std.fs.cwd().createFile(filename, .{ .read = true });
            defer {
                file.close();
                std.fs.cwd().deleteFile(filename) catch {};
            }

            try reg.write(testing.allocator, file.writer());

            try file.seekTo(0);
            const file_data = try file.readToEndAlloc(testing.allocator, std.math.maxInt(usize));
            defer testing.allocator.free(file_data);

            try testing.expectEqualStrings(tc.exp, file_data);
        }
    }
}

test "registry options" {
    var reg = try Registry(.{ .max_metrics = 1, .max_name_len = 4 }).create(testing.allocator);
    defer reg.destroy();

    {
        try testing.expectError(error.NameTooLong, reg.getOrCreateCounter("hello"));
        _ = try reg.getOrCreateCounter("foo");
    }

    {
        try testing.expectError(error.TooManyMetrics, reg.getOrCreateCounter("bar"));
    }
}

test "prometheus.registry: test default registry" {
    registry = try Registry(.{}).init(testing.allocator);
    defer registry.deinit();
    var counter = try registry.getOrCreateCounter("hello");
    counter.inc();
}
