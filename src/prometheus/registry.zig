const std = @import("std");
const sig = @import("../lib.zig");
const fmt = std.fmt;
const hash_map = std.hash_map;
const heap = std.heap;
const mem = std.mem;
const testing = std.testing;

const OnceCell = @import("../sync/once_cell.zig").OnceCell;

const Metric = @import("metric.zig").Metric;
const Counter = @import("counter.zig").Counter;
const Gauge = @import("gauge.zig").Gauge;
const GaugeFn = @import("gauge_fn.zig").GaugeFn;
const GaugeCallFnType = @import("gauge_fn.zig").GaugeCallFnType;
const Histogram = @import("histogram.zig").Histogram;
const DEFAULT_BUCKETS = @import("histogram.zig").DEFAULT_BUCKETS;

const ReturnType = sig.utils.types.ReturnType;

pub const GetMetricError = error{
    /// Returned when trying to add a metric to an already full registry.
    TooManyMetrics,
    /// Returned when the name of name is bigger than the configured max_name_len.
    NameTooLong,

    OutOfMemory,
    /// Attempted to get a metric of the wrong type.
    InvalidType,
};

/// Global registry singleton for convenience.
///
/// The registry is initialized the first time this is called
/// and reused for future calls.
pub fn globalRegistry() *Registry(.{}) {
    return global_registry_owned.getOrInit(
        Registry(.{}).init,
        .{gpa.allocator()},
    );
}
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var global_registry_owned: OnceCell(Registry(.{})) = .{};

const RegistryOptions = struct {
    max_metrics: comptime_int = 8192,
    max_name_len: comptime_int = 1024,
};

pub fn Registry(comptime options: RegistryOptions) type {
    return struct {
        const Self = @This();

        const MetricMap = hash_map.StringHashMapUnmanaged(struct {
            /// Used to validate the pointer is cast into a valid  type.
            type_name: []const u8,
            metric: *Metric,
        });

        arena_state: heap.ArenaAllocator,
        mutex: std.Thread.Mutex,
        metrics: MetricMap,

        pub fn init(allocator: mem.Allocator) Self {
            return .{
                .arena_state = heap.ArenaAllocator.init(allocator),
                .mutex = .{},
                .metrics = MetricMap{},
            };
        }

        pub fn deinit(self: *Self) void {
            self.arena_state.deinit();
        }

        fn nbMetrics(self: *const Self) usize {
            return self.metrics.count();
        }

        pub fn getOrCreateCounter(self: *Self, name: []const u8) GetMetricError!*Counter {
            return self.getOrCreateMetric(name, Counter, .{});
        }

        pub fn getOrCreateGauge(self: *Self, name: []const u8, comptime T: type) GetMetricError!*Gauge(T) {
            return self.getOrCreateMetric(name, Gauge(T), .{});
        }

        pub fn getOrCreateGaugeFn(
            self: *Self,
            name: []const u8,
            state: anytype,
            callFn: GaugeCallFnType(@TypeOf(state), f64),
        ) GetMetricError!*GaugeFn(@TypeOf(state), ReturnType(@TypeOf(callFn))) {
            return self.getOrCreateMetric(
                name,
                GaugeFn(@TypeOf(state), ReturnType(@TypeOf(callFn))),
                .{ callFn, state },
            );
        }

        pub fn getOrCreateHistogram(
            self: *Self,
            name: []const u8,
            buckets: []const f64,
        ) GetMetricError!*Histogram {
            return self.getOrCreateMetric(name, Histogram, .{buckets});
        }

        /// MetricType must be initializable in one of these ways:
        /// - try MetricType.init(allocator, ...args)
        /// - MetricType.init(...args)
        /// - as args struct (only if no init method is defined)
        fn getOrCreateMetric(
            self: *Self,
            name: []const u8,
            comptime MetricType: type,
            args: anytype,
        ) GetMetricError!*MetricType {
            if (self.nbMetrics() >= options.max_metrics) return error.TooManyMetrics;
            if (name.len > options.max_name_len) return error.NameTooLong;

            var allocator = self.arena_state.allocator();

            const duped_name = try allocator.dupe(u8, name);

            self.mutex.lock();
            defer self.mutex.unlock();

            const gop = try self.metrics.getOrPut(allocator, duped_name);
            if (!gop.found_existing) {
                var real_metric = try allocator.create(MetricType);
                if (@hasDecl(MetricType, "init")) {
                    const params = @typeInfo(@TypeOf(MetricType.init)).Fn.params;
                    if (params.len != 0 and params[0].type.? == mem.Allocator) {
                        real_metric.* = try @call(.auto, MetricType.init, .{allocator} ++ args);
                    } else {
                        real_metric.* = @call(.auto, MetricType.init, args);
                    }
                } else {
                    real_metric.* = args;
                }
                gop.value_ptr.* = .{
                    .type_name = @typeName(MetricType),
                    .metric = &real_metric.metric,
                };
            } else if (!std.mem.eql(u8, gop.value_ptr.*.type_name, @typeName(MetricType))) {
                return GetMetricError.InvalidType;
            }

            return @as(*MetricType, @fieldParentPtr("metric", gop.value_ptr.*.metric));
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
                var value = map.get(key) orelse unreachable;
                try value.metric.write(allocator, writer, key);
            }
        }
    };
}

fn stringLessThan(context: void, lhs: []const u8, rhs: []const u8) bool {
    _ = context;
    return mem.lessThan(u8, lhs, rhs);
}

test "prometheus.registry: getOrCreateCounter" {
    var registry = Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    const name = try fmt.allocPrint(testing.allocator, "http_requests{{status=\"{d}\"}}", .{500});
    defer testing.allocator.free(name);

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var counter = try registry.getOrCreateCounter(name);
        counter.inc();
    }

    var counter = try registry.getOrCreateCounter(name);
    try testing.expectEqual(@as(u64, 10), counter.get());
}

test "prometheus.registry: getOrCreateX requires the same type" {
    var registry = Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    const name = try fmt.allocPrint(testing.allocator, "http_requests{{status=\"{d}\"}}", .{500});
    defer testing.allocator.free(name);

    _ = try registry.getOrCreateCounter(name);
    if (registry.getOrCreateGauge(name, u64)) |_| try testing.expect(false) else |_| {}
}

test "prometheus.registry: write" {
    const TestCase = struct {
        counter_name: []const u8,
        gauge_name: []const u8,
        gauge_fn_name: []const u8,
        histogram_name: []const u8,
        exp: []const u8,
    };

    const exp1 =
        \\http_conn_pool_size 4.000000
        \\http_gauge 13
        \\http_request_size_bucket{le="0.005"} 0
        \\http_request_size_bucket{le="0.01"} 0
        \\http_request_size_bucket{le="0.025"} 0
        \\http_request_size_bucket{le="0.05"} 0
        \\http_request_size_bucket{le="0.1"} 0
        \\http_request_size_bucket{le="0.25"} 0
        \\http_request_size_bucket{le="0.5"} 0
        \\http_request_size_bucket{le="1"} 0
        \\http_request_size_bucket{le="2.5"} 1
        \\http_request_size_bucket{le="5"} 1
        \\http_request_size_bucket{le="10"} 2
        \\http_request_size_sum 18.703599999999998
        \\http_request_size_count 3
        \\http_requests 2
        \\
    ;

    const exp2 =
        \\http_conn_pool_size{route="/api/v2/users"} 4.000000
        \\http_gauge{route="/api/v2/users"} 13
        \\http_request_size_bucket{route="/api/v2/users",le="0.005"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.01"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.025"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.05"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.1"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.25"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="0.5"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="1"} 0
        \\http_request_size_bucket{route="/api/v2/users",le="2.5"} 1
        \\http_request_size_bucket{route="/api/v2/users",le="5"} 1
        \\http_request_size_bucket{route="/api/v2/users",le="10"} 2
        \\http_request_size_sum{route="/api/v2/users"} 18.703599999999998
        \\http_request_size_count{route="/api/v2/users"} 3
        \\http_requests{route="/api/v2/users"} 2
        \\
    ;

    const test_cases = &[_]TestCase{
        .{
            .counter_name = "http_requests",
            .gauge_name = "http_gauge",
            .gauge_fn_name = "http_conn_pool_size",
            .histogram_name = "http_request_size",
            .exp = exp1,
        },
        .{
            .counter_name = "http_requests{route=\"/api/v2/users\"}",
            .gauge_name = "http_gauge{route=\"/api/v2/users\"}",
            .gauge_fn_name = "http_conn_pool_size{route=\"/api/v2/users\"}",
            .histogram_name = "http_request_size{route=\"/api/v2/users\"}",
            .exp = exp2,
        },
    };

    inline for (test_cases) |tc| {
        var registry = Registry(.{}).init(testing.allocator);
        defer registry.deinit();

        // Add some counters
        {
            const counter = try registry.getOrCreateCounter(tc.counter_name);
            counter.* = .{ .value = .{ .raw = 2 } };
        }

        // Add some gauges
        {
            const counter = try registry.getOrCreateGauge(tc.gauge_name, u64);
            counter.* = .{ .value = .{ .raw = 13 } };
        }

        // Add some gauge_fns
        {
            _ = try registry.getOrCreateGaugeFn(
                tc.gauge_fn_name,
                @as(f64, 4.0),
                struct {
                    fn get(s: *f64) f64 {
                        return s.*;
                    }
                }.get,
            );
        }

        // Add a histogram
        {
            var histogram = try registry.getOrCreateHistogram(tc.histogram_name, &DEFAULT_BUCKETS);

            histogram.observe(5.0012);
            histogram.observe(12.30240);
            histogram.observe(1.40);
        }

        // Write to a buffer
        {
            var buffer = std.ArrayList(u8).init(testing.allocator);
            defer buffer.deinit();

            try registry.write(testing.allocator, buffer.writer());

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

            try registry.write(testing.allocator, file.writer());

            try file.seekTo(0);
            const file_data = try file.readToEndAlloc(testing.allocator, std.math.maxInt(usize));
            defer testing.allocator.free(file_data);

            try testing.expectEqualStrings(tc.exp, file_data);
        }
    }
}

test "prometheus.registry: options" {
    var registry = Registry(.{ .max_metrics = 1, .max_name_len = 4 }).init(testing.allocator);
    defer registry.deinit();

    {
        try testing.expectError(error.NameTooLong, registry.getOrCreateCounter("hello"));
        _ = try registry.getOrCreateCounter("foo");
    }

    {
        try testing.expectError(error.TooManyMetrics, registry.getOrCreateCounter("bar"));
    }
}

test {
    testing.refAllDecls(@This());
}
