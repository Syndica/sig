const std = @import("std");
const fmt = std.fmt;
const math = std.math;
const mem = std.mem;
const testing = std.testing;

const Metric = @import("metric.zig").Metric;
const HistogramResult = @import("metric.zig").HistogramResult;

const e10_min = -9;
const e10_max = 18;
const buckets_per_decimal = 18;
const decimal_buckets_count = e10_max - e10_min;
const buckets_count = decimal_buckets_count * buckets_per_decimal;

const lower_bucket_range = blk: {
    var buf: [64]u8 = undefined;
    break :blk fmt.bufPrint(&buf, "0...{e:.3}", .{math.pow(f64, 10, e10_min)}) catch unreachable;
};
const upper_bucket_range = blk: {
    var buf: [64]u8 = undefined;
    break :blk fmt.bufPrint(&buf, "{e:.3}...+Inf", .{math.pow(f64, 10, e10_max)}) catch unreachable;
};

const bucket_ranges: [buckets_count][]const u8 = blk: {
    const bucket_multiplier = math.pow(f64, 10.0, 1.0 / @as(f64, buckets_per_decimal));

    var v = math.pow(f64, 10, e10_min);

    var start = blk2: {
        var buf: [64]u8 = undefined;
        break :blk2 fmt.bufPrint(&buf, "{e:.3}", .{v}) catch unreachable;
    };

    var result: [buckets_count][]const u8 = undefined;
    for (&result) |*range| {
        v *= bucket_multiplier;

        const end = blk3: {
            var buf: [64]u8 = undefined;
            break :blk3 fmt.bufPrint(&buf, "{e:.3}", .{v}) catch unreachable;
        };

        range.* = start ++ "..." ++ end;

        start = end;
    }

    break :blk result;
};

test "bucket ranges" {
    try testing.expectEqualStrings("0...1.000e-09", lower_bucket_range);
    try testing.expectEqualStrings("1.000e+18...+Inf", upper_bucket_range);

    try testing.expectEqualStrings("1.000e-09...1.136e-09", bucket_ranges[0]);
    try testing.expectEqualStrings("1.136e-09...1.292e-09", bucket_ranges[1]);
    try testing.expectEqualStrings("8.799e-09...1.000e-08", bucket_ranges[buckets_per_decimal - 1]);
    try testing.expectEqualStrings("1.000e-08...1.136e-08", bucket_ranges[buckets_per_decimal]);
    try testing.expectEqualStrings("8.799e-01...1.000e+00", bucket_ranges[buckets_per_decimal * (-e10_min) - 1]);
    try testing.expectEqualStrings("1.000e+00...1.136e+00", bucket_ranges[buckets_per_decimal * (-e10_min)]);
    try testing.expectEqualStrings("8.799e+17...1.000e+18", bucket_ranges[buckets_per_decimal * (e10_max - e10_min) - 1]);
}

/// Histogram based on https://github.com/VictoriaMetrics/metrics/blob/master/histogram.go.
pub const Histogram = struct {
    const Self = @This();

    metric: Metric = .{
        .getResultFn = getResult,
    },

    mutex: std.Thread.Mutex = .{},
    decimal_buckets: [decimal_buckets_count][buckets_per_decimal]u64 = undefined,

    lower: u64 = 0,
    upper: u64 = 0,

    sum: f64 = 0.0,

    pub fn init(allocator: mem.Allocator) !*Self {
        const self = try allocator.create(Self);

        self.* = .{};
        for (&self.decimal_buckets) |*bucket| {
            @memset(bucket, 0);
        }

        return self;
    }

    pub fn update(self: *Self, value: f64) void {
        if (math.isNan(value) or value < 0) {
            return;
        }

        const bucket_idx: f64 = (math.log10(value) - e10_min) * buckets_per_decimal;

        // Keep a lock while updating the histogram.
        self.mutex.lock();
        defer self.mutex.unlock();

        self.sum += value;

        if (bucket_idx < 0) {
            self.lower += 1;
        } else if (bucket_idx >= buckets_count) {
            self.upper += 1;
        } else {
            const idx: usize = blk: {
                const tmp: usize = @intFromFloat(bucket_idx);

                if (bucket_idx == @as(f64, @floatFromInt(tmp)) and tmp > 0) {
                    // Edge case for 10^n values, which must go to the lower bucket
                    // according to Prometheus logic for `le`-based histograms.
                    break :blk tmp - 1;
                } else {
                    break :blk tmp;
                }
            };

            const decimal_bucket_idx = idx / buckets_per_decimal;
            const offset = idx % buckets_per_decimal;

            var bucket: []u64 = &self.decimal_buckets[decimal_bucket_idx];
            bucket[offset] += 1;
        }
    }

    pub fn get(self: *const Self) u64 {
        _ = self;
        return 0;
    }

    fn isBucketAllZero(bucket: []const u64) bool {
        for (bucket) |v| {
            if (v != 0) return false;
        }
        return true;
    }

    fn getResult(metric: *Metric, allocator: mem.Allocator) Metric.Error!Metric.Result {
        const self = @fieldParentPtr(Histogram, "metric", metric);

        // Arbitrary maximum capacity
        var buckets = try std.ArrayList(HistogramResult.Bucket).initCapacity(allocator, 16);
        var count_total: u64 = 0;

        // Keep a lock while querying the histogram.
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.lower > 0) {
            try buckets.append(.{
                .vmrange = lower_bucket_range,
                .count = self.lower,
            });
            count_total += self.lower;
        }

        for (&self.decimal_buckets, 0..) |bucket, decimal_bucket_idx| {
            if (isBucketAllZero(&bucket)) continue;

            for (bucket, 0..) |count, offset| {
                if (count <= 0) continue;

                const bucket_idx = (decimal_bucket_idx * buckets_per_decimal) + offset;
                const vmrange = bucket_ranges[bucket_idx];

                try buckets.append(.{
                    .vmrange = vmrange,
                    .count = count,
                });
                count_total += count;
            }
        }

        if (self.upper > 0) {
            try buckets.append(.{
                .vmrange = upper_bucket_range,
                .count = self.upper,
            });
            count_total += self.upper;
        }

        return Metric.Result{
            .histogram = .{
                .buckets = try buckets.toOwnedSlice(),
                .sum = .{ .value = self.sum },
                .count = count_total,
            },
        };
    }
};

test "write empty" {
    var histogram = try Histogram.init(testing.allocator);
    defer testing.allocator.destroy(histogram);

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    var metric = &histogram.metric;
    try metric.write(testing.allocator, buffer.writer(), "myhistogram");

    try testing.expectEqual(@as(usize, 0), buffer.items.len);
}

test "update then write" {
    var histogram = try Histogram.init(testing.allocator);
    defer testing.allocator.destroy(histogram);

    var i: usize = 98;
    while (i < 218) : (i += 1) {
        histogram.update(@floatFromInt(i));
    }

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    var metric = &histogram.metric;
    try metric.write(testing.allocator, buffer.writer(), "myhistogram");

    const exp =
        \\myhistogram_bucket{vmrange="8.799e+01...1.000e+02"} 3
        \\myhistogram_bucket{vmrange="1.000e+02...1.136e+02"} 13
        \\myhistogram_bucket{vmrange="1.136e+02...1.292e+02"} 16
        \\myhistogram_bucket{vmrange="1.292e+02...1.468e+02"} 17
        \\myhistogram_bucket{vmrange="1.468e+02...1.668e+02"} 20
        \\myhistogram_bucket{vmrange="1.668e+02...1.896e+02"} 23
        \\myhistogram_bucket{vmrange="1.896e+02...2.154e+02"} 26
        \\myhistogram_bucket{vmrange="2.154e+02...2.448e+02"} 2
        \\myhistogram_sum 18900
        \\myhistogram_count 120
        \\
    ;

    try testing.expectEqualStrings(exp, buffer.items);
}

test "update then write with labels" {
    var histogram = try Histogram.init(testing.allocator);
    defer testing.allocator.destroy(histogram);

    var i: usize = 98;
    while (i < 218) : (i += 1) {
        histogram.update(@floatFromInt(i));
    }

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    var metric = &histogram.metric;
    try metric.write(testing.allocator, buffer.writer(), "myhistogram{route=\"/api/v2/users\"}");

    const exp =
        \\myhistogram_bucket{route="/api/v2/users",vmrange="8.799e+01...1.000e+02"} 3
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.000e+02...1.136e+02"} 13
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.136e+02...1.292e+02"} 16
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.292e+02...1.468e+02"} 17
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.468e+02...1.668e+02"} 20
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.668e+02...1.896e+02"} 23
        \\myhistogram_bucket{route="/api/v2/users",vmrange="1.896e+02...2.154e+02"} 26
        \\myhistogram_bucket{route="/api/v2/users",vmrange="2.154e+02...2.448e+02"} 2
        \\myhistogram_sum{route="/api/v2/users"} 18900
        \\myhistogram_count{route="/api/v2/users"} 120
        \\
    ;

    try testing.expectEqualStrings(exp, buffer.items);
}
