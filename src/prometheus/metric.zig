const std = @import("std");
const prometheus = @import("lib.zig");

const fmt = std.fmt;
const mem = std.mem;
const testing = std.testing;

const HistogramSnapshot = prometheus.histogram.HistogramSnapshot;
const VariantCounts = prometheus.variant_counter.VariantCounts;

pub const Metric = struct {
    pub const Error =
        std.mem.Allocator.Error ||
        std.posix.WriteError;

    pub const Result = union(enum) {
        counter: u64,
        gauge: f64,
        gauge_int: u64,
        histogram: HistogramSnapshot,
        variant_counter: VariantCounts,

        pub fn deinit(self: Result, allocator: mem.Allocator) void {
            switch (self) {
                .histogram => |v| {
                    allocator.free(v.buckets);
                },
                else => {},
            }
        }
    };

    getResultFn: *const fn (self: *Metric, allocator: mem.Allocator) Error!Result,

    pub fn write(
        self: *Metric,
        allocator: mem.Allocator,
        writer: *std.Io.Writer,
        name: []const u8,
    ) (std.Io.Writer.Error || Error)!void {
        const result = try self.getResultFn(self, allocator);
        defer result.deinit(allocator);

        switch (result) {
            .counter, .gauge_int => |v| {
                return try writer.print("{s} {d}\n", .{ name, v });
            },
            .gauge => |v| {
                return try writer.print("{s} {d:.6}\n", .{ name, v });
            },
            .variant_counter => |counts| {
                for (counts.counts, counts.names) |counter, label| {
                    try writer.print(
                        "{s}_count{{variant=\"{s}\"}} {d}\n",
                        .{ name, label, counter.load(.monotonic) },
                    );
                }
            },
            .histogram => |v| {
                if (v.buckets.len <= 0) return;

                const name_and_labels = splitName(name);

                if (name_and_labels.labels.len > 0) {
                    for (v.buckets) |bucket| {
                        try writer.print("{s}_bucket{{{s},le=\"{d}\"}} {d:.6}\n", .{
                            name_and_labels.name,
                            name_and_labels.labels,
                            bucket.upper_bound,
                            bucket.cumulative_count,
                        });
                    }
                    try writer.print("{s}_sum{{{s}}} {:.6}\n", .{
                        name_and_labels.name,
                        name_and_labels.labels,
                        v.sum,
                    });
                    try writer.print("{s}_count{{{s}}} {d}\n", .{
                        name_and_labels.name,
                        name_and_labels.labels,
                        v.count,
                    });
                } else {
                    for (v.buckets) |bucket| {
                        try writer.print("{s}_bucket{{le=\"{d}\"}} {d:.6}\n", .{
                            name_and_labels.name,
                            bucket.upper_bound,
                            bucket.cumulative_count,
                        });
                    }
                    try writer.print("{s}_sum {:.6}\n", .{
                        name_and_labels.name,
                        v.sum,
                    });
                    try writer.print("{s}_count {d}\n", .{
                        name_and_labels.name,
                        v.count,
                    });
                }
            },
        }
    }
};

pub const MetricType = enum {
    counter,
    variant_counter,
    gauge,
    gauge_fn,
    histogram,
};

const NameAndLabels = struct {
    name: []const u8,
    labels: []const u8 = "",
};

fn splitName(name: []const u8) NameAndLabels {
    const bracket_pos = mem.indexOfScalar(u8, name, '{');
    return if (bracket_pos) |pos| .{
        .name = name[0..pos],
        .labels = name[pos + 1 .. name.len - 1],
    } else .{ .name = name };
}

test "prometheus.metric: ensure splitName works" {
    const TestCase = struct {
        input: []const u8,
        exp: NameAndLabels,
    };

    const test_cases = &[_]TestCase{
        .{
            .input = "foobar",
            .exp = .{
                .name = "foobar",
            },
        },
        .{
            .input = "foobar{route=\"/home\"}",
            .exp = .{
                .name = "foobar",
                .labels = "route=\"/home\"",
            },
        },
        .{
            .input = "foobar{route=\"/home\",status=\"500\"}",
            .exp = .{
                .name = "foobar",
                .labels = "route=\"/home\",status=\"500\"",
            },
        },
    };

    inline for (test_cases) |tc| {
        const res = splitName(tc.input);

        try testing.expectEqualStrings(tc.exp.name, res.name);
        try testing.expectEqualStrings(tc.exp.labels, res.labels);
    }
}
