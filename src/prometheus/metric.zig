const std = @import("std");
const fmt = std.fmt;
const mem = std.mem;
const testing = std.testing;

const HistogramSnapshot = @import("histogram.zig").HistogramSnapshot;

pub const Metric = struct {
    pub const Error = error{OutOfMemory} || std.posix.WriteError || std.http.Server.Response.WriteError;

    pub const Result = union(enum) {
        const Self = @This();

        counter: u64,
        gauge: f64,
        gauge_int: u64,
        histogram: HistogramSnapshot,

        pub fn deinit(self: Self, allocator: mem.Allocator) void {
            switch (self) {
                .histogram => |v| {
                    allocator.free(v.buckets);
                },
                else => {},
            }
        }
    };

    getResultFn: *const fn (self: *Metric, allocator: mem.Allocator) Error!Result,

    pub fn write(self: *Metric, allocator: mem.Allocator, writer: anytype, name: []const u8) Error!void {
        const result = try self.getResultFn(self, allocator);
        defer result.deinit(allocator);

        switch (result) {
            .counter, .gauge_int => |v| {
                return try writer.print("{s} {d}\n", .{ name, v });
            },
            .gauge => |v| {
                return try writer.print("{s} {d:.6}\n", .{ name, v });
            },
            .histogram => |v| {
                if (v.buckets.len <= 0) return;

                const name_and_labels = splitName(name);

                if (name_and_labels.labels.len > 0) {
                    for (v.buckets) |bucket| {
                        try writer.print("{s}_bucket{{{s},le=\"{s}\"}} {d:.6}\n", .{
                            name_and_labels.name,
                            name_and_labels.labels,
                            floatMetric(bucket.upper_bound),
                            bucket.cumulative_count,
                        });
                    }
                    try writer.print("{s}_sum{{{s}}} {:.6}\n", .{
                        name_and_labels.name,
                        name_and_labels.labels,
                        floatMetric(v.sum),
                    });
                    try writer.print("{s}_count{{{s}}} {d}\n", .{
                        name_and_labels.name,
                        name_and_labels.labels,
                        v.count,
                    });
                } else {
                    for (v.buckets) |bucket| {
                        try writer.print("{s}_bucket{{le=\"{s}\"}} {d:.6}\n", .{
                            name_and_labels.name,
                            floatMetric(bucket.upper_bound),
                            bucket.cumulative_count,
                        });
                    }
                    try writer.print("{s}_sum {:.6}\n", .{
                        name_and_labels.name,
                        floatMetric(v.sum),
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

/// Converts a float into an anonymous type that can be formatted properly for prometheus.
pub fn floatMetric(value: anytype) struct {
    value: @TypeOf(value),

    pub fn format(self: @This(), comptime format_string: []const u8, options: fmt.FormatOptions, writer: anytype) !void {
        _ = format_string;

        const as_int: u64 = @intFromFloat(self.value);
        if (@as(f64, @floatFromInt(as_int)) == self.value) {
            try fmt.formatInt(as_int, 10, .lower, options, writer);
        } else {
            try fmt.formatFloatDecimal(self.value, options, writer);
        }
    }
} {
    return .{ .value = value };
}

const NameAndLabels = struct {
    name: []const u8,
    labels: []const u8 = "",
};

fn splitName(name: []const u8) NameAndLabels {
    const bracket_pos = mem.indexOfScalar(u8, name, '{');
    if (bracket_pos) |pos| {
        return NameAndLabels{
            .name = name[0..pos],
            .labels = name[pos + 1 .. name.len - 1],
        };
    } else {
        return NameAndLabels{
            .name = name,
        };
    }
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
