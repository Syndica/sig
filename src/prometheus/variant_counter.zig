const std = @import("std");
const prometheus = @import("lib.zig");

const Atomic = std.atomic.Value;

const Metric = prometheus.metric.Metric;
const MetricType = prometheus.metric.MetricType;

/// Separately count the occurrence of each variant within an enum or error set.
///
/// This is a composite metric, similar to a histogram, except the "buckets" are
/// discrete, unordered, and identified by name, instead of representing numeric ranges.
pub fn VariantCounter(comptime EnumOrError: type) type {
    const indexer = VariantIndexer.init(EnumOrError);
    const names = indexer.names();

    return struct {
        counts: [names.len]Atomic(u64) = .{Atomic(u64).init(0)} ** names.len,
        metric: Metric = .{ .getResultFn = getResult },

        const Self = @This();

        pub const metric_type: MetricType = .variant_counter;
        pub const Type = EnumOrError;

        pub fn observe(self: *Self, err: EnumOrError) void {
            _ = self.counts[indexer.index(err)].fetchAdd(1, .monotonic);
        }

        pub fn getResult(metric: *Metric, _: std.mem.Allocator) Metric.Error!Metric.Result {
            const self: *Self = @fieldParentPtr("metric", metric);
            return .{ .variant_counter = .{
                .counts = &self.counts,
                .names = &names,
            } };
        }
    };
}

pub const VariantCounts = struct {
    counts: []const Atomic(u64),
    names: []const []const u8,
};

/// Assigns a continuous sequence of integers starting at 0 to the
/// variants. For example, if you have an variant set with 10 variants,
/// it will assign the numbers 0-9 to each of the variants.
///
/// Enums usually already have numbers with this property, but it's
/// not guaranteed. This is particularly useful for errors, whose
/// integers are likely not continuous.
///
/// Call `index` to determine the index for a variant.
///
/// This struct must be initialized at comptime, but it can be used
/// at any time.
const VariantIndexer = struct {
    EnumOrError: type,
    offset: u16,
    index_to_int: []const u16,
    int_to_index: []const u16,
    len: usize,

    const Self = @This();

    pub fn init(comptime EnumOrError: type) Self {
        const variants = switch (@typeInfo(EnumOrError)) {
            .ErrorSet => |es| es.?,
            .Enum => |e| e.fields,
            else => @compileError(@typeName(EnumOrError) ++ " is neither error nor enum"),
        };

        // get min and max to determine array bounds and offset
        var max: u16 = 0;
        var min: u16 = std.math.maxInt(u16);
        for (variants) |variant| {
            const int = toInt(@field(EnumOrError, variant.name));
            max = @max(max, int);
            min = @min(min, int);
        }
        const offset = min;

        // populate maps translating between the index and the variant's int representation
        var init_index_to_int: [variants.len]u16 = undefined;
        var init_int_to_index: [1 + max - min]u16 = undefined;
        for (variants, 0..) |variant, i| {
            const int = toInt(@field(EnumOrError, variant.name));
            init_index_to_int[i] = int;
            init_int_to_index[int - offset] = @intCast(i);
        }
        const index_to_int = init_index_to_int;
        const int_to_index = init_int_to_index;

        return .{
            .EnumOrError = EnumOrError,
            .offset = offset,
            .index_to_int = &index_to_int,
            .int_to_index = &int_to_index,
            .len = index_to_int.len,
        };
    }

    pub fn index(self: Self, err: self.EnumOrError) usize {
        return self.int_to_index[toInt(err) - self.offset];
    }

    pub fn names(self: Self) [self.len][]const u8 {
        var name_array: [self.len][]const u8 = undefined;
        for (0..self.len) |i| {
            name_array[i] = self.toName(self.fromInt(self.index_to_int[i]));
        }
        return name_array;
    }

    fn toInt(err: anytype) u16 {
        return switch (@typeInfo(@TypeOf(err))) {
            .ErrorSet => @intFromError(err),
            .Enum => @intFromEnum(err),
            else => unreachable, // init prevents this
        };
    }

    fn fromInt(self: Self, int: u16) self.EnumOrError {
        return switch (@typeInfo(self.EnumOrError)) {
            .ErrorSet => @errorCast(@errorFromInt(int)),
            .Enum => @enumFromInt(int),
            else => unreachable, // init prevents this
        };
    }

    fn toName(self: Self, item: self.EnumOrError) []const u8 {
        return switch (@typeInfo(self.EnumOrError)) {
            .ErrorSet => @errorName(item),
            .Enum => @tagName(item),
            else => unreachable, // init prevents this
        };
    }
};
