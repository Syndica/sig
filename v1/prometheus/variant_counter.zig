const std = @import("std");
const prometheus = @import("lib.zig");

const Atomic = std.atomic.Value;

const Metric = prometheus.metric.Metric;
const MetricType = prometheus.metric.MetricType;

/// Separately count the occurrence of each variant within an enum, error set, or tagged union.
///
/// This is a composite metric, similar to a histogram, except the "buckets" are
/// discrete, unordered, and identified by name, instead of representing numeric ranges.
pub fn VariantCounter(comptime T: type) type {
    // If T is a tagged union, index by its tag enum.
    const EnumOrError = switch (@typeInfo(T)) {
        .@"union" => |u| u.tag_type.?,
        else => T,
    };

    const indexer = VariantIndexer.init(EnumOrError);
    const names = indexer.names();

    return struct {
        counts: [names.len]Atomic(u64) = .{Atomic(u64).init(0)} ** names.len,
        metric: Metric = .{ .getResultFn = getResult },

        const Self = @This();

        pub const metric_type: MetricType = .variant_counter;
        /// The observed type.
        pub const ObservedType = T;
        /// The internal tag/error type used for indexing.
        pub const Type = EnumOrError;

        pub fn observe(self: *Self, value: T) void {
            _ = self.counts[indexer.index(value)].fetchAdd(1, .monotonic);
        }

        pub fn reset(self: *Self) void {
            for (&self.counts) |*count| _ = count.store(0, .monotonic);
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

    pub fn init(comptime Item: type) Self {
        // Accept either the enum/error type directly, or a union whose tag is the enum/error.
        const EnumOrError = switch (@typeInfo(Item)) {
            .@"union" => |u| u.tag_type.?,
            else => Item,
        };

        const variants = switch (@typeInfo(EnumOrError)) {
            .error_set => |es| es.?,
            .@"enum" => |e| e.fields,
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
            .error_set => @intFromError(err),
            .@"enum" => @intFromEnum(err),
            else => unreachable, // init prevents this
        };
    }

    fn fromInt(self: Self, int: u16) self.EnumOrError {
        return switch (@typeInfo(self.EnumOrError)) {
            .error_set => @errorCast(@errorFromInt(int)),
            .@"enum" => @enumFromInt(int),
            else => unreachable, // init prevents this
        };
    }

    fn toName(self: Self, item: self.EnumOrError) []const u8 {
        return switch (@typeInfo(self.EnumOrError)) {
            .error_set => @errorName(item),
            .@"enum" => @tagName(item),
            else => unreachable, // init prevents this
        };
    }
};

test "VariantCounter.observe: enum counts" {
    const SwitchForkDecision = enum { Accept, Reject, Ignore };
    const indexer = VariantIndexer.init(SwitchForkDecision);

    var counter = VariantCounter(SwitchForkDecision){};
    // Accept 4 times
    // Reject 3 times
    // Ignore 3 times
    counter.observe(SwitchForkDecision.Accept);
    counter.observe(SwitchForkDecision.Accept);
    counter.observe(SwitchForkDecision.Accept);
    counter.observe(SwitchForkDecision.Reject);
    counter.observe(SwitchForkDecision.Reject);
    counter.observe(SwitchForkDecision.Ignore);
    counter.observe(SwitchForkDecision.Accept);
    counter.observe(SwitchForkDecision.Ignore);
    counter.observe(SwitchForkDecision.Reject);
    counter.observe(SwitchForkDecision.Ignore);

    const counts = counter.counts;

    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Accept)].load(.monotonic) == 4);
    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Reject)].load(.monotonic) == 3);
    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Ignore)].load(.monotonic) == 3);
}

test "VariantCounter.observe: tagged-union counts" {
    const SwitchForkDecision = enum { Accept, Reject, Ignore };
    const DecisionUnion = union(SwitchForkDecision) {
        Accept: u32,
        Reject: []const u8,
        Ignore: void,
    };
    const indexer = VariantIndexer.init(SwitchForkDecision);

    var counter = VariantCounter(DecisionUnion){};
    // Accept 2 times
    // Reject 3 times
    // Ignore 1 time
    counter.observe(DecisionUnion{ .Accept = 42 });
    counter.observe(DecisionUnion{ .Reject = "foo" });
    counter.observe(DecisionUnion{ .Reject = "bar" });
    counter.observe(DecisionUnion{ .Ignore = {} });
    counter.observe(DecisionUnion{ .Accept = 99 });
    counter.observe(DecisionUnion{ .Reject = "baz" });

    const counts = counter.counts;
    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Accept)].load(.monotonic) == 2);
    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Reject)].load(.monotonic) == 3);
    try std.testing.expect(counts[indexer.index(SwitchForkDecision.Ignore)].load(.monotonic) == 1);
}

test "VariantCounter.observe: union(enum) counts" {
    const Hash = [32]u8;
    const Slot = u64;
    const SwitchForkDecision = union(enum) {
        switch_proof: Hash,
        same_fork,
        failed_switch_threshold: struct {
            switch_proof_stake: u64,
            total_stake: u64,
        },
        failed_switch_duplicate_rollback: Slot,
        pub fn canVote(self: *const @This()) bool {
            return switch (self.*) {
                .failed_switch_threshold => false,
                .failed_switch_duplicate_rollback => false,
                .same_fork => true,
                .switch_proof => true,
            };
        }
    };

    const indexer = VariantIndexer.init(SwitchForkDecision);
    var counter = VariantCounter(SwitchForkDecision){};

    // switch_proof 2 times
    counter.observe(SwitchForkDecision{ .switch_proof = [_]u8{0} ** 32 });
    counter.observe(SwitchForkDecision{ .switch_proof = [_]u8{1} ** 32 });

    // same_fork 1 time
    counter.observe(SwitchForkDecision{ .same_fork = {} });

    // failed_switch_threshold 3 times
    counter.observe(
        SwitchForkDecision{
            .failed_switch_threshold = .{ .switch_proof_stake = 10, .total_stake = 100 },
        },
    );
    counter.observe(
        SwitchForkDecision{
            .failed_switch_threshold = .{ .switch_proof_stake = 20, .total_stake = 200 },
        },
    );
    counter.observe(
        SwitchForkDecision{
            .failed_switch_threshold = .{ .switch_proof_stake = 30, .total_stake = 300 },
        },
    );

    // failed_switch_duplicate_rollback 2 times
    counter.observe(SwitchForkDecision{ .failed_switch_duplicate_rollback = 42 });
    counter.observe(SwitchForkDecision{ .failed_switch_duplicate_rollback = 99 });

    const counts = counter.counts;
    try std.testing.expect(
        counts[indexer.index(.switch_proof)].load(.monotonic) == 2,
    );
    try std.testing.expect(
        counts[indexer.index(.same_fork)].load(.monotonic) == 1,
    );
    try std.testing.expect(
        counts[indexer.index(.failed_switch_threshold)].load(.monotonic) == 3,
    );
    try std.testing.expect(
        counts[indexer.index(.failed_switch_duplicate_rollback)].load(.monotonic) == 2,
    );
}
