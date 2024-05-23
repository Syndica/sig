const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Random = std.Random;

const ChaChaRng = sig.rand.ChaChaRng;

/// Uniformly samples a collection of weighted items. This struct only deals with
/// the weights, and it tells you which index it selects.
///
/// This deterministically selects the same sequence of items as WeightedIndex
/// from the rust crate rand_chacha, assuming you use a compatible pseudo-random
/// number generator.
///
/// Each index's probability of being selected is the ratio of its weight to the
/// sum of all weights.
///
/// For example, for the weights [1, 3, 2], the probability of `sample` returning
/// each index is:
/// 0. -> 1/6
/// 1. -> 1/2
/// 3. -> 1/3
pub fn WeightedRandomSampler(comptime uint: type) type {
    return struct {
        allocator: Allocator,
        random: Random,
        cumulative_weights: []const uint,
        total: uint,

        const Self = @This();

        pub fn init(
            allocator: Allocator,
            random: Random,
            weights: []const uint,
        ) Allocator.Error!Self {
            var cumulative_weights: []uint = try allocator.alloc(uint, weights.len);
            var total: uint = 0;
            for (0..weights.len) |i| {
                total += weights[i];
                cumulative_weights[i] = total;
            }
            return .{
                .allocator = allocator,
                .random = random,
                .cumulative_weights = cumulative_weights,
                .total = total,
            };
        }

        pub fn deinit(self: Self) void {
            self.allocator.free(self.cumulative_weights);
        }

        /// Returns the index of the selected item
        pub fn sample(self: *const Self) uint {
            const want = self.random.uintLessThan(uint, self.total);
            var lower: usize = 0;
            var upper: usize = self.cumulative_weights.len - 1;
            var guess = upper / 2;
            for (0..self.cumulative_weights.len) |_| {
                if (self.cumulative_weights[guess] >= want) {
                    upper = guess;
                } else {
                    lower = guess + 1;
                }
                if (upper == lower) {
                    return upper;
                }
                guess = lower + (upper - lower) / 2;
            }
            unreachable;
        }
    };
}

/// Wrapper for random number generators which generate blocks of [64]u32.
/// Minimizes calls to the underlying random number generator by recycling unused
/// data from previous calls. Port of BlockRng from rust which ensures the same
/// sequence is generated.
pub fn BlockRng(
    comptime T: type,
    comptime generate: fn (*T, *[64]u32) void,
) type {
    return struct {
        results: [64]u32 = undefined,
        index: usize = 64,
        core: T,

        const Self = @This();

        pub fn random(self: *Self) Random {
            return Random.init(self, fill);
        }

        pub fn fill(self: *Self, dest: []u8) void {
            var completed_bytes: usize = 0;
            while (completed_bytes < dest.len) {
                if (self.index >= self.results.len) {
                    generate(&self.core, &self.results);
                    self.index = 0;
                }
                const src: [*]u8 = @ptrCast(self.results[self.index..].ptr);
                const num_u8s = @min(4 * (64 - self.index), dest.len - completed_bytes);
                @memcpy(dest[completed_bytes..][0..num_u8s], src[0..num_u8s]);

                self.index += (num_u8s + 3) / 4;
                completed_bytes += num_u8s;
            }
        }
    };
}

test "WeightedRandomSampler matches rust with chacha" {
    // generate data
    var rng = ChaChaRng(20).fromSeed(.{0} ** 32);
    var random = rng.random();
    var items: [100]u64 = undefined;
    for (0..100) |i| {
        items[i] = @intCast(random.int(u32));
    }

    // run test
    const idx = try WeightedRandomSampler(u64).init(std.testing.allocator, random, &items);
    defer idx.deinit();
    for (0..100) |i| {
        const choice = items[idx.sample()];
        try std.testing.expect(expected_weights[i] == choice);
    }
}

const expected_weights = [_]u64{
    2956161493, 1129244316, 3088700093, 3781961315, 3373288848, 3202811807, 3373288848,
    3848953152, 2448479257, 3848953152, 772637944,  3781961315, 2813985970, 3612365086,
    1651635039, 2419978656, 1300932346, 3678279626, 683509331,  3612365086, 2086224346,
    3678279626, 3328365435, 3230977993, 2115397425, 3478228973, 2687045579, 3438229160,
    1973446681, 3373288848, 2419978656, 4248444456, 1867348299, 4064846400, 3678279626,
    4064846400, 3373288848, 3373288848, 2240211114, 3678279626, 1300932346, 2254827186,
    3848953152, 1867348299, 1194017814, 2254827186, 3373288848, 1651635039, 3328365435,
    3202811807, 3848953152, 2370328401, 3230977993, 2050511189, 2917185654, 3612365086,
    2576249230, 3438229160, 2866421973, 3438229160, 3612365086, 1669812906, 1768285000,
    877052848,  3755235835, 1651635039, 1931970043, 2813985970, 3781961315, 1004543717,
    2702218887, 2419978656, 2576249230, 2229903491, 4248444456, 3984256562, 4248444456,
    3339548555, 2576249230, 3848953152, 1071654007, 4064846400, 772637944,  4248444456,
    2448479257, 2229903491, 4294454303, 2813985970, 2971532662, 147947182,  2370328401,
    1981921065, 3478228973, 1387042214, 3755235835, 3384151174, 2448479257, 1768285000,
    102030521,  1813932776,
};
