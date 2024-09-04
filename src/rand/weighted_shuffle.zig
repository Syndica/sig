const std = @import("std");
const sig = @import("../lib.zig");

const Random = std.Random;

pub fn WeightedShuffle(comptime T: type) type {
    return struct {
        // Underlying array implementing the tree.
        // tree[i][j] is the sum of all weights in the j'th sub-tree of node i.
        tree: std.ArrayList([FANOUT - 1]T),
        // Current sum of all weights, excluding already sampled ones.
        weight: T,
        // Indices of zero weighted entries.
        zeros: std.ArrayList(usize),

        // Each tree node has FANOUT many child nodes with indices:
        //     (index << BIT_SHIFT) + 1, (index << BIT_SHIFT) + 2, ..., (index << BIT_SHIFT) + FANOUT
        // Conversely, for each node, the parent node is obtained by:
        //     (index - 1) >> BIT_SHIFT
        const BIT_SHIFT: usize = 4;
        const FANOUT: usize = 1 << BIT_SHIFT;
        const BIT_MASK: usize = FANOUT - 1;

        pub fn init(allocator: std.mem.Allocator, weights: []const T) !WeightedShuffle(T) {
            var sum: T = 0;
            var tree = try std.ArrayList([FANOUT - 1]T).initCapacity(
                allocator,
                getTreeSize(weights.len),
            );
            for (0..tree.capacity) |_| try tree.append([_]T{0} ** (FANOUT - 1));
            var zeros = std.ArrayList(usize).init(allocator);
            var num_negative: usize = 0;
            var num_overflow: usize = 0;
            for (weights, 0..) |weight, k| {
                if (!(weight >= 0)) {
                    try zeros.append(k);
                    num_negative += 1;
                    continue;
                } else if (weight == 0) {
                    try zeros.append(k);
                    continue;
                } else if (std.math.maxInt(T) - sum < weight) {
                    try zeros.append(k);
                    num_overflow += 1;
                    continue;
                }
                sum = sum + weight;
                var index = tree.items.len + k;
                while (index != 0) {
                    const offset = index & BIT_MASK;
                    index = (index - 1) >> BIT_SHIFT;
                    if (offset > 0) {
                        tree.items[index][offset - 1] += weight;
                    }
                }
            }
            if (num_negative > 0) {
                std.debug.print("WeightedShuffle: {} negative weights were set to zero.\n", .{num_negative});
            }
            if (num_overflow > 0) {
                std.debug.print("WeightedShuffle: {} weights were set to zero due to overflow.\n", .{num_overflow});
            }
            return .{
                .tree = tree,
                .weight = sum,
                .zeros = zeros,
            };
        }

        pub fn deinit(self: *WeightedShuffle(T)) void {
            self.tree.deinit();
            self.zeros.deinit();
        }

        pub fn clone(self: *const WeightedShuffle(T)) WeightedShuffle(T) {
            return .{
                .tree = self.tree.clone(),
                .weight = self.weight,
                .zeros = self.zeros.clone(),
            };
        }

        // Removes given weight at index k.
        pub fn remove(self: *WeightedShuffle(T), k: usize, weight: T) void {
            std.debug.assert(self.weight >= weight);
            self.weight -= weight;
            var index = self.tree.items.len + k;
            while (index != 0) {
                const offset = index & BIT_MASK;
                index = (index - 1) >> BIT_SHIFT;
                if (offset > 0) {
                    std.debug.assert(self.tree.items[index][offset - 1] >= weight);
                    self.tree.items[index][offset - 1] -= weight;
                }
            }
        }

        // Returns smallest index such that sum of weights[..=k] > val,
        // along with its respective weight.
        pub fn search(self: *const WeightedShuffle(T), _val: T) struct { usize, T } {
            var val = _val;
            if (val < 0) std.debug.print("val: {}\n", .{val});
            std.debug.assert(val >= 0);
            std.debug.assert(val < self.weight);
            var index: usize = 0;
            var weight = self.weight;
            while (index < self.tree.items.len) {
                var continue_to_next_iter = false;
                for (self.tree.items[index], 0..) |node, j| {
                    if (val < node) {
                        weight = node;
                        index = (index << BIT_SHIFT) + j + 1;
                        continue_to_next_iter = true;
                        break;
                    }
                    std.debug.assert(weight >= node);
                    weight -= node;
                    val -= node;
                }
                if (continue_to_next_iter) continue;
                index = (index << BIT_SHIFT) + FANOUT;
            }
            return .{ index - self.tree.items.len, weight };
        }

        pub fn removeIndex(self: *WeightedShuffle(T), k: usize) void {
            var index = self.tree.items.len + k;
            var weight: T = 0;
            while (index != 0) {
                const offset = index & BIT_MASK;
                index = (index - 1) >> BIT_SHIFT;
                if (offset > 0) {
                    if (self.tree.items[index][offset - 1] != weight) {
                        self.remove(k, self.tree.items[index][offset - 1] - weight);
                    } else {
                        self.removeZero(k);
                    }
                    return;
                }
                for (self.tree.items[index]) |node| {
                    weight += node;
                }
            }
            if (self.weight != weight) {
                self.remove(k, self.weight - weight);
            } else {
                self.removeZero(k);
            }
        }

        pub fn removeZero(self: *WeightedShuffle(T), k: usize) void {
            // TODO: Replace with better implementation.
            var found = false;
            for (self.zeros.items, 0..) |i, j| {
                if (i == k) {
                    found = true;
                } else if (found) {
                    self.zeros.items[j - 1] = j;
                }
            }
            if (found) _ = self.zeros.pop();
        }

        /// Returns the index of the first sampled weight.
        /// The function is non-destructive and does not remove the weights from the internal state.
        pub fn first(self: *const WeightedShuffle(T), rng: Random) ?usize {
            if (self.weight > 0) {
                const sample = uintLessThan(T, rng, self.weight);
                const index, _ = self.search(sample);
                return index;
            }
            if (self.zeros.items.len == 0) {
                return null;
            }
            const index = uintLessThan(usize, rng, self.zeros.items.len);
            return self.zeros.items[index];
        }

        /// Returns a shuffled list of weights.
        /// The function is destructive and removes the weights from the internal state.
        pub fn shuffle(self: *WeightedShuffle(T), rng: Random) Iterator {
            return .{
                .shuffle = self,
                .rng = rng,
                .index = 0,
            };
        }

        fn getTreeSize(count: usize) usize {
            var size: usize = if (count == 1) 1 else 0;
            var nodes: usize = 1;
            while (nodes < count) {
                size += nodes;
                nodes *= FANOUT;
            }
            return size;
        }

        /// Custom Rng downsampling function designed to match the agave sampler used
        /// in the agave implementation of the weighted shuffle.
        fn uintLessThan(comptime I: type, rng: Random, less_than: I) I {
            const unsigned = switch (I) {
                i8, u8 => u8,
                i16, u16 => u16,
                i32, u32 => u32,
                i64, u64 => u64,
                i128, u128 => u128,
                isize, usize => usize,
                else => @panic("Unsupported signed integer type"),
            };

            const unsigned_large = switch (unsigned) {
                u8, u16, u32 => u32,
                else => unsigned,
            };

            const bits = @typeInfo(I).Int.bits;
            const range: unsigned_large = @intCast(less_than);
            if (range == 0) return rng.int(I);

            const zone: unsigned_large = if (std.math.maxInt(unsigned) <= std.math.maxInt(u16)) blk: {
                const unsigned_max = std.math.maxInt(unsigned_large);
                const ints_to_reject = (unsigned_max - range + 1) % range;
                break :blk unsigned_max - ints_to_reject;
            } else blk: {
                break :blk (range << @truncate(@clz(range))) -% 1;
            };

            while (true) {
                const v = rng.int(unsigned_large);
                const m = std.math.mulWide(unsigned_large, v, range);
                const lo: unsigned_large = @truncate(m);
                const hi: unsigned = @truncate(m >> bits);
                if (lo <= zone) {
                    return @intCast(hi);
                }
            }
        }

        const Iterator = struct {
            shuffle: *WeightedShuffle(T),
            rng: Random,
            index: usize = 0,

            pub fn next(self: *Iterator) ?usize {
                if (self.shuffle.weight > 0) {
                    const sample = uintLessThan(T, self.rng, self.shuffle.weight);
                    const index, const weight = self.shuffle.search(sample);
                    self.shuffle.remove(index, weight);
                    self.index += 1;
                    return index;
                }
                if (self.shuffle.zeros.items.len == 0) return null;
                self.index += 1;
                const index = uintLessThan(usize, self.rng, self.shuffle.zeros.items.len);
                return self.shuffle.zeros.swapRemove(index);
            }

            pub fn consume(self: *Iterator) void {
                while (self.next() != null) {}
            }

            pub fn count(self: *Iterator) usize {
                self.consume();
                return self.index;
            }

            pub fn asArrayList(self: *Iterator, allocator: std.mem.Allocator) !std.ArrayList(usize) {
                var list = std.ArrayList(usize).init(allocator);
                while (self.next()) |k| {
                    try list.append(k);
                }
                return list;
            }
        };
    };
}

const ChaChaRng = sig.rand.ChaChaRng(20);

test "WeightedShuffle.uintLessThan" {
    const seed = [_]u8{1} ** 32;
    var chacha = ChaChaRng.fromSeed(seed);
    const rng = chacha.random();

    for (0..1000) |_| {
        const val = WeightedShuffle(i32).uintLessThan(u64, rng, 1);
        try std.testing.expect(val == 0);
    }
}

test "WeightedShuffle.getTreeSize" {
    try std.testing.expectEqual(WeightedShuffle(u64).getTreeSize(0), 0);
    for (1..17) |count| {
        try std.testing.expectEqual(WeightedShuffle(u64).getTreeSize(count), 1);
    }
    for (17..257) |count| {
        try std.testing.expectEqual(WeightedShuffle(u64).getTreeSize(count), 1 + 16);
    }
    for (257..4097) |count| {
        try std.testing.expectEqual(WeightedShuffle(u64).getTreeSize(count), 1 + 16 + 16 * 16);
    }
    for (4097..65537) |count| {
        try std.testing.expectEqual(WeightedShuffle(u64).getTreeSize(count), 1 + 16 + 16 * 16 + 16 * 16 * 16);
    }
}

test "WeightedShuffle: empty weights" {
    const allocator = std.testing.allocator;
    const weights = [_]u64{};
    var default = std.rand.DefaultPrng.init(0);
    const rng = default.random();

    var shuffle = try WeightedShuffle(u64).init(allocator, &weights);
    defer shuffle.deinit();
    try std.testing.expectEqual(shuffle.first(rng), null);

    var shuffled = shuffle.shuffle(rng);
    try std.testing.expectEqual(shuffled.count(), 0);
}

test "WeightedShuffle: zero weights" {
    const weights = [_]u64{ 0, 0, 0, 0, 0 };
    const seed = [_]u8{37} ** 32;
    var chacha = ChaChaRng.fromSeed(seed);
    const rng = chacha.random();

    var shuffle = try WeightedShuffle(u64).init(std.testing.allocator, &weights);
    defer shuffle.deinit();

    var shuffled = shuffle.shuffle(rng);
    const actual = try shuffled.asArrayList(std.testing.allocator);
    defer actual.deinit();
    try std.testing.expectEqualSlices(
        usize,
        &[_]usize{ 1, 4, 2, 3, 0 },
        actual.items,
    );
}

test "WeightedShuffle: sanity check" {
    const weights = [_]i32{ 1, 0, 1000, 0, 0, 10, 100, 0 };
    var seed = [_]u8{1} ** 32;
    for (1..32) |i| seed[i] = seed[i - 1] + 3;
    var chacha = ChaChaRng.fromSeed(seed);
    const rng = chacha.random();

    var counts = [_]usize{0} ** 8;
    for (0..100_000) |_| {
        var shuffle = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        var shuffled = shuffle.shuffle(rng);
        counts[shuffled.next().?] += 1;
        shuffled.consume();
    }

    try std.testing.expectEqualSlices(
        usize,
        &[_]usize{ 95, 0, 90069, 0, 0, 908, 8928, 0 },
        &counts,
    );

    counts = [_]usize{0} ** 8;
    for (0..100_000) |_| {
        var shuffle = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        shuffle.removeIndex(5);
        shuffle.removeIndex(3);
        shuffle.removeIndex(1);
        var shuffled = shuffle.shuffle(rng);
        counts[shuffled.next().?] += 1;
        shuffled.consume();
    }

    try std.testing.expectEqualSlices(
        usize,
        &[_]usize{ 97, 0, 90862, 0, 0, 0, 9041, 0 },
        &counts,
    );
}

test "WeightedShuffle: negatvie overflow" {
    const seed = [_]u8{48} ** 32;

    {
        const weights = [_]i64{ 19, 23, 7, 0, 0, 23, 3, 0, 5, 0, 19, 29 };
        var chacha = ChaChaRng.fromSeed(seed);
        const rng = chacha.random();

        var shuffle = try WeightedShuffle(i64).init(std.testing.allocator, &weights);
        defer shuffle.deinit();

        var shuffled = shuffle.shuffle(rng);
        const actual = try shuffled.asArrayList(std.testing.allocator);
        defer actual.deinit();
        try std.testing.expectEqualSlices(
            usize,
            &[_]usize{ 8, 1, 5, 10, 11, 0, 2, 6, 9, 4, 3, 7 },
            actual.items,
        );
    }

    {
        const max = std.math.maxInt(i64);
        const weights = [_]i64{ 19, 23, 7, -57, max, 23, 3, max, 5, -79, 19, 29 };
        var chacha = ChaChaRng.fromSeed(seed);
        const rng = chacha.random();

        var shuffle = try WeightedShuffle(i64).init(std.testing.allocator, &weights);
        defer shuffle.deinit();

        var shuffled = shuffle.shuffle(rng);
        const actual = try shuffled.asArrayList(std.testing.allocator);
        defer actual.deinit();
        try std.testing.expectEqualSlices(
            usize,
            &[_]usize{ 8, 1, 5, 10, 11, 0, 2, 6, 9, 4, 3, 7 },
            actual.items,
        );
    }
}

// TODO: Implement remaining tests from agave
// fn test_weighted_shuffle_hard_coded()
// fn test_weighted_shuffle_match_slow()
// fn test_weighted_shuffle_paranoid()
