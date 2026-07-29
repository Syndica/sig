const std = @import("std");
const sig = @import("../sig.zig");

const ChaChaRng = sig.rand.ChaChaRng(20);

/// Implements an iterator where indices are shuffled according to their
/// weights:
///   - Returned indices are unique in the range [0, weights.len()).
///   - Higher weighted indices tend to appear earlier proportional to their
///     weight.
///   - Zero weighted indices are shuffled and appear only at the end, after
///     non-zero weighted indices.
pub fn WeightedShuffle(comptime Int: type) type {
    return struct {
        allocator: std.mem.Allocator,
        // Underlying array implementing the tree.
        // tree[i][j] is the sum of all weights in the j'th sub-tree of node i.
        tree: std.ArrayListUnmanaged([FANOUT - 1]Int),
        // Current sum of all weights, excluding already sampled ones.
        weight: Int,
        // Indices of zero weighted entries.
        zeros: std.ArrayListUnmanaged(usize),

        // Each tree node has FANOUT many child nodes with indices:
        //     (index << BIT_SHIFT) + 1, (index << BIT_SHIFT) + 2, ..., (index << BIT_SHIFT) + FANOUT
        // Conversely, for each node, the parent node is obtained by:
        //     (index - 1) >> BIT_SHIFT
        const BIT_SHIFT: usize = 4;
        const FANOUT: usize = 1 << BIT_SHIFT;
        const BIT_MASK: usize = FANOUT - 1;

        const Self = @This();

        /// If weights are negative or overflow the total sum they are treated as zero.
        pub fn init(allocator: std.mem.Allocator, weights: []const Int) !Self {
            var tree = try std.ArrayListUnmanaged([FANOUT - 1]Int).initCapacity(
                allocator,
                getTreeSize(weights.len),
            );
            for (0..tree.capacity) |_| tree.appendAssumeCapacity([_]Int{0} ** (FANOUT - 1));
            var sum: Int = 0;
            var zeros = try std.ArrayListUnmanaged(usize).initCapacity(
                allocator,
                0,
            );

            var num_negative: usize = 0;
            var num_overflow: usize = 0;
            for (weights, 0..) |weight, k| {
                if (weight < 0) {
                    try zeros.append(allocator, k);
                    num_negative += 1;
                    continue;
                } else if (weight == 0) {
                    try zeros.append(allocator, k);
                    continue;
                } else if (std.math.maxInt(Int) - sum < weight) {
                    try zeros.append(allocator, k);
                    num_overflow += 1;
                    continue;
                }
                sum += weight;
                var index = tree.items.len + k;
                while (index != 0) {
                    const offset = index & BIT_MASK;
                    index = (index - 1) >> BIT_SHIFT;
                    if (offset > 0) {
                        tree.items[index][offset - 1] += weight;
                    }
                }
            }

            // NOTE: datapointerror is recorded here in agave, should we parse a
            // logger and log an error or just ignore it?
            // std.debug.assert(num_negative == 0);
            // std.debug.assert(num_overflow == 0);

            return .{
                .allocator = allocator,
                .tree = tree,
                .weight = sum,
                .zeros = zeros,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tree.deinit(self.allocator);
            self.zeros.deinit(self.allocator);
        }

        pub fn clone(self: *const Self) !Self {
            return .{
                .allocator = self.allocator,
                .tree = try self.tree.clone(self.allocator),
                .weight = self.weight,
                .zeros = try self.zeros.clone(self.allocator),
            };
        }

        // Removes given weight at the specified index
        pub fn remove(self: *Self, index: usize, weight: Int) void {
            std.debug.assert(self.weight >= weight);
            self.weight -= weight;
            // Traverse the tree from the leaf node upwards to the root,
            // updating the sub-tree sums along the way
            var curr_index = self.tree.items.len + index; // leaf node
            while (curr_index != 0) {
                const offset = curr_index & BIT_MASK;
                curr_index = (curr_index - 1) >> BIT_SHIFT; // parent node
                if (offset > 0) {
                    std.debug.assert(self.tree.items[curr_index][offset - 1] >= weight);
                    self.tree.items[curr_index][offset - 1] -= weight;
                }
            }
        }

        // Returns smallest index such that sum of weights[..=k] > val,
        // along with its respective weight.
        pub fn search(self: *const Self, value: Int) struct { usize, Int } {
            var val = value;

            std.debug.assert(val >= 0);
            std.debug.assert(val < self.weight);

            // Traverse the tree downwards from the root while maintaining the
            // weight of the subtree which contains the target leaf node.
            var index: usize = 0;
            var weight = self.weight;
            while (index < self.tree.items.len) {
                const continue_to_next_iter = for (self.tree.items[index], 0..) |node, j| {
                    if (val < node) {
                        // Traverse to the j+1 subtree of self.tree[index].
                        weight = node;
                        index = (index << BIT_SHIFT) + j + 1;
                        break true;
                    }
                    std.debug.assert(weight >= node);
                    weight -= node;
                    val -= node;
                } else false;
                if (continue_to_next_iter) continue;
                // Traverse to the right-most subtree of self.tree[index].
                index = (index << BIT_SHIFT) + FANOUT;
            }
            return .{ index - self.tree.items.len, weight };
        }

        pub fn removeIndex(self: *Self, index: usize) void {
            // Traverse the tree from the leaf node upwards to the root, while
            // maintaining the sum of weights of subtrees *not* containing the leaf node.
            var curr_index = self.tree.items.len + index; // leaf node
            var weight: Int = 0;
            while (curr_index != 0) {
                const offset = curr_index & BIT_MASK;
                curr_index = (curr_index - 1) >> BIT_SHIFT; // parent node
                if (offset > 0) {
                    if (self.tree.items[curr_index][offset - 1] != weight) {
                        self.remove(index, self.tree.items[curr_index][offset - 1] - weight);
                    } else {
                        self.removeZero(index);
                    }
                    return;
                }
                // The leaf node is in the right-most subtree of self.tree[index].
                for (self.tree.items[curr_index]) |node| {
                    weight += node;
                }
            }
            // The leaf node is the right-most node of the whole tree.
            if (self.weight != weight) {
                self.remove(index, self.weight - weight);
            } else {
                self.removeZero(index);
            }
        }

        pub fn removeZero(self: *Self, k: usize) void {
            var found = false;
            for (self.zeros.items, 0..) |i, j| {
                if (i == k) {
                    found = true;
                } else if (found) {
                    self.zeros.items[j - 1] = self.zeros.items[j];
                }
            }
            if (found) _ = self.zeros.pop();
        }

        /// Returns the index of the first sampled weight.
        /// The function is non-destructive and does not remove the weights from the internal state.
        pub fn first(self: *const Self, rng: std.Random) ?usize {
            if (self.weight > 0) {
                const sample = uintLessThanRust(Int, rng, self.weight);
                const index, _ = self.search(sample);
                return index;
            }
            if (self.zeros.items.len == 0) {
                return null;
            }
            const index = uintLessThanRust(usize, rng, self.zeros.items.len);
            return self.zeros.items[index];
        }

        /// Returns an iterator that generates a shuffled list of weights.
        /// The function is destructive and removes the weights from the internal state.
        pub fn shuffle(self: *Self, random: std.Random) Iterator {
            return .{
                .shuffle = self,
                .rng = random,
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

        pub const Iterator = struct {
            shuffle: *Self,
            rng: std.Random,
            index: usize = 0,

            pub fn next(self: *Iterator) ?usize {
                if (self.shuffle.weight > 0) {
                    const sample = uintLessThanRust(Int, self.rng, self.shuffle.weight);
                    const index, const weight = self.shuffle.search(sample);
                    self.shuffle.remove(index, weight);
                    self.index += 1;
                    return index;
                }
                if (self.shuffle.zeros.items.len == 0) return null;
                self.index += 1;
                const index = uintLessThanRust(usize, self.rng, self.shuffle.zeros.items.len);
                return self.shuffle.zeros.swapRemove(index);
            }

            pub fn intoArrayList(
                self: *Iterator,
                allocator: std.mem.Allocator,
            ) !std.array_list.Managed(usize) {
                var list = std.array_list.Managed(usize).init(allocator);
                while (self.next()) |k| {
                    try list.append(k);
                }
                return list;
            }
        };
    };
}

/// Custom Rng downsampling function designed to match the agave sampler used
/// in the agave implementation of the weighted shuffle.
/// For use in place of: <T as SampleUniform>::Sampler::sample_single
pub fn intRangeLessThanRust(comptime T: type, random: std.Random, at_least: T, less_than: T) T {
    const Unsigned, const UnsignedLarge = switch (T) {
        i8, u8 => .{ u8, u32 },
        i16, u16 => .{ u16, u32 },
        i32, u32 => .{u32} ** 2,
        i64, u64 => .{u64} ** 2,
        i128, u128 => .{u128} ** 2,
        isize, usize => .{usize} ** 2,
        else => @compileError("Unsupported signed integer type"),
    };

    const range_t = less_than -% at_least;
    const range_u: Unsigned = @intCast(range_t);
    const range_ul: UnsignedLarge = @intCast(range_u);

    if (range_ul == 0) return random.int(T);

    const zone_ul: UnsignedLarge = if (std.math.maxInt(Unsigned) <= std.math.maxInt(u16)) blk: {
        const unsigned_max = std.math.maxInt(UnsignedLarge);
        const ints_to_reject = (unsigned_max - range_ul + 1) % range_ul;
        break :blk unsigned_max - ints_to_reject;
    } else blk: {
        break :blk (range_ul << @truncate(@clz(range_ul))) -% 1;
    };

    while (true) {
        const v_ul = random.int(UnsignedLarge);
        const tmp = std.math.mulWide(UnsignedLarge, v_ul, range_ul);
        const lo: UnsignedLarge = @truncate(tmp);
        const hi: Unsigned = @truncate(tmp >> @typeInfo(UnsignedLarge).int.bits);
        if (lo <= zone_ul) return at_least + @as(T, @intCast(hi));
    }
}

/// Custom Rng downsampling function designed to match the agave sampler used
/// in the agave implementation of the weighted shuffle.
/// For use in place of: <T as SampleUniform>::Sampler::sample_single
pub fn uintLessThanRust(comptime T: type, random: std.Random, less_than: T) T {
    return intRangeLessThanRust(T, random, 0, less_than);
}

fn testShuffledIndicesMatchExpected(
    T: type,
    random: std.Random,
    shuffle: *WeightedShuffle(T),
    expected_slice: []const usize,
) !void {
    var shuffle_cloned = try shuffle.clone();
    defer shuffle_cloned.deinit();
    var shuffled_iter = shuffle_cloned.shuffle(random);
    const shuffled = try shuffled_iter.intoArrayList(std.testing.allocator);
    defer shuffled.deinit();
    try std.testing.expectEqualSlices(usize, expected_slice, shuffled.items);
}

fn testWeightedShuffleSlow(
    allocator: std.mem.Allocator,
    random: std.Random,
    weights: []u64,
) !std.array_list.Managed(usize) {
    // Initialise high as sum of weights and zeros as indices of zero weights
    var high: u64 = 0;
    var zeros = try std.array_list.Managed(usize).initCapacity(allocator, weights.len);
    defer zeros.deinit();
    for (weights, 0..) |weight, k| {
        if (weight == 0) {
            zeros.appendAssumeCapacity(k);
        } else {
            high += weight;
        }
    }

    // Shuffle indices according to their weights
    var shuffle = try std.array_list.Managed(usize).initCapacity(allocator, weights.len);
    while (high != 0) {
        const sample = uintLessThanRust(u64, random, high);
        var sum: u64 = 0;
        for (weights, 0..) |weight, k| {
            sum += weight;
            if (sum > sample) {
                shuffle.appendAssumeCapacity(k);
                high -= weight;
                weights[k] = 0;
                break;
            }
        }
    }

    // Add zeros to the end
    while (zeros.items.len > 0) {
        const index = uintLessThanRust(usize, random, zeros.items.len);
        shuffle.appendAssumeCapacity(zeros.swapRemove(index));
    }

    return shuffle;
}

test "uintLessThan" {
    const seed = [_]u8{1} ** 32;
    var chacha = ChaChaRng.fromSeed(seed);

    const random = chacha.random();

    try std.testing.expectEqual(12, intRangeLessThanRust(u8, random, 0, 100));
    try std.testing.expectEqual(76, intRangeLessThanRust(u16, random, 0, 100));
    try std.testing.expectEqual(11, intRangeLessThanRust(u32, random, 0, 100));
    try std.testing.expectEqual(52, intRangeLessThanRust(u64, random, 0, 100));
    try std.testing.expectEqual(81, intRangeLessThanRust(u128, random, 0, 100));
    try std.testing.expectEqual(55, intRangeLessThanRust(usize, random, 0, 100));

    try std.testing.expectEqual(82, intRangeLessThanRust(u8, random, 50, 150));
    try std.testing.expectEqual(56, intRangeLessThanRust(u16, random, 50, 150));
    try std.testing.expectEqual(53, intRangeLessThanRust(u32, random, 50, 150));
    try std.testing.expectEqual(77, intRangeLessThanRust(u64, random, 50, 150));
    try std.testing.expectEqual(129, intRangeLessThanRust(u128, random, 50, 150));
    try std.testing.expectEqual(94, intRangeLessThanRust(usize, random, 50, 150));

    try std.testing.expectEqual(-1, intRangeLessThanRust(i8, random, -5, 5));
    try std.testing.expectEqual(3, intRangeLessThanRust(i16, random, -5, 5));
    try std.testing.expectEqual(-4, intRangeLessThanRust(i32, random, -5, 5));
    try std.testing.expectEqual(-4, intRangeLessThanRust(i64, random, -5, 5));
    try std.testing.expectEqual(-1, intRangeLessThanRust(i128, random, -5, 5));
    try std.testing.expectEqual(-1, intRangeLessThanRust(isize, random, -5, 5));
}

test "agave: get tree size" {
    try std.testing.expectEqual(0, WeightedShuffle(u64).getTreeSize(0));
    for (1..17) |count| {
        try std.testing.expectEqual(1, WeightedShuffle(u64).getTreeSize(count));
    }
    for (17..257) |count| {
        try std.testing.expectEqual(1 + 16, WeightedShuffle(u64).getTreeSize(count));
    }
    for (257..4097) |count| {
        try std.testing.expectEqual(1 + 16 + 16 * 16, WeightedShuffle(u64).getTreeSize(count));
    }
    for (4097..65537) |count| {
        try std.testing.expectEqual(
            1 + 16 + 16 * 16 + 16 * 16 * 16,
            WeightedShuffle(u64).getTreeSize(count),
        );
    }
}

test "agave: empty weights" {
    const weights = [_]u64{};

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var shuffle = try WeightedShuffle(u64).init(std.testing.allocator, &weights);
    defer shuffle.deinit();

    var shuffle_cloned = try shuffle.clone();
    defer shuffle_cloned.deinit();
    var shuffle_cloned_iter = shuffle_cloned.shuffle(random);

    try std.testing.expectEqual(shuffle_cloned_iter.next(), null);
    try std.testing.expectEqual(shuffle.first(random), null);
}

test "agave: zero weights" {
    const weights = [_]u64{ 0, 0, 0, 0, 0 };

    const seed = [_]u8{37} ** 32;

    var shuffle = try WeightedShuffle(u64).init(std.testing.allocator, &weights);
    defer shuffle.deinit();

    {
        var chacha = ChaChaRng.fromSeed(seed);
        try testShuffledIndicesMatchExpected(
            u64,
            chacha.random(),
            &shuffle,
            &[_]u64{ 1, 4, 2, 3, 0 },
        );
    }

    {
        var chacha = ChaChaRng.fromSeed(seed);
        try std.testing.expectEqual(1, shuffle.first(chacha.random()));
    }
}

test "agave: sanity check" {
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    const weights = [_]i32{ 1, 0, 1000, 0, 0, 10, 100, 0 };

    var seed = [_]u8{1} ** 32;
    for (1..32) |i| seed[i] = seed[i - 1] + 3;

    var chacha = ChaChaRng.fromSeed(seed);
    const random = chacha.random();

    var counts = [_]usize{0} ** 8;
    for (0..100_000) |_| {
        var shuffle = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        var shuffled = shuffle.shuffle(random);
        counts[shuffled.next().?] += 1;
        while (shuffled.next() != null) {}
    }

    try std.testing.expectEqualSlices(
        usize,
        &[_]usize{ 95, 0, 90069, 0, 0, 908, 8928, 0 },
        &counts,
    );

    @memset(&counts, 0);
    for (0..100_000) |_| {
        var shuffle = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        shuffle.removeIndex(5);
        shuffle.removeIndex(3);
        shuffle.removeIndex(1);
        var shuffled = shuffle.shuffle(random);
        counts[shuffled.next().?] += 1;
        while (shuffled.next() != null) {}
    }

    try std.testing.expectEqualSlices(
        usize,
        &[_]usize{ 97, 0, 90862, 0, 0, 0, 9041, 0 },
        &counts,
    );
}

test "agave: negative overflow" {
    const seed = [_]u8{48} ** 32;
    const expected = [_]usize{ 8, 1, 5, 10, 11, 0, 2, 6, 9, 4, 3, 7 };

    {
        const weights = [_]i64{ 19, 23, 7, 0, 0, 23, 3, 0, 5, 0, 19, 29 };
        var chacha = ChaChaRng.fromSeed(seed);
        var shuffle = try WeightedShuffle(i64).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        try testShuffledIndicesMatchExpected(
            i64,
            chacha.random(),
            &shuffle,
            &expected,
        );
    }

    {
        const max = std.math.maxInt(i64);
        const weights = [_]i64{ 19, 23, 7, -57, max, 23, 3, max, 5, -79, 19, 29 };
        var chacha = ChaChaRng.fromSeed(seed);
        var shuffle = try WeightedShuffle(i64).init(std.testing.allocator, &weights);
        defer shuffle.deinit();
        try testShuffledIndicesMatchExpected(
            i64,
            chacha.random(),
            &shuffle,
            &expected,
        );
    }
}

test "agave: hard coded" {
    const weights = [_]i32{
        78, 70, 38, 27, 21,
        0,  82, 42, 21, 77,
        77, 0,  17, 4,  50,
        96, 0,  83, 33, 16,
        72,
    };

    const seed_a = [_]u8{48} ** 32;
    var shuffle_a = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
    defer shuffle_a.deinit();

    {
        var chacha = ChaChaRng.fromSeed(seed_a);
        try testShuffledIndicesMatchExpected(
            i32,
            chacha.random(),
            &shuffle_a,
            &[_]usize{ 2, 12, 18, 0, 14, 15, 17, 10, 1, 9, 7, 6, 13, 20, 4, 19, 3, 8, 11, 16, 5 },
        );
    }
    {
        var chacha = ChaChaRng.fromSeed(seed_a);
        try std.testing.expectEqual(2, shuffle_a.first(chacha.random()));
    }
    {
        shuffle_a.removeIndex(11);
        shuffle_a.removeIndex(3);
        shuffle_a.removeIndex(15);
        shuffle_a.removeIndex(0);
        var chacha = ChaChaRng.fromSeed(seed_a);
        try testShuffledIndicesMatchExpected(
            i32,
            chacha.random(),
            &shuffle_a,
            &[_]usize{ 4, 6, 1, 12, 19, 14, 17, 20, 2, 9, 10, 8, 7, 18, 13, 5, 16 },
        );
    }
    {
        var chacha = ChaChaRng.fromSeed(seed_a);
        try std.testing.expectEqual(4, shuffle_a.first(chacha.random()));
    }

    const seed_b = [_]u8{37} ** 32;
    var shuffle_b = try WeightedShuffle(i32).init(std.testing.allocator, &weights);
    defer shuffle_b.deinit();

    {
        var chacha = ChaChaRng.fromSeed(seed_b);
        try testShuffledIndicesMatchExpected(
            i32,
            chacha.random(),
            &shuffle_b,
            &[_]usize{ 19, 3, 15, 14, 6, 10, 17, 18, 9, 2, 4, 1, 0, 7, 8, 20, 12, 13, 16, 5, 11 },
        );
    }
    {
        var chacha = ChaChaRng.fromSeed(seed_b);
        try std.testing.expectEqual(19, shuffle_b.first(chacha.random()));
    }
    {
        shuffle_b.removeIndex(16);
        shuffle_b.removeIndex(8);
        shuffle_b.removeIndex(20);
        shuffle_b.removeIndex(5);
        shuffle_b.removeIndex(19);
        shuffle_b.removeIndex(4);
        var chacha = ChaChaRng.fromSeed(seed_b);
        try testShuffledIndicesMatchExpected(
            i32,
            chacha.random(),
            &shuffle_b,
            &[_]usize{ 17, 2, 9, 14, 6, 10, 12, 1, 15, 13, 7, 0, 18, 3, 11 },
        );
    }
    {
        var chacha = ChaChaRng.fromSeed(seed_b);
        try std.testing.expectEqual(17, shuffle_b.first(chacha.random()));
    }
}

test "agave: match slow" {
    // Initialise random weights
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var weights = try std.array_list.Managed(u64).initCapacity(std.testing.allocator, 997);
    defer weights.deinit();
    for (0..997) |_| weights.appendAssumeCapacity(random.intRangeLessThan(u64, 0, 1_000));

    //
    for (0..10) |_| {
        // Create random seed
        var seed: [32]u8 = undefined;
        random.bytes(&seed);

        // Get shuffled indices using the fast implementation
        const shuffled_fast = blk: {
            var chacha = ChaChaRng.fromSeed(seed);
            var shuffle = try WeightedShuffle(u64).init(
                std.testing.allocator,
                weights.items,
            );
            defer shuffle.deinit();
            var shuffle_iter = shuffle.shuffle(chacha.random());
            break :blk try shuffle_iter.intoArrayList(std.testing.allocator);
        };
        defer shuffled_fast.deinit();

        // Get shuffled indices using the slow implementation
        const shuffled_slow = blk: {
            var chacha = ChaChaRng.fromSeed(seed);
            break :blk try testWeightedShuffleSlow(
                std.testing.allocator,
                chacha.random(),
                weights.items,
            );
        };
        defer shuffled_slow.deinit();

        // Compare the two shuffled indices
        try std.testing.expectEqualSlices(usize, shuffled_slow.items, shuffled_fast.items);
    }
}

test "agave: paranoid" {
    // Default rng
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const end = if (sig.build_options.long_tests) 1351 else 3;

    for (0..end) |size| {
        // Create random weights
        var weights = try std.array_list.Managed(u64).initCapacity(std.testing.allocator, size);
        defer weights.deinit();
        for (0..size) |_| weights.appendAssumeCapacity(random.intRangeLessThan(u64, 0, 1_000));

        // Create random seed
        var seed: [32]u8 = undefined;
        random.bytes(&seed);

        // Get shuffled indices using the fast implementation
        const shuffled_fast = blk: {
            var chacha = ChaChaRng.fromSeed(seed);
            var shuffle = try WeightedShuffle(u64).init(std.testing.allocator, weights.items);
            defer shuffle.deinit();
            var shuffle_iter = shuffle.shuffle(chacha.random());
            break :blk try shuffle_iter.intoArrayList(std.testing.allocator);
        };
        defer shuffled_fast.deinit();

        // Get the first shuffled index using the fast implementation
        const maybe_shuffled_fast_first = blk: {
            var chacha = ChaChaRng.fromSeed(seed);
            var shuffle = try WeightedShuffle(u64).init(std.testing.allocator, weights.items);
            defer shuffle.deinit();
            break :blk shuffle.first(chacha.random());
        };

        // Get shuffled indices using the slow implementation
        const shuffled_slow = blk: {
            var chacha = ChaChaRng.fromSeed(seed);
            break :blk try testWeightedShuffleSlow(
                std.testing.allocator,
                chacha.random(),
                weights.items,
            );
        };
        defer shuffled_slow.deinit();

        // Compare the two shuffled indices
        if (maybe_shuffled_fast_first) |shuffled_fast_first| {
            try std.testing.expectEqual(shuffled_slow.items[0], shuffled_fast_first);
        }
        try std.testing.expectEqualSlices(usize, shuffled_slow.items, shuffled_fast.items);
    }
}
