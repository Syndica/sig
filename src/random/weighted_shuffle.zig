const std = @import("std");
const sig = @import("../sig.zig");

const ChaCha = sig.crypto.ChaCha;

/// See comment above `SamplerTree.uniform` to understand the difference.
const Mode = enum {
    mod,
    shift,
};

pub fn SamplerTree(mode: Mode) type {
    return struct {
        tree: [1024]Element, // TODO: compute size correctly

        total_count: u64,
        total_weight: u64,
        unremoved_count: u64,
        unremoved_weight: u64,

        internal_node_count: u64,
        height: u64,

        rng: ChaCha(.twenty), // TODO: probably will be making the whole tree structure generic over mode

        const Self = @This();

        /// The Radix of the tree.
        const R = 9;

        const Element = struct {
            left_sum: [R - 1]u64,

            const zero: Element = .{ .left_sum = @splat(0) };
        };

        pub fn init(num_elements: u64, key: [32]u8) Self {
            const height, const internal_count = computeHeight(num_elements);
            return .{
                .tree = @splat(.zero), // zero out the tree

                .total_count = 0,
                .total_weight = 0,
                .unremoved_count = 0,
                .unremoved_weight = 0,

                .internal_node_count = internal_count,
                .height = height,

                .rng = .init(key),
            };
        }

        fn computeHeight(num_elements: u64) struct { u64, u64 } {
            var height: u64 = 0;
            var internal: u64 = 0;
            var powRh: u64 = 1; // R^height
            while (num_elements > powRh) {
                internal += powRh;
                powRh *= R;
                height += 1;
            }
            return .{ height, internal };
        }

        pub fn addWeight(self: *Self, weight: u64) void {
            std.debug.assert(weight != 0);

            var i = self.internal_node_count + self.unremoved_count;
            for (0..self.height) |_| {
                const parent = (i - 1) / R;
                const child_index = (i - 1) - (R * parent); // in [0, R)
                for (child_index..R - 1) |k| self.tree[parent].left_sum[k] += weight;
                i = parent;
            }

            self.unremoved_count += 1;
            self.total_count += 1;
            self.unremoved_weight += weight;
            self.total_weight += weight;
        }

        pub fn sample(self: *Self) !u64 {
            if (self.unremoved_weight == 0) return error.Empty;
            const uniform = self.roll(self.unremoved_weight);
            return self.mapSample(uniform).index;
        }

        const V = @Vector(8, u64);
        const C = @Vector(8, u16);
        const Pair = struct { index: u64, weight: u64 };

        fn mapSample(self: *Self, input: u64) Pair {
            var cursor: u64 = 0;
            var query: u64 = input;
            var S: u64 = self.unremoved_weight;
            for (0..self.height) |_| {
                const e = self.tree[cursor];
                const x: u64 = query;

                // TODO: clean this up, maybe
                const mask = @as(V, e.left_sum) <= @as(V, @splat(x));
                const child_index: u64 = @popCount(@as(u8, @bitCast(mask)));

                // TODO: explore firedancer's branchless approach here, although i doubt i'll use it. perf?
                const li = if (child_index < R - 1) e.left_sum[child_index] else S;
                const lm1 = if (child_index > 0) e.left_sum[child_index - 1] else 0;

                query -= lm1;
                S = li - lm1;
                cursor = (R * cursor) + child_index + 1;
            }
            return .{
                .index = cursor - self.internal_node_count,
                .weight = S,
            };
        }

        pub fn remove(self: *Self, idx: u64) void {
            const weight = self.findWeight(idx);
            self.removePair(.{ .weight = weight, .index = idx });
        }

        fn findWeight(self: *Self, idx: u64) u64 {
            var cursor = idx + self.internal_node_count;
            var lm1: u64 = 0;
            var li: u64 = self.unremoved_weight;

            for (0..self.height) |_| {
                const parent = (cursor - 1) / R;
                const child_index = (cursor - 1) - (R * parent); // in [0, R)

                lm1 += if (child_index > 0) self.tree[parent].left_sum[child_index - 1] else 0;
                if (child_index < R - 1) {
                    li = self.tree[parent].left_sum[child_index];
                    break;
                }

                cursor = parent;
            }

            return li - lm1;
        }

        pub fn removePair(self: *Self, to_remove: Pair) void {
            var cursor = to_remove.index + self.internal_node_count;

            for (0..self.height) |_| {
                const parent = (cursor - 1) / R;
                const child_index = (cursor - 1) - (R * parent); // in [0, R)

                const indices: C = @splat(@truncate(child_index));
                const weight: V = @splat(to_remove.weight);
                const left_sum: V = self.tree[parent].left_sum;
                self.tree[parent].left_sum = @select(
                    u64,
                    indices < std.simd.iota(u16, R - 1) + @as(C, @splat(1)),
                    left_sum -% weight,
                    left_sum,
                );

                cursor = parent;
            }
            self.unremoved_count -= 1;
            self.unremoved_weight -= to_remove.weight;
        }

        pub fn sampleAndRemove(self: *Self) !u64 {
            if (self.unremoved_weight == 0) return error.Empty;
            const uniform = self.roll(self.unremoved_weight);
            const pair = self.mapSample(uniform);
            self.removePair(pair);
            return pair.index;
        }

        /// Returns an uniform independant and identically distributed integer (IDD) in [0, N)
        ///
        /// A bit of a description on how it works,
        ///
        /// We want to generate a uniform random integer in [0, N), starting from a 64-bit uniform
        /// integer v ∈ [0, 2^64).
        ///
        /// The problem:
        /// ---
        /// If 2^64 is divisible by n, then mapping v -> v mod n is perfectly uniform.
        /// But usually n /| 2^64, so the naive map v -> v mod n is biased: some residues
        /// occur slightly more often.
        ///
        /// The solution is something known as "rejection sampling":
        /// ---
        /// We choose an interval [0, zone] inside [0, 2^64) such that the size of the interval
        /// is a multiple of n. Then we accept v if v <= zone and output (v mod n). Otherwise,
        /// we reject and resample.
        ///
        /// - We need k such that k * N <= 2^64.
        /// - Then [0, k * n) is divisble into equal-size classes of n.
        /// - Define zone = k * n - 1, so that the accepted interval [0, zone] has length exactly k * n.
        /// - Every residue in [0, n) appears exactly k times, giving uniformity.
        ///
        /// Agave uses two different modes, `mod` for the leader schedule and `shift` for the turbine tree.
        /// - `mod`:
        ///     - Choose the largest possible k = floor(2^64 / n).
        ///     - Then zone = k * n - 1 = 2^64 - (2^64 mod n) - 1.
        ///     - This gives the widest possible acceptance interval, so the expected number of rejections is minimized.
        ///     - The downside of this approach is that computing the zone requires a modulus operation.
        /// (Used in leader schedule where time isn't as big of a factor)
        ///
        /// - `shift`:
        ///     - Choose k to be the largest power of two with k * n <= 2^64 (equivalently, the smallest
        /// power of two with k * n >= 2^63).
        ///     - This removes the modulus from the hot path, since these powers of two are just shifts.
        ///     - The downside of this approach is that the acceptance interval [0, k * n) is slightly larger,
        /// so the expected number of resamples is larger.
        ///
        /// Instead of computing v mod n, we can compute floor(v * n / 2^64). This maps [0, 2^64) to [0, n),
        /// but rejectionis still needed to discard values outside [0, zone].
        ///
        /// Compatible with `<rand_chacha::ChaCha20Rng as rand::Rng>::gen<rand::distributions::Uniform<u64>>()`.
        pub fn roll(self: *Self, n: u64) u64 {
            std.debug.assert(n != 0); // not really needed since we don't use `bsr`, but still helps.
            std.debug.assert(n != std.math.maxInt(u64));

            const max: u64 = std.math.maxInt(u64);
            const zone: u64 = switch (mode) {
                .mod => max - ((0 -% n) % n),
                .shift => (n << @intCast(@clz(n))) - 1,
            };

            while (true) {
                const v: u128 = self.rng.int();
                const result = v * n; // compiles down to a `mulx`
                const hi: u64 = @intCast(result >> 64);
                const lo: u64 = @truncate(result);

                if (lo <= zone) return hi;
            }
        }
    };
}

test "roll shift" {
    var sampler = SamplerTree(.shift).init(0, @splat(0x41));

    for ([_]u64{ 8, 7, 2, 5, 7, 6, 5, 6, 9, 6 }) |expected| {
        try std.testing.expectEqual(expected, sampler.roll(10));
    }

    for ([_]u64{
        3252524226, 3847107912, 2388546007, 1795840680, 1493882641,
        2627412178, 2509655068, 2770564418, 368683988,  318451188,
    }) |expected| {
        try std.testing.expectEqual(expected, sampler.roll(4294967231));
    }
}

test "roll mod" {
    var sampler = SamplerTree(.mod).init(0, @splat(0x41));

    for ([_]u64{ 8, 7, 1, 2, 5, 7, 6, 2, 9, 5 }) |expected| {
        try std.testing.expectEqual(expected, sampler.roll(10));
    }

    for ([_]u64{
        2659576357, 4036770383, 2578672018, 3252524226, 3847107912,
        2388546007, 1795840680, 1493882641, 2627412178, 2509655068,
    }) |expected| {
        try std.testing.expectEqual(expected, sampler.roll(4294967231));
    }
}

// TODO
// test "iterated" {
//     // if (!sig.build_options.long_tests) return error.SkipZigTest;
//     var chacha = ChaCha(.twenty).init(@splat(0x41));
//     var n: u64 = 100000000;
//     for (0..1000000000) |_| n = 3 *% chacha.uniform(.mod, n) + 3;
//     try std.testing.expectEqual(10620388038139726539, n);
// }

test "SamplerTree solana" {
    {
        var tree = SamplerTree(.mod).init(2, @splat(0));

        tree.addWeight(2);
        tree.addWeight(1);

        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(1, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
        try std.testing.expectEqual(0, try tree.sample());
    }

    {
        var tree = SamplerTree(.shift).init(18, @splat(48));
        for ([_]u64{
            78, 70, 38, 27, 21, 82, 42, 21, 77,
            77, 17, 4,  50, 96, 83, 33, 16, 72,
        }) |weight| tree.addWeight(weight);

        for ([_]u64{
            9, 3,  12, 15, 0,  8,  16, 5, 2,
            1, 14, 6,  11, 13, 17, 10, 4, 7,
        }) |expected| {
            try std.testing.expectEqual(expected, try tree.sampleAndRemove());
        }
    }
}

test "SamplerTree remove idx" {
    var tree = SamplerTree(.shift).init(2, @splat(0));
    tree.addWeight(2);
    tree.addWeight(1);

    tree.remove(1);
    for (0..10) |_| try std.testing.expect(try tree.sample() != 1);

    tree.remove(1); // shouldn't do anything because we aleady removed 1
    for (0..10) |_| try std.testing.expect(try tree.sample() == 0);

    try std.testing.expectEqual(0, try tree.sampleAndRemove());
}
