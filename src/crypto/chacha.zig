const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

/// SIMD optimized ChaCha stream cipher implementation.
///
/// - ChaCha operates on a 4x4 matrix of 32-bit words ("state"):
/// ```ascii
///       [  c0   c1   c2   c3 ]   <- constants ("expand 32-byte k")
///       [  k0   k1   k2   k3 ]   <- first 128 bits of key
///       [  k4   k5   k6   k7 ]   <- second 128 bits of key
///       [ ctr   n0   n1   n2 ]   <- block counter + nonce
/// ```
///
/// A "round" applies the "quarter-round" function to:
/// - first the **columns** (vertical)
/// - then the **diagonals** (slanted)
///
/// Repeating this step gives good diffusion over the whole 4x4 matrix and creates a cipher.
///
/// Our implementation groups 4 ChaCha instances together into a "lane". Each `V = @Vector(16, u32)`
/// holds one row across 4 instances.
/// That looks something like:
///```ascii
///     zmm[0] = [ inst0.row0 | inst1.row0 | inst2.row0 | inst3.row0 ]
///     zmm[1] = [ inst0.row1 | inst1.row1 | inst2.row1 | inst3.row1 ]
///     zmm[2] = [ inst0.row2 | inst1.row2 | inst2.row2 | inst3.row2 ]
///     zmm[3] = [ inst0.row3 | inst1.row3 | inst2.row3 | inst3.row3 ]
/// ```
///
/// This layout lets the SIMD quarter-rounds and shuffles to run across four ChaCha states in parallel.
///
/// With AVX512, or specifically the larger number of vector registers (other than VPROL, we don't
/// rely on any AVX512 specific instructions), we interleave **two lanes** (total of 8 instances),
/// for more ILP, to allow the CPU to issue more instructions to IDQ (given they are not dependent),
/// and allows us to hide the shuffle latencies more.
///
/// A bit more detail on each of the transformations:
///
/// 1. Quarter-round:
/// - Each `zmm[i]` holds the **same row** across 4 instances.
/// - Addition, XOR, and rotation (ARX) are applied elementwise.
/// - This realizes the "column round" of the scalar algorithm.
///
/// 2. Diagonalization shuffles:
/// - `zmm[1]` rotated by `(1, 2, 3, 0)`
/// - `zmm[2]` rotated by `(2, 3, 0, 1)`
/// - `zmm[3]` rotated by `(3, 0, 1, 2)`
///
/// 3. After these shuffles, what was once "row-wise aligned" becomes "diagnal aligned", matching
/// the scalar ChaCha diagonal round. Each instance's diagonal words are now aligned to the same
/// SIMD lane. We then perform quarter-rounds on these lanes.
///
/// 4. After the second wave of quarter-rounds, we then "undiagonalize" them with the inverse of the same shuffles.
///
/// 5. Finalization:
/// - We have the vectors organized as row-per-lane.
/// - Transpose rearranges them back into instance-per-block.
/// - Output is standard 64-byte ChaCha blocks.
///
pub fn ChaCha(comptime rounds: enum { eight, twenty }) type {
    return struct {
        key: [32]u8,
        buffers: [num_lanes][64 * 4]u8 align(@alignOf(V)),
        counter: u64,
        /// Number of u64s read from buffers.
        read: u64,

        // When compiling for AVX512 enabled target, we use two interleaved 4x4 kernels (lanes == 2).
        // For AVX2 (and things like aarch64 apple_m3), we set lanes = 1 in order to not have it spill into another loop.
        const num_lanes = if (builtin.cpu.arch == .x86_64 and
            std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f)) 2 else 1;

        const count = switch (rounds) {
            .eight => 8,
            .twenty => 20,
        };

        const Self = @This();
        /// Output size of ChaCha block function.
        const block_size = 64;
        const buffer_size = block_size * 4 * num_lanes;
        const V = @Vector(16, u32);

        pub fn init(key: [32]u8) Self {
            var chacha: Self = .{
                .key = key,
                .buffers = undefined,
                .counter = 0,
                .read = 0,
            };
            chacha.refill();
            return chacha;
        }

        fn refill(self: *Self) void {
            @branchHint(.cold);

            const base: [4]V = .{
                @bitCast([_][16]u8{"expand 32-byte k".*} ** 4),
                @bitCast([_][16]u8{self.key[0..16].*} ** 4),
                @bitCast([_][16]u8{self.key[16..32].*} ** 4),
                @bitCast([_]u128{self.counter} ** 4),
            };

            // Prepare lanes of 4x chacha state:
            // - each lane is 4 chacha instances
            // - each vec per lane is 1 row from each of the 4 chacha instances in that lane
            var offset: @Vector(4, u128) = .{ 0, 1, 2, 3 };
            var lanes: [num_lanes][4]V = undefined;
            for (0..num_lanes) |i| {
                lanes[i] = base; // base lane state
                lanes[i][3] += @bitCast(offset);
                offset += @splat(4);
            }

            // chacha permute each lane (allow compiler to interleave them)
            const pre_permute = lanes;
            for (0..count / 2) |_| {
                for (&lanes) |*chunk| kernel(chunk);
            }

            for (&lanes, pre_permute, &self.buffers) |*lane, pre, *out| {
                for (lane, pre) |*l, p| l.* +%= p; // add pre-round states into permuted-states.
                transpose(lane); // shuffle lane from vec-per-row to vec-per-instance
                out.* = @bitCast(lane.*); // write out instances to buffer
            }

            self.counter += 4 * num_lanes;
            self.read = 0;
        }

        fn quarter(zmm: *[4]V) void {
            zmm[0] +%= zmm[1];
            zmm[3] = std.math.rotl(V, zmm[3] ^ zmm[0], 16);
            zmm[2] +%= zmm[3];
            zmm[1] = std.math.rotl(V, zmm[1] ^ zmm[2], 12);

            zmm[0] +%= zmm[1];
            zmm[3] = std.math.rotl(V, zmm[3] ^ zmm[0], 8);
            zmm[2] +%= zmm[3];
            zmm[1] = std.math.rotl(V, zmm[1] ^ zmm[2], 7);
        }

        // sig fmt: off
        fn kernel(zmm: *[4]V) void {
            quarter(zmm);
            // diagonalize
            zmm[1] = @shuffle(u32, zmm[1], undefined, [_]i32{ 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12 }); // (1, 2, 3, 0) 4x
            zmm[2] = @shuffle(u32, zmm[2], undefined, [_]i32{ 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 }); // (2, 3, 0, 1) 4x
            zmm[3] = @shuffle(u32, zmm[3], undefined, [_]i32{ 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 }); // (3, 0, 1, 2) 4x

            quarter(zmm);
            // undiagonalize
            zmm[3] = @shuffle(u32, zmm[3], undefined, [_]i32{ 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12 }); // (1, 2, 3, 0) 4x
            zmm[2] = @shuffle(u32, zmm[2], undefined, [_]i32{ 2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13 }); // (2, 3, 0, 1) 4x
            zmm[1] = @shuffle(u32, zmm[1], undefined, [_]i32{ 3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14 }); // (3, 0, 1, 2) 4x
        }

        fn transpose(zmm: *[4]V) void {
            // v{chacha_instance}{row_in_instance}
            const v00_10_01_11 = @shuffle(u32, zmm[0], zmm[1], [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7, -8 });
            const v20_30_21_31 = @shuffle(u32, zmm[0], zmm[1], [_]i32{ 8, 9, 10, 11, 12, 13, 14, 15, -9, -10, -11, -12, -13, -14, -15, -16 });
            const v02_12_03_13 = @shuffle(u32, zmm[2], zmm[3], [_]i32{ 0, 1, 2, 3, 4, 5, 6, 7, -1, -2, -3, -4, -5, -6, -7, -8 });
            const v22_32_23_33 = @shuffle(u32, zmm[2], zmm[3], [_]i32{ 8, 9, 10, 11, 12, 13, 14, 15, -9, -10, -11, -12, -13, -14, -15, -16 });

            zmm[0] = @shuffle(u32, v00_10_01_11, v02_12_03_13, [_]i32{ 0, 1, 2, 3, 8, 9, 10, 11, -1, -2, -3, -4, -9, -10, -11, -12 });
            zmm[1] = @shuffle(u32, v00_10_01_11, v02_12_03_13, [_]i32{ 4, 5, 6, 7, 12, 13, 14, 15, -5, -6, -7, -8, -13, -14, -15, -16 });
            zmm[2] = @shuffle(u32, v20_30_21_31, v22_32_23_33, [_]i32{ 0, 1, 2, 3, 8, 9, 10, 11, -1, -2, -3, -4, -9, -10, -11, -12 });
            zmm[3] = @shuffle(u32, v20_30_21_31, v22_32_23_33, [_]i32{ 4, 5, 6, 7, 12, 13, 14, 15, -5, -6, -7, -8, -13, -14, -15, -16 });
        }
        // sig fmt: off

        // rng functions
        pub fn int(self: *Self) u64 {
            if (self.read == @sizeOf(@FieldType(Self, "buffers")) / @sizeOf(u64)) self.refill();
            const items: []const u64 = @ptrCast(&self.buffers);
            defer self.read += 1;
            return items[self.read];
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
        pub fn roll(self: *Self, comptime mode: sig.random.weighted_shuffle.Mode, n: u64) u64 {
            std.debug.assert(n != 0); // not really needed since we don't use `bsr`, but still helps.
            std.debug.assert(n != std.math.maxInt(u64));

            const max: u64 = std.math.maxInt(u64);
            const zone: u64 = switch (mode) {
                .mod => max - ((0 -% n) % n),
                .shift => (n << @intCast(@clz(n))) - 1,
            };

            while (true) {
                const v: u128 = self.int();
                const result = v * n; // compiles down to a `mulx`
                const hi: u64 = @intCast(result >> 64);
                const lo: u64 = @truncate(result);

                if (lo <= zone) return hi;
            }
        }
    };
}

test "basic output" {
    const key: [32]u8 = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    var chacha = ChaCha(.twenty).init(key);
    try std.testing.expectEqual(0x6a19c5d97d2bfd39, chacha.int());

    var x: u64 = 0;
    for (0..100000) |_| x ^= chacha.int();
    try std.testing.expectEqual(0xb425be48c89d4f75, x);
}

test "roll shift" {
    var chacha: ChaCha(.twenty) = .init(@splat(0x41));

    for ([_]u64{ 8, 7, 2, 5, 7, 6, 5, 6, 9, 6 }) |expected| {
        try std.testing.expectEqual(expected, chacha.roll(.shift, 10));
    }

    for ([_]u64{
        3252524226, 3847107912, 2388546007, 1795840680, 1493882641,
        2627412178, 2509655068, 2770564418, 368683988,  318451188,
    }) |expected| {
        try std.testing.expectEqual(expected, chacha.roll(.shift, 4294967231));
    }
}

test "roll mod" {
    var chacha: ChaCha(.twenty) = .init(@splat(0x41));

    for ([_]u64{ 8, 7, 1, 2, 5, 7, 6, 2, 9, 5 }) |expected| {
        try std.testing.expectEqual(expected, chacha.roll(.mod, 10));
    }

    for ([_]u64{
        2659576357, 4036770383, 2578672018, 3252524226, 3847107912,
        2388546007, 1795840680, 1493882641, 2627412178, 2509655068,
    }) |expected| {
        try std.testing.expectEqual(expected, chacha.roll(.mod, 4294967231));
    }
}
