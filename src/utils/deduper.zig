// fn new_random_state<R: Rng>(rng: &mut R) -> RandomState {
//     RandomState::with_seeds(rng.gen(), rng.gen(), rng.gen(), rng.gen())
// }
const std = @import("std");
const sig = @import("../sig.zig");

const AtomicU64 = std.atomic.Value(u64);

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

pub fn Deduper(comptime K: usize, comptime T: type) type {
    return struct {
        num_bits: u64,
        bits: std.ArrayList(AtomicU64),
        state: [K]RandomState,
        clock: Instant,
        popcount: AtomicU64,

        pub fn init(
            allocator: std.mem.Allocator,
            rand: std.rand.Random,
            num_bits: u64,
        ) !Deduper(K, T) {
            const size: usize = @intCast((num_bits + 63) / 64);
            var bits = try std.ArrayList(AtomicU64).initCapacity(allocator, size);
            for (0..size) |_| try bits.append(AtomicU64.init(0));
            var state: [K]RandomState = undefined;
            for (0..K) |i| state[i] = RandomState.withRandomSeeds(rand);
            return .{
                .num_bits = num_bits,
                .bits = bits,
                .state = state,
                .clock = Instant.now(),
                .popcount = AtomicU64.init(0),
            };
        }

        pub fn deinit(self: Deduper(K, T)) void {
            self.bits.deinit();
        }

        pub fn falsePositiveRate(self: *Deduper(K, T)) f64 {
            const popcount = self.popcount.load(.unordered);
            const numerator: f64 = @floatFromInt(@min(popcount, self.num_bits));
            const denominator: f64 = @floatFromInt(self.num_bits);
            const ones_ratio = numerator / denominator;
            return std.math.pow(f64, ones_ratio, @as(f64, K));
        }

        /// Resets the Deduper if either it is older than the reset_cycle or it is
        /// saturated enough that false positive rate exceeds specified threshold.
        /// Returns true if the deduper was saturated.
        pub fn maybeReset(
            self: *Deduper(K, T),
            rand: std.rand.Random,
            false_positive_rate: f64,
            reset_cycle: Duration,
        ) bool {
            std.debug.assert(0.0 < false_positive_rate and false_positive_rate < 1.0);
            const saturated = self.falsePositiveRate() >= false_positive_rate;
            if (saturated or self.clock.elapsed().asNanos() >= reset_cycle.asNanos()) {
                for (self.bits.items) |_bit| {
                    var bit = _bit;
                    bit = AtomicU64.init(0);
                }
                for (0..K) |i| self.state[i] = RandomState.withRandomSeeds(rand);
                self.clock = Instant.now();
                self.popcount = AtomicU64.init(0);
            }
            return saturated;
        }

        pub fn dedup(self: *Deduper(K, T), data: *const T) bool {
            var duplicate = true;
            for (0..K) |i| {
                var hasher = self.state[i].buildHasher();
                hasher.hash(T, data);
                const hash: u64 = hasher.finish() % self.num_bits;
                const mask: u64 = @as(u64, 1) << @truncate(hash);
                const index = @as(usize, hash >> 6);
                const old = self.bits.items[index].fetchOr(mask, .acquire);
                if (old & mask == 0) {
                    _ = self.popcount.fetchAdd(1, .acquire);
                    duplicate = false;
                }
            }
            return duplicate;
        }
    };
}

test "Deduper" {
    var xoshiro = std.rand.Xoshiro256.init(0);

    var deduper = try Deduper(2, u64).init(std.testing.allocator, xoshiro.random(), 32);
    defer deduper.deinit();

    std.debug.print("{any}\n", .{deduper.falsePositiveRate()});

    try std.testing.expect(!deduper.dedup(&1_000_000));
    try std.testing.expect(deduper.dedup(&1_000_000));
    try std.testing.expect(!deduper.dedup(&1_000_001));
    try std.testing.expect(deduper.dedup(&1_000_001));

    std.debug.print("{any}\n", .{deduper.falsePositiveRate()});

    _ = deduper.maybeReset(xoshiro.random(), 0.001, Duration.fromSecs(10));

    std.debug.print("{any}\n", .{deduper.falsePositiveRate()});
}

pub const RandomState = struct {
    k0: u64,
    k1: u64,
    k2: u64,
    k3: u64,

    const PI2 = [_]u64{
        0x4528_21e6_38d0_1377,
        0xbe54_66cf_34e9_0c6c,
        0xc0ac_29b7_c97c_50dd,
        0x3f84_d5b5_b547_0917,
    };

    pub fn withRandomSeeds(rand: std.rand.Random) RandomState {
        return RandomState.withSeeds(
            rand.int(u64),
            rand.int(u64),
            rand.int(u64),
            rand.int(u64),
        );
    }

    pub fn withSeeds(k0: u64, k1: u64, k2: u64, k3: u64) RandomState {
        return .{
            .k0 = k0 ^ PI2[0],
            .k1 = k1 ^ PI2[1],
            .k2 = k2 ^ PI2[2],
            .k3 = k3 ^ PI2[3],
        };
    }

    pub fn buildHasher(self: RandomState) AHasher {
        return AHasher.fromRandomState(self);
    }
};

pub const AHasher = struct {
    buffer: u64,
    pad: u64,
    extra_keys: [2]u64,

    // This constant comes from Kunth's prng (Empirically it works better than those from splitmix32).
    const MULTIPLE: u64 = 6364136223846793005;
    const ROTATE: u32 = 23;

    pub fn fromRandomState(rand_state: RandomState) AHasher {
        return .{
            .buffer = rand_state.k0,
            .pad = rand_state.k1,
            .extra_keys = .{ rand_state.k2, rand_state.k3 },
        };
    }

    pub fn hash(self: *AHasher, comptime T: type, data: *const T) void {
        switch (@typeInfo(T)) {
            .Int => self.update(@intCast(data.*)),
            .Array => |array| self.hashSlice(array.child, data),
            else => unreachable,
        }
    }

    pub fn hashSlice(self: *AHasher, comptime T: type, data: []const T) void {
        self.write(std.mem.asBytes(&data.len));
        for (data) |elem| self.hash(T, &elem);
    }

    pub fn finish(self: *const AHasher) u64 {
        const rot: u32 = @intCast(self.buffer & 63);
        return std.math.rotl(u64, foldedMultiply(self.buffer, self.pad), rot);
    }

    inline fn update(self: *AHasher, new_data: u64) void {
        self.buffer = foldedMultiply(new_data ^ self.buffer, MULTIPLE);
    }

    inline fn largeUpdate(self: *AHasher, new_data: u128) void {
        const high: u64 = @intCast(new_data >> 64);
        const low: u64 = @intCast((new_data << 64) >> 64);
        const combined = foldedMultiply(low ^ self.extra_keys[0], high ^ self.extra_keys[1]);
        self.buffer = std.math.rotl(u64, ((self.buffer +% self.pad) ^ combined), ROTATE);
    }

    fn write(self: *AHasher, input: []const u8) void {
        var data = input;
        const len: u64 = @intCast(data.len);
        self.buffer = (self.buffer +% len) *% MULTIPLE;
        if (data.len > 8) {
            if (data.len > 16) {
                self.largeUpdate(readLastInt(u128, data));
                while (data.len > 16) {
                    self.largeUpdate(readFirstInt(u128, data));
                    data = data[16..];
                }
            } else {
                self.largeUpdate(readFirstInt(u128, data[0..8] ++ data[(data.len - 8)..][0..8]));
            }
        } else {
            var parts = [2]u64{ 0, 0 };
            if (data.len >= 2) {
                if (data.len >= 4) {
                    parts = .{ @as(u64, readFirstInt(u32, data)), @as(u64, readLastInt(u32, data)) };
                } else {
                    parts = .{ @as(u64, readFirstInt(u16, data)), @as(u64, data[data.len - 1]) };
                }
            } else if (data.len > 0) {
                parts = .{ @as(u64, data[0]), @as(u64, data[0]) };
            }
            self.largeUpdate(readFirstInt(u128, std.mem.asBytes(&parts[0]) ++ std.mem.asBytes(&parts[1])));
        }
    }
};

inline fn readFirstInt(comptime T: type, data: []const u8) T {
    return std.mem.readInt(T, data[0..@sizeOf(T)], .little);
}

inline fn readLastInt(comptime T: type, data: []const u8) T {
    const size: usize = @sizeOf(T);
    return std.mem.readInt(T, data[(data.len - size)..][0..size], .little);
}

inline fn foldedMultiply(s: u64, by: u64) u64 {
    const prod = @as(u128, s) *% @as(u128, by);
    const left: u64 = @intCast(prod & 0xffff_ffff_ffff_ffff);
    const right: u64 = @intCast(prod >> 64);
    return left ^ right;
}

test "AHasher.write" {
    const random_state = RandomState.withSeeds(0, 0, 0, 0);

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: usize = 0;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(11097478002403803964, hasher.finish());
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: usize = 3;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(4385934533294099554, hasher.finish());
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: usize = 1_241_947;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(2608624253679196293, hasher.finish());
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: u128 = 0;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(8143685863221665689, hasher.finish());
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: u128 = 3;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(3584941868004640750, hasher.finish());
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const input: u128 = 1_241_947;
        hasher.write(std.mem.asBytes(&input));
        try std.testing.expectEqual(429598539248477650, hasher.finish());
    }
}

test "AHasher.hash" {
    const random_state = RandomState.withSeeds(0, 0, 0, 0);

    {
        var hasher = AHasher.fromRandomState(random_state);
        const data: u32 = 10;
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        hasher.hash(@TypeOf(data), &data);
        std.debug.print("{any}\n", .{hasher.finish()});
    }

    {
        var hasher = AHasher.fromRandomState(random_state);
        const data = [_]u8{ 10, 3, 5 };
        hasher.hash(@TypeOf(data), &data);
        std.debug.print("{any}\n", .{hasher.finish()});
    }
}
