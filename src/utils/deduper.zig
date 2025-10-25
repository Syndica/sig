const std = @import("std");
const sig = @import("../sig.zig");

const Atomic = std.atomic.Value(u64);

const ChaCha = sig.crypto.ChaCha(.twenty);
const Instant = sig.time.Instant;
const Duration = sig.time.Duration;
const Seed = sig.utils.AHasher.Seed;
const AHasher = sig.utils.AHasher;

/// Deduper which uses the AHash algorithm across K different seeds/hashers to find possible duplicates.
pub fn Deduper(comptime T: type) type {
    return struct {
        num_bits: u64,
        bits: []Atomic,
        state: [n_hashers]Seed,
        last_reset_instant: Instant,
        masked_count: Atomic,

        const Self = @This();
        const n_hashers = 2;

        pub fn init(
            allocator: std.mem.Allocator,
            chacha: *ChaCha,
            num_bits: u64,
        ) !Self {
            const size = try std.math.divCeil(u64, num_bits, 64);

            const bits = try allocator.alloc(Atomic, size);
            errdefer allocator.free(bits);
            @memset(bits, .init(0));

            var state: [n_hashers]Seed = undefined;
            for (0..n_hashers) |i| state[i] = .fromSeeds(
                chacha.int(),
                chacha.int(),
                chacha.int(),
                chacha.int(),
            );

            return .{
                .num_bits = num_bits,
                .bits = bits,
                .state = state,
                .last_reset_instant = .now(),
                .masked_count = .init(0),
            };
        }

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.bits);
        }

        /// Resets the Self if the false positive rate is too high or the reset cycle has elapsed.
        pub fn maybeReset(
            self: *Self,
            chacha: *ChaCha,
            false_positive_rate: f64,
            reset_cycle: Duration,
        ) bool {
            std.debug.assert(0.0 < false_positive_rate and false_positive_rate < 1.0);
            const saturated = self.falsePositiveRate() >= false_positive_rate;
            if (saturated or
                self.last_reset_instant.elapsed().asNanos() >= reset_cycle.asNanos())
            {
                @memset(self.bits, .init(0));
                for (0..n_hashers) |i| self.state[i] = .fromSeeds(
                    chacha.int(),
                    chacha.int(),
                    chacha.int(),
                    chacha.int(),
                );
                self.last_reset_instant = Instant.now();
                self.masked_count = .init(0);
            }
            return saturated;
        }

        /// Returns true if the data is likely a duplicate.
        pub fn dedup(self: *Self, data: T) bool {
            var duplicate = true;
            for (0..n_hashers) |i| {
                var hasher = AHasher.fromSeed(self.state[i]);
                hasher.hash(T, &data);
                const hash: u64 = hasher.finish() % self.num_bits;
                const mask: u64 = @as(u64, 1) << @truncate(hash);
                const index = hash >> 6;
                const old = self.bits[index].fetchOr(mask, .monotonic);
                if (old & mask == 0) {
                    _ = self.masked_count.fetchAdd(1, .monotonic);
                    duplicate = false;
                }
            }
            return duplicate;
        }

        /// False positive rate computed from the current popcount and num_bits.
        pub fn falsePositiveRate(self: *Self) f64 {
            const popcount = self.masked_count.load(.monotonic);
            const numerator: f64 = @floatFromInt(@min(popcount, self.num_bits));
            const denominator: f64 = @floatFromInt(self.num_bits);
            const ones_ratio = numerator / denominator;
            return std.math.pow(f64, ones_ratio, n_hashers);
        }
    };
}

/// Test method from agave.
/// Calculate the capacity of the deduper before exceeding the false positive rate.
fn testGetCapacity(comptime K: usize, num_bits: u64, false_positive_rate: f64) u64 {
    return @intFromFloat(
        (@as(f64, @floatFromInt(num_bits)) * std.math.pow(
            f64,
            false_positive_rate,
            (1 / @as(f64, @floatFromInt(K))),
        )),
    );
}

/// Test method from agave.
/// Checks that the deduper with a specific number of bits and false positive rate
/// has the correct capacity.
fn testDedupCapacity(num_bits: u64, false_positive_rate: f64, capacity: u64) !void {
    var xoshiro = std.Random.DefaultPrng.init(0);
    const rng = xoshiro.random();

    try std.testing.expectEqual(
        testGetCapacity(2, num_bits, false_positive_rate),
        capacity,
    );

    var deduper = try Deduper([]const u8).init(std.testing.allocator, rng, num_bits);
    defer deduper.deinit();
    try std.testing.expectEqual(
        0.0,
        deduper.falsePositiveRate(),
    );

    deduper.masked_count.store(capacity, .monotonic);
    try std.testing.expect(deduper.falsePositiveRate() < false_positive_rate);

    deduper.masked_count.store(capacity + 1, .monotonic);
    try std.testing.expect(deduper.falsePositiveRate() >= false_positive_rate);
    try std.testing.expect(deduper.maybeReset(
        rng,
        false_positive_rate,
        Duration.fromMillis(0),
    ));
}

/// Test method from agave.
/// Checks that the deduper produces the expected number of duplicates and popcount
/// when seeded with a specific seed.
fn testDedupSeeded(
    seed: [32]u8,
    num_bits: u64,
    capacity: u64,
    num_packets: usize,
    num_dups: usize,
    popcount: u64,
) !void {
    const allocator = std.testing.allocator;
    const packet_data_size = 1280 - 40 - 8;
    const false_positive_rate = 0.001;

    var chacha: sig.crypto.ChaCha(.twenty) = .init(seed);

    var deduper = try Deduper([]const u8).init(allocator, &chacha, num_bits);
    defer deduper.deinit(allocator);

    try std.testing.expectEqual(capacity, testGetCapacity(2, num_bits, false_positive_rate));

    var dup_count: usize = 0;
    for (0..num_packets) |_| {
        const size = chacha.roll(.shift, packet_data_size);
        var data: [packet_data_size]u8 = @splat(0);
        for (std.mem.bytesAsSlice(u64, &data)) |*int| int.* = chacha.int();
        if (deduper.dedup(data[0..size])) dup_count += 1;
        try std.testing.expect(deduper.dedup(data[0..size]));
    }

    try std.testing.expectEqual(num_dups, num_dups);
    try std.testing.expectEqual(
        popcount,
        deduper.masked_count.load(.monotonic),
    );
    try std.testing.expect(deduper.falsePositiveRate() < false_positive_rate);
    try std.testing.expect(!deduper.maybeReset(
        &chacha,
        false_positive_rate,
        Duration.fromMillis(0),
    ));
}

// test "agave: dedup capacity" {
//     try testDedupCapacity(63_999_979, 0.001, 2_023_857);
//     if (sig.build_options.long_tests) {
//         try testDedupCapacity(622_401_961, 0.001, 19_682_078);
//         try testDedupCapacity(622_401_979, 0.001, 19_682_078);
//         try testDedupCapacity(629_145_593, 0.001, 19_895_330);
//         try testDedupCapacity(632_455_543, 0.001, 20_000_000);
//         try testDedupCapacity(637_534_199, 0.001, 20_160_601);
//         try testDedupCapacity(622_401_961, 0.0001, 6_224_019);
//         try testDedupCapacity(622_401_979, 0.0001, 6_224_019);
//         try testDedupCapacity(629_145_593, 0.0001, 6_291_455);
//         try testDedupCapacity(632_455_543, 0.0001, 6_324_555);
//         try testDedupCapacity(637_534_199, 0.0001, 6_375_341);
//     }
// }

test "agave: dedup seeded" {
    try testDedupSeeded(@splat(0xf9), 3_199_997, 101_192, 51_414, 66, 101_121);
    // if (sig.build_options.long_tests) {
    //     try testDedupSeeded(@splat(0xdc), 3_200_003, 101_192, 51_414, 60, 101_092);
    //     try testDedupSeeded(@splat(0xa5), 6_399_971, 202_384, 102_828, 125, 202_178);
    //     try testDedupSeeded(@splat(0xdb), 6_400_013, 202_386, 102_828, 135, 202_235);
    //     try testDedupSeeded(@splat(0xcd), 12_799_987, 404_771, 205_655, 285, 404_410);
    //     try testDedupSeeded(@splat(0xc3), 12_800_009, 404_771, 205_656, 293, 404_397);
    // }
}
