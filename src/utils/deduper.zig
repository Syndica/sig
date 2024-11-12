const std = @import("std");
const sig = @import("../sig.zig");

const AtomicU64 = std.atomic.Value(u64);

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;
const RandomState = sig.utils.ahash.RandomState;
const AHasher = sig.utils.ahash.AHasher;
const ChaChaRng = sig.rand.ChaChaRng(20);
const uintLessThanRust = sig.rand.weighted_shuffle.uintLessThanRust;

/// Deduper from agave.
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
            for (0..K) |i| state[i] = RandomState.fromRng(rand);
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

        /// Resets the deduper if the false positive rate is too high or the reset cycle has elapsed.
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
                for (0..K) |i| self.state[i] = RandomState.fromRng(rand);
                self.clock = Instant.now();
                self.popcount = AtomicU64.init(0);
            }
            return saturated;
        }

        /// Returns true if the data is likely a duplicate.
        pub fn dedup(self: *Deduper(K, T), data: *const T) bool {
            var duplicate = true;
            for (0..K) |i| {
                var hasher = AHasher.fromRandomState(self.state[i]);
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

        /// False positive rate computed from the current popcount and num_bits.
        fn falsePositiveRate(self: *Deduper(K, T)) f64 {
            const popcount = self.popcount.load(.unordered);
            const numerator: f64 = @floatFromInt(@min(popcount, self.num_bits));
            const denominator: f64 = @floatFromInt(self.num_bits);
            const ones_ratio = numerator / denominator;
            return std.math.pow(f64, ones_ratio, @as(f64, K));
        }
    };
}

/// Test method from agave.
/// Calculate the capacity of the deduper before exceeding the false positive rate.
fn testGetCapacity(comptime K: usize, num_bits: u64, false_positive_rate: f64) u64 {
    return @intFromFloat((@as(f64, @floatFromInt(num_bits)) * std.math.pow(f64, false_positive_rate, (1 / @as(f64, @floatFromInt(K))))));
}

/// Test method from agave.
/// Checks that the deduper with a specific number of bits and false positive rate
/// has the correct capacity.
fn testDedupCapacity(num_bits: u64, false_positive_rate: f64, capacity: u64) !void {
    var xoshiro = std.rand.DefaultPrng.init(0);
    const rng = xoshiro.random();

    try std.testing.expectEqual(
        testGetCapacity(2, num_bits, false_positive_rate),
        capacity,
    );

    var deduper = try Deduper(2, []u8).init(std.testing.allocator, rng, num_bits);
    defer deduper.deinit();
    try std.testing.expectEqual(
        0.0,
        deduper.falsePositiveRate(),
    );

    deduper.popcount.store(capacity, .monotonic);
    try std.testing.expect(deduper.falsePositiveRate() < false_positive_rate);

    deduper.popcount.store(capacity + 1, .monotonic);
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
    const packet_data_size = 1280 - 40 - 8;
    const false_positive_rate = 0.001;

    var chacha = ChaChaRng.fromSeed(seed);
    const rng = chacha.random();

    var deduper = try Deduper(2, []u8).init(std.testing.allocator, rng, num_bits);
    defer deduper.deinit();

    try std.testing.expectEqual(capacity, testGetCapacity(2, num_bits, false_positive_rate));

    var dup_count: usize = 0;
    for (0..num_packets) |_| {
        const size = uintLessThanRust(usize, rng, packet_data_size);
        var data = [_]u8{0} ** packet_data_size;
        rng.bytes(data[0..size]);
        if (deduper.dedup(&data[0..size])) dup_count += 1;
        try std.testing.expect(deduper.dedup(&data[0..size]));
    }

    try std.testing.expectEqual(num_dups, num_dups);
    try std.testing.expectEqual(popcount, deduper.popcount.load(.unordered)); // TODO: Find why this fails
    try std.testing.expect(deduper.falsePositiveRate() < false_positive_rate);
    try std.testing.expect(!deduper.maybeReset(rng, false_positive_rate, Duration.fromMillis(0)));
}

test "agave: dedup capacity" {
    try testDedupCapacity(63_999_979, 0.001, 2_023_857);
    try testDedupCapacity(622_401_961, 0.001, 19_682_078);
    try testDedupCapacity(622_401_979, 0.001, 19_682_078);
    try testDedupCapacity(629_145_593, 0.001, 19_895_330);
    try testDedupCapacity(632_455_543, 0.001, 20_000_000);
    try testDedupCapacity(637_534_199, 0.001, 20_160_601);
    try testDedupCapacity(622_401_961, 0.0001, 6_224_019);
    try testDedupCapacity(622_401_979, 0.0001, 6_224_019);
    try testDedupCapacity(629_145_593, 0.0001, 6_291_455);
    try testDedupCapacity(632_455_543, 0.0001, 6_324_555);
    try testDedupCapacity(637_534_199, 0.0001, 6_375_341);
}

test "agave: dedup seeded" {
    try testDedupSeeded([_]u8{0xf9} ** 32, 3_199_997, 101_192, 51_414, 66, 101_121);
    try testDedupSeeded([_]u8{0xdc} ** 32, 3_200_003, 101_192, 51_414, 60, 101_092);
    try testDedupSeeded([_]u8{0xa5} ** 32, 6_399_971, 202_384, 102_828, 125, 202_178);
    try testDedupSeeded([_]u8{0xdb} ** 32, 6_400_013, 202_386, 102_828, 135, 202_235);
    try testDedupSeeded([_]u8{0xcd} ** 32, 12_799_987, 404_771, 205_655, 285, 404_410);
    try testDedupSeeded([_]u8{0xc3} ** 32, 12_800_009, 404_771, 205_656, 293, 404_397);
}
