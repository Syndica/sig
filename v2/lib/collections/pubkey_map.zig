const std = @import("std");

const Pubkey = @import("../solana/pubkey.zig").Pubkey;

/// Open-addressed, linear-probed, fixed-capacity `Pubkey` → `V` map.
///
/// Invariants:
/// - `capacity` is a comptime power of two. Slot selection is a
///   single `& (capacity - 1)`.
/// - Caller sizes `capacity` at ≥ 2× expected occupancy. At load
///   factor ≤ 0.5, linear probes stay short in the common case.
/// - `Pubkey.ZEROES` is the empty-slot sentinel. Callers must never
///   insert it; `insert` asserts, `getPtr` returns null for it.
/// - No delete. Rebuild by calling `init` again.
/// - `V` must be extern-compatible so the map itself can live inside
///   another `extern struct` (e.g. `EpochVoters`).
pub fn FixedPubkeyMap(comptime V: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    comptime std.debug.assert(std.math.isPowerOfTwo(capacity));

    return extern struct {
        keys: [capacity]Pubkey,
        values: [capacity]V,

        const Self = @This();
        pub const cap: usize = capacity;
        const mask: u64 = capacity - 1;
        const HASH_SEED: u64 = 0;

        pub fn init(self: *Self) void {
            @memset(&self.keys, Pubkey.ZEROES);
            // `values` intentionally left undefined; only read after
            // a key match.
        }

        /// Insert `(pk, v)`. If `pk` is already present, overwrites
        /// its value. Returns `error.MapFull` if capacity is
        /// exhausted (should never occur when sized per the 2×
        /// invariant above).
        pub fn insert(self: *Self, pk: Pubkey, v: V) !void {
            std.debug.assert(!std.mem.eql(u8, &pk.data, &Pubkey.ZEROES.data));
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (std.mem.eql(u8, &slot.data, &Pubkey.ZEROES.data)) {
                    slot.* = pk;
                    self.values[idx] = v;
                    return;
                }
                if (std.mem.eql(u8, &slot.data, &pk.data)) {
                    self.values[idx] = v;
                    return;
                }
                idx = (idx + 1) & mask;
            }
            return error.MapFull;
        }

        /// Returns a pointer to the stored value, or null if `pk` is
        /// not present. Pointer is stable until the next `insert` or
        /// `init`.
        pub fn getPtr(self: *Self, pk: Pubkey) ?*V {
            if (std.mem.eql(u8, &pk.data, &Pubkey.ZEROES.data)) return null;
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (std.mem.eql(u8, &slot.data, &Pubkey.ZEROES.data)) return null;
                if (std.mem.eql(u8, &slot.data, &pk.data)) return &self.values[idx];
                idx = (idx + 1) & mask;
            }
            return null;
        }

        pub fn getPtrConst(self: *const Self, pk: Pubkey) ?*const V {
            if (std.mem.eql(u8, &pk.data, &Pubkey.ZEROES.data)) return null;
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (std.mem.eql(u8, &slot.data, &Pubkey.ZEROES.data)) return null;
                if (std.mem.eql(u8, &slot.data, &pk.data)) return &self.values[idx];
                idx = (idx + 1) & mask;
            }
            return null;
        }
    };
}

test "insert + getPtr round-trip" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 1;
    var pk_b: Pubkey = .{ .data = .{0} ** 32 };
    pk_b.data[0] = 2;

    try m.insert(pk_a, 100);
    try m.insert(pk_b, 200);

    try std.testing.expectEqual(@as(u32, 100), m.getPtr(pk_a).?.*);
    try std.testing.expectEqual(@as(u32, 200), m.getPtr(pk_b).?.*);
}

test "missing key returns null" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var pk: Pubkey = .{ .data = .{0} ** 32 };
    pk.data[0] = 1;
    try m.insert(pk, 42);

    var missing: Pubkey = .{ .data = .{0} ** 32 };
    missing.data[0] = 99;
    try std.testing.expectEqual(@as(?*u32, null), m.getPtr(missing));
}

test "zero pubkey rejected on lookup" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();
    try std.testing.expectEqual(@as(?*u32, null), m.getPtr(Pubkey.ZEROES));
}

test "duplicate insert overwrites value" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var pk: Pubkey = .{ .data = .{0} ** 32 };
    pk.data[0] = 7;

    try m.insert(pk, 1);
    try m.insert(pk, 999);
    try std.testing.expectEqual(@as(u32, 999), m.getPtr(pk).?.*);
}

test "getPtr returns stable pointer across further inserts" {
    const M = FixedPubkeyMap(u32, 32);
    var m: M = undefined;
    m.init();

    var pk_target: Pubkey = .{ .data = .{0} ** 32 };
    pk_target.data[0] = 42;
    try m.insert(pk_target, 555);
    const ptr_before = m.getPtr(pk_target).?;

    // Insert unrelated keys.
    for (1..10) |i| {
        var pk: Pubkey = .{ .data = .{0} ** 32 };
        pk.data[0] = @intCast(i + 100);
        try m.insert(pk, @intCast(i));
    }

    const ptr_after = m.getPtr(pk_target).?;
    try std.testing.expectEqual(ptr_before, ptr_after);
    try std.testing.expectEqual(@as(u32, 555), ptr_after.*);
}

test "fill to capacity with random keys" {
    const M = FixedPubkeyMap(u32, 64);
    var m: M = undefined;
    m.init();

    var prng: std.Random.Xoshiro256 = .init(0xDEADBEEF);
    const rand = prng.random();

    // Load to 50%: 32 keys into 64 slots.
    var inserted: [32]Pubkey = undefined;
    for (&inserted, 0..) |*pk, i| {
        while (true) {
            pk.* = Pubkey.initRandom(rand);
            if (!std.mem.eql(u8, &pk.data, &Pubkey.ZEROES.data)) break;
        }
        try m.insert(pk.*, @intCast(i));
    }

    // All must be retrievable.
    for (inserted, 0..) |pk, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), m.getPtr(pk).?.*);
    }
}
