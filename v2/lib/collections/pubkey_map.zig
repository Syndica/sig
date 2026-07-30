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
/// - `TOMBSTONE` (all-`0xFF` pubkey) is the deleted-slot sentinel.
///   Callers must never insert it either. `getPtr` treats
///   tombstoned slots as "keep probing"; `insert` reuses them for
///   new keys. Tombstones accumulate over churn; there is no
///   automatic compaction. Rebuild via `init` if measured probe
///   distance degrades.
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
        pub const TOMBSTONE: Pubkey = .{ .data = .{0xFF} ** 32 };

        pub fn init(self: *Self) void {
            @memset(&self.keys, Pubkey.ZEROES);
            // `values` intentionally left undefined; only read after
            // a key match.
        }

        fn isEmpty(slot: *const Pubkey) bool {
            return std.mem.eql(u8, &slot.data, &Pubkey.ZEROES.data);
        }

        fn isTombstone(slot: *const Pubkey) bool {
            return std.mem.eql(u8, &slot.data, &TOMBSTONE.data);
        }

        /// Insert `(pk, v)`. If `pk` is already present, overwrites
        /// its value. Reuses tombstoned slots. Returns
        /// `error.MapFull` if capacity is exhausted (should never
        /// occur when sized per the 2× invariant above).
        pub fn insert(self: *Self, pk: Pubkey, v: V) !void {
            std.debug.assert(!isEmpty(&pk));
            std.debug.assert(!isTombstone(&pk));
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            var first_tombstone: ?u64 = null;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (isEmpty(slot)) {
                    const dst = first_tombstone orelse idx;
                    self.keys[dst] = pk;
                    self.values[dst] = v;
                    return;
                }
                if (isTombstone(slot)) {
                    if (first_tombstone == null) first_tombstone = idx;
                } else if (std.mem.eql(u8, &slot.data, &pk.data)) {
                    self.values[idx] = v;
                    return;
                }
                idx = (idx + 1) & mask;
            }
            if (first_tombstone) |dst| {
                self.keys[dst] = pk;
                self.values[dst] = v;
                return;
            }
            return error.MapFull;
        }

        /// Returns a pointer to the stored value, or null if `pk` is
        /// not present. Pointer is stable until the next `insert`,
        /// `remove`, or `init`.
        pub fn getPtr(self: *Self, pk: Pubkey) ?*V {
            if (isEmpty(&pk)) return null;
            if (isTombstone(&pk)) return null;
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (isEmpty(slot)) return null;
                if (!isTombstone(slot) and std.mem.eql(u8, &slot.data, &pk.data)) {
                    return &self.values[idx];
                }
                idx = (idx + 1) & mask;
            }
            return null;
        }

        pub fn getPtrConst(self: *const Self, pk: Pubkey) ?*const V {
            if (isEmpty(&pk)) return null;
            if (isTombstone(&pk)) return null;
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (isEmpty(slot)) return null;
                if (!isTombstone(slot) and std.mem.eql(u8, &slot.data, &pk.data)) {
                    return &self.values[idx];
                }
                idx = (idx + 1) & mask;
            }
            return null;
        }

        /// Delete `pk` if present. Returns whether a live entry was
        /// removed. Marks the slot with `TOMBSTONE` so subsequent
        /// probes for other keys in the same cluster don't stop
        /// early; subsequent inserts may reuse the slot.
        pub fn remove(self: *Self, pk: Pubkey) bool {
            if (isEmpty(&pk)) return false;
            if (isTombstone(&pk)) return false;
            var idx: u64 = pk.hash(HASH_SEED) & mask;
            var probe: u64 = 0;
            while (probe < capacity) : (probe += 1) {
                const slot = &self.keys[idx];
                if (isEmpty(slot)) return false;
                if (!isTombstone(slot) and std.mem.eql(u8, &slot.data, &pk.data)) {
                    self.keys[idx] = TOMBSTONE;
                    self.values[idx] = undefined;
                    return true;
                }
                idx = (idx + 1) & mask;
            }
            return false;
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

test "remove: returns false on missing key, true on present" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var pk: Pubkey = .{ .data = .{0} ** 32 };
    pk.data[0] = 1;
    var pk_missing: Pubkey = .{ .data = .{0} ** 32 };
    pk_missing.data[0] = 2;

    try m.insert(pk, 42);
    try std.testing.expectEqual(false, m.remove(pk_missing));
    try std.testing.expectEqual(true, m.remove(pk));
    try std.testing.expectEqual(@as(?*u32, null), m.getPtr(pk));
    try std.testing.expectEqual(false, m.remove(pk));
}

test "remove: probes past tombstones to find later-inserted key" {
    // Two keys that map to the same initial slot (or adjacent slots
    // in the same probe cluster) — ensure removing the first still
    // lets us find the second.
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var prng: std.Random.Xoshiro256 = .init(0xC0FFEE);
    const rand = prng.random();

    // Collide-force: try many random pairs until two hash to the
    // same slot. Cheap given a small map.
    var pk_a: Pubkey = undefined;
    var pk_b: Pubkey = undefined;
    while (true) {
        pk_a = Pubkey.initRandom(rand);
        pk_b = Pubkey.initRandom(rand);
        if (std.mem.eql(u8, &pk_a.data, &Pubkey.ZEROES.data)) continue;
        if (std.mem.eql(u8, &pk_b.data, &Pubkey.ZEROES.data)) continue;
        if (std.mem.eql(u8, &pk_a.data, &pk_b.data)) continue;
        if ((pk_a.hash(0) & 15) == (pk_b.hash(0) & 15)) break;
    }

    try m.insert(pk_a, 100);
    try m.insert(pk_b, 200);
    try std.testing.expectEqual(@as(u32, 100), m.getPtr(pk_a).?.*);
    try std.testing.expectEqual(@as(u32, 200), m.getPtr(pk_b).?.*);

    try std.testing.expectEqual(true, m.remove(pk_a));
    try std.testing.expectEqual(@as(?*u32, null), m.getPtr(pk_a));
    try std.testing.expectEqual(@as(u32, 200), m.getPtr(pk_b).?.*);
}

test "remove: subsequent insert reuses tombstone slot" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 1;
    var pk_c: Pubkey = .{ .data = .{0} ** 32 };
    pk_c.data[0] = 3;

    try m.insert(pk_a, 1);
    _ = m.remove(pk_a);
    try m.insert(pk_c, 3);

    try std.testing.expectEqual(@as(u32, 3), m.getPtr(pk_c).?.*);

    // Count live keys — should be exactly one.
    var live: usize = 0;
    for (m.keys) |k| {
        if (std.mem.eql(u8, &k.data, &Pubkey.ZEROES.data)) continue;
        if (std.mem.eql(u8, &k.data, &M.TOMBSTONE.data)) continue;
        live += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), live);
}

test "remove: tombstone key sentinel is rejected on insert / getPtr" {
    const M = FixedPubkeyMap(u32, 16);
    var m: M = undefined;
    m.init();

    // getPtr on the tombstone sentinel returns null (never inserted).
    try std.testing.expectEqual(@as(?*u32, null), m.getPtr(M.TOMBSTONE));
    // remove on the tombstone sentinel is a no-op.
    try std.testing.expectEqual(false, m.remove(M.TOMBSTONE));
}
