const builtin = @import("builtin");
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    entries: std14.BoundedArray(Entry, MAX_ENTRIES),

    pub const INIT: SlotHashes = .{ .entries = .{} };

    pub const Entry = extern struct {
        slot: Slot,
        hash: Hash,

        pub fn sortCmp(_: void, a: Entry, b: Entry) bool {
            return b.slot < a.slot; // Sort by descending slot
        }

        pub fn searchCmp(key: Slot, mid_item: Entry) std.math.Order {
            return std.math.order(mid_item.slot, key);
        }
    };

    pub const ID: Pubkey = .parse("SysvarS1otHashes111111111111111111111111111");

    pub const MAX_ENTRIES: usize = 512;

    pub const STORAGE_SIZE: usize = 20_488;

    pub fn getIndex(self: *const SlotHashes, slot: u64) ?usize {
        return std.sort.binarySearch(Entry, self.entries.constSlice(), slot, Entry.searchCmp);
    }

    pub fn get(self: *const SlotHashes, slot: Slot) ?Hash {
        return if (self.getIndex(slot)) |index|
            self.entries.buffer[index].hash
        else
            null;
    }

    pub fn add(self: *SlotHashes, slot: Slot, hash: Hash) void {
        const index = std.sort.lowerBound(Entry, self.entries.constSlice(), slot, Entry.searchCmp);
        // If the slot is to old, do not insert. Otherwise if the entries are full, pop the last entry.
        if (index == MAX_ENTRIES) return;

        // If the entries are full, pop the last entry to make space for the new one.
        if (self.entries.len == MAX_ENTRIES) _ = self.entries.pop();

        // If the slot already exists update the hash, otherwise insert a new entry.
        if (index < self.entries.len and self.entries.buffer[index].slot == slot) {
            self.entries.buffer[index].hash = hash;
        } else {
            // SAFETY: entries has space for at least one more entry due to popping the last entry if it was full.
            self.entries.insert(index, .{ .slot = slot, .hash = hash }) catch unreachable;
        }
    }

    pub fn initWithEntries(entries: []const Entry) SlotHashes {
        if (!builtin.is_test) @compileError("only for testing");
        std.debug.assert(entries.len <= MAX_ENTRIES);

        var self: SlotHashes = .INIT;
        self.entries.appendSlice(entries) catch unreachable;
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
        return self;
    }

    pub fn initRandom(random: std.Random) SlotHashes {
        if (!builtin.is_test) @compileError("only for testing");

        var self: SlotHashes = .INIT;
        for (0..random.uintLessThan(usize, MAX_ENTRIES)) |_| self.add(
            random.intRangeAtMost(Slot, 0, 1_000),
            Hash.initRandom(random),
        );
        std.sort.heap(Entry, self.entries.slice(), {}, Entry.sortCmp);
        return self;
    }
};

test "add and get" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var slot_hashes: SlotHashes = .INIT;

    const hash_0 = Hash.initRandom(random);
    slot_hashes.add(0, hash_0);
    try std.testing.expectEqual(hash_0, slot_hashes.get(0));

    const hash_1 = Hash.initRandom(random);
    slot_hashes.add(1, hash_1);
    try std.testing.expectEqual(hash_1, slot_hashes.get(1));

    const hash_2 = Hash.initRandom(random);
    slot_hashes.add(2, hash_2);
    try std.testing.expectEqual(hash_2, slot_hashes.get(2));

    const hash_4 = Hash.initRandom(random);
    slot_hashes.add(4, hash_4);
    try std.testing.expectEqual(hash_4, slot_hashes.get(4));

    const hash_3 = Hash.initRandom(random);
    slot_hashes.add(3, hash_3);
    try std.testing.expectEqual(hash_3, slot_hashes.get(3));

    try std.testing.expectEqualSlices(
        SlotHashes.Entry,
        &.{
            .{ .slot = 4, .hash = hash_4 },
            .{ .slot = 3, .hash = hash_3 },
            .{ .slot = 2, .hash = hash_2 },
            .{ .slot = 1, .hash = hash_1 },
            .{ .slot = 0, .hash = hash_0 },
        },
        slot_hashes.entries.constSlice(),
    );
}

test "serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    {
        const serialized = try bincode.writeAlloc(allocator, SlotHashes.INIT, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, SlotHashes, serialized, .{});

        try std.testing.expectEqualSlices(
            SlotHashes.Entry,
            &.{},
            deserialized.entries.constSlice(),
        );
    }

    {
        var slot_hashes: SlotHashes = .INIT;
        slot_hashes.add(0, Hash.initRandom(random));

        const serialized = try bincode.writeAlloc(allocator, slot_hashes, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, SlotHashes, serialized, .{});

        try std.testing.expectEqualSlices(
            SlotHashes.Entry,
            slot_hashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
