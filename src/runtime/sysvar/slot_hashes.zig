const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    inner: std.ArrayListUnmanaged(Entry),

    pub const Entry = struct { slot: Slot, hash: Hash };

        pub fn sortCmp(_: void, a: Entry, b: Entry) bool {
            return b.slot < a.slot; // Sort by descending slot
        }

    pub const MAX_ENTRIES: usize = 512;

    pub const SIZE_OF: usize = 20_488;

    pub fn init(allocator: std.mem.Allocator, max_entries: u64) !SlotHashes {
        return .{ .inner = try .initCapacity(allocator, max_entries) };
    }

    pub fn deinit(self: SlotHashes, allocator: std.mem.Allocator) void {
        allocator.free(self.inner.allocatedSlice());
    }

    pub fn default(allocator: std.mem.Allocator) !SlotHashes {
        return .{
            .inner = try .initCapacity(
                allocator,
                MAX_ENTRIES + 1, // Allows .insertAssumeCapacity in `add` method
            ),
        };
    }

    pub fn defaultWithEntries(allocator: std.mem.Allocator, entries: []const Entry) !SlotHashes {
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try SlotHashes.default(allocator);
        try self.inner.appendSlice(allocator, entries);
        std.sort.heap(Entry, self.inner.items, {}, struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                return a.slot >= b.slot;
            }
        }.lessThan);
        return self;
    }

    fn compareFn(key: Slot, mid_item: Entry) std.math.Order {
        return std.math.order(mid_item.slot, key);
    }

    pub fn getIndex(self: *const SlotHashes, slot: u64) ?usize {
        return std.sort.binarySearch(Entry, self.inner.items, slot, compareFn);
    }

    pub fn get(self: *const SlotHashes, slot: Slot) ?Hash {
        return if (self.getIndex(slot)) |index|
            self.inner.items[index].hash
        else
            null;
    }

    pub fn add(self: *SlotHashes, slot: Slot, hash: Hash) void {
        const index = std.sort.lowerBound(Entry, self.inner.items, slot, compareFn);
        // Slot is too old, greater than max entries
        if (index == self.inner.items.len) return;
        // Slot exists, overwrite hash
        if (self.inner.items[index].slot == slot) self.inner.items[index].hash = hash;
        // Insert and pop last slot
        self.inner.insertAssumeCapacity(index, .{ .slot = slot, .hash = hash });
        _ = self.inner.pop();
    }
};

test "add and get" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var slot_hashes = try SlotHashes.init(allocator);
    defer slot_hashes.deinit(allocator);

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
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    {
        var slot_hashes = try SlotHashes.initRandom(allocator, random);
        defer slot_hashes.deinit(allocator);

        const serialized = try bincode.writeAlloc(allocator, slot_hashes, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, SlotHashes, serialized, .{});
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(SlotHashes.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            SlotHashes.Entry,
            slot_hashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }

    {
        var slot_hashes = try SlotHashes.init(allocator);
        defer slot_hashes.deinit(allocator);
        slot_hashes.add(0, Hash.initRandom(random));

        const serialized = try bincode.writeAlloc(allocator, slot_hashes, .{});
        defer allocator.free(serialized);

        const deserialized = try bincode.readFromSlice(allocator, SlotHashes, serialized, .{});
        defer deserialized.deinit(allocator);

        try std.testing.expectEqual(SlotHashes.MAX_ENTRIES, deserialized.entries.capacity());
        try std.testing.expectEqualSlices(
            SlotHashes.Entry,
            slot_hashes.entries.constSlice(),
            deserialized.entries.constSlice(),
        );
    }
}
