const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    entries: std.ArrayListUnmanaged(Entry),

    pub const Entry = struct {
        slot: Slot,
        hash: Hash,

        pub fn sortCmp(_: void, a: Entry, b: Entry) bool {
            return b.slot < a.slot; // Sort by descending slot
        }

        pub fn searchCmp(key: Slot, mid_item: Entry) std.math.Order {
            return std.math.order(mid_item.slot, key);
        }
    };

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;

    pub const MAX_ENTRIES: usize = 512;

    pub const SIZE_OF: usize = 20_488;

    pub fn default(allocator: Allocator) Allocator.Error!SlotHashes {
        return .{
            .entries = try .initCapacity(
                allocator,
                MAX_ENTRIES + 1, // Allows .insertAssumeCapacity in `add` method
            ),
        };
    }

    pub fn deinit(self: SlotHashes, allocator: Allocator) void {
        allocator.free(self.entries.allocatedSlice());
    }

    pub fn getIndex(self: *const SlotHashes, slot: u64) ?usize {
        return std.sort.binarySearch(Entry, self.entries.items, slot, Entry.searchCmp);
    }

    pub fn get(self: *const SlotHashes, slot: Slot) ?Hash {
        return if (self.getIndex(slot)) |index|
            self.entries.items[index].hash
        else
            null;
    }

    pub fn add(self: *SlotHashes, slot: Slot, hash: Hash) void {
        const index = std.sort.lowerBound(Entry, self.entries.items, slot, Entry.searchCmp);
        // Slot is too old, greater than max entries
        if (index == self.entries.items.len) return;
        // Slot exists, overwrite hash
        if (self.entries.items[index].slot == slot) self.entries.items[index].hash = hash;
        // Insert and pop last slot
        self.entries.insertAssumeCapacity(index, .{ .slot = slot, .hash = hash });
        _ = self.entries.pop();
    }

    pub fn initWithEntries(
        allocator: Allocator,
        entries: []const Entry,
    ) Allocator.Error!SlotHashes {
        if (!builtin.is_test) @compileError("only for testing");
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self = try SlotHashes.default(allocator);
        try self.entries.appendSlice(allocator, entries);
        std.sort.heap(Entry, self.entries.items, {}, Entry.sortCmp);
        return self;
    }

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!SlotHashes {
        if (!builtin.is_test) @compileError("only for testing");
        var self = try SlotHashes.default(allocator);
        for (0..MAX_ENTRIES) |_| self.add(
            random.intRangeAtMost(Slot, 0, 1_000),
            Hash.initRandom(random),
        );
        std.sort.heap(Entry, self.entries.items, {}, Entry.sortCmp);
        return self;
    }
};
