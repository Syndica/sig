const std = @import("std");
const sig = @import("../../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    inner: std.ArrayListUnmanaged(Entry),

    pub const Entry = struct { slot: Slot, hash: Hash };

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;

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
