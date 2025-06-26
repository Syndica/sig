const std = @import("std");
const sig = @import("../../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    entries: std.BoundedArray(SlotAndHash, MAX_ENTRIES) = .{},

    pub const SlotAndHash = struct { Slot, Hash };

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;

    pub const DEFAULT: SlotHashes = .{ .entries = .{} };

    pub const MAX_ENTRIES: usize = 512;

    pub const SIZE_OF: usize = 20_488;

    pub fn initWithEntries(entries: []const SlotAndHash) SlotHashes {
        std.debug.assert(entries.len <= MAX_ENTRIES);
        var self: SlotHashes = .{};
        for (entries) |entry| self.entries.appendAssumeCapacity(entry);
        return self;
    }

    fn compareFn(key: Slot, mid_item: SlotAndHash) std.math.Order {
        return std.math.order(key, mid_item[0]);
    }

    pub fn getIndex(self: *const SlotHashes, slot: u64) ?usize {
        return std.sort.binarySearch(SlotAndHash, self.entries.slice(), slot, compareFn);
    }

    pub fn get(self: *const SlotHashes, slot: u64) ?Hash {
        return self.entries.slice()[(self.getIndex(slot) orelse return null)][1];
    }
};
