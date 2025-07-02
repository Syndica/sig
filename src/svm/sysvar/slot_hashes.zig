const std = @import("std");
const sig = @import("../../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    entries: []const Entry,

    pub const Entry = struct { Slot, Hash };

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;

    pub const DEFAULT = SlotHashes{
        .entries = &.{},
    };

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/834edeb5acf996377210729b0982819c42027227/sysvar/src/slot_hashes.rs#L59
    pub const SIZE_OF: usize = 20_488;

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/9148b5cc95b43319f3451391ec66d0086deb5cfa/slot-hashes/src/lib.rs#L21
    pub const MAX_ENTRIES: usize = 512;

    fn compareFn(key: Slot, mid_item: Entry) std.math.Order {
        return std.math.order(key, mid_item[0]);
    }

    pub fn deinit(self: SlotHashes, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
    }

    pub fn getIndex(self: *const SlotHashes, slot: u64) ?usize {
        return std.sort.binarySearch(Entry, self.entries, slot, compareFn);
    }

    pub fn get(self: *const SlotHashes, slot: u64) ?Hash {
        return self.entries[(self.getIndex(slot) orelse return null)][1];
    }
};
