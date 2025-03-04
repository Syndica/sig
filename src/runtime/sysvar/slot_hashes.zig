const std = @import("std");
const sig = @import("../../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/slot-hashes/src/lib.rs#L43
pub const SlotHashes = struct {
    const Entry = struct { Slot, Hash };

    entries: []const Entry,

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHashes111111111111111111111111111") catch unreachable;

    fn compareFn(context: void, key: Slot, mid_item: Entry) std.math.Order {
        _ = context;
        return std.math.order(key, mid_item[0]);
    }

    pub fn get(self: *const SlotHashes, slot: u64) ?Hash {
        const found_index = std.sort.binarySearch(Entry, slot, self.entries, {}, compareFn) orelse
            return null;
        return self.entries[found_index][1];
    }
};
