//! system variables definitions and addresses (clock, slot_history, …)
const std = @import("std");
const sig = @import("../../sig.zig");

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;

pub const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

/// Analogous to [Check](https://github.com/anza-xyz/agave/blob/fc2a8794be2526e9fd6cdbc9b304c055b2d9cc57/sdk/program/src/slot_history.rs#L46)
pub const SlotCheckResult = enum { future, too_old, found, not_found };

/// Analogous to [SlotHistory](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/slot_history.rs#L16)
pub const SlotHistory = struct {
    bits: DynamicArrayBitSet(u64),
    next_slot: Slot,

    pub const @"!bincode-config:bits" = BitVecConfig(u64);

    pub const ID =
        Pubkey.parseBase58String("SysvarS1otHistory11111111111111111111111111") catch unreachable;

    pub fn deinit(self: SlotHistory, allocator: std.mem.Allocator) void {
        sig.bincode.free(allocator, self);
    }

    pub fn check(self: *const SlotHistory, slot: Slot) SlotCheckResult {
        if (slot > self.newest()) {
            return SlotCheckResult.future;
        } else if (slot < self.oldest()) {
            return SlotCheckResult.too_old;
        } else if (self.bits.isSet(slot % MAX_ENTRIES)) {
            return SlotCheckResult.found;
        } else {
            return SlotCheckResult.not_found;
        }
    }

    pub fn newest(self: *const SlotHistory) Slot {
        return self.next_slot - 1;
    }

    pub fn oldest(self: *const SlotHistory) Slot {
        return self.next_slot -| MAX_ENTRIES;
    }
};
