//! system variables definitions and addresses (clock, slot_history, …)
const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;

/// Analogous to [Check](https://github.com/anza-xyz/agave/blob/fc2a8794be2526e9fd6cdbc9b304c055b2d9cc57/sdk/program/src/slot_history.rs#L46)
pub const SlotCheckResult = enum { future, too_old, found, not_found };

/// Analogous to [SlotHistory](https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/slot_history.rs#L16)
pub const SlotHistory = struct {
    bits: DynamicArrayBitSet(u64),
    next_slot: Slot,

    pub const @"!bincode-config:bits" = BitVecConfig(u64);

    pub const ID: Pubkey = .parse("SysvarS1otHistory11111111111111111111111111");

    pub const STORAGE_SIZE: u64 = 131_097;

    pub const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

    /// Agave initialises new slot history with the first slot set.
    /// This only impacts gensis when the slot history is not fully populated.
    pub fn init(allocator: Allocator) Allocator.Error!SlotHistory {
        var bits = try DynamicArrayBitSet(u64).initEmpty(allocator, MAX_ENTRIES);
        bits.set(0);
        return .{
            .bits = bits,
            .next_slot = 1,
        };
    }

    pub fn deinit(self: SlotHistory, allocator: Allocator) void {
        self.bits.deinit(allocator);
    }

    pub fn add(self: *SlotHistory, slot: u64) void {
        if (slot > self.next_slot and
            slot - self.next_slot >= MAX_ENTRIES)
        {
            const masks_to_clear = (MAX_ENTRIES + @bitSizeOf(u64) - 1) / @bitSizeOf(u64);
            @memset(self.bits.masks[0..masks_to_clear], 0);
        } else {
            if (self.next_slot <= slot) {
                for (self.next_slot..slot) |skipped| {
                    self.bits.unset(skipped % MAX_ENTRIES);
                }
            }
        }

        self.bits.set(slot % MAX_ENTRIES);
        self.next_slot = slot + 1;
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

    pub fn initRandom(allocator: Allocator, random: std.Random) Allocator.Error!SlotHistory {
        var self = try SlotHistory.init(allocator);
        for (0..random.intRangeAtMost(u64, 1, MAX_ENTRIES)) |_| {
            self.add(random.intRangeAtMost(Slot, 0, 1_000));
        }
        return self;
    }
};
