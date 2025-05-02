//! Dependencies of replay that, in agave, would be defined as part of a
//! different component, but in sig, they were not yet implemented. So they were
//! added here with the minimal amount of necessary functionality to support
//! replay.

const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const EpochConstants = sig.core.EpochConstants;
const EpochSchedule = sig.core.EpochSchedule;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;

pub const tower_storage = struct {
    pub fn load() !?Tower {
        return Tower.init();
    }
};

pub const Tower = struct {
    pub fn init() Tower {
        return .{};
    }
};

/// Central registry that tracks high-level info about slots and how they fork.
///
/// This is a lean version of `BankForks` from agave, focused on storing the
/// minimal information about slots to serve its core focus, rather than the
/// kitchen-sink style approach of storing everything under the sun.
///
/// [BankForks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank_forks.rs#L75)
pub const SlotTracker = struct {
    slots: std.AutoArrayHashMapUnmanaged(Slot, Element) = .{},

    const Element = struct {
        constants: SlotConstants,
        state: SlotState, // TODO properly handle mutations and lifetime
    };

    pub fn activeSlots(
        self: *const SlotTracker,
        allocator: Allocator,
    ) Allocator.Error![]const Slot {
        var list = std.ArrayListUnmanaged(Slot){};
        var iter = self.slots.iterator();
        while (iter.next()) |entry| {
            if (!entry.value_ptr.state.isFrozen()) {
                try list.append(allocator, entry.key_ptr.*);
            }
        }
        return try list.toOwnedSlice(allocator);
    }
};

pub const EpochTracker = struct {
    epochs: std.AutoArrayHashMapUnmanaged(Epoch, EpochConstants) = .{},
    schedule: EpochSchedule,

    pub fn deinit(self: EpochTracker, allocator: Allocator) void {
        var epochs = self.epochs;
        epochs.deinit(allocator);
    }

    pub fn getForSlot(self: *const EpochTracker, slot: Slot) ?EpochConstants {
        return self.epochs.get(self.schedule.getEpoch(slot));
    }
};

pub const ProgressMap = struct {
    map: std.AutoHashMapUnmanaged(Slot, ForkProgress) = .{},
};

pub const ForkProgress = struct {
    is_dead: bool,
    confirmation_progress: ConfirmationProgress,

    pub const ConfirmationProgress = struct {
        last_entry: Hash,
        tick_hash_count: u64,
        num_shreds: u64,
        num_entries: usize,
        num_txs: usize,
    };
};
