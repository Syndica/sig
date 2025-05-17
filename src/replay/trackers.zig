const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Rc = sig.sync.Rc;

const Epoch = sig.core.Epoch;
const EpochConstants = sig.core.EpochConstants;
const EpochSchedule = sig.core.EpochSchedule;
const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;

/// Central registry that tracks high-level info about slots and how they fork.
///
/// This is a lean version of `BankForks` from agave, focused on storing the
/// minimal information about slots to serve its core focus, rather than the
/// kitchen-sink style approach of storing everything under the sun.
///
/// [BankForks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank_forks.rs#L75)
///
/// This struct is *not* thread safe. Ensure the elements are not being used by
/// other threads when putting items in the map.
pub const SlotTracker = struct {
    slots: std.AutoArrayHashMapUnmanaged(Slot, Element) = .{},
    rw_lock: std.Thread.RwLock,

    const Element = struct {
        constants: SlotConstants,
        state: Rc(SlotState), // TODO properly handle mutations and lifetime
    };

    pub fn put(
        self: *SlotTracker,
        allocator: Allocator,
        slot: Slot,
        constants: SlotConstants,
        state: SlotState,
    ) !void {
        try allocator.create(Element);
        try self.slots.put(allocator, slot, .{ .constants = constants, .state = state });
    }

    pub fn getConstants(self: *const SlotTracker, slot: Slot) SlotConstants {
        _ = slot; // autofix
        self.rw_lock.lockShared();
        defer self.rw_lock.unlockShared();
        self.slots.get();
    }

    pub fn readState(self: *const SlotTracker) *const SlotState {
        _ = self; // autofix
    }

    pub fn writeState(self: *const SlotTracker) *SlotState {
        _ = self; // autofix
    }

    pub fn releaseState(self: *const SlotTracker, state: *SlotState) void {
        _ = state; // autofix
        _ = self; // autofix
    }

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
