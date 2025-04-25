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

pub const AccountLocks = struct {
    write_locks: std.AutoArrayHashMapUnmanaged(Pubkey, void) = .{},
    readonly_locks: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{},

    const LockError = Allocator.Error | error{LockFailed};

    /// Either locks all accounts, or locks none and returns an error.
    pub fn lock(
        self: *AccountLocks,
        allocator: Allocator,
        /// { account to lock, write access needed }
        accounts: []const struct { Pubkey, bool },
    ) LockError!void {
        for (accounts) |account| {
            const address, const write = account;
            if (write) {
                if (self.readonly_locks.contains(address) or self.write_locks.contains(address)) {
                    return error.LockFailed;
                }
            } else if (self.write_locks.contains(address)) {
                return error.LockFailed;
            }
        }
        for (accounts, 0..) |account, i| {
            errdefer std.debug.assert(0 == self.unlock(accounts[0..i]));
            const address, const write = account;
            if (write) {
                _ = try self.write_locks.getOrPut(allocator, address);
            } else {
                const entry = try self.readonly_locks.getOrPut(allocator, address);
                entry.value_ptr.* += 1;
            }
        }
    }

    /// Infallible function that guarantees all the provided accounts will be
    /// unlocked after it returns.
    ///
    /// Returns the number of items that were already unlocked and thus did not
    /// need to be unlocked. You can use this in a calling scope to assert that
    /// this struct is not being misused.
    pub fn unlock(
        self: *AccountLocks,
        accounts: []struct { Pubkey, bool },
    ) u64 {
        var already_unlocked: u64 = 0;
        for (accounts) |account| {
            const address, const write = account;
            if (write) {
                self.write_locks.swapRemove(address);
            } else {
                const index = self.readonly_locks.getIndex(address) orelse {
                    already_unlocked += 1;
                    continue;
                };
                const value = &self.readonly_locks.entries.slice().items(.value)[index];
                if (value.* == 0) {
                    // this means there is an internal bug within the unlock
                    // method, since the next block here should remove the item
                    // before this number would ever reach zero.
                    unreachable;
                } else if (value.* == 1) {
                    self.readonly_locks.swapRemoveAt(index);
                } else {
                    value.* -= 1;
                }
            }
        }
        return already_unlocked;
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
