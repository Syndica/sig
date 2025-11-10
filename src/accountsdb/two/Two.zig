//! Thin wrapper around Rooted and Unrooted that ties everything together to be used by the account store.

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
pub const Rooted = @import("Rooted.zig");
pub const Unrooted = @import("Unrooted.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const AccountSharedData = sig.runtime.AccountSharedData;

const Db = @This();

allocator: std.mem.Allocator,
rooted: Rooted,
unrooted: Unrooted,

pub fn init(allocator: std.mem.Allocator, rooted: Rooted) !Db {
    var unrooted: Unrooted = try .init(allocator);
    errdefer unrooted.deinit(allocator);

    return .{
        .allocator = allocator,
        .rooted = rooted,
        .unrooted = unrooted,
    };
}

pub fn deinit(self: *Db) void {
    const allocator = self.allocator;
    self.rooted.deinit();
    self.unrooted.deinit(allocator);
}

/// Clones the account shared data.
pub fn put(self: *Db, slot: Slot, address: Pubkey, data: AccountSharedData) !void {
    const cloned = try data.clone(self.allocator);
    errdefer cloned.deinit(self.allocator);
    try self.unrooted.put(self.allocator, slot, address, cloned);
}

// TODO: this should be trivial to put on another thread; this currently blocks the main replay
// thread for 30-40ms per slot on testnet.
pub fn onSlotRooted(self: *Db, newly_rooted_slot: Slot) error{FailedToRoot}!void {
    _ = self;
    _ = newly_rooted_slot;

    // const rooted_index: *Unrooted.SlotIndex = for (self.unrooted.slots) |*index| {
    //     if (index.is_empty.load(.acquire)) continue;
    //     if (index.slot != newly_rooted_slot) continue;
    //     break index;
    // } else unreachable; // we can't root a slot that doesn't exist!

    // // Get read lock on unrooted slot, commit to db
    // {
    //     rooted_index.lock.lockShared();
    //     defer rooted_index.lock.unlockShared();

    //     std.debug.assert(rooted_index.slot == newly_rooted_slot);
    //     std.debug.assert(!rooted_index.is_empty.load(.acquire));

    //     self.rooted.beginTransation() catch return error.FailedToRoot;

    //     var entries = rooted_index.entries.iterator();
    //     while (entries.next()) |entry| {
    //         self.rooted.put(entry.key_ptr.*, newly_rooted_slot, entry.value_ptr.*) catch
    //             return error.FailedToRoot;
    //     }

    //     self.rooted.commitTransation() catch return error.FailedToRoot;
    // }

    // // Get write lock on unrooted slot, remove from unrooted
    // {
    //     rooted_index.lock.lock();
    //     defer rooted_index.lock.unlock();

    //     std.debug.assert(rooted_index.slot == newly_rooted_slot);
    //     std.debug.assert(!rooted_index.is_empty.load(.acquire));

    //     rooted_index.entries.clearRetainingCapacity();
    //     rooted_index.is_empty.store(true, .release);
    // }

    // if (builtin.is_test) {
    //     self.rooted.largest_rooted_slot = @max(
    //         self.rooted.largest_rooted_slot orelse 0,
    //         newly_rooted_slot,
    //     );
    // }
}

pub fn get(
    self: *Db,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: *const Ancestors,
) !?Account {
    // first try finding it in the unrooted storage
    if (self.unrooted.get(address, ancestors)) |data| {
        return data;
    }
    // then try finding it in the rooted storage
    if (try self.rooted.get(allocator, address)) |data| {
        return data.toOwnedAccount();
    }
    // doesn't exist
    return null;
}

pub const SlotModifiedIterator = struct {
    slot: *Unrooted.SlotIndex,
    cursor: u64,

    pub fn unlock(self: *SlotModifiedIterator) void {
        self.cursor = std.math.maxInt(u64);
        self.slot.lock.unlockShared();
    }

    pub fn len(self: *SlotModifiedIterator) usize {
        return self.slot.entries.count();
    }

    pub fn next(
        self: *SlotModifiedIterator,
        allocator: std.mem.Allocator,
    ) !?struct { Pubkey, Account } {
        defer self.cursor += 1;
        if (self.cursor >= self.len()) return null;

        const pubkey = self.slot.entries.keys()[self.cursor];
        const acc = self.slot.entries.values()[self.cursor];

        var account = acc.asAccount();
        account.data = .{ .owned_allocation = try allocator.dupe(u8, acc.data) };

        return .{ pubkey, account };
    }
};

pub fn slotModifiedIterator(self: *Db, slot: Slot) ?SlotModifiedIterator {
    const index = slot % Unrooted.MAX_SLOTS;
    const entry = &self.unrooted.slots[index];
    if (entry.is_empty.load(.acquire)) return null;
    entry.lock.lockShared();
    return .{
        .slot = entry,
        .cursor = 0,
    };
}
