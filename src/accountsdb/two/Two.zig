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

pub const TestContext = struct {
    db: Db,
    tmp: std.testing.TmpDir,

    pub fn deinit(self: *TestContext) void {
        Rooted.deinitThreadLocals();
        self.db.deinit();
        self.tmp.cleanup();
    }
};

/// Initializes a temporary empty rooted storage. Call tmp.cleanup() when done with it.
pub fn initTest(allocator: std.mem.Allocator) !TestContext {
    const tmp = std.testing.tmpDir(.{});
    var tmp_dir_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try tmp.dir.realpath(".", &tmp_dir_buffer);

    var buffer: [std.fs.max_path_bytes + 1]u8 = undefined;
    const path = try std.fmt.bufPrintZ(&buffer, "{s}/accounts.db", .{tmp_path});

    var rooted: Rooted = try .init(path);
    errdefer rooted.deinit();

    const db: @This() = try .init(allocator, rooted);
    return .{ .db = db, .tmp = tmp };
}

pub fn deinit(self: *Db) void {
    const allocator = self.allocator;
    self.rooted.deinit();
    self.unrooted.deinit(allocator);
}

/// Clones the account shared data.
pub fn put(self: *Db, slot: Slot, address: Pubkey, data: AccountSharedData) !void {
    if (self.rooted.largest_rooted_slot) |lrs|
        if (lrs >= slot) return error.CannotWriteRootedSlot;

    const cloned = try data.clone(self.allocator);
    errdefer cloned.deinit(self.allocator);
    try self.unrooted.put(self.allocator, slot, address, cloned);
}

// TODO: this should be trivial to put on another thread; this currently blocks the main replay
// thread for 30-40ms per slot on testnet.
pub fn onSlotRooted(self: *Db, newly_rooted_slot: Slot, ancestors: *const Ancestors) void {
    self.rooted.beginTransaction();
    defer {
        self.rooted.commitTransaction();
        self.rooted.largest_rooted_slot = newly_rooted_slot;
    }

    // Ancestors are kept in a way where the "head" slot is stored.
    std.debug.assert(ancestors.containsSlot(newly_rooted_slot));
    // This assert is satifisied via the implementation of ancestors, however
    // we want to show that we'll never need to iterate over more than MAX_SLOTs cases.
    std.debug.assert(ancestors.ancestors.count() < Unrooted.MAX_SLOTS);

    // TODO: We can probably avoid running through the full range of slots
    // by computing something like:
    // range = new_slot - old_slot;
    // for (0..range) |i| (old_slot + i) % MAX_SLOTS;

    for (self.unrooted.slots) |*index| {
        if (index.is_empty.load(.acquire)) continue;
        if (index.slot > newly_rooted_slot) continue;

        index.lock.lock();
        defer index.lock.unlock();

        if (ancestors.containsSlot(index.slot)) {
            // TODO: batch put() into rooted
            var entries = index.entries.iterator();
            while (entries.next()) |entry| {
                self.rooted.put(entry.key_ptr.*, index.slot, entry.value_ptr.*);
            }
        }

        for (index.entries.values()) |data| data.deinit(self.allocator);
        index.entries.clearRetainingCapacity();
        index.is_empty.store(true, .release);
    }
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

// The behaviour of the db is mostly tested via:
// - `replay/consensus/core.zig`
// - `replay/update_sysvar.zig`
// - `accountsdb/account_store.zig`
// We can consider adding some more specific tests into this file.
