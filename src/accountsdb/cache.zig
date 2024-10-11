const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");

const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;

const LruCacheCustom = sig.common.lru.LruCacheCustom;

/// Stores read-only in-memory copies of commonly used accounts
pub const AccountsCache = struct {
    /// Atomically refcounted account
    pub const CachedAccount = struct {
        account: Account,
        // this account has since been mutated, and will not progress to newer slots
        // TODO: when we start mutating accounts, make sure to set this field
        is_dirty: std.atomic.Value(bool) = .{ .raw = false },
        ref_count: std.atomic.Value(usize),

        pub fn init(allocator: std.mem.Allocator, account: Account) !CachedAccount {
            return .{
                .account = try account.clone(allocator),
                .ref_count = std.atomic.Value(usize).init(1),
            };
        }

        pub fn deinit(self: *CachedAccount, allocator: std.mem.Allocator) void {
            self.account.deinit(allocator);
            self.* = undefined;
        }

        pub fn releaseOrDestroy(self: *CachedAccount, allocator: std.mem.Allocator) void {
            const current_count = self.ref_count.load(.acquire);
            if (current_count == 1) {
                self.deinit(allocator);
                allocator.destroy(self);
            } else {
                _ = self.ref_count.fetchSub(1, .acq_rel);
            }
        }

        // satisfies the type LruCacheCustom expects
        pub fn releaseOrDestroyDoublePtr(self: **CachedAccount, allocator: std.mem.Allocator) void {
            releaseOrDestroy(self.*, allocator);
        }

        pub fn copyRef(self: *CachedAccount) *CachedAccount {
            _ = self.ref_count.fetchAdd(1, .acq_rel);
            return self;
        }
    };

    pub const LRU = LruCacheCustom(
        .locking,
        Pubkey,
        *CachedAccount,
        std.mem.Allocator,
        CachedAccount.releaseOrDestroyDoublePtr,
    );
    pub const SlotLRUs = std.AutoHashMapUnmanaged(Slot, LRU);

    const Self = @This();

    slot_lrus: SlotLRUs,
    allocator: std.mem.Allocator,
    max_items: usize,
    max_slots: usize,
    highest_slot: ?Slot,

    pub fn init(
        allocator: std.mem.Allocator,
        max_items: usize,
        max_slots: usize,
    ) !AccountsCache {
        return .{
            .slot_lrus = .{},
            .allocator = allocator,
            .max_items = max_items,
            .max_slots = max_slots,
            .highest_slot = null,
        };
    }

    pub fn get(self: *const Self, slot: Slot, pubkey: Pubkey) ?CachedAccount {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse return null;
        return (slot_lru.get(pubkey) orelse return null).*;
    }

    /// should only be called iff account is not already present
    pub fn put(self: *Self, slot: Slot, pubkey: Pubkey, account: Account) !void {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse blk: {
            if (self.highest_slot) |highest_slot| {
                if (slot > highest_slot) {
                    try self.shiftLRUForward(highest_slot, slot);
                    break :blk self.slot_lrus.getPtr(slot).?;
                } else {
                    return error.SlotLowerThanPrevious;
                }
            } else {
                try self.slot_lrus.put(
                    self.allocator,
                    slot,
                    try LRU.initWithContext(self.allocator, self.max_items, self.allocator),
                );

                break :blk self.slot_lrus.getPtr(slot).?;
            }
        };

        if (self.highest_slot == null or slot > self.highest_slot.?) {
            self.highest_slot = slot;
        }

        self.enforceMaxSlotCount();

        const new_cached_account = try self.allocator.create(CachedAccount);
        errdefer self.allocator.destroy(new_cached_account);
        new_cached_account.* = try CachedAccount.init(self.allocator, account);
        errdefer new_cached_account.deinit(self.allocator);

        slot_lru.putNoClobber(pubkey, new_cached_account) catch |err| switch (err) {
            error.EntryAlreadyExists => return error.AlreadyExistsInCache,
        };
    }

    /// remove slot lru, decreasing ref_counts on CachedAccounts (optionally removing)
    pub fn purgeSlot(self: *Self, slot: Slot) void {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse return;
        slot_lru.deinit();
        _ = self.slot_lrus.remove(slot);
    }

    /// bring slot lru forward to new slot, increasing ref_counts
    pub fn shiftLRUForward(self: *Self, old_slot: Slot, new_slot: Slot) !void {
        const old_slot_lru = self.slot_lrus.getPtr(old_slot) orelse return error.SlotNotFound;

        var new_slot_lru = try LRU.initWithContext(self.allocator, self.max_items, self.allocator);

        // copy from old to new slot lru
        {
            old_slot_lru.mux.lock();
            defer old_slot_lru.mux.unlock();

            var it = old_slot_lru.dbl_link_list.first;
            while (it) |node| : (it = node.next) {
                if (node.data.value.is_dirty.load(.acquire)) continue; // do not copy forward modified accounts

                _ = new_slot_lru.put(node.data.key, node.data.value.copyRef());
            }
        }

        try self.slot_lrus.put(self.allocator, new_slot, new_slot_lru);

        self.enforceMaxSlotCount();

        if (self.highest_slot == null or new_slot > self.highest_slot.?) {
            self.highest_slot = new_slot;
        }
    }

    /// removes lowest slot when exceeding .max_slots
    pub fn enforceMaxSlotCount(self: *Self) void {
        if (self.slot_lrus.count() > self.max_slots) {
            var lowest_slot: Slot = std.math.maxInt(usize);
            var iter = self.slot_lrus.iterator();
            while (iter.next()) |entry| {
                if (entry.key_ptr.* < lowest_slot) lowest_slot = entry.key_ptr.*;
            }
            self.purgeSlot(lowest_slot);
        }
    }

    pub fn deinit(self: *Self) void {
        var slot_iter = self.slot_lrus.iterator();
        while (slot_iter.next()) |entry| {
            const slot_lru_ptr = entry.value_ptr;
            slot_lru_ptr.deinit();
        }
        self.slot_lrus.deinit(self.allocator);
    }
};

test "CachedAccount ref_count" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    const cached_account = try allocator.create(AccountsCache.CachedAccount);
    cached_account.* = try AccountsCache.CachedAccount.init(allocator, account);
    defer cached_account.releaseOrDestroy(allocator);

    try std.testing.expectEqual(cached_account.ref_count.load(.acquire), 1);

    const cached_account_ref = cached_account.copyRef();

    try std.testing.expectEqual(cached_account.ref_count.load(.acquire), 2);

    cached_account_ref.releaseOrDestroy(allocator);

    try std.testing.expectEqual(cached_account.ref_count.load(.acquire), 1);
}

test "AccountsCache put and get account" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(rng);
    const slot = 1;

    try accounts_cache.put(slot, pubkey, account);

    const cached_account = accounts_cache.get(slot, pubkey);
    try std.testing.expect(cached_account != null);
}

test "AccountsCache returns null when account is missing" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const pubkey = Pubkey.random(rng);
    const slot = 1;

    const result = accounts_cache.get(slot, pubkey);
    try std.testing.expect(result == null);
}

test "AccountsCache put & copySlot ref counting" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 2);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(rng);
    const old_slot = 1;
    const new_slot = 2;

    try accounts_cache.put(old_slot, pubkey, account);

    try std.testing.expectEqual(accounts_cache.get(old_slot, pubkey).?.ref_count.load(.acquire), 1);

    try accounts_cache.shiftLRUForward(old_slot, new_slot);

    try std.testing.expectEqual(accounts_cache.get(old_slot, pubkey).?.ref_count.load(.acquire), 2);

    const cached_account = accounts_cache.get(new_slot, pubkey);
    try std.testing.expect(cached_account != null);
}

test "AccountsCache max slots" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 2);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(rng);

    try accounts_cache.put(1, pubkey, account);
    try std.testing.expect(accounts_cache.get(1, pubkey) != null);
    try accounts_cache.shiftLRUForward(1, 2);
    try std.testing.expect(accounts_cache.get(1, pubkey) != null);
    // create 3rd slot, max slots = 2, 1st slot evicted
    try accounts_cache.shiftLRUForward(2, 3);
    try std.testing.expect(accounts_cache.get(1, pubkey) == null);
    try std.testing.expect(accounts_cache.slot_lrus.count() == 2);
}

test "AccountsCache put returns error on duplicate" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const pubkey = Pubkey.random(rng);
    const slot = 1;

    try accounts_cache.put(slot, pubkey, account);

    // Trying to insert the same account again should fail
    try std.testing.expectEqual(error.AlreadyExistsInCache, accounts_cache.put(slot, pubkey, account));
}

test "AccountsCache purgeSlot removes the slot and accounts" {
    const allocator = std.testing.allocator;
    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, rng, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(rng);

    const slot = 1;
    try accounts_cache.put(slot, pubkey, account);
    accounts_cache.purgeSlot(slot);
    const result = accounts_cache.get(slot, pubkey);
    try std.testing.expect(result == null);
}
