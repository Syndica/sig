const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");

const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const LruCacheCustom = sig.common.lru.LruCacheCustom;
const ReferenceCounter = sig.sync.reference_counter.ReferenceCounter;

/// Stores read-only in-memory copies of commonly used accounts
pub const AccountsCache = struct {
    slot_lrus: SlotLRUs,
    allocator: std.mem.Allocator,
    max_items: usize,
    max_slots: usize,
    highest_slot: ?Slot,

    /// Atomically refcounted account
    pub const CachedAccount = struct {
        account: Account,
        /// represents whether this account has been mutated, and shouldn't progress to newer slots
        // TODO: when we start mutating accounts, make sure to set this field
        is_dirty: std.atomic.Value(bool) = .{ .raw = false },
        ref_count: ReferenceCounter,

        pub fn init(allocator: std.mem.Allocator, account: Account) !CachedAccount {
            return .{
                .account = try account.clone(allocator),
                .ref_count = .{},
            };
        }

        pub fn deinit(self: *CachedAccount, allocator: std.mem.Allocator) void {
            self.account.deinit(allocator);
            self.* = undefined;
        }

        pub fn releaseOrDestroy(self: *CachedAccount, allocator: std.mem.Allocator) void {
            if (self.ref_count.release()) {
                self.deinit(allocator);
                allocator.destroy(self);
            }
        }

        // satisfies the type LruCacheCustom expects
        pub fn releaseOrDestroyDoublePtr(self: **CachedAccount, allocator: std.mem.Allocator) void {
            releaseOrDestroy(self.*, allocator);
        }

        pub fn copyRef(self: *CachedAccount) *CachedAccount {
            if (self.ref_count.acquire()) {
                return self;
            } else {
                @panic("Attempted to acquire reference to destroyed CachedAccount");
            }
        }

        pub fn getMeta(self: *CachedAccount) CachedAccountMeta {
            return .{
                .is_dirty = self.is_dirty.load(.monotonic),
                .ref_count = self.ref_count,
            };
        }
    };

    /// A copy of a CachedAccout's fields, without the account
    pub const CachedAccountMeta = struct {
        is_dirty: bool,
        ref_count: ReferenceCounter,
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

    /// user is expected to release the returned CachedAccount
    pub fn get(self: *const Self, slot: Slot, pubkey: Pubkey) ?*CachedAccount {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse return null;
        const account = slot_lru.get(pubkey) orelse return null;
        return account.copyRef();
    }

    /// Returns a copy of the CachedAccount's meta. Likely shouldn't be used outside of tests.
    pub fn getMeta(self: *const Self, slot: Slot, pubkey: Pubkey) ?CachedAccountMeta {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse return null;
        const account = slot_lru.get(pubkey) orelse return null;
        return account.getMeta();
    }

    /// does not influence underlying LRU's cache ordering
    pub fn contains(self: *const Self, slot: Slot, pubkey: Pubkey) bool {
        const slot_lru = self.slot_lrus.getPtr(slot) orelse return false;
        return slot_lru.contains(pubkey);
    }

    /// will return an error for existing entries, leaving the state unmodified
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
                if (node.data.value.is_dirty.load(.monotonic)) continue; // do not copy forward modified accounts

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
                lowest_slot = @min(lowest_slot, entry.key_ptr.*);
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
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    const cached_account = try allocator.create(AccountsCache.CachedAccount);
    cached_account.* = try AccountsCache.CachedAccount.init(allocator, account);
    defer cached_account.releaseOrDestroy(allocator);

    try std.testing.expectEqual(cached_account.ref_count.state.raw, 1);

    const cached_account_ref = cached_account.copyRef();

    try std.testing.expectEqual(cached_account.ref_count.state.raw, 2);

    cached_account_ref.releaseOrDestroy(allocator);

    try std.testing.expectEqual(cached_account.ref_count.state.raw, 1);
}

test "AccountsCache put and get account" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(random);
    const slot = 1;

    try accounts_cache.put(slot, pubkey, account);

    const cached_account = accounts_cache.get(slot, pubkey);
    defer if (cached_account) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(cached_account != null);
}

test "AccountsCache returns null when account is missing" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const pubkey = Pubkey.random(random);
    const slot = 1;

    const result = accounts_cache.get(slot, pubkey);
    defer if (result) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(result == null);
}

test "AccountsCache put & copySlot ref counting" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 2);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(random);
    const old_slot = 1;
    const new_slot = 2;

    try accounts_cache.put(old_slot, pubkey, account);

    try std.testing.expectEqual(accounts_cache.getMeta(old_slot, pubkey).?.ref_count.state.raw, 1);

    try accounts_cache.shiftLRUForward(old_slot, new_slot);

    try std.testing.expectEqual(accounts_cache.getMeta(old_slot, pubkey).?.ref_count.state.raw, 2);

    const cached_account = accounts_cache.get(new_slot, pubkey);
    defer if (cached_account) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(cached_account != null);
}

test "AccountsCache max slots" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 2);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(random);

    try accounts_cache.put(1, pubkey, account);
    try std.testing.expect(accounts_cache.contains(1, pubkey));
    try accounts_cache.shiftLRUForward(1, 2);
    try std.testing.expect(accounts_cache.contains(1, pubkey));
    // create 3rd slot, max slots = 2, 1st slot evicted
    try accounts_cache.shiftLRUForward(2, 3);
    try std.testing.expect(!accounts_cache.contains(1, pubkey));
    try std.testing.expect(accounts_cache.slot_lrus.count() == 2);
}

test "AccountsCache put returns error on duplicate" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const pubkey = Pubkey.random(random);
    const slot = 1;

    try accounts_cache.put(slot, pubkey, account);

    // Trying to insert the same account again should fail
    try std.testing.expectEqual(error.AlreadyExistsInCache, accounts_cache.put(slot, pubkey, account));
}

test "AccountsCache purgeSlot removes the slot and accounts" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10, 1);
    defer accounts_cache.deinit();

    const account = try Account.random(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.random(random);

    const slot = 1;
    try accounts_cache.put(slot, pubkey, account);
    accounts_cache.purgeSlot(slot);
    const result = accounts_cache.get(slot, pubkey);
    defer if (result) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(result == null);
}
