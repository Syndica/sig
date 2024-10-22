const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");

const Account = sig.core.Account;
const Pubkey = sig.core.pubkey.Pubkey;
const LruCacheCustom = sig.common.lru.LruCacheCustom;
const ReferenceCounter = sig.sync.reference_counter.ReferenceCounter;
const Slot = sig.core.Slot;

/// Stores read-only in-memory copies of commonly used *rooted* accounts
pub const AccountsCache = struct {
    lru: LRU,
    allocator: std.mem.Allocator,
    cache_hits: usize = 0,
    cache_misses: usize = 0,

    /// Atomically refcounted account
    pub const CachedAccount = struct {
        account: Account,
        ref_count: ReferenceCounter,
        /// the slot that this version of the account originates from
        slot: Slot,

        pub fn init(allocator: std.mem.Allocator, account: Account, slot: Slot) error{OutOfMemory}!CachedAccount {
            return .{
                .account = try account.clone(allocator),
                .ref_count = .{},
                .slot = slot,
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

        pub fn copyRef(self: *CachedAccount) *CachedAccount {
            if (self.ref_count.acquire()) {
                return self;
            } else {
                unreachable;
            }
        }

        fn getMeta(self: *CachedAccount) CachedAccountMeta {
            return .{
                .ref_count = self.ref_count,
            };
        }
    };

    /// A copy of a CachedAccout's fields, without the account
    const CachedAccountMeta = struct {
        ref_count: ReferenceCounter,
    };

    pub const LRU = LruCacheCustom(
        .non_locking,
        Pubkey,
        *CachedAccount,
        std.mem.Allocator,
        CachedAccount.releaseOrDestroy,
    );

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        max_items: usize,
    ) error{OutOfMemory}!AccountsCache {
        return .{
            .lru = try LRU.initWithContext(allocator, max_items, allocator),
            .allocator = allocator,
        };
    }

    /// User is expected to release the returned CachedAccount.
    pub fn get(self: *Self, pubkey: Pubkey, slot: Slot) ?*CachedAccount {
        const account: *CachedAccount = self.lru.get(pubkey) orelse {
            self.cache_misses += 1;
            return null;
        };
        if (account.slot == slot) {
            self.cache_hits += 1;
            return account.copyRef();
        } else {
            self.cache_misses += 1;
            return null;
        }
    }

    /// Returns a copy of the CachedAccount's meta. Likely shouldn't be used outside of tests.
    fn getMeta(self: *Self, pubkey: Pubkey, slot: Slot) ?CachedAccountMeta {
        const account: *CachedAccount = self.lru.peek(pubkey) orelse return null;
        if (account.slot == slot) {
            return account.getMeta();
        } else {
            return null;
        }
    }

    /// Replaces the previous entry, if one existed
    pub fn put(self: *Self, pubkey: Pubkey, slot: Slot, account: Account) error{OutOfMemory}!void {
        if (self.lru.peek(pubkey)) |existing_entry| {
            if (existing_entry.slot < slot) {
                existing_entry.releaseOrDestroy(self.allocator);

                const new_entry = try self.allocator.create(CachedAccount);
                new_entry.* = try CachedAccount.init(self.allocator, account, slot);
                _ = self.lru.put(pubkey, new_entry);
            } else {
                // do nothing, prefer newer slots in cache
            }
        } else {
            const new_entry = try self.allocator.create(CachedAccount);
            new_entry.* = try CachedAccount.init(self.allocator, account, slot);
            _ = self.lru.put(pubkey, new_entry);
        }
    }

    pub fn deinit(self: *Self) void {
        self.lru.deinit();
    }
};

test "CachedAccount ref_count" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    const account = try Account.initRandom(allocator, random, 1);
    defer account.deinit(allocator);

    const cached_account = try allocator.create(AccountsCache.CachedAccount);
    cached_account.* = try AccountsCache.CachedAccount.init(allocator, account, 1);
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

    var accounts_cache = try AccountsCache.init(allocator, 10);
    defer accounts_cache.deinit();

    const account = try Account.initRandom(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);

    try accounts_cache.put(pubkey, 1, account);

    const cached_account = accounts_cache.get(pubkey, 1);
    defer if (cached_account) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(cached_account != null);
}

test "AccountsCache returns null when account is missing" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10);
    defer accounts_cache.deinit();

    const pubkey = Pubkey.initRandom(random);

    const result = accounts_cache.get(pubkey, 1);
    defer if (result) |cached| cached.releaseOrDestroy(allocator);

    try std.testing.expect(result == null);
}

test "AccountsCache put ref counting" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(19);
    const random = prng.random();

    var accounts_cache = try AccountsCache.init(allocator, 10);
    defer accounts_cache.deinit();

    const account = try Account.initRandom(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);

    const slot_1 = 1;
    const slot_2 = 2;

    // put: refcount = 1
    try accounts_cache.put(pubkey, slot_1, account);
    try std.testing.expectEqual(1, accounts_cache.getMeta(pubkey, slot_1).?.ref_count.state.raw);

    // get: refcount += 1
    const account_ref = accounts_cache.get(pubkey, slot_1).?;
    defer account_ref.releaseOrDestroy(allocator);
    try std.testing.expectEqual(2, account_ref.ref_count.state.raw);

    // new entry added at pubkey, old entry's refcount decremented
    // new entry's refcount also starts at 1
    try accounts_cache.put(pubkey, slot_2, account);
    try std.testing.expectEqual(1, account_ref.ref_count.state.raw);
    try std.testing.expectEqual(1, accounts_cache.getMeta(pubkey, slot_2).?.ref_count.state.raw);

    const account_ref_2 = accounts_cache.get(pubkey, slot_2).?;
    defer account_ref_2.releaseOrDestroy(allocator);

    try std.testing.expectEqual(2, account_ref_2.ref_count.state.raw);
}
