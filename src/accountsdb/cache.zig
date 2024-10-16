const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");
const zstd = @import("zstd");

const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const LruCacheCustom = sig.common.lru.LruCacheCustom;
const ReferenceCounter = sig.sync.reference_counter.ReferenceCounter;

/// Stores read-only in-memory copies of commonly used *rooted* accounts
pub const AccountsCache = struct {
    lru: LRU,
    allocator: std.mem.Allocator,

    /// Atomically refcounted account
    pub const CachedAccount = struct {
        account: Account,
        ref_count: ReferenceCounter,

        pub fn init(allocator: std.mem.Allocator, account: Account) error{OutOfMemory}!CachedAccount {
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
        .locking,
        Pubkey,
        *CachedAccount,
        std.mem.Allocator,
        CachedAccount.releaseOrDestroyDoublePtr,
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
    pub fn get(self: *Self, pubkey: Pubkey) ?*CachedAccount {
        const account: *CachedAccount = self.lru.get(pubkey) orelse return null;
        return account.copyRef();
    }

    /// Returns a copy of the CachedAccount's meta. Likely shouldn't be used outside of tests.
    fn getMeta(self: *Self, pubkey: Pubkey) ?CachedAccountMeta {
        const account: *CachedAccount = self.lru.peek(pubkey) orelse return null;
        return account.getMeta();
    }

    /// Does not influence underlying LRU's cache ordering
    pub fn contains(self: *const Self, pubkey: Pubkey) bool {
        return self.lru.contains(pubkey);
    }

    /// Replaces the previous entry, if one existed
    pub fn put(self: *Self, pubkey: Pubkey, account: Account) error{OutOfMemory}!void {
        const new_entry = try self.allocator.create(CachedAccount);
        new_entry.* = try CachedAccount.init(self.allocator, account);

        if (self.lru.put(pubkey, new_entry)) |old_entry| {
            old_entry.releaseOrDestroy(self.allocator);
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

    var accounts_cache = try AccountsCache.init(allocator, 10);
    defer accounts_cache.deinit();

    const account = try Account.initRandom(allocator, random, 1);
    defer account.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);

    try accounts_cache.put(pubkey, account);

    const cached_account = accounts_cache.get(pubkey);
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

    const result = accounts_cache.get(pubkey);
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

    // put: refcount = 1
    try accounts_cache.put(pubkey, account);
    try std.testing.expectEqual(1, accounts_cache.getMeta(pubkey).?.ref_count.state.raw);

    // get: refcount += 1
    const account_ref = accounts_cache.get(pubkey).?;
    defer account_ref.releaseOrDestroy(allocator);
    try std.testing.expectEqual(2, account_ref.ref_count.state.raw);

    // new entry added at pubkey, old entry's refcount decremented
    // new entry's refcount also starts at 1
    try accounts_cache.put(pubkey, account);
    try std.testing.expectEqual(1, account_ref.ref_count.state.raw);
    try std.testing.expectEqual(1, accounts_cache.getMeta(pubkey).?.ref_count.state.raw);

    const account_ref_2 = accounts_cache.get(pubkey).?;
    defer account_ref_2.releaseOrDestroy(allocator);

    try std.testing.expectEqual(2, account_ref_2.ref_count.state.raw);
}
