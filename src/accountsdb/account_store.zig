//! Simplified interfaces for the common operations of writing and reading
//! accounts to and from a database.

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const accounts_db = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Account = sig.core.Account;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const AccountSharedData = sig.runtime.AccountSharedData;
const CompressedAccountPrefetchResult = accounts_db.CompressedAccountStore.PrefetchResult;
const CompressedAccountBatchDecodeResult = accounts_db.CompressedAccountStore.BatchDecodeResult;
const AtomicU64 = std.atomic.Value(u64);

pub const SlotAccountCacheStats = struct {
    get_calls: AtomicU64 = AtomicU64.init(0),
    cache_hits: AtomicU64 = AtomicU64.init(0),
    cache_misses: AtomicU64 = AtomicU64.init(0),
    fallback_found: AtomicU64 = AtomicU64.init(0),
    fallback_missing: AtomicU64 = AtomicU64.init(0),
    fallback_ns: AtomicU64 = AtomicU64.init(0),
    fallback_cache_fills: AtomicU64 = AtomicU64.init(0),
    fallback_cache_fill_races: AtomicU64 = AtomicU64.init(0),
    fallback_tombstone_fills: AtomicU64 = AtomicU64.init(0),
    cache_puts: AtomicU64 = AtomicU64.init(0),
    cache_put_replacements: AtomicU64 = AtomicU64.init(0),
    deferred_puts: AtomicU64 = AtomicU64.init(0),
    deferred_unique_writes: AtomicU64 = AtomicU64.init(0),
    deferred_flush_writes: AtomicU64 = AtomicU64.init(0),
    deferred_flush_missing: AtomicU64 = AtomicU64.init(0),
    deferred_flush_ns: AtomicU64 = AtomicU64.init(0),

    pub const Snapshot = struct {
        get_calls: u64,
        cache_hits: u64,
        cache_misses: u64,
        fallback_found: u64,
        fallback_missing: u64,
        fallback_ns: u64,
        fallback_cache_fills: u64,
        fallback_cache_fill_races: u64,
        fallback_tombstone_fills: u64,
        cache_puts: u64,
        cache_put_replacements: u64,
        deferred_puts: u64,
        deferred_unique_writes: u64,
        deferred_flush_writes: u64,
        deferred_flush_missing: u64,
        deferred_flush_ns: u64,
    };

    pub fn snapshot(self: *const SlotAccountCacheStats) Snapshot {
        return .{
            .get_calls = self.get_calls.load(.monotonic),
            .cache_hits = self.cache_hits.load(.monotonic),
            .cache_misses = self.cache_misses.load(.monotonic),
            .fallback_found = self.fallback_found.load(.monotonic),
            .fallback_missing = self.fallback_missing.load(.monotonic),
            .fallback_ns = self.fallback_ns.load(.monotonic),
            .fallback_cache_fills = self.fallback_cache_fills.load(.monotonic),
            .fallback_cache_fill_races = self.fallback_cache_fill_races.load(.monotonic),
            .fallback_tombstone_fills = self.fallback_tombstone_fills.load(.monotonic),
            .cache_puts = self.cache_puts.load(.monotonic),
            .cache_put_replacements = self.cache_put_replacements.load(.monotonic),
            .deferred_puts = self.deferred_puts.load(.monotonic),
            .deferred_unique_writes = self.deferred_unique_writes.load(.monotonic),
            .deferred_flush_writes = self.deferred_flush_writes.load(.monotonic),
            .deferred_flush_missing = self.deferred_flush_missing.load(.monotonic),
            .deferred_flush_ns = self.deferred_flush_ns.load(.monotonic),
        };
    }
};

/// Interface for both reading and writing accounts.
///
/// Do not use this unless you need to *write* into the database generically.
/// Otherwise use AccountReader if you only need to read accounts.
pub const AccountStore = union(enum) {
    accounts_db: *accounts_db.Db,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn reader(self: AccountStore) AccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = db },
            .thread_safe_map => |map| .{ .thread_safe_map = map },
            .noop => .noop,
        };
    }

    pub fn forSlot(self: AccountStore, slot: Slot, ancestors: *const Ancestors) SlotAccountStore {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = .{ db, slot, ancestors } },
            .thread_safe_map => |map| .{ .thread_safe_map = .{ map, slot, ancestors } },
            .noop => .noop,
        };
    }

    pub fn put(self: AccountStore, slot: Slot, address: Pubkey, account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountStore.put" });
        defer zone.deinit();

        return switch (self) {
            .accounts_db => |db| try db.put(slot, address, account),
            .thread_safe_map => |map| try map.put(slot, address, account),
            .noop => {},
        };
    }

    /// To be called from consensus when a slot is rooted
    pub fn onSlotRooted(
        self: AccountStore,
        newly_rooted_slot: Slot,
        ancestors: *const Ancestors,
    ) !void {
        var zone = tracy.Zone.init(@src(), .{ .name = "onSlotRooted" });
        defer zone.deinit();
        zone.value(newly_rooted_slot);

        switch (self) {
            .accounts_db => |db| db.onSlotRooted(newly_rooted_slot, ancestors),
            .thread_safe_map => |db| try db.onSlotRooted(newly_rooted_slot),
            .noop => {},
        }
    }

    pub fn onSlotRootedTimed(
        self: AccountStore,
        newly_rooted_slot: Slot,
        ancestors: *const Ancestors,
        perform_memory_relief: bool,
    ) !?accounts_db.Db.RootSlotTiming {
        var zone = tracy.Zone.init(@src(), .{ .name = "onSlotRootedTimed" });
        defer zone.deinit();
        zone.value(newly_rooted_slot);

        return switch (self) {
            .accounts_db => |db| db.onSlotRootedTimed(
                newly_rooted_slot,
                ancestors,
                perform_memory_relief,
            ),
            .thread_safe_map => |db| blk: {
                try db.onSlotRooted(newly_rooted_slot);
                break :blk null;
            },
            .noop => null,
        };
    }
};

/// Interface for only reading accounts
pub const AccountReader = union(enum) {
    accounts_db: *accounts_db.Db,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn forSlot(self: AccountReader, ancestors: *const Ancestors) SlotAccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = .{ db, ancestors } },
            .thread_safe_map => |map| .{ .thread_safe_map = .{ map, ancestors } },
            .noop => .noop,
        };
    }

    /// Returns the latest known version of an account, if it exists.
    ///
    /// Deinit all returned accounts using `account_reader.allocator()`
    pub fn getLatest(self: AccountReader, allocator: std.mem.Allocator, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |db| {
                var latest_known: struct { Slot, ?Account } = .{ 0, null };
                errdefer if (latest_known[1]) |acc| acc.deinit(allocator);

                // search through unrooted
                for (db.unrooted.slots) |*slot| {
                    slot.lock.lockShared();
                    defer slot.lock.unlockShared();
                    for (slot.entries.keys(), slot.entries.values()) |*key, data| {
                        if (address.equals(key)) {
                            const cloned = try data.clone(allocator);
                            if (slot.slot >= latest_known[0]) {
                                if (latest_known[1]) |acc| acc.deinit(allocator);
                                latest_known = .{ slot.slot, cloned.toOwnedAccount() };
                            } else {
                                cloned.deinit(allocator);
                            }
                        }
                    }
                }
                // if we found it, return. unrooted storage will always have newer
                // versions than rooted.
                if (latest_known[1]) |account| {
                    // Filter out zero-lamport accounts (deleted accounts)
                    if (account.lamports == 0) {
                        account.deinit(allocator);
                        return null;
                    }
                    return account;
                }

                // see if we have that account in rooted storage
                const account = (try db.rooted.get(allocator, address)) orelse return null;
                const owned = account.toOwnedAccount();
                // Filter out zero-lamport accounts (deleted accounts)
                if (owned.lamports == 0) {
                    owned.deinit(allocator);
                    return null;
                }
                return owned;
            },
            .thread_safe_map => |map| try map.getLatest(address),
            .noop => null,
        };
    }

    /// Returns an iterator that iterates over every account that was modified
    /// in the slot.
    ///
    /// Holds the read lock on the index, so unlock it when done, and be careful
    /// how long you hold this.
    pub fn slotModifiedIterator(self: AccountReader, slot: Slot) ?SlotModifiedIterator {
        switch (self) {
            inline .accounts_db, .thread_safe_map => |db, tag| {
                const iterator = db.slotModifiedIterator(slot) orelse return null;
                return @unionInit(SlotModifiedIterator, @tagName(tag), iterator);
            },
            .noop => return .noop,
        }
    }

    pub fn getLargestRootedSlot(self: AccountReader) ?Slot {
        if (!builtin.is_test) @compileError("only used in tests");
        return switch (self) {
            .accounts_db => |db| db.rooted.getLargestRootedSlot(),
            .thread_safe_map => |tsm| tsm.getLargestRootedSlot(),
            .noop => null,
        };
    }
};

pub const SlotModifiedIterator = union(enum) {
    accounts_db: accounts_db.Db.SlotModifiedIterator,
    thread_safe_map: ThreadSafeAccountMap.SlotModifiedIterator,
    noop,

    pub fn unlock(self: *SlotModifiedIterator) void {
        return switch (self.*) {
            inline else => |*item| item.unlock(),
            .noop => {},
        };
    }

    pub fn len(self: *SlotModifiedIterator) usize {
        return switch (self.*) {
            inline else => |*item| item.len(),
            .noop => 0,
        };
    }

    pub fn next(
        self: *SlotModifiedIterator,
        allocator: std.mem.Allocator,
    ) !?struct { Pubkey, Account } {
        return switch (self.*) {
            inline else => |*item| try item.next(allocator),
            .noop => null,
        };
    }
};

/// Interface for reading any account as it should appear during a particular slot.
///
/// For example, let's say the cluster has the following forking scenario:
///
/// ```
///      1
///     / \
///    2   3
///   /   / \
///  4   5   6
///           \
///            7
///```
///
/// A SlotAccountReader will be specialized for *one* of these slots. For
/// example, let's say you have the SlotAccountReader that's specialized for
/// slot 6, and you're using it to `get` an account was modified in slots 1, 2,
/// 3, 4, 5, and 7 (every slot except 6). It will return the version of the
/// account from slot 3 because it's the latest version on the current fork
/// that's less than or equal to slot 6. If the account was modified in slot 6,
/// then you'll get the version of the account from slot 6.
pub const SlotAccountStore = union(enum) {
    accounts_db: struct { *accounts_db.Db, Slot, *const Ancestors },
    cached_accounts_db: struct {
        *accounts_db.Db,
        Slot,
        *const Ancestors,
        Allocator,
        *sig.sync.RwLock,
        *sig.utils.collections.PubkeyMap(AccountSharedData),
        *sig.utils.collections.PubkeyMap(*const AccountSharedData),
        *sig.utils.collections.PubkeyMap(AccountSharedData),
        *sig.utils.collections.PubkeyMap(?usize),
        *SlotAccountCacheStats,
        *sig.utils.collections.PubkeyMap(void),
        bool,
        bool,
    },
    /// Contains many versions of accounts and becomes fork-aware using
    /// ancestors, like accountsdb.
    thread_safe_map: struct { *ThreadSafeAccountMap, Slot, *const Ancestors },
    account_shared_data_map: struct {
        Allocator,
        *sig.utils.collections.PubkeyMap(AccountSharedData),
    },
    noop,

    pub fn put(self: SlotAccountStore, address: Pubkey, account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "SlotAccountStore.put" });
        defer zone.deinit();

        return switch (self) {
            .accounts_db => |tuple| {
                const db, const slot, _ = tuple;
                try db.put(slot, address, account);
            },
            .cached_accounts_db => |tuple| {
                const db, const slot, _, const allocator, const cache_lock, const cache, _, const original_accounts, const account_data_lens, const stats, const deferred_dirty, const defer_writes, const record_lt_hash_originals = tuple;
                const cloned = try account.clone(allocator);
                errdefer cloned.deinit(allocator);

                if (!defer_writes) {
                    try db.put(slot, address, account);
                }

                cache_lock.lock();
                defer cache_lock.unlock();

                var first_deferred_write = false;
                if (defer_writes) {
                    const dirty_gop = try deferred_dirty.getOrPut(allocator, address);
                    if (!dirty_gop.found_existing) {
                        dirty_gop.value_ptr.* = {};
                        first_deferred_write = true;
                        _ = stats.deferred_unique_writes.fetchAdd(1, .monotonic);
                    }
                    _ = stats.deferred_puts.fetchAdd(1, .monotonic);
                }

                const gop = try cache.getOrPut(allocator, address);
                if (gop.found_existing) {
                    if (first_deferred_write and record_lt_hash_originals) {
                        const original_gop = try original_accounts.getOrPut(allocator, address);
                        std.debug.assert(!original_gop.found_existing);
                        original_gop.value_ptr.* = gop.value_ptr.*;
                    } else {
                        gop.value_ptr.deinit(allocator);
                    }
                }
                gop.value_ptr.* = cloned;
                try account_data_lens.put(
                    allocator,
                    address,
                    if (account.lamports == 0) null else account.data.len,
                );
                _ = stats.cache_puts.fetchAdd(1, .monotonic);
                if (gop.found_existing) {
                    _ = stats.cache_put_replacements.fetchAdd(1, .monotonic);
                }
            },
            .thread_safe_map => |tuple| {
                const map, const slot, _ = tuple;
                try map.put(slot, address, account);
            },
            .account_shared_data_map => |tuple| {
                const allocator, const map = tuple;
                const account_to_store = try account.clone(allocator);
                errdefer account_to_store.deinit(allocator);
                try map.put(allocator, address, account_to_store);
            },
            .noop => {},
        };
    }

    pub fn reader(self: SlotAccountStore) SlotAccountReader {
        return switch (self) {
            .accounts_db => |tuple| .{ .accounts_db = .{ tuple[0], tuple[2] } },
            .cached_accounts_db => |tuple| .{
                .cached_accounts_db = .{
                    tuple[0], tuple[2], tuple[3], tuple[4], tuple[5], tuple[6], tuple[8], tuple[9],
                },
            },
            .thread_safe_map => |tuple| .{ .thread_safe_map = .{ tuple[0], tuple[2] } },
            .account_shared_data_map => |tuple| .{ .account_shared_data_map = tuple[1] },
            .noop => .noop,
        };
    }
};

pub const SlotAccountReader = union(enum) {
    accounts_db: struct { *accounts_db.Db, *const Ancestors },
    cached_accounts_db: struct {
        *accounts_db.Db,
        *const Ancestors,
        Allocator,
        *sig.sync.RwLock,
        *sig.utils.collections.PubkeyMap(AccountSharedData),
        *sig.utils.collections.PubkeyMap(*const AccountSharedData),
        *sig.utils.collections.PubkeyMap(?usize),
        *SlotAccountCacheStats,
    },
    /// Contains many versions of accounts and becomes fork-aware using
    /// ancestors, like accountsdb.
    thread_safe_map: struct { *ThreadSafeAccountMap, *const Ancestors },
    /// Only stores the current slot's version of each account.
    /// Should only store borrowed accounts, or else it will panic on deinit.
    account_map: *const sig.utils.collections.PubkeyMap(Account),
    /// same as `account_map` but stores AccountSharedData
    account_shared_data_map: *const sig.utils.collections.PubkeyMap(AccountSharedData),
    noop,

    pub fn get(self: SlotAccountReader, alloc: std.mem.Allocator, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |pair| {
                const account = try pair[0].get(
                    alloc,
                    address,
                    pair[1],
                ) orelse return null;
                if (account.lamports == 0) {
                    account.deinit(alloc);
                    return null;
                }
                return account;
            },
            .cached_accounts_db => |tuple| {
                const db, const ancestors, const allocator, const cache_lock, const cache, const borrowed_cache, const account_data_lens, const stats = tuple;
                _ = stats.get_calls.fetchAdd(1, .monotonic);
                {
                    cache_lock.lockShared();
                    defer cache_lock.unlockShared();
                    if (cache.get(address)) |asd| {
                        _ = stats.cache_hits.fetchAdd(1, .monotonic);
                        if (asd.lamports == 0) return null;
                        return (try asd.clone(alloc)).toOwnedAccount();
                    }
                    if (borrowed_cache.get(address)) |asd| {
                        _ = stats.cache_hits.fetchAdd(1, .monotonic);
                        if (asd.lamports == 0) return null;
                        return (try asd.clone(alloc)).toOwnedAccount();
                    }
                }
                _ = stats.cache_misses.fetchAdd(1, .monotonic);
                var fallback_timer = sig.time.Timer.start();
                var account = (try db.get(alloc, address, ancestors)) orelse {
                    _ = stats.fallback_ns.fetchAdd(fallback_timer.read().asNanos(), .monotonic);
                    _ = stats.fallback_missing.fetchAdd(1, .monotonic);
                    try cacheFallbackIfAbsent(
                        allocator,
                        cache_lock,
                        cache,
                        account_data_lens,
                        stats,
                        address,
                        AccountSharedData.EMPTY,
                        true,
                    );
                    return null;
                };
                errdefer account.deinit(alloc);
                _ = stats.fallback_ns.fetchAdd(fallback_timer.read().asNanos(), .monotonic);
                if (account.lamports == 0) {
                    account.deinit(alloc);
                    _ = stats.fallback_missing.fetchAdd(1, .monotonic);
                    try cacheFallbackIfAbsent(
                        allocator,
                        cache_lock,
                        cache,
                        account_data_lens,
                        stats,
                        address,
                        AccountSharedData.EMPTY,
                        true,
                    );
                    return null;
                }
                _ = stats.fallback_found.fetchAdd(1, .monotonic);
                const cache_account = try AccountSharedData.fromAccount(allocator, &account);
                try cacheFallbackIfAbsent(
                    allocator,
                    cache_lock,
                    cache,
                    account_data_lens,
                    stats,
                    address,
                    cache_account,
                    false,
                );
                return account;
            },
            .thread_safe_map => |pair| pair[0].get(address, pair[1]),
            .account_map => |pair| pair.get(address),
            .account_shared_data_map => |map| {
                const asd = map.get(address) orelse return null;
                return .{
                    .lamports = asd.lamports,
                    .data = .{ .unowned_allocation = asd.data },
                    .owner = asd.owner,
                    .executable = asd.executable,
                    .rent_epoch = asd.rent_epoch,
                };
            },
            .noop => null,
        };
    }

    /// Returns a shallow immutable view only when the account's backing data
    /// has a lifetime independent of the slot cache's hash-table storage.
    /// The compressed decoded-account cache owns borrowed entries until the
    /// AccountsDB is deinitialized, so callers can consume the returned data
    /// after the cache lock is released without cloning the allocation.
    pub fn getStableBorrowedAccountSharedData(
        self: SlotAccountReader,
        address: Pubkey,
    ) ?AccountSharedData {
        return switch (self) {
            .cached_accounts_db => |tuple| blk: {
                const cache_lock = tuple[3];
                const borrowed_cache = tuple[5];
                cache_lock.lockShared();
                defer cache_lock.unlockShared();

                const account = borrowed_cache.get(address) orelse break :blk null;
                if (account.lamports == 0) break :blk null;
                break :blk account.*;
            },
            // This variant is immutable for the lifetime of the reader and is
            // useful for exercising the same no-clone path in unit tests.
            .account_shared_data_map => |map| blk: {
                const account = map.get(address) orelse break :blk null;
                if (account.lamports == 0) break :blk null;
                break :blk account;
            },
            else => null,
        };
    }

    pub fn accountDataLen(
        self: SlotAccountReader,
        alloc: std.mem.Allocator,
        address: Pubkey,
    ) !?usize {
        return switch (self) {
            .accounts_db => |pair| try pair[0].accountDataLen(alloc, address, pair[1]),
            .cached_accounts_db => |tuple| blk: {
                const cache_lock = tuple[3];
                const cache = tuple[4];
                const borrowed_cache = tuple[5];
                const account_data_lens = tuple[6];
                {
                    cache_lock.lockShared();
                    defer cache_lock.unlockShared();

                    if (cache.get(address)) |asd| {
                        if (asd.lamports == 0) return null;
                        break :blk asd.data.len;
                    }
                    if (borrowed_cache.get(address)) |asd| {
                        if (asd.lamports == 0) return null;
                        break :blk asd.data.len;
                    }
                    if (account_data_lens.get(address)) |data_len| break :blk data_len;
                }

                const data_len = try tuple[0].accountDataLen(alloc, address, tuple[1]);
                {
                    cache_lock.lock();
                    defer cache_lock.unlock();
                    const gop = try account_data_lens.getOrPut(tuple[2], address);
                    if (!gop.found_existing) gop.value_ptr.* = data_len;
                }
                break :blk data_len;
            },
            .account_shared_data_map => |map| {
                const asd = map.get(address) orelse return null;
                if (asd.lamports == 0) return null;
                return asd.data.len;
            },
            else => {
                var account = try self.get(alloc, address) orelse return null;
                defer account.deinit(alloc);
                return account.data.len();
            },
        };
    }

    pub fn compressedAccountChunkId(self: SlotAccountReader, address: Pubkey) !?u32 {
        return switch (self) {
            .accounts_db => |pair| try pair[0].compressedAccountChunkId(address),
            .cached_accounts_db => |tuple| try tuple[0].compressedAccountChunkId(address),
            else => null,
        };
    }

    pub fn compressedAccountChunkCached(self: SlotAccountReader, chunk_id: u32) bool {
        return switch (self) {
            .accounts_db => |pair| pair[0].compressedAccountChunkCached(chunk_id),
            .cached_accounts_db => |tuple| tuple[0].compressedAccountChunkCached(chunk_id),
            else => false,
        };
    }

    pub fn prefetchCompressedChunks(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
    ) !CompressedAccountPrefetchResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].prefetchCompressedAccountChunks(allocator, pubkeys),
            .cached_accounts_db => |tuple| try tuple[0].prefetchCompressedAccountChunks(allocator, pubkeys),
            else => .{ .pubkeys = @intCast(pubkeys.len) },
        };
    }

    pub fn batchDecodeCompressedAccounts(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
    ) !CompressedAccountBatchDecodeResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].batchDecodeCompressedAccounts(allocator, pubkeys),
            .cached_accounts_db => |tuple| try tuple[0].batchDecodeCompressedAccounts(allocator, pubkeys),
            else => .{ .pubkeys = @intCast(pubkeys.len), .accounts_skipped = @intCast(pubkeys.len) },
        };
    }

    pub fn batchLoadCompressedAccounts(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    ) !CompressedAccountBatchDecodeResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].batchLoadCompressedAccounts(allocator, pubkeys, accounts),
            .cached_accounts_db => |tuple| try tuple[0].batchLoadCompressedAccounts(allocator, pubkeys, accounts),
            else => .{ .pubkeys = @intCast(pubkeys.len), .accounts_skipped = @intCast(pubkeys.len) },
        };
    }

    pub fn batchLoadCompressedAccountsBorrowed(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
        borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
    ) !CompressedAccountBatchDecodeResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].batchLoadCompressedAccountsBorrowed(
                allocator,
                pubkeys,
                accounts,
                borrowed_accounts,
            ),
            .cached_accounts_db => |tuple| try tuple[0].batchLoadCompressedAccountsBorrowed(
                allocator,
                pubkeys,
                accounts,
                borrowed_accounts,
            ),
            else => .{ .pubkeys = @intCast(pubkeys.len), .accounts_skipped = @intCast(pubkeys.len) },
        };
    }

    pub fn batchLoadCompressedAccountsBorrowedPriority(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
        borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
    ) !CompressedAccountBatchDecodeResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].batchLoadCompressedAccountsBorrowedPriority(
                allocator,
                pubkeys,
                accounts,
                borrowed_accounts,
            ),
            .cached_accounts_db => |tuple| try tuple[0].batchLoadCompressedAccountsBorrowedPriority(
                allocator,
                pubkeys,
                accounts,
                borrowed_accounts,
            ),
            else => .{ .pubkeys = @intCast(pubkeys.len), .accounts_skipped = @intCast(pubkeys.len) },
        };
    }

    pub fn batchLoadUnrootedAccounts(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    ) !accounts_db.Unrooted.BatchLoadResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].unrooted.batchLoad(allocator, pubkeys, pair[1], accounts),
            .cached_accounts_db => |tuple| try tuple[0].unrooted.batchLoad(allocator, pubkeys, tuple[1], accounts),
            else => .{ .pubkeys = @intCast(pubkeys.len) },
        };
    }

    /// Loads only accounts retained in the recent rooted SQLite overlay. This
    /// must run after fork-visible unrooted loading and before compressed cold
    /// state so writes moved across the rooting boundary retain precedence.
    pub fn batchLoadRootedOverlayAccounts(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    ) !accounts_db.Rooted.BatchLoadOverlayResult {
        return switch (self) {
            .accounts_db => |pair| try pair[0].rooted.batchLoadOverlayAccounts(
                allocator,
                pubkeys,
                accounts,
            ),
            .cached_accounts_db => |tuple| try tuple[0].rooted.batchLoadOverlayAccounts(
                allocator,
                pubkeys,
                accounts,
            ),
            else => .{ .pubkeys = @intCast(pubkeys.len) },
        };
    }

    /// Loads only versions written in `slot`, without scanning the rest of the
    /// fork. Slot initialization writes sysvars and rewards before transaction
    /// execution, so a read frame must prefer these versions over rooted
    /// compressed state even on the slot's first replay invocation.
    pub fn batchLoadUnrootedAccountsAtSlot(
        self: SlotAccountReader,
        allocator: std.mem.Allocator,
        slot: Slot,
        pubkeys: []const Pubkey,
        accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    ) !accounts_db.Unrooted.BatchLoadResult {
        var current_slot_ancestors = try Ancestors.initWithSlots(allocator, &.{slot});
        defer current_slot_ancestors.deinit(allocator);

        return switch (self) {
            .accounts_db => |pair| try pair[0].unrooted.batchLoad(
                allocator,
                pubkeys,
                &current_slot_ancestors,
                accounts,
            ),
            .cached_accounts_db => |tuple| try tuple[0].unrooted.batchLoad(
                allocator,
                pubkeys,
                &current_slot_ancestors,
                accounts,
            ),
            else => .{ .pubkeys = @intCast(pubkeys.len) },
        };
    }

    pub fn hasUnrootedAccount(self: SlotAccountReader, address: Pubkey) bool {
        return switch (self) {
            .accounts_db => |pair| pair[0].unrooted.get(address, pair[1]) != null,
            .cached_accounts_db => |tuple| tuple[0].unrooted.get(address, tuple[1]) != null,
            else => false,
        };
    }
};

fn cacheFallbackIfAbsent(
    allocator: Allocator,
    cache_lock: *sig.sync.RwLock,
    cache: *sig.utils.collections.PubkeyMap(AccountSharedData),
    account_data_lens: *sig.utils.collections.PubkeyMap(?usize),
    stats: *SlotAccountCacheStats,
    address: Pubkey,
    account: AccountSharedData,
    tombstone: bool,
) !void {
    var cache_account = account;
    errdefer cache_account.deinit(allocator);

    cache_lock.lock();
    defer cache_lock.unlock();

    const data_len_gop = try account_data_lens.getOrPut(allocator, address);
    if (!data_len_gop.found_existing) {
        data_len_gop.value_ptr.* = if (tombstone) null else cache_account.data.len;
    }

    const gop = try cache.getOrPut(allocator, address);
    if (gop.found_existing) {
        cache_account.deinit(allocator);
        _ = stats.fallback_cache_fill_races.fetchAdd(1, .monotonic);
        return;
    }

    gop.value_ptr.* = cache_account;
    if (tombstone) {
        _ = stats.fallback_tombstone_fills.fetchAdd(1, .monotonic);
    } else {
        _ = stats.fallback_cache_fills.fetchAdd(1, .monotonic);
    }
}

/// Simple implementation of AccountReader and AccountStore, used for tests
const ThreadSafeAccountMap = struct {
    rwlock: sig.sync.RwLock,
    allocator: Allocator,
    /// Ordering of slots (the entry keys) is not guaranteed.
    slot_map: SlotMap,
    /// Ordering of the list of versions in each entry value is sorted highest to lowest.
    pubkey_map: PubkeyMap,
    largest_rooted_slot: ?Slot,

    const SlotMap = std.AutoArrayHashMapUnmanaged(
        Slot,
        std.ArrayListUnmanaged(struct { Pubkey, AccountSharedData }),
    );
    const PubkeyMap = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        std.ArrayListUnmanaged(struct { Slot, AccountSharedData }),
    );

    pub fn init(allocator: Allocator) ThreadSafeAccountMap {
        return .{
            .rwlock = .{},
            .allocator = allocator,
            .slot_map = .empty,
            .pubkey_map = .empty,
            .largest_rooted_slot = null,
        };
    }

    pub fn deinit(self: *ThreadSafeAccountMap) void {
        if (!self.rwlock.tryLock()) {
            std.debug.panic("deiniting a ThreadSafeAccountMap while a lock is held on it.", .{});
        }

        const pubkey_map = &self.pubkey_map;
        for (pubkey_map.values()) |*list| {
            for (list.items) |pair| {
                _, const account = pair;
                account.deinit(self.allocator);
            }
            list.deinit(self.allocator);
        }
        pubkey_map.deinit(self.allocator);

        const slot_map = &self.slot_map;
        for (slot_map.values()) |*list| {
            list.deinit(self.allocator);
        }
        slot_map.deinit(self.allocator);
    }

    pub fn accountStore(self: *ThreadSafeAccountMap) AccountStore {
        return .{ .thread_safe_map = self };
    }

    pub fn accountReader(self: *ThreadSafeAccountMap) AccountReader {
        return .{ .thread_safe_map = self };
    }

    pub fn get(
        self: *ThreadSafeAccountMap,
        address: Pubkey,
        ancestors: *const Ancestors,
    ) ?Account {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        const pubkey_map = &self.pubkey_map;
        const slot_account_pairs = pubkey_map.get(address) orelse return null;
        for (slot_account_pairs.items) |slot_account| {
            const slot, const account = slot_account;
            if (ancestors.containsSlot(slot)) {
                return if (account.lamports == 0)
                    null
                else
                    asAccount(account);
            }
            if (self.largest_rooted_slot) |largest_rooted_slot| if (slot <= largest_rooted_slot) {
                return if (account.lamports == 0) null else asAccount(account);
            };
        }

        return null;
    }

    pub fn getLatest(self: *ThreadSafeAccountMap, address: Pubkey) !?Account {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        const list = self.pubkey_map.get(address) orelse return null;
        if (list.items.len == 0) return null;
        return asAccount(list.items[0][1]);
    }

    fn asAccount(account: AccountSharedData) Account {
        return .{
            .lamports = account.lamports,
            .data = .{ .unowned_allocation = account.data },
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        };
    }

    pub const PutError = error{
        CannotWriteRootedSlot,
    } || std.mem.Allocator.Error;
    pub fn put(
        self: *ThreadSafeAccountMap,
        slot: Slot,
        address: Pubkey,
        put_account: AccountSharedData,
    ) PutError!void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        if (self.largest_rooted_slot) |largest_rooted_slot| {
            if (slot <= largest_rooted_slot) {
                return error.CannotWriteRootedSlot;
            }
        }

        const account = try put_account.clone(self.allocator);
        errdefer account.deinit(self.allocator);

        slot_map: {
            const slot_map = &self.slot_map;
            const slot_gop = try slot_map.getOrPut(self.allocator, slot);
            if (!slot_gop.found_existing) slot_gop.value_ptr.* = .empty;
            for (slot_gop.value_ptr.items) |*pubkey_account| {
                if (pubkey_account[0].equals(&address)) {
                    self.allocator.free(pubkey_account[1].data);
                    pubkey_account[1] = account;
                    break :slot_map;
                }
            }

            try slot_gop.value_ptr.append(self.allocator, .{ address, account });
        }

        {
            const pubkey_map = &self.pubkey_map;
            const pubkey_gop = try pubkey_map.getOrPut(self.allocator, address);
            const versions_list = pubkey_gop.value_ptr;
            if (!pubkey_gop.found_existing) versions_list.* = .empty;

            const helper = struct {
                fn compare(s: Slot, elem: struct { Slot, AccountSharedData }) std.math.Order {
                    return std.math.order(elem[0], s); // sorted descending to simplify getters
                }
            };
            const index = std.sort.lowerBound(
                struct { Slot, AccountSharedData },
                versions_list.items,
                slot,
                helper.compare,
            );

            if (index != versions_list.items.len and versions_list.items[index][0] == slot) {
                versions_list.items[index] = .{ slot, account };
            } else {
                try versions_list.insert(self.allocator, index, .{ slot, account });
            }
        }
    }

    fn onSlotRooted(
        self: *ThreadSafeAccountMap,
        newly_rooted_slot: Slot,
    ) !void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        if (self.largest_rooted_slot) |previously_rooted| {
            if (newly_rooted_slot < previously_rooted) return error.SlotNotFound;
        }

        self.largest_rooted_slot = newly_rooted_slot;

        const rooted_slot_entries = self.slot_map.get(newly_rooted_slot) orelse
            return; // No account modifications in the newly rooted slot? Skipping cleanup.

        // for each pubkey modified in the newly rooted slot...
        for (rooted_slot_entries.items) |account_entry| {
            const pubkey, _ = account_entry;

            // there were accounts mutated in this slot => we must have an entry
            const pubkey_entries = self.pubkey_map.getPtr(pubkey) orelse unreachable;
            std.debug.assert(pubkey_entries.items.len > 0);

            // attempt removal from pubkey_entry, trying backwards (oldest first)
            var i = pubkey_entries.items.len;
            while (i > 0) {
                i -= 1;
                const old_slot, const account = pubkey_entries.items[i];
                if (old_slot >= newly_rooted_slot) break;
                // This account has a newer rooted counterpart, we should remove it.

                // remove account from pubkey_map(pubkey)->accounts, and free the account
                const slot_popped, const account_popped = pubkey_entries.pop().?;
                defer account_popped.deinit(self.allocator);
                std.debug.assert(slot_popped == old_slot);
                std.debug.assert(account_popped.equals(&account));

                // find the same account in slot_map(slot)->accounts, and remove it from the list
                const slot_entries = self.slot_map.getPtr(old_slot).?;
                const removal_idx: usize = for (slot_entries.items, 0..) |slot_entry, j| {
                    if (!slot_entry.@"0".equals(&pubkey)) continue;
                    break j;
                } else unreachable;
                const removed_pubkey, const removed_account =
                    slot_entries.orderedRemove(removal_idx);
                std.debug.assert(removed_pubkey.equals(&pubkey));
                std.debug.assert(removed_account.equals(&account_popped));

                // if the len of slot_entries has shrunk considerably, shrink the capacity
                if (slot_entries.items.len > 0 and
                    slot_entries.capacity > slot_entries.items.len * 10)
                {
                    slot_entries.shrinkAndFree(self.allocator, slot_entries.items.len);
                }

                // if the slot has no more entries, deinit and remove it
                if (slot_entries.items.len == 0) {
                    slot_entries.deinit(self.allocator);
                    std.debug.assert(self.slot_map.orderedRemove(old_slot));
                }
            }
        }
    }

    /// Returns an iterator that iterates over every account that was modified
    /// in the slot.
    ///
    /// Holds the read lock on the index, so unlock it when done, and be careful
    /// how long you hold this.
    pub fn slotModifiedIterator(
        self: *ThreadSafeAccountMap,
        slot: Slot,
    ) ?ThreadSafeAccountMap.SlotModifiedIterator {
        self.rwlock.lockShared();
        const slot_map = &self.slot_map;
        const slot_list = slot_map.get(slot) orelse {
            self.rwlock.unlockShared();
            return null;
        };
        return .{
            .allocator = self.allocator,
            .rwlock = &self.rwlock,
            .slot_list = slot_list.items,
            .cursor = 0,
        };
    }

    pub const SlotModifiedIterator = struct {
        allocator: Allocator,
        rwlock: *sig.sync.RwLock,
        slot_list: []const struct { Pubkey, AccountSharedData },
        cursor: usize,

        pub fn unlock(self: *ThreadSafeAccountMap.SlotModifiedIterator) void {
            self.cursor = std.math.maxInt(usize);
            self.rwlock.unlockShared();
        }

        pub fn len(self: ThreadSafeAccountMap.SlotModifiedIterator) usize {
            return self.slot_list.len;
        }

        pub fn next(
            self: *ThreadSafeAccountMap.SlotModifiedIterator,
            allocator: std.mem.Allocator,
        ) !?struct { Pubkey, Account } {
            std.debug.assert(self.cursor != std.math.maxInt(usize));
            defer self.cursor += 1;
            if (self.cursor >= self.slot_list.len) return null;
            const pubkey, const acc = self.slot_list[self.cursor];

            var account = asAccount(acc);
            account.data = .{ .owned_allocation = try allocator.dupe(u8, acc.data) };

            return .{ pubkey, account };
        }
    };

    pub fn getLargestRootedSlot(self: *ThreadSafeAccountMap) ?Slot {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        return self.largest_rooted_slot;
    }
};

test "AccountStore does not return 0-lamport accounts from accountsdb" {
    const allocator = std.testing.allocator;

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const zero_lamport_address = Pubkey.ZEROES;
    const one_lamport_address = Pubkey{ .data = @splat(9) };

    try db.put(0, zero_lamport_address, .{
        .lamports = 0,
        .data = &.{},
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    try db.put(0, one_lamport_address, .{
        .lamports = 1,
        .data = &.{},
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    const reader: AccountReader = .{ .accounts_db = db };

    try std.testing.expectEqual(null, try reader.getLatest(allocator, zero_lamport_address));
    try std.testing.expectEqual(1, (try reader.getLatest(
        allocator,
        one_lamport_address,
    )).?.lamports);

    var ancestors = Ancestors{};
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.ancestors.put(allocator, 0, {});
    const slot_reader = reader.forSlot(&ancestors);

    try std.testing.expectEqual(null, try slot_reader.get(allocator, zero_lamport_address));
    try std.testing.expectEqual(1, (try slot_reader.get(
        allocator,
        one_lamport_address,
    )).?.lamports);
}

test "cached SlotAccountReader fills fallback hits and tombstones" {
    const allocator = std.testing.allocator;

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, 0, {});

    const existing_address = Pubkey{ .data = @splat(7) };
    const missing_address = Pubkey{ .data = @splat(8) };
    var existing_data = "cached-fallback".*;
    try db.put(0, existing_address, .{
        .lamports = 42,
        .data = existing_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    var cache_lock: sig.sync.RwLock = .{};
    var cache: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    var borrowed_cache: sig.utils.collections.PubkeyMap(*const AccountSharedData) = .{};
    var account_data_lens: sig.utils.collections.PubkeyMap(?usize) = .{};
    defer {
        for (cache.values()) |*account| account.deinit(allocator);
        cache.deinit(allocator);
        borrowed_cache.deinit(allocator);
        account_data_lens.deinit(allocator);
    }
    var stats = SlotAccountCacheStats{};

    const reader: SlotAccountReader = .{ .cached_accounts_db = .{
        db,
        &ancestors,
        allocator,
        &cache_lock,
        &cache,
        &borrowed_cache,
        &account_data_lens,
        &stats,
    } };

    try std.testing.expectEqual(
        @as(?usize, existing_data.len),
        try reader.accountDataLen(allocator, existing_address),
    );
    try std.testing.expectEqual(
        null,
        try reader.accountDataLen(allocator, missing_address),
    );
    try std.testing.expectEqual(@as(usize, 0), cache.count());
    try std.testing.expectEqual(@as(usize, 2), account_data_lens.count());

    const first_existing = (try reader.get(allocator, existing_address)).?;
    defer first_existing.deinit(allocator);
    const second_existing = (try reader.get(allocator, existing_address)).?;
    defer second_existing.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 42), first_existing.lamports);
    try std.testing.expectEqual(@as(u64, 42), second_existing.lamports);

    try std.testing.expectEqual(null, try reader.get(allocator, missing_address));
    try std.testing.expectEqual(null, try reader.get(allocator, missing_address));

    const snapshot = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 4), snapshot.get_calls);
    try std.testing.expectEqual(@as(u64, 2), snapshot.cache_hits);
    try std.testing.expectEqual(@as(u64, 2), snapshot.cache_misses);
    try std.testing.expectEqual(@as(u64, 1), snapshot.fallback_found);
    try std.testing.expectEqual(@as(u64, 1), snapshot.fallback_missing);
    try std.testing.expectEqual(@as(u64, 1), snapshot.fallback_cache_fills);
    try std.testing.expectEqual(@as(u64, 0), snapshot.fallback_cache_fill_races);
    try std.testing.expectEqual(@as(u64, 1), snapshot.fallback_tombstone_fills);
}

test "cached SlotAccountReader prefers owned overlay over borrowed base" {
    const allocator = std.testing.allocator;

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var cache_lock: sig.sync.RwLock = .{};
    var cache: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    var borrowed_cache: sig.utils.collections.PubkeyMap(*const AccountSharedData) = .{};
    var account_data_lens: sig.utils.collections.PubkeyMap(?usize) = .{};
    defer {
        for (cache.values()) |*account| account.deinit(allocator);
        cache.deinit(allocator);
        borrowed_cache.deinit(allocator);
        account_data_lens.deinit(allocator);
    }
    var stats = SlotAccountCacheStats{};

    const borrowed_only_address = Pubkey{ .data = @splat(10) };
    const overlay_address = Pubkey{ .data = @splat(11) };
    var borrowed_only_data = "borrowed-only".*;
    var borrowed_overlay_data = "borrowed-base".*;
    const borrowed_only_account: AccountSharedData = .{
        .lamports = 7,
        .data = borrowed_only_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
    const borrowed_overlay_account: AccountSharedData = .{
        .lamports = 8,
        .data = borrowed_overlay_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    };
    try borrowed_cache.put(allocator, borrowed_only_address, &borrowed_only_account);
    try borrowed_cache.put(allocator, overlay_address, &borrowed_overlay_account);

    var owned_overlay = try borrowed_overlay_account.clone(allocator);
    owned_overlay.lamports = 9;
    var owns_overlay = true;
    errdefer if (owns_overlay) owned_overlay.deinit(allocator);
    try cache.put(allocator, overlay_address, owned_overlay);
    owns_overlay = false;

    const reader: SlotAccountReader = .{ .cached_accounts_db = .{
        db,
        &ancestors,
        allocator,
        &cache_lock,
        &cache,
        &borrowed_cache,
        &account_data_lens,
        &stats,
    } };

    const borrowed = (try reader.get(allocator, borrowed_only_address)).?;
    defer borrowed.deinit(allocator);
    const overlaid = (try reader.get(allocator, overlay_address)).?;
    defer overlaid.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 7), borrowed.lamports);
    try std.testing.expectEqualStrings("borrowed-only", borrowed.data.owned_allocation);
    try std.testing.expectEqual(@as(u64, 9), overlaid.lamports);
    try std.testing.expectEqualStrings("borrowed-base", overlaid.data.owned_allocation);
    try std.testing.expectEqual(@as(?usize, "borrowed-base".len), try reader.accountDataLen(
        allocator,
        overlay_address,
    ));
}

test "cached SlotAccountStore can defer DB writes into dirty set" {
    const allocator = std.testing.allocator;

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const slot: Slot = 1;
    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    var cache_lock: sig.sync.RwLock = .{};
    var cache: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    var borrowed_cache: sig.utils.collections.PubkeyMap(*const AccountSharedData) = .{};
    var original_accounts: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    var account_data_lens: sig.utils.collections.PubkeyMap(?usize) = .{};
    var dirty: sig.utils.collections.PubkeyMap(void) = .{};
    defer {
        for (cache.values()) |*account| account.deinit(allocator);
        cache.deinit(allocator);
        borrowed_cache.deinit(allocator);
        for (original_accounts.values()) |*account| account.deinit(allocator);
        original_accounts.deinit(allocator);
        account_data_lens.deinit(allocator);
        dirty.deinit(allocator);
    }
    var stats = SlotAccountCacheStats{};

    const address = Pubkey{ .data = @splat(9) };
    var original_data = "deferred-original".*;
    var first_data = "deferred-first".*;
    var second_data = "deferred-second".*;

    try cache.put(allocator, address, try (AccountSharedData{
        .lamports = 10,
        .data = original_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    }).clone(allocator));

    const store: SlotAccountStore = .{ .cached_accounts_db = .{
        db,
        slot,
        &ancestors,
        allocator,
        &cache_lock,
        &cache,
        &borrowed_cache,
        &original_accounts,
        &account_data_lens,
        &stats,
        &dirty,
        true,
        true,
    } };

    try store.put(address, .{
        .lamports = 11,
        .data = first_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });
    try store.put(address, .{
        .lamports = 12,
        .data = second_data[0..],
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    const cached = (try store.reader().get(allocator, address)).?;
    defer cached.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 12), cached.lamports);
    try std.testing.expectEqual(
        @as(?usize, second_data.len),
        try store.reader().accountDataLen(allocator, address),
    );
    try std.testing.expectEqual(@as(usize, 1), dirty.count());
    try std.testing.expectEqual(@as(usize, 1), original_accounts.count());
    const original = original_accounts.get(address).?;
    try std.testing.expectEqual(@as(u64, 10), original.lamports);
    try std.testing.expectEqualStrings("deferred-original", original.data);

    if (try db.get(allocator, address, &ancestors)) |db_account| {
        defer db_account.deinit(allocator);
        return error.TestExpectedNoDbWrite;
    }

    const snapshot = stats.snapshot();
    try std.testing.expectEqual(@as(u64, 2), snapshot.cache_puts);
    try std.testing.expectEqual(@as(u64, 2), snapshot.cache_put_replacements);
    try std.testing.expectEqual(@as(u64, 2), snapshot.deferred_puts);
    try std.testing.expectEqual(@as(u64, 1), snapshot.deferred_unique_writes);
}

test ThreadSafeAccountMap {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(3653);
    const random = prng.random();

    var tsm: ThreadSafeAccountMap = .init(allocator);
    defer tsm.deinit();

    const account_store = tsm.accountStore();
    const account_reader = tsm.accountReader();

    var ancestors1: Ancestors = .{};
    defer ancestors1.deinit(allocator);
    const slot1: Slot = 1;
    const addr1: Pubkey = .initRandom(random);
    try ancestors1.ancestors.put(allocator, slot1, {});

    var expected_data: [128]u8 = undefined;
    random.bytes(&expected_data);
    const expected_account: AccountSharedData = .{
        .lamports = random.int(u64),
        .data = &expected_data,
        .owner = .initRandom(random),
        .executable = random.boolean(),
        .rent_epoch = random.int(sig.core.Epoch),
    };
    try account_store.put(slot1, addr1, expected_account);

    try expectAccount(
        allocator,
        account_reader,
        addr1,
        null,
        sharedToCoreAccount(expected_account),
    );
    try expectAccount(
        allocator,
        account_reader,
        addr1,
        ancestors1,
        sharedToCoreAccount(expected_account),
    );
}

fn expectAccount(
    allocator: std.mem.Allocator,
    account_reader: AccountReader,
    address: Pubkey,
    maybe_ancestors: ?Ancestors,
    expected: ?sig.core.Account,
) !void {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    const actual = if (maybe_ancestors) |*ancestors|
        try account_reader.forSlot(ancestors).get(allocator, address)
    else
        try account_reader.getLatest(allocator, address);

    if ((expected == null) != (actual == null)) {
        try std.testing.expectEqual(expected, actual);
        unreachable; // the `try` above is guaranteed to return an error
    }

    const expected_account = expected orelse return;
    const actual_account = actual.?; // if the above is non-null, this is also non-null

    try std.testing.expectEqual(expected_account.lamports, actual_account.lamports);
    try std.testing.expectEqual(expected_account.owner, actual_account.owner);
    try std.testing.expectEqual(expected_account.executable, actual_account.executable);
    try std.testing.expectEqual(expected_account.rent_epoch, actual_account.rent_epoch);

    const expected_data = try expected_account.data.readAllAllocate(std.testing.allocator);
    defer std.testing.allocator.free(expected_data);

    const actual_data = try actual_account.data.readAllAllocate(std.testing.allocator);
    defer std.testing.allocator.free(actual_data);

    try std.testing.expectEqualSlices(u8, expected_data, actual_data);
}

fn sharedToCoreAccount(account: AccountSharedData) sig.core.Account {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    return .{
        .lamports = account.lamports,
        .data = .{ .unowned_allocation = account.data },
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

test "insertion basic" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var simple_state: ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    const simple_store = simple_state.accountStore();
    const real_store: AccountStore = .{ .accounts_db = real_state };
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    try expectEqualDatabaseWithAncestors(
        allocator,
        &.EMPTY,
        simple_state.pubkey_map.keys(),
        simple_store.reader(),
        real_store.reader(),
    );

    var ancestor_set: Ancestors = .EMPTY;
    defer ancestor_set.deinit(allocator);

    for (0..100) |i| {
        const slot: Slot = i;
        errdefer std.log.err("At slot {}", .{slot});

        const pubkey: Pubkey = .initRandom(random);
        const account = try createRandomAccount(allocator, random);
        defer account.deinit(allocator);

        try ancestor_set.addSlot(allocator, slot);
        try putAccountIntoStores({}, &stores, slot, pubkey, account);
        try expectEqualDatabaseWithAncestors(
            allocator,
            &ancestor_set,
            simple_state.pubkey_map.keys(),
            simple_store.reader(),
            real_store.reader(),
        );
    }

    var ancestors_subset: Ancestors = .EMPTY;
    defer ancestors_subset.deinit(allocator);

    for (0..100) |i| {
        const slot: Slot = i;
        try ancestor_set.subsetInto(slot, allocator, &ancestors_subset);
        try expectEqualDatabaseWithAncestors(
            allocator,
            &ancestors_subset,
            simple_state.pubkey_map.keys(),
            simple_store.reader(),
            real_store.reader(),
        );
    }

    try std.testing.expectEqual({}, simple_store.put(1, .ZEROES, .EMPTY));
    try std.testing.expectEqual({}, real_store.put(1, .ZEROES, .EMPTY));

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{ 1, 2 });
    defer ancestors.deinit(allocator);

    try simple_state.onSlotRooted(2);
    real_state.onSlotRooted(2, &ancestors);
    try putAccountIntoStores(error.CannotWriteRootedSlot, &stores, 1, .ZEROES, .EMPTY);

    // this backtracking wouldn't/shouldn't really ever happen, but just
    // to demonstrate that the error is based on the rooted slot:
    simple_state.largest_rooted_slot = null;
    real_state.rooted.largest_rooted_slot = null;
    try putAccountIntoStores({}, &stores, 1, .ZEROES, .EMPTY);
}

test "insertion out of order" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var simple_state: ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    const simple_store = simple_state.accountStore();
    const real_store: AccountStore = .{ .accounts_db = real_state };
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    try expectEqualDatabaseWithAncestors(
        allocator,
        &.EMPTY,
        simple_state.pubkey_map.keys(),
        simple_store.reader(),
        real_store.reader(),
    );

    var ancestor_set: Ancestors = .EMPTY;
    defer ancestor_set.deinit(allocator);

    for (0..100) |i| {
        const slot: Slot = while (true) {
            const slot = random.uintLessThan(Slot, 1000);
            if (ancestor_set.containsSlot(slot)) continue;
            break slot;
        };
        errdefer std.log.err("At slot {} (iteration {d})", .{ slot, i });

        const pubkey: Pubkey = .initRandom(random);
        const account = try createRandomAccount(allocator, random);
        defer account.deinit(allocator);

        try ancestor_set.addSlot(allocator, slot);
        try putAccountIntoStores({}, &stores, slot, pubkey, account);

        try expectEqualDatabaseWithAncestors(
            allocator,
            &ancestor_set,
            simple_state.pubkey_map.keys(),
            simple_store.reader(),
            real_store.reader(),
        );
    }

    for (ancestor_set.ancestors.keys()) |slot| {
        var ancestors_subset: Ancestors = .EMPTY;
        defer ancestors_subset.deinit(allocator);
        try ancestor_set.subsetInto(slot, allocator, &ancestors_subset);
        try expectEqualDatabaseWithAncestors(
            allocator,
            &ancestors_subset,
            simple_state.pubkey_map.keys(),
            simple_store.reader(),
            real_store.reader(),
        );
    }

    try std.testing.expectEqual({}, simple_store.put(1, .ZEROES, .EMPTY));
    try std.testing.expectEqual({}, real_store.put(1, .ZEROES, .EMPTY));
    try ancestor_set.addSlot(allocator, 1);

    const slot_to_try_write_while_rooted = slot: {
        const slots = simple_state.slot_map.keys();
        break :slot slots[random.uintLessThan(usize, slots.len)];
    };
    const pk_of_ones: Pubkey = .{ .data = @splat(1) };

    var ancestors_subset: Ancestors = .EMPTY;
    defer ancestors_subset.deinit(allocator);
    try ancestor_set.subsetInto(slot_to_try_write_while_rooted, allocator, &ancestors_subset);

    try simple_state.onSlotRooted(slot_to_try_write_while_rooted);
    real_state.onSlotRooted(slot_to_try_write_while_rooted, &ancestors_subset);

    try std.testing.expectEqual(
        error.CannotWriteRootedSlot,
        simple_store.put(1, pk_of_ones, .EMPTY),
    );
    try std.testing.expectEqual(
        error.CannotWriteRootedSlot,
        real_store.put(1, pk_of_ones, .EMPTY),
    );
}

test "put and get zero lamports before & after cleanup" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var simple_state: ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    const simple_store = simple_state.accountStore();
    const real_store: AccountStore = .{ .accounts_db = real_state };
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    const pk1, const pk2, const pk3, const pk4 = pks: {
        var pks: [4]Pubkey = undefined;
        for (&pks, 0..) |*pubkey, i| while (true) {
            pubkey.* = .initRandom(random);
            if (pubkey.indexIn(pks[0..i]) == null) break;
        };
        break :pks pks;
    };

    const slot100: Slot = 100;
    const slot200: Slot = 200;

    var ancestors_after: Ancestors = .EMPTY;
    defer ancestors_after.deinit(allocator);
    try ancestors_after.addSlot(allocator, slot100);
    try ancestors_after.addSlot(allocator, slot200);

    var ancestors_before: Ancestors = .EMPTY;
    defer ancestors_before.deinit(allocator);
    try ancestors_after.subsetInto(slot200 -| 1, allocator, &ancestors_before);

    const zero_lamports: AccountSharedData = .{
        .data = &.{},
        .executable = false,
        .lamports = 0,
        .owner = .ZEROES,
        .rent_epoch = 0,
    };
    const one_lamport: AccountSharedData = .{
        .data = &.{},
        .executable = false,
        .lamports = 1,
        .owner = .ZEROES,
        .rent_epoch = 0,
    };

    // lamports: zero before and after
    try putAccountIntoStores({}, &stores, slot100, pk1, zero_lamports);
    try putAccountIntoStores({}, &stores, slot200, pk1, zero_lamports);

    // lamports: zero before, non-zero after
    try putAccountIntoStores({}, &stores, slot100, pk2, zero_lamports);
    try putAccountIntoStores({}, &stores, slot200, pk2, one_lamport);

    // lamports: non-zero before, zero after
    try putAccountIntoStores({}, &stores, slot100, pk3, one_lamport);
    try putAccountIntoStores({}, &stores, slot200, pk3, zero_lamports);

    // lamports: non-zero before, non-zero after
    try putAccountIntoStores({}, &stores, slot100, pk4, one_lamport);
    try putAccountIntoStores({}, &stores, slot200, pk4, one_lamport);

    // where lamports == 0, treated as non-present, before and after
    try expectAccountFromStores(&stores, &ancestors_before, pk1, null);
    try expectAccountFromStores(&stores, &ancestors_after, pk1, null);
    try expectAccountFromStores(&stores, &ancestors_before, pk2, null);
    try expectAccountFromStores(&stores, &ancestors_after, pk2, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_before, pk3, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_after, pk3, null);
    try expectAccountFromStores(&stores, &ancestors_before, pk4, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_after, pk4, one_lamport.asAccount());

    // but it still exists in the unrooted account map regardless
    try expectDbUnrootedPubkeysInSlot(real_state, slot100, &.{ pk1, pk2, pk3, pk4 });
    try expectDbUnrootedPubkeysInSlot(real_state, slot200, &.{ pk1, pk2, pk3, pk4 });

    // but after we run the manager on it to clean it up...
    try real_store.onSlotRooted(slot100, &ancestors_before);
    try simple_store.onSlotRooted(slot100, &ancestors_before);

    // the unrooted entry for slot100 is removed, and all the zero-lamport accounts should
    // not be present in the flushed accounts.
    try expectDbUnrootedPubkeysInSlot(real_state, slot100, null);

    // although they should all still exist in the unrooted slot200.
    try expectDbUnrootedPubkeysInSlot(real_state, slot200, &.{ pk1, pk2, pk3, pk4 });

    // and display the same outward behaviour as before.
    try expectAccountFromStores(&stores, &ancestors_before, pk1, null);
    try expectAccountFromStores(&stores, &ancestors_after, pk1, null);
    try expectAccountFromStores(&stores, &ancestors_before, pk2, null);
    try expectAccountFromStores(&stores, &ancestors_after, pk2, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_before, pk3, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_after, pk3, null);
    try expectAccountFromStores(&stores, &ancestors_before, pk4, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &ancestors_after, pk4, one_lamport.asAccount());

    // and after we run the manager on it to clean up slot200 as well...
    try real_store.onSlotRooted(slot200, &ancestors_after);
    try simple_store.onSlotRooted(slot200, &ancestors_after);

    try expectDbUnrootedPubkeysInSlot(real_state, slot200, null);
}

test "put and get zero lamports across forks" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var simple_state: ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    const simple_store = simple_state.accountStore();
    const real_store: AccountStore = .{ .accounts_db = real_state };
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    const zero_lamports: AccountSharedData = .{
        .data = &.{},
        .executable = false,
        .lamports = 0,
        .owner = .ZEROES,
        .rent_epoch = 0,
    };
    const one_lamport: AccountSharedData = .{
        .data = &.{},
        .executable = false,
        .lamports = 1,
        .owner = .ZEROES,
        .rent_epoch = 0,
    };

    const pk: Pubkey = .initRandom(random);
    const slot1: Slot = 200;
    const slot2: Slot = 300;
    const slot3: Slot = 400;

    try putAccountIntoStores({}, &stores, slot1, pk, zero_lamports);
    try putAccountIntoStores({}, &stores, slot2, pk, one_lamport);
    try putAccountIntoStores({}, &stores, slot3, pk, zero_lamports);

    const fork_a: Ancestors = try .initWithSlots(allocator, &.{slot1});
    defer fork_a.deinit(allocator);

    const fork_b: Ancestors = try .initWithSlots(allocator, &.{ slot1, slot2 });
    defer fork_b.deinit(allocator);

    const fork_c: Ancestors = try .initWithSlots(allocator, &.{ slot1, slot3 });
    defer fork_c.deinit(allocator);

    try expectAccountFromStores(&stores, &fork_a, pk, null);
    try expectAccountFromStores(&stores, &fork_b, pk, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &fork_c, pk, null);
}

test "put and get across competing forks" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var simple_state: ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();
    const real_state = &test_state.db;

    const simple_store = simple_state.accountStore();
    const real_store: AccountStore = .{ .accounts_db = real_state };
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    const helper = struct {
        fn dummyAccountSharedData(lamports: u64) AccountSharedData {
            return .{
                .data = &.{},
                .executable = false,
                .lamports = lamports,
                .owner = .ZEROES,
                .rent_epoch = 0,
            };
        }
    };
    const asd_a: AccountSharedData = helper.dummyAccountSharedData(1000);
    const asd_b: AccountSharedData = helper.dummyAccountSharedData(2000);
    const asd_c: AccountSharedData = helper.dummyAccountSharedData(3000);

    const pk: Pubkey = .initRandom(random);
    const slot1: Slot = 200;
    const slot2: Slot = 300;
    const slot3: Slot = 400;

    const fork_a: Ancestors = try .initWithSlots(allocator, &.{slot1});
    defer fork_a.deinit(allocator);

    const fork_b: Ancestors = try .initWithSlots(allocator, &.{ slot1, slot2 });
    defer fork_b.deinit(allocator);

    const fork_c: Ancestors = try .initWithSlots(allocator, &.{ slot1, slot3 });
    defer fork_c.deinit(allocator);

    // insert slot 1 state and root it (assume it exists in the ancestors)
    try putAccountIntoStores({}, &stores, slot1, pk, asd_a);
    try simple_state.onSlotRooted(slot1);
    real_state.onSlotRooted(slot1, &fork_a);

    // two unrooted entries, which will end up competing with the given ancestors
    try putAccountIntoStores({}, &stores, slot2, pk, asd_b);
    try putAccountIntoStores({}, &stores, slot3, pk, asd_c);

    try expectAccountFromStores(&stores, &fork_a, pk, asd_a.asAccount());
    try expectAccountFromStores(&stores, &fork_b, pk, asd_b.asAccount());
    try expectAccountFromStores(&stores, &fork_c, pk, asd_c.asAccount());
}

test "SlotAccountReader batch-loads only current-slot unrooted versions" {
    const allocator = std.testing.allocator;

    var test_state = try accounts_db.Db.initTest(allocator);
    defer test_state.deinit();

    const address: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const parent_slot: Slot = 10;
    const current_slot: Slot = 11;
    try test_state.db.put(parent_slot, address, .{
        .data = &.{},
        .executable = false,
        .lamports = 10,
        .owner = .ZEROES,
        .rent_epoch = 0,
    });
    try test_state.db.put(current_slot, address, .{
        .data = &.{},
        .executable = false,
        .lamports = 11,
        .owner = .ZEROES,
        .rent_epoch = 0,
    });

    var ancestors = try Ancestors.initWithSlots(
        allocator,
        &.{ parent_slot, current_slot },
    );
    defer ancestors.deinit(allocator);

    var accounts: sig.utils.collections.PubkeyMap(AccountSharedData) = .{};
    defer {
        for (accounts.values()) |*account| account.deinit(allocator);
        accounts.deinit(allocator);
    }

    const reader: SlotAccountReader = .{ .accounts_db = .{ &test_state.db, &ancestors } };
    const result = try reader.batchLoadUnrootedAccountsAtSlot(
        allocator,
        parent_slot,
        &.{address},
        &accounts,
    );

    try std.testing.expectEqual(@as(u64, 1), result.resolved);
    try std.testing.expectEqual(@as(u64, 10), accounts.get(address).?.lamports);
}

fn expectDbUnrootedPubkeysInSlot(
    db: *accounts_db.Db,
    slot: Slot,
    maybe_expected_pubkeys: ?[]const Pubkey,
) !void {
    for (db.unrooted.slots) |index| if (index.slot == slot) {
        if (index.is_empty.load(.unordered)) continue; // dead slot entry
        const actual_pubkeys = index.entries.keys();
        const expected_pubkeys = maybe_expected_pubkeys orelse {
            std.log.err("\nExpected pubkeys: null,\nactual pubkeys:   {any}", .{actual_pubkeys});
            return error.TestMissingExpectedSlot;
        };
        return try std.testing.expectEqualSlices(Pubkey, expected_pubkeys, actual_pubkeys);
    };
    if (maybe_expected_pubkeys) |expected_pubkeys| {
        std.log.err("\nExpected pubkeys: {any},\nactual pubkeys:   null", .{expected_pubkeys});
        return error.TestMissingExpectedSlot;
    }
}

fn putAccountIntoStores(
    expected_result: anyerror!void,
    stores: []const sig.accounts_db.AccountStore,
    slot: Slot,
    pubkey: Pubkey,
    account: AccountSharedData,
) !void {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    for (stores) |store| {
        errdefer std.log.err("Error occurred with implementation '{s}'", .{@tagName(store)});
        try std.testing.expectEqual(expected_result, store.put(slot, pubkey, account));
    }
}

fn expectAccountFromStores(
    stores: []const sig.accounts_db.AccountStore,
    ancestors: *const Ancestors,
    address: Pubkey,
    maybe_expected_account: ?Account,
) !void {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    const allocator = std.testing.allocator;

    var data_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer data_buf.deinit(allocator);

    if (maybe_expected_account) |expected_account| {
        try data_buf.ensureTotalCapacityPrecise(allocator, expected_account.data.len());
    }

    for (stores) |store| {
        errdefer std.log.err("Occurred with store impl '{s}'", .{@tagName(store)});
        const reader = store.reader();
        const actual_account = try reader.forSlot(ancestors).get(allocator, address) orelse {
            try std.testing.expectEqual(maybe_expected_account, null);
            continue;
        };
        defer actual_account.deinit(allocator);

        const expected_account = maybe_expected_account orelse {
            try std.testing.expectEqual(null, actual_account);
            continue;
        };
        try actual_account.expectEquals(expected_account);
    }
}

fn expectEqualDatabaseWithAncestors(
    allocator: std.mem.Allocator,
    ancestors: *const Ancestors,
    pubkeys: []const Pubkey,
    expected: sig.accounts_db.AccountReader,
    actual: sig.accounts_db.AccountReader,
) !void {
    if (!@import("builtin").is_test) @compileError("Only intended for use in tests.");
    try std.testing.expectEqual(expected.getLargestRootedSlot(), actual.getLargestRootedSlot());

    const expected_for_slot = expected.forSlot(ancestors);
    const actual_for_slot = actual.forSlot(ancestors);
    for (pubkeys) |pubkey| {
        const expected_account_opt = try expected_for_slot.get(allocator, pubkey);
        defer if (expected_account_opt) |acc| acc.deinit(allocator);

        const actual_account_opt = try actual_for_slot.get(allocator, pubkey);
        defer if (actual_account_opt) |acc| acc.deinit(allocator);

        if (expected_account_opt == null and
            actual_account_opt == null)
        {
            continue;
        }

        const expected_account = expected_account_opt orelse {
            std.log.err("Got unexpected account '{f}' for ancestors.", .{pubkey});
            return error.TestGotUnexpectedAccount;
        };
        const actual_account = actual_account_opt orelse {
            std.log.err("Missing account '{f}' for ancestors.", .{pubkey});
            return error.TestMissingExpectedAccount;
        };
        try actual_account.expectEquals(expected_account);
    }

    var expected_map: sig.utils.collections.PubkeyMap(AccountSharedData) = .empty;
    defer expected_map.deinit(allocator);

    var actual_map: sig.utils.collections.PubkeyMap(AccountSharedData) = .empty;
    defer actual_map.deinit(allocator);

    for (ancestors.ancestors.keys()) |slot| {
        defer expected_map.clearRetainingCapacity();
        defer for (expected_map.values()) |acc| acc.deinit(allocator);

        defer actual_map.clearRetainingCapacity();
        defer for (actual_map.values()) |acc| acc.deinit(allocator);

        const expected_has_slot =
            try collectModifiedSlotsIntoMap(allocator, &expected_map, expected, slot);
        const actual_has_slot =
            try collectModifiedSlotsIntoMap(allocator, &actual_map, actual, slot);
        if (expected_has_slot and !actual_has_slot) {
            std.log.err("Actual database is missing slot '{d}'", .{slot});
            return error.TestMissingExpectedSlot;
        }

        if (!expected_has_slot and actual_has_slot) {
            std.log.err("Actual database contains unexpected slot '{d}'", .{slot});
            return error.TestGotUnexpectedSlot;
        }

        try std.testing.expectEqualSlices(Pubkey, expected_map.keys(), actual_map.keys());
        try std.testing.expectEqualDeep(expected_map.values(), actual_map.values());
    }
}

fn collectModifiedSlotsIntoMap(
    allocator: std.mem.Allocator,
    map: *sig.utils.collections.PubkeyMap(AccountSharedData),
    account_reader: sig.accounts_db.AccountReader,
    slot: Slot,
) !bool {
    var iter = account_reader.slotModifiedIterator(slot) orelse return false;
    defer iter.unlock();
    try map.ensureTotalCapacity(allocator, iter.len());
    while (true) {
        const address, const account = try iter.next(allocator) orelse break;
        defer account.deinit(allocator);
        map.putAssumeCapacity(address, .{
            .lamports = account.lamports,
            .data = try account.data.readAllAllocate(allocator),
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        });
    }
    const SortCtx = struct {
        keys: []const Pubkey,

        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return ctx.keys[a_index].order(ctx.keys[b_index]) == .lt;
        }
    };
    const sort_ctx: SortCtx = .{ .keys = map.keys() };
    map.sort(sort_ctx);
    return true;
}

fn createRandomAccount(
    allocator: std.mem.Allocator,
    random: std.Random,
) !AccountSharedData {
    if (!@import("builtin").is_test) @compileError("only for testing");

    const data_size = random.uintAtMost(u64, 1_024);
    const data = try allocator.alloc(u8, data_size);
    random.bytes(data);

    return .{
        .lamports = random.uintAtMost(u64, 1_000_000),
        .data = data,
        .owner = Pubkey.initRandom(random),
        .executable = random.boolean(),
        .rent_epoch = random.uintAtMost(u64, 1_000_000),
    };
}
