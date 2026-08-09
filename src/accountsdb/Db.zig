//! Thin wrapper around Rooted and Unrooted that ties everything together to be used by the account store.

const std = @import("std");
const sig = @import("../sig.zig");
pub const Rooted = @import("Rooted.zig");
pub const Unrooted = @import("Unrooted.zig");
const CompressedAccountStore = @import("CompressedAccountStore.zig");

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
    _ = self.onSlotRootedTimed(newly_rooted_slot, ancestors, true);
}

pub const RootSlotTiming = struct {
    begin_ns: u64,
    scan_upsert_ns: u64,
    commit: Rooted.CommitTransactionTiming,
    total_ns: u64,
    slots_scanned: u64,
    populated_slots_scanned: u64,
    rooted_slots_flushed: u64,
    accounts_upserted: u64,
    accounts_cleared: u64,
};

/// Roots the slot synchronously and always commits its account updates. The
/// flag controls only the post-commit maintenance reported in `commit`.
pub fn onSlotRootedTimed(
    self: *Db,
    newly_rooted_slot: Slot,
    ancestors: *const Ancestors,
    perform_memory_relief: bool,
) RootSlotTiming {
    var total_timer = sig.time.Timer.start();
    var phase_timer = sig.time.Timer.start();
    self.rooted.beginTransaction();
    const begin_ns = phase_timer.read().asNanos();

    // Ancestors are kept in a way where the "head" slot is stored.
    std.debug.assert(ancestors.containsSlot(newly_rooted_slot));
    // This assert is satifisied via the implementation of ancestors, however
    // we want to show that we'll never need to iterate over more than MAX_SLOTs cases.
    std.debug.assert(ancestors.ancestors.count() < Unrooted.MAX_SLOTS);

    const start_slot = if (self.rooted.largest_rooted_slot) |lrs| lrs + 1 else 0;
    const range = newly_rooted_slot - start_slot + 1;
    var populated_slots_scanned: u64 = 0;
    var rooted_slots_flushed: u64 = 0;
    var accounts_upserted: u64 = 0;
    var accounts_cleared: u64 = 0;

    phase_timer.reset();
    for (0..range) |i| {
        const slot = start_slot + i;
        const index = &self.unrooted.slots[slot % Unrooted.MAX_SLOTS];

        if (index.is_empty.load(.acquire)) continue;
        if (index.slot != slot) continue;
        populated_slots_scanned += 1;

        index.lock.lock();
        defer index.lock.unlock();

        if (ancestors.containsSlot(index.slot)) {
            rooted_slots_flushed += 1;
            // TODO: batch put() into rooted
            var entries = index.entries.iterator();
            while (entries.next()) |entry| {
                self.rooted.put(entry.key_ptr.*, index.slot, entry.value_ptr.*);
                accounts_upserted += 1;
            }
        }

        accounts_cleared += index.entries.count();
        for (index.entries.values()) |data| data.deinit(self.allocator);
        index.entries.clearRetainingCapacity();
        index.is_empty.store(true, .release);
    }
    const scan_upsert_ns = phase_timer.read().asNanos();

    const commit = self.rooted.commitTransactionTimed(perform_memory_relief);
    self.rooted.largest_rooted_slot = newly_rooted_slot;

    return .{
        .begin_ns = begin_ns,
        .scan_upsert_ns = scan_upsert_ns,
        .commit = commit,
        .total_ns = total_timer.read().asNanos(),
        .slots_scanned = range,
        .populated_slots_scanned = populated_slots_scanned,
        .rooted_slots_flushed = rooted_slots_flushed,
        .accounts_upserted = accounts_upserted,
        .accounts_cleared = accounts_cleared,
    };
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

pub fn accountDataLen(
    self: *Db,
    allocator: std.mem.Allocator,
    address: Pubkey,
    ancestors: *const Ancestors,
) !?usize {
    if (self.unrooted.accountDataLen(address, ancestors)) |result| {
        if (result.lamports == 0) return null;
        return result.data_len;
    }
    return try self.rooted.accountDataLen(allocator, address);
}

pub fn compressedAccountChunkId(self: *Db, address: Pubkey) !?u32 {
    return try self.rooted.compressedAccountChunkId(address);
}

pub fn compressedAccountChunkCached(self: *Db, chunk_id: u32) bool {
    return self.rooted.compressedAccountChunkCached(chunk_id);
}

pub fn prefetchCompressedAccountChunks(
    self: *Db,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
) !CompressedAccountStore.PrefetchResult {
    return try self.rooted.prefetchCompressedChunksForPubkeys(allocator, pubkeys);
}

pub fn batchDecodeCompressedAccounts(
    self: *Db,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
) !CompressedAccountStore.BatchDecodeResult {
    return try self.rooted.batchDecodeCompressedAccountsForPubkeys(allocator, pubkeys);
}

pub fn batchLoadCompressedAccounts(
    self: *Db,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
) !CompressedAccountStore.BatchDecodeResult {
    return try self.rooted.batchLoadCompressedAccountsForPubkeys(allocator, pubkeys, accounts);
}

pub fn batchLoadCompressedAccountsBorrowed(
    self: *Db,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
) !CompressedAccountStore.BatchDecodeResult {
    return try self.rooted.batchLoadCompressedAccountsForPubkeysBorrowed(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
    );
}

pub fn batchLoadCompressedAccountsBorrowedPriority(
    self: *Db,
    allocator: std.mem.Allocator,
    pubkeys: []const Pubkey,
    accounts: *sig.utils.collections.PubkeyMap(AccountSharedData),
    borrowed_accounts: *sig.utils.collections.PubkeyMap(*const AccountSharedData),
) !CompressedAccountStore.BatchDecodeResult {
    return try self.rooted.batchLoadCompressedAccountsForPubkeysBorrowedPriority(
        allocator,
        pubkeys,
        accounts,
        borrowed_accounts,
    );
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

const testing = struct {
    fn convert(account: Account) AccountSharedData {
        return .{
            .data = account.data.owned_allocation,
            .executable = account.executable,
            .lamports = account.lamports,
            .owner = account.owner,
            .rent_epoch = account.rent_epoch,
        };
    }
};

test "onSlotRootedTimed commits while memory relief is deferred" {
    const allocator = std.testing.allocator;

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    var account_data = [_]u8{ 1, 2, 3 };
    try db.put(0, .ZEROES, .{
        .lamports = 42,
        .data = &account_data,
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 7,
    });

    const timing = db.onSlotRootedTimed(0, &ancestors, false);
    try std.testing.expect(!timing.commit.memory_relief_performed);
    try std.testing.expectEqual(@as(u64, 1), timing.slots_scanned);
    try std.testing.expectEqual(@as(u64, 1), timing.populated_slots_scanned);
    try std.testing.expectEqual(@as(u64, 1), timing.rooted_slots_flushed);
    try std.testing.expectEqual(@as(u64, 1), timing.accounts_upserted);
    try std.testing.expectEqual(@as(u64, 1), timing.accounts_cleared);
    try std.testing.expectEqual(@as(u64, 0), timing.commit.db_release_ns);
    try std.testing.expectEqual(@as(u64, 0), timing.commit.global_release_ns);
    try std.testing.expectEqual(@as(u64, 0), timing.commit.pressure_relief_ns);
    try std.testing.expectEqual(@as(?Slot, 0), db.rooted.getLargestRootedSlot());

    const account = (try db.get(allocator, .ZEROES, &ancestors)) orelse
        return error.MissingCommittedAccount;
    defer account.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 42), account.lamports);
    try std.testing.expect(account.data.eqlSlice(&account_data));
}

test "many slots, many accounts" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    for (0..Unrooted.MAX_SLOTS * 2) |i| {
        defer if (i > 50) db.onSlotRooted(i, &ancestors); // start rooting after 50 slots

        const random_account = try Account.initRandom(allocator, random, 30);
        defer random_account.deinit(allocator);
        const random_pubkey = Pubkey.initRandom(random);

        try ancestors.addSlot(allocator, i);
        ancestors.cleanup();

        try db.put(i, random_pubkey, testing.convert(random_account));
    }
    // Ensure we end up with a clean slate, not leaking any entries.
    try ancestors.addSlot(allocator, Unrooted.MAX_SLOTS * 2);
    ancestors.cleanup();
    db.onSlotRooted(Unrooted.MAX_SLOTS * 2, &ancestors);
    for (db.unrooted.slots) |entry| {
        std.debug.assert(entry.is_empty.load(.acquire));
    }
}

test "many slots, same account" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    const random_pubkey = Pubkey.initRandom(random);
    for (0..Unrooted.MAX_SLOTS * 2) |i| {
        defer if (i % 64 == 0) db.onSlotRooted(i, &ancestors); // root every 64 slots

        const random_account = try Account.initRandom(allocator, random, 30);
        defer random_account.deinit(allocator);

        try ancestors.addSlot(allocator, i);
        ancestors.cleanup();

        try db.put(i, random_pubkey, testing.convert(random_account));
    }
    try ancestors.addSlot(allocator, Unrooted.MAX_SLOTS * 2);
    ancestors.cleanup();
    db.onSlotRooted(Unrooted.MAX_SLOTS * 2, &ancestors);
    for (db.unrooted.slots) |entry| {
        std.debug.assert(entry.is_empty.load(.acquire));
    }
}

test "rooting must handle wraparound and non-consecutive roots" {
    const allocator = std.testing.allocator;

    var test_state = try Db.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var ancestors = Ancestors.EMPTY;
    defer ancestors.deinit(allocator);

    for (0..Unrooted.MAX_SLOTS * 2) |slot| {
        try ancestors.addSlot(allocator, slot);
        ancestors.cleanup();

        try db.put(slot, .ZEROES, .{
            .lamports = slot * 10,
            .data = &.{},
            .owner = .ZEROES,
            .executable = false,
            .rent_epoch = 0,
        });

        {
            const account = try db.get(allocator, .ZEROES, &ancestors);
            defer account.?.deinit(allocator);
            try std.testing.expectEqual(slot * 10, account.?.lamports);
        }

        if (slot % 2 == 0) {
            db.onSlotRooted(slot, &ancestors);
            const account = try db.get(allocator, .ZEROES, &ancestors);
            defer account.?.deinit(allocator);
            try std.testing.expectEqual(slot * 10, account.?.lamports);
        }
    }
}
