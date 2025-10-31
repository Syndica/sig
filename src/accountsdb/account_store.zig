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

const AccountsDB = accounts_db.AccountsDB;

/// Interface for both reading and writing accounts.
///
/// Do not use this unless you need to *write* into the database generically.
/// Otherwise use AccountReader if you only need to read accounts.
pub const AccountStore = union(enum) {
    accounts_db: *AccountsDB,
    accounts_db_two: *accounts_db.Two,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn reader(self: AccountStore) AccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = db },
            .accounts_db_two => |db| .{ .accounts_db_two = db },
            .thread_safe_map => |map| .{ .thread_safe_map = map },
            .noop => .noop,
        };
    }

    pub fn put(self: AccountStore, slot: Slot, address: Pubkey, account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountStore.put" });
        defer zone.deinit();

        return switch (self) {
            .accounts_db => |db| db.putAccount(slot, address, account),
            .accounts_db_two => |db| try db.put(slot, address, account),
            .thread_safe_map => |map| try map.put(slot, address, account),
            .noop => {},
        };
    }

    /// To be called from consensus when a slot is rooted
    pub fn onSlotRooted(
        self: AccountStore,
        allocator: std.mem.Allocator,
        newly_rooted_slot: Slot,
        lamports_per_signature: u64,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountStore.onSlotRooted" });
        defer zone.deinit();

        switch (self) {
            .accounts_db => |db| try accounts_db.manager.onSlotRooted(
                allocator,
                db,
                newly_rooted_slot,
                lamports_per_signature,
            ),
            .accounts_db_two => |db| try db.onSlotRooted(newly_rooted_slot),
            .thread_safe_map => |db| try db.onSlotRooted(newly_rooted_slot),
            .noop => {},
        }
    }
};

/// Interface for only reading accounts
pub const AccountReader = union(enum) {
    accounts_db: *AccountsDB,
    accounts_db_two: *accounts_db.Two,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn forSlot(self: AccountReader, ancestors: *const Ancestors) SlotAccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = .{ db, ancestors } },
            .accounts_db_two => |db| .{ .accounts_db_two = .{ db, ancestors } },
            .thread_safe_map => |map| .{ .thread_safe_map = .{ map, ancestors } },
            .noop => .noop,
        };
    }

    /// Deinit all returned accounts using `account_reader.allocator()`
    pub fn getLatest(self: AccountReader, allocator: std.mem.Allocator, address: Pubkey) !?Account {
        if (!builtin.is_test) @compileError("only used for tests");
        return switch (self) {
            .accounts_db => |db| {
                const account = try db.getAccountLatest(allocator, &address) orelse return null;
                if (account.lamports == 0) {
                    // TODO: implement this check in accountsdb to avoid the unnecessary allocation
                    account.deinit(allocator);
                    return null;
                }
                return account;
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
        return switch (self) {
            .accounts_db => |db| .{
                .accounts_db = db.slotModifiedIterator(slot) orelse return null,
            },
            .accounts_db_two => |db| .{ .accounts_db_two = db.slotModifiedIterator(slot) },
            .thread_safe_map => |map| .{
                .thread_safe_map = map.slotModifiedIterator(slot) orelse return null,
            },
            .noop => .noop,
        };
    }

    pub fn getLargestRootedSlot(self: AccountReader) ?Slot {
        if (!builtin.is_test) @compileError("only used for tests");

        return switch (self) {
            .accounts_db => |db| db.getLargestRootedSlot(),
            .thread_safe_map => |tsm| tsm.getLargestRootedSlot(),
            .noop => null,
        };
    }
};

pub const SlotModifiedIterator = union(enum) {
    accounts_db: AccountsDB.SlotModifiedIterator,
    accounts_db_two: accounts_db.Two.SlotModifiedIterator,
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
pub const SlotAccountReader = union(enum) {
    accounts_db: struct { *AccountsDB, *const Ancestors },
    accounts_db_two: struct { *accounts_db.Two, *const Ancestors },
    /// Contains many versions of accounts and becomes fork-aware using
    /// ancestors, like accountsdb.
    thread_safe_map: struct { *ThreadSafeAccountMap, *const Ancestors },
    /// Only stores the current slot's version of each account.
    /// Should only store borrowed accounts, or else it will panic on deinit.
    single_version_map: *const std.AutoArrayHashMapUnmanaged(Pubkey, Account),
    noop,

    /// Deinit all returned accounts using `account_reader.allocator()`
    pub fn get(self: SlotAccountReader, alloc: std.mem.Allocator, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |pair| {
                const db, const ancestors = pair;
                const account = try db.getAccountWithAncestors(
                    alloc,
                    &address,
                    ancestors,
                ) orelse return null;
                if (account.lamports == 0) {
                    account.deinit(alloc);
                    return null;
                }
                return account;
            },
            .accounts_db_two => |pair| try pair[0].get(address, pair[1]),
            .thread_safe_map => |pair| pair[0].get(address, pair[1]),
            .single_version_map => |pair| pair.get(address),
            .noop => null,
        };
    }
};

/// Simple implementation of AccountReader and AccountStore, mainly for tests
pub const ThreadSafeAccountMap = struct {
    rwlock: std.Thread.RwLock.DefaultRwLock,
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
        rwlock: *std.Thread.RwLock.DefaultRwLock,
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

    var db, var dir = try AccountsDB.initForTest(allocator);
    defer {
        db.deinit();
        dir.cleanup();
    }

    const zero_lamport_address = Pubkey.ZEROES;
    const one_lamport_address = Pubkey{ .data = @splat(9) };

    try db.putAccount(0, zero_lamport_address, .{
        .lamports = 0,
        .data = &.{},
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    try db.putAccount(0, one_lamport_address, .{
        .lamports = 1,
        .data = &.{},
        .owner = .ZEROES,
        .executable = false,
        .rent_epoch = 0,
    });

    const reader = db.accountReader();

    try std.testing.expectEqual(null, try reader.getLatest(allocator, zero_lamport_address));
    try std.testing.expectEqual(1, (try reader.getLatest(
        allocator,
        one_lamport_address,
    )).?.lamports);

    var ancestors = Ancestors{};
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.ancestors.put(allocator, 0, {});
    const slot_reader = db.accountReader().forSlot(&ancestors);

    try std.testing.expectEqual(null, try slot_reader.get(allocator, zero_lamport_address));
    try std.testing.expectEqual(1, (try slot_reader.get(
        allocator,
        one_lamport_address,
    )).?.lamports);
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

    var prng_state: std.Random.Xoshiro256 = .init(346715);
    const prng = prng_state.random();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var simple_state: sig.accounts_db.ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var real_state: AccountsDB = try .init(.minimal(allocator, .FOR_TESTS, tmp_dir.dir, null));
    defer real_state.deinit();

    const simple_store = simple_state.accountStore();
    const real_store = real_state.accountStore();
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

        const pubkey: Pubkey = .initRandom(prng);
        const account = try createRandomAccount(allocator, prng);
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

    setRootedLargestSlotForTest(&simple_state, &real_state, 2);
    try putAccountIntoStores(error.CannotWriteRootedSlot, &stores, 1, .ZEROES, .EMPTY);

    // this backtracking wouldn't/shouldn't really ever happen, but just
    // to demonstrate that the error is based on the rooted slot:
    setRootedLargestSlotForTest(&simple_state, &real_state, null);
    try putAccountIntoStores({}, &stores, 1, .ZEROES, .EMPTY);
}

test "insertion out of order" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.Xoshiro256 = .init(346715);
    const prng = prng_state.random();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var simple_state: sig.accounts_db.ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var real_state: AccountsDB = try .init(.minimal(allocator, .FOR_TESTS, tmp_dir.dir, null));
    defer real_state.deinit();

    const simple_store = simple_state.accountStore();
    const real_store = real_state.accountStore();
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
            const slot = prng.uintLessThan(Slot, 1000);
            if (ancestor_set.containsSlot(slot)) continue;
            break slot;
        };
        errdefer std.log.err("At slot {} (iteration {d})", .{ slot, i });

        const pubkey: Pubkey = .initRandom(prng);
        const account = try createRandomAccount(allocator, prng);
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

    for (ancestor_set.ancestors.keys()) |slot| {
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

    const slot_to_try_write_while_rooted = slot: {
        const slots = simple_state.slot_map.keys();
        break :slot slots[prng.uintLessThan(usize, slots.len)];
    };
    const pk_of_ones: Pubkey = .{ .data = @splat(1) };
    setRootedLargestSlotForTest(&simple_state, &real_state, slot_to_try_write_while_rooted);
    try std.testing.expectEqual(
        error.CannotWriteRootedSlot,
        simple_store.put(1, pk_of_ones, .EMPTY),
    );
    try std.testing.expectEqual(
        error.CannotWriteRootedSlot,
        real_store.put(1, pk_of_ones, .EMPTY),
    );
    setRootedLargestSlotForTest(&simple_state, &real_state, null);
    try putAccountIntoStores({}, &stores, 1, pk_of_ones, .EMPTY);
}

test "put and get zero lamports before & after cleanup" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.Xoshiro256 = .init(346715);
    const prng = prng_state.random();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var simple_state: sig.accounts_db.ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var real_state: AccountsDB = try .init(.minimal(allocator, .FOR_TESTS, tmp_dir.dir, null));
    real_state.on_root_config.do_cleaning = true;
    defer real_state.deinit();

    const simple_store = simple_state.accountStore();
    const real_store = real_state.accountStore();
    const stores = [_]sig.accounts_db.AccountStore{ simple_store, real_store };

    const pk1, const pk2, const pk3, const pk4 = pks: {
        var pks: [4]Pubkey = undefined;
        for (&pks, 0..) |*pubkey, i| while (true) {
            pubkey.* = .initRandom(prng);
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
    try expectDbUnrootedPubkeysInSlot(&real_state, slot100, &.{ pk1, pk2, pk3, pk4 });
    try expectDbUnrootedPubkeysInSlot(&real_state, slot200, &.{ pk1, pk2, pk3, pk4 });

    // but after we run the manager on it to clean it up...
    setRootedLargestSlotForTest(&simple_state, &real_state, slot100);
    try real_store.onSlotRooted(allocator, slot100, 5000);
    try simple_store.onSlotRooted(allocator, slot100, 5000);

    // the unrooted entry for slot100 is removed, and all the zero-lamport accounts should
    // not be present in the flushed accounts.
    try expectDbUnrootedPubkeysInSlot(&real_state, slot100, null);
    try std.testing.expectEqual(false, real_state.account_index.exists(&pk1, slot100));
    try std.testing.expectEqual(false, real_state.account_index.exists(&pk2, slot100));
    try std.testing.expectEqual(true, real_state.account_index.exists(&pk3, slot100));
    try std.testing.expectEqual(true, real_state.account_index.exists(&pk4, slot100));

    // although they should all still exist in the unrooted slot200.
    try expectDbUnrootedPubkeysInSlot(&real_state, slot200, &.{ pk1, pk2, pk3, pk4 });

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
    setRootedLargestSlotForTest(&simple_state, &real_state, slot200);
    try real_store.onSlotRooted(allocator, slot200, 5000);
    try simple_store.onSlotRooted(allocator, slot200, 5000);

    try expectDbUnrootedPubkeysInSlot(&real_state, slot200, null);
    try std.testing.expectEqual(false, real_state.account_index.exists(&pk1, slot200));
    try std.testing.expectEqual(true, real_state.account_index.exists(&pk2, slot200));
    try std.testing.expectEqual(false, real_state.account_index.exists(&pk3, slot200));
    try std.testing.expectEqual(true, real_state.account_index.exists(&pk4, slot200));
}

test "put and get zero lamports across forks" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.Xoshiro256 = .init(346715);
    const prng = prng_state.random();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var simple_state: sig.accounts_db.ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var real_state: AccountsDB = try .init(.minimal(allocator, .FOR_TESTS, tmp_dir.dir, null));
    defer real_state.deinit();

    const simple_store = simple_state.accountStore();
    const real_store = real_state.accountStore();
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

    const pk: Pubkey = .initRandom(prng);
    const slot1: Slot = 100;
    const slot2: Slot = 200;
    const slot3: Slot = 300;
    const slot4: Slot = 400;

    setRootedLargestSlotForTest(&simple_state, &real_state, slot1);
    try putAccountIntoStores({}, &stores, slot2, pk, zero_lamports);
    try putAccountIntoStores({}, &stores, slot3, pk, one_lamport);
    try putAccountIntoStores({}, &stores, slot4, pk, zero_lamports);

    const fork_a: Ancestors = try .initWithSlots(allocator, &.{slot2});
    defer fork_a.deinit(allocator);

    const fork_b: Ancestors = try .initWithSlots(allocator, &.{ slot2, slot3 });
    defer fork_b.deinit(allocator);

    const fork_c: Ancestors = try .initWithSlots(allocator, &.{ slot2, slot4 });
    defer fork_c.deinit(allocator);

    try expectAccountFromStores(&stores, &fork_a, pk, null);
    try expectAccountFromStores(&stores, &fork_b, pk, one_lamport.asAccount());
    try expectAccountFromStores(&stores, &fork_c, pk, null);
}

test "put and get across competing forks" {
    const allocator = std.testing.allocator;

    var prng_state: std.Random.Xoshiro256 = .init(346715);
    const prng = prng_state.random();

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var simple_state: sig.accounts_db.ThreadSafeAccountMap = .init(allocator);
    defer simple_state.deinit();

    var real_state: AccountsDB = try .init(.minimal(allocator, .FOR_TESTS, tmp_dir.dir, null));
    defer real_state.deinit();

    const simple_store = simple_state.accountStore();
    const real_store = real_state.accountStore();
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

    const pk: Pubkey = .initRandom(prng);
    const slot1: Slot = 100;
    const slot2: Slot = 200;
    const slot3: Slot = 300;
    const slot4: Slot = 400;

    try putAccountIntoStores({}, &stores, slot1, pk, asd_a);
    setRootedLargestSlotForTest(&simple_state, &real_state, slot1);
    try putAccountIntoStores({}, &stores, slot3, pk, asd_b);
    try putAccountIntoStores({}, &stores, slot4, pk, asd_c);

    const fork_a: Ancestors = try .initWithSlots(allocator, &.{slot2});
    defer fork_a.deinit(allocator);

    const fork_b: Ancestors = try .initWithSlots(allocator, &.{ slot2, slot3 });
    defer fork_b.deinit(allocator);

    const fork_c: Ancestors = try .initWithSlots(allocator, &.{ slot2, slot4 });
    defer fork_c.deinit(allocator);

    try expectAccountFromStores(&stores, &fork_a, pk, asd_a.asAccount());
    try expectAccountFromStores(&stores, &fork_b, pk, asd_b.asAccount());
    try expectAccountFromStores(&stores, &fork_c, pk, asd_c.asAccount());
}

fn expectDbUnrootedPubkeysInSlot(
    db: *AccountsDB,
    slot: Slot,
    maybe_expected_pubkeys: ?[]const Pubkey,
) !void {
    const unrooted, var unrooted_lg = db.unrooted_accounts.readWithLock();
    defer unrooted_lg.unlock();

    const pubkey_accounts_mal = unrooted.get(slot) orelse {
        if (maybe_expected_pubkeys) |expected_pubkeys| {
            std.log.err("\nExpected pubkeys: {any},\nactual pubkeys:   null", .{expected_pubkeys});
            return error.TestMissingExpectedSlot;
        }
        return;
    };
    const actual_pubkeys: []const Pubkey = pubkey_accounts_mal.items(.pubkey);
    const expected_pubkeys = maybe_expected_pubkeys orelse {
        std.log.err("\nExpected pubkeys: null,\nactual pubkeys:   {any}", .{actual_pubkeys});
        return error.TestMissingExpectedSlot;
    };
    try std.testing.expectEqualSlices(Pubkey, expected_pubkeys, actual_pubkeys);
}

fn setRootedLargestSlotForTest(
    simple: *sig.accounts_db.ThreadSafeAccountMap,
    real: *AccountsDB,
    largest_rooted_slot: ?Slot,
) void {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    {
        simple.rwlock.lock();
        defer simple.rwlock.unlock();
        simple.largest_rooted_slot = largest_rooted_slot;
    }
    {
        const max_slots, var max_slots_lg = real.max_slots.writeWithLock();
        defer max_slots_lg.unlock();
        max_slots.rooted = largest_rooted_slot;
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
            std.log.err("Got unexpected account '{}' for ancestors.", .{pubkey});
            return error.TestGotUnexpectedAccount;
        };
        const actual_account = actual_account_opt orelse {
            std.log.err("Missing account '{}' for ancestors.", .{pubkey});
            return error.TestMissingExpectedAccount;
        };
        try actual_account.expectEquals(expected_account);
    }

    var expected_map: std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) = .empty;
    defer expected_map.deinit(allocator);

    var actual_map: std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) = .empty;
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
    map: *std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
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
