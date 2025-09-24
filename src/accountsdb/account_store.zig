//! Simplified interfaces for the common operations of writing and reading
//! accounts to and from a database.

const std = @import("std");
const sig = @import("../sig.zig");
const accounts_db = @import("lib.zig");

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
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn reader(self: AccountStore) AccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = db },
            .thread_safe_map => |map| .{ .thread_safe_map = map },
            .noop => .noop,
        };
    }

    pub fn put(self: AccountStore, slot: Slot, address: Pubkey, account: AccountSharedData) !void {
        return switch (self) {
            .accounts_db => |db| db.putAccount(slot, address, account),
            .thread_safe_map => |map| try map.put(slot, address, account),
            .noop => {},
        };
    }
};

/// Interface for only reading accounts
pub const AccountReader = union(enum) {
    accounts_db: *AccountsDB,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    /// use this to deinit accounts returned by get methods
    pub fn allocator(self: AccountReader) Allocator {
        return switch (self) {
            .noop => sig.utils.allocators.failing.allocator(.{}),
            inline else => |item| item.allocator,
        };
    }

    pub fn forSlot(self: AccountReader, ancestors: *const Ancestors) SlotAccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = .{ db, ancestors } },
            .thread_safe_map => |map| .{ .thread_safe_map = .{ map, ancestors } },
            .noop => .noop,
        };
    }

    /// Deinit all returned accounts using `account_reader.allocator()`
    pub fn getLatest(self: AccountReader, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |db| {
                const account = try db.getAccountLatest(&address) orelse return null;
                if (account.lamports == 0) {
                    // TODO: implement this check in accountsdb to avoid the unnecessary allocation
                    account.deinit(db.allocator);
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
            .thread_safe_map => |map| .{
                .thread_safe_map = map.slotModifiedIterator(slot) orelse return null,
            },
            .noop => .noop,
        };
    }
};

pub const SlotModifiedIterator = union(enum) {
    accounts_db: AccountsDB.SlotModifiedIterator,
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

    pub fn next(self: *SlotModifiedIterator) !?struct { Pubkey, Account } {
        return switch (self.*) {
            inline else => |*item| try item.next(),
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
    /// Contains many versions of accounts and becomes fork-aware using
    /// ancestors, like accountsdb.
    thread_safe_map: struct { *ThreadSafeAccountMap, *const Ancestors },
    /// Only stores the current slot's version of each account.
    /// Should only store borrowed accounts, or else it will panic on deinit.
    single_version_map: *const std.AutoArrayHashMapUnmanaged(Pubkey, Account),
    noop,

    /// use this to deinit accounts returned by get methods
    pub fn allocator(self: SlotAccountReader) Allocator {
        return switch (self) {
            .noop => sig.utils.allocators.failing.allocator(.{}),
            .single_version_map => sig.utils.allocators.failing.allocator(.{
                .alloc = .panics,
                .resize = .panics,
                .free = .panics,
            }),
            inline else => |item| item[0].allocator,
        };
    }

    /// Deinit all returned accounts using `account_reader.allocator()`
    pub fn get(self: SlotAccountReader, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |pair| {
                const db, const ancestors = pair;
                const account = try db.getAccountWithAncestors(&address, ancestors) orelse
                    return null;
                if (account.lamports == 0) {
                    account.deinit(db.allocator);
                    return null;
                }
                return account;
            },
            .thread_safe_map => |pair| try pair[0].get(address, pair[1]),
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
    last_rooted_slot: ?Slot,

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
            .last_rooted_slot = null,
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
    ) !?Account {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();

        const pubkey_map = &self.pubkey_map;
        const slot_account_pairs = pubkey_map.get(address) orelse return null;
        for (slot_account_pairs.items) |slot_account| {
            const slot, const account = slot_account;
            if (ancestors.containsSlot(slot)) {
                return if (account.lamports == 0) null else try toAccount(self.allocator, account);
            }
            if (self.last_rooted_slot) |last_rooted_slot| if (slot <= last_rooted_slot) {
                return if (account.lamports == 0) null else try toAccount(self.allocator, account);
            };
        }

        return null;
    }

    pub fn getLatest(self: *ThreadSafeAccountMap, address: Pubkey) !?Account {
        self.rwlock.lockShared();
        defer self.rwlock.unlockShared();
        const list = self.pubkey_map.get(address) orelse return null;
        if (list.items.len == 0) return null;
        _, const account = list.items[0];
        return try toAccount(self.allocator, account);
    }

    fn toAccount(allocator: Allocator, account: AccountSharedData) !Account {
        const data = try allocator.dupe(u8, account.data);
        errdefer allocator.free(account.data);

        return .{
            .lamports = account.lamports,
            .data = .{ .owned_allocation = data },
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        };
    }

    pub fn put(
        self: *ThreadSafeAccountMap,
        slot: Slot,
        address: Pubkey,
        account: AccountSharedData,
    ) !void {
        self.rwlock.lock();
        defer self.rwlock.unlock();

        const data = try self.allocator.dupe(u8, account.data);
        errdefer self.allocator.free(account.data);

        const account_shared_data: AccountSharedData = .{
            .lamports = account.lamports,
            .data = data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        };

        slot_map: {
            const slot_map = &self.slot_map;
            const slot_gop = try slot_map.getOrPut(self.allocator, slot);
            if (!slot_gop.found_existing) slot_gop.value_ptr.* = .empty;
            for (slot_gop.value_ptr.items) |*pubkey_account| {
                if (pubkey_account[0].equals(&address)) {
                    self.allocator.free(pubkey_account[1].data);
                    pubkey_account[1] = account_shared_data;
                    break :slot_map;
                }
            }
            try slot_gop.value_ptr.append(self.allocator, .{ address, account_shared_data });
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
                versions_list.items[index] = .{ slot, account_shared_data };
            } else {
                try versions_list.insert(self.allocator, index, .{ slot, account_shared_data });
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

        pub fn next(self: *ThreadSafeAccountMap.SlotModifiedIterator) !?struct { Pubkey, Account } {
            std.debug.assert(self.cursor != std.math.maxInt(usize));
            defer self.cursor += 1;
            if (self.cursor >= self.slot_list.len) return null;
            const pubkey, const account = self.slot_list[self.cursor];
            return .{ pubkey, try toAccount(self.allocator, account) };
        }
    };
};

test "AccountStore does not return 0-lamport accounts from accountsdb" {
    var db, var dir = try AccountsDB.initForTest(std.testing.allocator);
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

    try std.testing.expectEqual(null, try reader.getLatest(zero_lamport_address));
    try std.testing.expectEqual(1, (try reader.getLatest(one_lamport_address)).?.lamports);

    var ancestors = Ancestors{};
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.ancestors.put(std.testing.allocator, 0, {});
    const slot_reader = db.accountReader().forSlot(&ancestors);

    try std.testing.expectEqual(null, try slot_reader.get(zero_lamport_address));
    try std.testing.expectEqual(1, (try slot_reader.get(one_lamport_address)).?.lamports);
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

    try expectAccount(account_reader, addr1, null, sharedToCoreAccount(expected_account));
    try expectAccount(account_reader, addr1, ancestors1, sharedToCoreAccount(expected_account));
}

fn expectAccount(
    account_reader: AccountReader,
    address: Pubkey,
    maybe_ancestors: ?Ancestors,
    expected: ?sig.core.Account,
) !void {
    if (!@import("builtin").is_test) @compileError("Not allowed outside of tests.");
    const actual = if (maybe_ancestors) |*ancestors|
        try account_reader.forSlot(ancestors).get(address)
    else
        try account_reader.getLatest(address);
    defer if (actual) |actual_account| actual_account.deinit(account_reader.allocator());

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
