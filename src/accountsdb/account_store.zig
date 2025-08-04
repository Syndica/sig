//! Simplified interfaces for the common operations of writing and reading
//! accounts to and from a database.

const std = @import("std");
const sig = @import("../sig.zig");
const accounts_db = @import("lib.zig");

const Allocator = std.mem.Allocator;

const RwMux = sig.sync.RwMux;

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
    allocator: Allocator,
    pubkey_map: RwMux(std.AutoArrayHashMapUnmanaged(
        Pubkey,
        std.ArrayListUnmanaged(struct { Slot, AccountSharedData }),
    )),
    slot_map: RwMux(SlotMap),

    const SlotMap = std.AutoArrayHashMapUnmanaged(
        Slot,
        std.ArrayListUnmanaged(struct { Pubkey, AccountSharedData }),
    );

    pub fn init(allocator: Allocator) ThreadSafeAccountMap {
        return .{
            .allocator = allocator,
            .slot_map = .init(.empty),
            .pubkey_map = .init(.empty),
        };
    }

    pub fn deinit(self: *ThreadSafeAccountMap) void {
        {
            const map, var lock = self.pubkey_map.writeWithLock();
            defer lock.unlock();

            for (map.values()) |val| {
                var list = val;
                for (list.items) |item| {
                    self.allocator.free(item[1].data);
                }
                list.deinit(self.allocator);
            }

            map.deinit(self.allocator);
        }
        {
            const map, var lock = self.slot_map.writeWithLock();
            defer lock.unlock();

            for (map.values()) |val| {
                var list = val;
                list.deinit(self.allocator);
            }

            map.deinit(self.allocator);
        }
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
        const map, var lock = self.pubkey_map.readWithLock();
        defer lock.unlock();

        const list = map.get(address) orelse return null;
        for (list.items) |slot_account| {
            const slot, const account = slot_account;
            if (ancestors.ancestors.contains(slot)) {
                return if (account.lamports == 0) null else try toAccount(self.allocator, account);
            }
        }
        return null;
    }

    pub fn getLatest(self: *ThreadSafeAccountMap, address: Pubkey) !?Account {
        const map, var lock = self.pubkey_map.readWithLock();
        defer lock.unlock();

        const list = map.get(address) orelse return null;
        if (list.items.len == 0) return null;
        return try toAccount(self.allocator, list.items[0][1]);
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
        const data = try self.allocator.dupe(u8, account.data);
        errdefer self.allocator.free(account.data);

        const account_shared_data = AccountSharedData{
            .lamports = account.lamports,
            .data = data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        };

        slot_map: {
            const slot_map, var slot_lock = self.slot_map.writeWithLock();
            defer slot_lock.unlock();

            const slot_gop = try slot_map.getOrPut(self.allocator, slot);
            if (!slot_gop.found_existing) {
                slot_gop.value_ptr.* = .empty;
            }

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
            const pubkey_map, var pubkey_lock = self.pubkey_map.writeWithLock();
            defer pubkey_lock.unlock();

            const gop = try pubkey_map.getOrPut(self.allocator, address);
            if (!gop.found_existing) {
                gop.value_ptr.* = .empty;
            }

            const versions = gop.value_ptr.items;

            const index = std.sort.lowerBound(
                struct { Slot, AccountSharedData },
                versions,
                slot,
                struct {
                    fn compare(s: Slot, elem: struct { Slot, AccountSharedData }) std.math.Order {
                        return std.math.order(elem[0], s); // sorted descending to simplify getters
                    }
                }.compare,
            );

            if (index != versions.len and versions[index][0] == slot) {
                versions[index] = .{ slot, account_shared_data };
            } else {
                try gop.value_ptr.insert(self.allocator, index, .{ slot, account_shared_data });
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
        var map = self.slot_map.read();

        const slot_list = map.get().get(slot) orelse return null;

        return .{
            .allocator = self.allocator,
            .lock = map,
            .slot_list = slot_list.items,
            .cursor = 0,
        };
    }

    pub const SlotModifiedIterator = struct {
        allocator: Allocator,
        lock: RwMux(SlotMap).RLockGuard,
        slot_list: []const struct { Pubkey, AccountSharedData },
        cursor: usize,

        pub fn unlock(self: *ThreadSafeAccountMap.SlotModifiedIterator) void {
            self.cursor = std.math.maxInt(usize);
            self.lock.unlock();
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
