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

    pub fn get(self: AccountReader, address: Pubkey, ancestors: *const Ancestors) !?Account {
        return switch (self) {
            .accounts_db => |db| try db.getAccount(&address), // TODO: PR #796
            .thread_safe_map => |map| try map.get(address, ancestors),
            .noop => null,
        };
    }

    pub fn getLatest(self: AccountReader, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |db| try db.getAccount(&address),
            .thread_safe_map => |map| try map.getLatest(address),
            .noop => null,
        };
    }
};

/// Interface for both reading and writing accounts.
///
/// Do not use this unless you need to *write* into the database generically.
/// Otherwise use AccountReader if you only need to read accounts.
pub const AccountStore = union(enum) {
    accounts_db: *AccountsDB,
    thread_safe_map: *ThreadSafeAccountMap,
    noop,

    pub fn accountReader(self: AccountStore) AccountReader {
        return switch (self) {
            .accounts_db => |db| .{ .accounts_db = db },
            .thread_safe_map => |map| .{ .thread_safe_map = map },
            .noop => .noop,
        };
    }

    /// use this to deinit accounts returned by get methods
    pub fn allocator(self: AccountStore) Allocator {
        return switch (self) {
            .noop => sig.utils.allocators.failing.allocator(.{}),
            inline else => |item| item.allocator,
        };
    }

    pub fn get(self: AccountStore, address: Pubkey, ancestors: *const Ancestors) !?Account {
        return switch (self) {
            .accounts_db => |db| try db.getAccount(&address), // TODO: PR #796
            .thread_safe_map => |map| try map.get(address, ancestors),
            .noop => null,
        };
    }

    pub fn getLatest(self: AccountStore, address: Pubkey) !?Account {
        return switch (self) {
            .accounts_db => |db| try db.getAccount(&address),
            .thread_safe_map => |map| try map.getLatest(address),
            .noop => null,
        };
    }

    pub fn put(self: AccountStore, slot: Slot, address: Pubkey, account: AccountSharedData) !void {
        return switch (self) {
            .accounts_db => unreachable, // TODO: PR #796
            .thread_safe_map => |map| try map.put(slot, address, account),
            .noop => {},
        };
    }
};

/// Simple implementation of AccountReader and AccountStore, mainly for tests
pub const ThreadSafeAccountMap = struct {
    allocator: Allocator,
    map: RwMux(std.AutoArrayHashMapUnmanaged(
        Pubkey,
        std.ArrayListUnmanaged(struct { Slot, AccountSharedData }),
    )),

    pub fn init(allocator: Allocator) ThreadSafeAccountMap {
        return .{ .allocator = allocator, .map = .init(.empty) };
    }

    pub fn deinit(self: *ThreadSafeAccountMap) void {
        const map, var lock = self.map.writeWithLock();
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
        const map, var lock = self.map.readWithLock();
        defer lock.unlock();

        const list = map.get(address) orelse return null;
        for (list.items) |item| {
            if (ancestors.ancestors.contains(item[0])) {
                return try toAccount(self.allocator, item[1]);
            }
        }
        return null;
    }

    pub fn getLatest(self: *ThreadSafeAccountMap, address: Pubkey) !?Account {
        const map, var lock = self.map.readWithLock();
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
        const map, var lock = self.map.writeWithLock();
        defer lock.unlock();

        const gop = try map.getOrPut(self.allocator, address);
        if (!gop.found_existing) {
            gop.value_ptr.* = .empty;
        }

        const data = try self.allocator.dupe(u8, account.data);
        errdefer self.allocator.free(account.data);

        try gop.value_ptr.append(self.allocator, .{ slot, .{
            .lamports = account.lamports,
            .data = data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        } });

        std.mem.sort(struct { Slot, AccountSharedData }, gop.value_ptr.items, {}, struct {
            fn lessThan(
                _: void,
                lhs: struct { Slot, AccountSharedData },
                rhs: struct { Slot, AccountSharedData },
            ) bool {
                return lhs[0] > rhs[0]; // sort descending so get methods are simpler
            }
        }.lessThan);
    }
};
