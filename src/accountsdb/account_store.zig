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

    /// Returns an iterator that iterates over every account that was modified
    /// in the slot.
    ///
    /// Holds the read lock on the index, so unlock it when done, and be careful
    /// how long you hold this.
    pub fn slotModifiedIterator(self: AccountStore, slot: Slot) ?SlotModifiedIterator {
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
        for (list.items) |item| {
            if (ancestors.ancestors.contains(item[0])) {
                return try toAccount(self.allocator, item[1]);
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

        const item = AccountSharedData{
            .lamports = account.lamports,
            .data = data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        };

        {
            const slot_map, var slot_lock = self.slot_map.writeWithLock();
            defer slot_lock.unlock();

            const slot_gop = try slot_map.getOrPut(self.allocator, slot);
            if (!slot_gop.found_existing) {
                slot_gop.value_ptr.* = .empty;
            }

            try slot_gop.value_ptr.append(self.allocator, .{ address, item });
        }

        {
            const pubkey_map, var pubkey_lock = self.pubkey_map.writeWithLock();
            defer pubkey_lock.unlock();

            const pubkey_gop = try pubkey_map.getOrPut(self.allocator, address);
            if (!pubkey_gop.found_existing) {
                pubkey_gop.value_ptr.* = .empty;
            }

            try pubkey_gop.value_ptr.append(self.allocator, .{ slot, item });
            std.mem.sort(struct { Slot, AccountSharedData }, pubkey_gop.value_ptr.items, {}, struct {
                fn lessThan(
                    _: void,
                    lhs: struct { Slot, AccountSharedData },
                    rhs: struct { Slot, AccountSharedData },
                ) bool {
                    return lhs[0] > rhs[0]; // sort descending so get methods are simpler
                }
            }.lessThan);
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
            if (self.cursor > self.slot_list.len) return null;
            const pubkey, const account = self.slot_list[self.cursor];
            return .{ pubkey, try toAccount(self.allocator, account) };
        }
    };
};
