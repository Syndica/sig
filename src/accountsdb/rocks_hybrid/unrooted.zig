const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ArrayMap = std.AutoArrayHashMapUnmanaged;

const Ancestors = sig.core.Ancestors;
const AccountFields = sig.core.AccountFields;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const RwMux = sig.sync.RwMux;
const ConstRcSlice = sig.sync.ConstRcSlice;

pub const AccountsDB = struct {};

/// Locking rules:
/// - never hold the lock to the index and the accounts simultaneously. if you
///   want to add an account, update the accounts first, then the index. if you
///   want to remove an account, update the index first, then the accounts.
/// - always acquire the outer lock first, then the inner lock
/// - always release inner lock before outer lock
const UnrootedDB = struct {
    allocator: Allocator,
    /// tells you which slot to look for an account
    index: NestedRwLockMap(Pubkey, RingBitSet),
    accounts: NestedRwLockMap(Slot, ArrayMap(Pubkey, OutputAccount)),

    pub fn init(allocator: Allocator) UnrootedDB {
        return UnrootedDB{
            .allocator = allocator,
            .index = .empty,
            .accounts = .empty,
        };
    }

    // pub fn deinit(self: *UnrootedDB, allocator: Allocator) void {}

    pub fn get(
        self: *UnrootedDB,
        address: Pubkey,
        ancestors: Ancestors,
    ) ?OutputAccount {
        const slot_to_check = index: {
            const index, var lock = self.index.read(address) orelse return null;
            defer lock.unlock();
            var iter = index.reverseIterator();
            while (iter.next()) |slot| if (ancestors.containsSlot(slot)) break :index slot;
            return null;
        };

        const map, var lock = self.accounts.read(slot_to_check) orelse
            return null; // slot must have been pruned after releasing above lock
        defer lock.unlock();
        var account = map.get(address) orelse return null;
        _ = account.data.acquire();
        return account;
    }

    pub fn put(
        self: *UnrootedDB,
        slot: Slot,
        address: Pubkey,
        account: InputAccount,
    ) error{ Deleted, OutOfMemory }!void {
        { // store the account
            const accounts, var lock = try self.accounts.write(self.allocator, slot, .empty);
            defer lock.unlock();

            const gop = try accounts.getOrPut(self.allocator, address);
            const old = gop.value_ptr.*;
            gop.value_ptr.* = .{
                .fields = account.fields,
                .data = try ConstRcSlice(u8).alloc(self.allocator, account.data.len),
            };
            if (gop.found_existing) {
                old.data.deinit(self.allocator);
            }
        }

        { // update the index
            const index, var lock = try self.index.write(self.allocator, address, .empty);
            defer lock.unlock();
            index.mark(slot) catch |e| switch (e) {
                // slot must have been flushed or pruned after inserting, no problem.
                error.Underflow => {},
            };
        }
    }
};

pub const InputAccount = struct {
    fields: AccountFields,
    data: []const u8,
};

pub const OutputAccount = struct {
    fields: AccountFields,
    data: ConstRcSlice(u8),
};

pub fn NestedRwLockMap(K: type, V: type) type {
    return struct {
        data: RwMux(ArrayMap(K, RwMux(V))),

        pub const empty = NestedRwLockMap(K, V){
            .data = .init(.empty),
        };

        pub fn read(
            self: *NestedRwLockMap(K, V),
            key: K,
        ) ?struct { *const V, ReadGuard } {
            const data, var lock = self.data.readWithLock();
            defer lock.unlock();
            if (data.getPtr(key)) |ptr| {
                const item, const inner_lock = ptr.readWithLock();
                return .{ item, .{ .outer_guard = lock, .inner_guard = inner_lock } };
            }
            return null;
        }

        pub fn write(
            self: *NestedRwLockMap(K, V),
            allocator: Allocator,
            key: K,
            default: V,
        ) error{ OutOfMemory, Deleted }!struct { *V, WriteGuard } {
            for (0..2) |i| {
                { // first, optimistic try, and retry after writing in pessimistic case
                    const data, var lock = self.data.readWithLock();
                    if (data.getPtr(key)) |ptr| {
                        const item, const write_lock = ptr.writeWithLock();
                        return .{ item, .{ .outer_guard = lock, .inner_guard = write_lock } };
                    }
                    lock.unlock();
                }

                if (i == 1) {
                    // if it fails again, that means it was immediately deleted by another
                    // thread, so return an error.
                    return error.Deleted;
                }

                { // fallback, create entry for key
                    const data, var lock = self.data.writeWithLock();
                    defer lock.unlock();
                    try data.put(allocator, key, .init(default));
                }
            }
            unreachable; // we'll hit error.Deleted before this.
        }

        pub const ReadGuard = struct {
            outer_guard: RwMux(ArrayMap(K, RwMux(V))).RLockGuard,
            inner_guard: RwMux(V).RLockGuard,

            pub fn unlock(self: *ReadGuard) void {
                self.inner_guard.unlock();
                self.outer_guard.unlock();
            }
        };

        pub const WriteGuard = struct {
            outer_guard: RwMux(ArrayMap(K, RwMux(V))).RLockGuard,
            inner_guard: RwMux(V).WLockGuard,

            pub fn unlock(self: *WriteGuard) void {
                self.inner_guard.unlock();
                self.outer_guard.unlock();
            }
        };
    };
}

/// A bit set that is allowed to progress forwards by setting bits out of bounds
/// and deleting old values, but not allowed to regress backwards.
pub const RingBitSet = struct {
    /// underlying bitset
    slots: std.bit_set.StaticBitSet(len),
    /// The lowest value represented
    bottom: usize,
    /// The highest value that has been set
    last_set: usize,

    const len = 128;

    pub const empty = RingBitSet{
        .slots = .initEmpty(),
        .bottom = 0,
        .last_set = 0,
    };

    pub fn mark(self: *RingBitSet, index: usize) error{Underflow}!void {
        if (index < self.bottom) return error.Underflow;
        if (index - self.bottom > len) {
            const wipe_start = self.bottom;
            self.bottom += index - len;
            const wipe_end = self.bottom;
            if (wipe_start % len > wipe_end % len) {
                self.slots.setRangeValue(.{ .start = wipe_start % len, .end = len }, false);
                self.slots.setRangeValue(.{ .start = 0, .end = wipe_end % len }, false);
            } else {
                self.slots.setRangeValue(.{ .start = wipe_start % len, .end = wipe_end % len }, false);
            }
        }
        self.last_set = index;
        self.slots.set(index % len);
    }

    pub fn reverseIterator(self: *const RingBitSet) ReverseIterator {
        return .{
            .marker = self,
            .cursor = self.bottom + len - 1,
        };
    }

    pub const ReverseIterator = struct {
        marker: *const RingBitSet,
        cursor: usize,

        pub fn next(self: *ReverseIterator) ?usize {
            while (self.cursor >= self.marker.bottom) {
                defer self.cursor -= 1;
                if (self.marker.slots.isSet(self.cursor % len)) {
                    return self.cursor;
                }
            }
            return null;
        }
    };
};

test UnrootedDB {
    var db: UnrootedDB = undefined;
    _ = db.get(undefined, undefined);
    try db.put(undefined, undefined, undefined);
}
