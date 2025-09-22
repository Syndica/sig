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

/// Locking rules:
/// - never hold the lock to the index and the accounts simultaneously. if you
///   want to add an account, update the accounts first, then the index. if you
///   want to remove an account, update the index first, then the accounts.
/// - always acquire the outer lock first, then the inner lock
/// - always release inner lock before outer lock
pub const UnrootedDB = struct {
    /// tells you which slot to look for an account
    index: NestedRwLockMap(Pubkey, RingBitSet),
    accounts: NestedRwLockMap(Slot, ArrayMap(Pubkey, OutputAccount)),

    pub const empty = UnrootedDB{
        .index = .empty,
        .accounts = .empty,
    };

    pub fn deinit(self: *UnrootedDB, allocator: Allocator) void {
        self.index.deinit(allocator);
        self.accounts.deinit(allocator);
    }

    pub fn get(
        self: *UnrootedDB,
        address: Pubkey,
        ancestors: *const Ancestors,
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
        if (account.fields.lamports == 0) return null;
        _ = account.data.acquire();
        return account;
    }

    pub fn put(
        self: *UnrootedDB,
        allocator: Allocator,
        slot: Slot,
        address: Pubkey,
        account: InputAccount,
    ) error{ Deleted, OutOfMemory }!void {
        { // store the account
            const accounts, var lock = try self.accounts.write(allocator, slot, .empty);
            defer lock.unlock();

            const gop = try accounts.getOrPut(allocator, address);
            const old = gop.value_ptr.*;
            gop.value_ptr.* = .{
                .fields = account.fields,
                .data = try ConstRcSlice(u8).alloc(allocator, account.data.len),
            };
            if (gop.found_existing) {
                old.data.deinit(allocator);
            }
        }

        { // update the index
            const index, var lock = try self.index.write(allocator, address, .empty);
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
        data: ArrayMap(K, struct {
            data: V,
            lock: RwLock,
        }),
        lock: RwLock,

        const RwLock = std.Thread.RwLock;
        const Self = NestedRwLockMap(K, V);

        pub const empty = Self{
            .data = .empty,
            .lock = .{},
        };

        pub fn deinit(self: *Self, allocator: Allocator) void {
            if (!self.lock.tryLock()) @panic("tried to deinit while lock was held");
            self.data.deinit(allocator);
        }

        pub fn read(self: *Self, key: K) ?struct { *const V, ReadUnlocker } {
            self.lock.lockShared();
            defer self.lock.unlock();
            if (self.data.getPtr(key)) |ptr| {
                ptr.lock.lockShared();
                return .{ &ptr.data, .{ .outer = &self.lock, .inner = &ptr.lock } };
            }
            return null;
        }

        pub fn write(
            self: *Self,
            allocator: Allocator,
            key: K,
            default: V,
        ) error{ OutOfMemory, Deleted }!struct { *V, WriteUnlocker } {
            for (0..2) |i| {
                { // first, optimistic try, and retry after writing in pessimistic case
                    self.lock.lockShared();
                    if (self.data.getPtr(key)) |ptr| {
                        ptr.lock.lock();
                        return .{ &ptr.data, .{ .outer = &self.lock, .inner = &ptr.lock } };
                    }
                    self.lock.unlockShared();
                }

                if (i == 1) {
                    // if it fails again, that means it was immediately deleted by another
                    // thread, so return an error.
                    return error.Deleted;
                }

                { // fallback, create entry for key
                    self.lock.lock();
                    defer self.lock.unlock();
                    try self.data.put(allocator, key, .{ .data = default, .lock = .{} });
                }
            }
            unreachable; // we'll hit error.Deleted before this.
        }

        /// Call Iterator.unlock when done with iterator
        pub fn iterator(self: *Self) Iterator {
            const guard = self.data.read();
            return .{
                .inner = guard.get().iterator(),
                .held_read_lock = guard,
            };
        }

        pub const Iterator = struct {
            inner: ArrayMap(K, RwMux(V)).Iterator,
            held_read_lock: *RwLock,

            pub fn unlock(self: *Iterator) void {
                self.held_read_lock.unlock();
            }

            /// Call unlock for each entry when done with that entry.
            pub fn next(self: *Iterator) ?Entry {
                if (self.inner.next()) |item| {
                    item.value_ptr.lock.lockShared();
                    return .{
                        .key = item.key_ptr,
                        .value = item.value_ptr.data,
                        .lock = item.value_ptr.lock,
                    };
                } else return null;
            }

            pub const Entry = struct {
                key: *K,
                value: *V,
                held_inner_read_lock: *RwLock,

                pub fn unlock(self: *Entry) void {
                    self.held_inner_read_lock.unlockShared();
                }
            };
        };

        pub const ReadUnlocker = struct {
            outer: *RwLock,
            inner: *RwLock,

            pub fn unlock(self: *ReadUnlocker) void {
                self.inner.unlockShared();
                self.outer.unlockShared();
            }
        };

        pub const WriteUnlocker = struct {
            outer: *RwLock,
            inner: *RwLock,

            pub fn unlock(self: *WriteUnlocker) void {
                self.inner.unlock();
                self.outer.unlockShared();
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
    var db: UnrootedDB = .empty;
    defer db.deinit(std.testing.allocator);
    if (false) {
        // TODO
        try db.put(std.testing.allocator, 0, .ZEROES, undefined);
        _ = db.get(.ZEROES, undefined);
    }
}
