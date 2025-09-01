const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ArrayMap = std.AutoArrayHashMapUnmanaged;

const Ancestors = sig.core.Ancestors;
const AccountMetadata = sig.core.AccountMetadata;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const RwMux = sig.sync.RwMux;
const RcSlice = sig.sync.RcSlice;

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
    accounts: NestedRwLockMap(Pubkey, ArrayMap(Pubkey, Account)),

    pub fn get(
        self: UnrootedDB,
        address: Pubkey,
        ancestors: Ancestors,
    ) ?Account {
        _ = ancestors; // autofix
        const index, const lock = self.index.read(address);
        _ = lock; // autofix
        _ = index; // autofix
    }

    pub fn put(
        self: *UnrootedDB,
        slot: Slot,
        address: Pubkey,
        account: Account,
    ) error{ Deleted, OutOfMemory }!void {
        { // store the account
            const accounts_rw, const lock = try self.accounts.write(slot);
            defer lock.unlock();

            const accounts, var inner_lock = accounts_rw.writeWithLock();
            defer inner_lock.unlock();
            const gop = try accounts.getOrPut(self.allocator, address);
            if (gop.found_existing) {
                self.allocator.free(gop.value_ptr.data);
            }
            gop.value_ptr.* = .{
                .metadata = account.metadata,
                .data = try self.allocator.dupe(account.data),
            };
        }

        { // update the index
            const index, const lock = try self.index.write(address);
            defer lock.unlock();
            index.mark(slot);
        }
    }
};

pub const Account = struct {
    metadata: AccountMetadata,
    data: []const u8,
};

/// Requires that V can be initialized as `.empty`
pub fn NestedRwLockMap(K: type, V: type) type {
    return struct {
        data: RwMux(ArrayMap(K, RwMux(V))),

        pub fn read(
            self: *NestedRwLockMap(K, V),
            key: K,
        ) error{ OutOfMemory, Deleted }!struct { *V, ReadGuard } {
            const accounts, var lock = self.accounts.readWithLock();
            if (accounts.getPtr(key)) |ptr| {
                const item, const inner_lock = ptr.readWithLock();
                return .{
                    item,
                    .{ .outer_guard = lock, .inner_guard = inner_lock },
                };
            }
            lock.unlock();
        }

        pub fn write(
            self: *NestedRwLockMap(K, V),
            key: K,
        ) error{ OutOfMemory, Deleted }!struct { *V, WriteGuard } {
            for (0..2) |i| {
                { // first, optimistic try, and retry after writing in pessimistic case
                    const accounts, var lock = self.accounts.readWithLock();
                    if (accounts.getPtr(key)) |ptr| {
                        const item, const write_lock = ptr.writeWithLock();
                        return .{
                            item,
                            .{ .outer_guard = lock, .inner_guard = write_lock },
                        };
                    }
                    lock.unlock();
                }

                if (i == 1) {
                    // if it fails again, that means it was immediately deleted by another
                    // thread, so return an error.
                    return error.Deleted;
                }

                { // fallback, create entry for key
                    const accounts, var lock = self.accounts.writeWithLock();
                    defer lock.unlock();
                    try accounts.put(self.allocator, key, .empty);
                }
            }
        }

        pub const ReadGuard = struct {
            outer_guard: RwMux(ArrayMap(K, RwMux(V))).RLockGuard,
            inner_guard: RwMux(V).RLockGuard,

            pub fn unlock(self: ReadGuard) void {
                self.inner_guard.unlock();
                self.outer_guard.unlock();
            }
        };

        pub const WriteGuard = struct {
            outer_guard: RwMux(ArrayMap(K, RwMux(V))).RLockGuard,
            inner_guard: RwMux(V).WLockGuard,

            pub fn unlock(self: WriteGuard) void {
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

    pub fn mark(self: *RingBitSet, index: usize) error{Underflow}!void {
        if (index < self.bottom) return error.Underflow;
        if (index - self.bottom > len) {
            // update the start slot
            self.start_slot = index - len + self.bottom;
            // delete stale values (set all to false)
            const wipe_start = self.bottom;
            const wipe_end = self.start_slot;
            if (wipe_start % len > wipe_end % len) {
                self.setRangeValue(.{ .start = wipe_start % len, .end = len }, false);
                self.setRangeValue(.{ .start = 0, .end = wipe_end % len }, false);
            } else {
                self.setRangeValue(.{ .start = wipe_start % len, .end = wipe_end % len }, false);
            }
        }
        self.last_set = index;
        self.slots.set(index % len);
    }

    pub fn reverseIterator(self: *const RingBitSet) void {
        return .{
            .marker = self,
            .start = self.last_set,
            .cursor = self.bottom,
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
