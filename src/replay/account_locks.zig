const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;

pub const LockableAccount = struct { address: Pubkey, writable: bool };

pub const AccountLocks = struct {
    write_locks: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{},
    readonly_locks: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{},

    const LockError = Allocator.Error || error{LockFailed};

    pub fn deinit(self: AccountLocks, allocator: Allocator) void {
        var write_locks = self.write_locks;
        var readonly_locks = self.readonly_locks;
        write_locks.deinit(allocator);
        readonly_locks.deinit(allocator);
    }

    /// Either locks all accounts, or locks none and returns an error.
    ///
    /// This function does not allow there to be any inner conflicts. In other
    /// words, if the passed batch has a single write lock, then any other
    /// attempts to lock the same account within this batch will result in
    /// failure.
    pub fn lockStrict(
        self: *AccountLocks,
        allocator: Allocator,
        accounts: []const LockableAccount,
    ) LockError!void {
        for (accounts, 0..) |account, i| {
            errdefer std.debug.assert(0 == self.unlock(accounts[0..i]));
            if (account.writable) {
                if (self.readonly_locks.contains(account.address)) {
                    return error.LockFailed;
                }
                const entry = try self.write_locks.getOrPut(allocator, account.address);
                if (entry.found_existing) {
                    return error.LockFailed;
                } else {
                    entry.value_ptr.* = 1;
                }
            } else {
                if (self.write_locks.contains(account.address)) {
                    return error.LockFailed;
                }
                const entry = try self.readonly_locks.getOrPut(allocator, account.address);
                if (entry.found_existing) {
                    entry.value_ptr.* += 1;
                } else {
                    entry.value_ptr.* = 1;
                }
            }
        }
    }

    /// Either locks all accounts, or locks none and returns an error.
    ///
    /// This function allows there to be inner conflicts within the passed
    /// batch, as long as it doesn't conflict with prior lock calls. In other
    /// words, the passed batch may succeed to lock with multiple write locks on
    /// the same account, as long as there were no pre-existing locks on that
    /// account before this function call.
    pub fn lockPermissive(
        self: *AccountLocks,
        allocator: Allocator,
        accounts: []const LockableAccount,
    ) LockError!void {
        for (accounts) |account| {
            if (account.writable) {
                if (self.readonly_locks.contains(account.address) or
                    self.write_locks.contains(account.address))
                {
                    return error.LockFailed;
                }
            } else if (self.write_locks.contains(account.address)) {
                return error.LockFailed;
            }
        }
        for (accounts, 0..) |account, i| {
            errdefer std.debug.assert(0 == self.unlock(accounts[0..i]));
            const locks = if (account.writable) &self.write_locks else &self.readonly_locks;
            const entry = try locks.getOrPut(allocator, account.address);
            if (entry.found_existing) {
                entry.value_ptr.* += 1;
            } else {
                entry.value_ptr.* = 1;
            }
        }
    }

    /// Infallible function that guarantees all the provided accounts will be
    /// unlocked after it returns.
    ///
    /// Returns the number of items that were already unlocked and thus did not
    /// need to be unlocked. You can use this in a calling scope to assert that
    /// this struct is not being misused.
    pub fn unlock(self: *AccountLocks, accounts: []const LockableAccount) u64 {
        var already_unlocked: u64 = 0;
        for (accounts) |account| {
            const locks = if (account.writable) &self.write_locks else &self.readonly_locks;
            already_unlocked += unlockOneGeneric(locks, account.address);
        }
        return already_unlocked;
    }

    /// assumes that
    fn lockOneGeneric(
        allocator: Allocator,
        locks: *std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        address: Pubkey,
    ) u64 {
        const entry = try locks.getOrPut(allocator, address);
        if (entry.found_existing) {
            entry.value_ptr.* = 1;
        } else {
            entry.value_ptr.* += 1;
        }
    }

    /// returns 0 if it was still locked, 1 if it was already unlocked.
    fn unlockOneGeneric(locks: *std.AutoArrayHashMapUnmanaged(Pubkey, u64), address: Pubkey) u64 {
        const index = locks.getIndex(address) orelse {
            return 1;
        };

        const value = &locks.entries.slice().items(.value)[index];
        if (value.* == 0) {
            // this means there is an internal bug within the unlock
            // method, since the next block here should remove the item
            // before this number would ever reach zero.
            unreachable;
        } else if (value.* == 1) {
            locks.swapRemoveAt(index);
        } else {
            value.* -= 1;
        }

        return 0;
    }
};

const expectError = std.testing.expectError;
const expectEqual = std.testing.expectEqual;

const test_keys = [_]Pubkey{
    Pubkey.parseBase58String("3Thhhj3omvVFfbhEHdFe8djwDZT5oS6BQ4k5KrZkYt1r") catch unreachable,
    Pubkey.parseBase58String("DttWaMuVvTiduZRnguLF7jNxTgiMBZ1hyAumKUiL2KRL") catch unreachable,
    Pubkey.parseBase58String("9fRXX5Bj3XWfCHtVkYtQVvMnAfoy4KjcpgHTBSmymzRu") catch unreachable,
    Pubkey.parseBase58String("5BUYHtAdv2rUM73A8iEWQ4hcVQXCRE8VrQFR39DKaWW8") catch unreachable,
    Pubkey.parseBase58String("9jo7RYY8HgxpU3Zs5zPFyRAkcUtx8J5RHc2fN9Btxfmi") catch unreachable,
    Pubkey.parseBase58String("FZgqDx8Guf649hif1WVuTb6mTV2LhotUFE12PYveAbC8") catch unreachable,
    Pubkey.parseBase58String("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4") catch unreachable,
    Pubkey.parseBase58String("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA") catch unreachable,
};

test "locking/unlocking basically works" {
    const allocator = std.testing.allocator;
    var locks = AccountLocks{};
    defer locks.deinit(allocator);

    inline for (.{ AccountLocks.lockStrict, AccountLocks.lockPermissive }) |lockFn| {
        try lockFn(&locks, allocator, &.{
            .{ .address = test_keys[0], .writable = true },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[1], .writable = false },
        });
        try lockFn(&locks, allocator, &.{
            .{ .address = test_keys[1], .writable = false },
        });

        try expectError(error.LockFailed, lockFn(&locks, allocator, &.{
            .{ .address = test_keys[0], .writable = false },
        }));
        try expectError(error.LockFailed, lockFn(&locks, allocator, &.{
            .{ .address = test_keys[0], .writable = true },
        }));
        try expectError(error.LockFailed, lockFn(&locks, allocator, &.{
            .{ .address = test_keys[2], .writable = false },
            .{ .address = test_keys[3], .writable = true },
            .{ .address = test_keys[1], .writable = true },
        }));

        try expectEqual(0, locks.unlock(&.{
            .{ .address = test_keys[0], .writable = true },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[1], .writable = false },
        }));

        try lockFn(&locks, allocator, &.{
            .{ .address = test_keys[0], .writable = true },
        });

        try expectEqual(0, locks.unlock(&.{
            .{ .address = test_keys[0], .writable = true },
        }));

        try expectEqual(6, locks.unlock(&.{
            .{ .address = test_keys[0], .writable = true },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[1], .writable = false },
            .{ .address = test_keys[2], .writable = false },
            .{ .address = test_keys[3], .writable = true },
        }));
    }
}

test "lockStrict is strict" {
    const allocator = std.testing.allocator;
    var locks = AccountLocks{};
    defer locks.deinit(allocator);

    try expectError(error.LockFailed, locks.lockStrict(allocator, &.{
        .{ .address = test_keys[0], .writable = true },
        .{ .address = test_keys[0], .writable = true },
    }));
    try expectError(error.LockFailed, locks.lockStrict(allocator, &.{
        .{ .address = test_keys[0], .writable = true },
        .{ .address = test_keys[0], .writable = false },
    }));

    try expectEqual(0, locks.write_locks.count());
    try expectEqual(0, locks.readonly_locks.count());
}

test "lockPermissive is permissive" {
    const allocator = std.testing.allocator;
    var locks = AccountLocks{};
    defer locks.deinit(allocator);

    try locks.lockPermissive(allocator, &.{
        .{ .address = test_keys[0], .writable = true },
        .{ .address = test_keys[0], .writable = true },
    });
    try locks.lockPermissive(allocator, &.{
        .{ .address = test_keys[1], .writable = true },
        .{ .address = test_keys[1], .writable = false },
    });

    try expectEqual(0, locks.unlock(&.{
        .{ .address = test_keys[0], .writable = true },
        .{ .address = test_keys[0], .writable = true },
        .{ .address = test_keys[1], .writable = true },
        .{ .address = test_keys[1], .writable = false },
    }));
}
