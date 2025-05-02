//! Dependencies of replay that, in agave, would be defined as part of a
//! different component, but in sig, they were not yet implemented. So they were
//! added here with the minimal amount of necessary functionality to support
//! replay.

const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;

pub const AccountLocks = struct {
    write_locks: std.AutoArrayHashMapUnmanaged(Pubkey, void) = .{},
    readonly_locks: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{},

    const LockError = Allocator.Error || error{LockFailed};

    pub fn lockTransactions() void {
        // TODO
    }

    /// Either locks all accounts, or locks none and returns an error.
    pub fn lock(
        self: *AccountLocks,
        allocator: Allocator,
        /// { account to lock, write access needed }
        accounts: []const struct { Pubkey, bool },
    ) LockError!void {
        for (accounts) |account| {
            const address, const write = account;
            if (write) {
                if (self.readonly_locks.contains(address) or self.write_locks.contains(address)) {
                    return error.LockFailed;
                }
            } else if (self.write_locks.contains(address)) {
                return error.LockFailed;
            }
        }
        for (accounts, 0..) |account, i| {
            errdefer std.debug.assert(0 == self.unlock(accounts[0..i]));
            const address, const write = account;
            if (write) {
                _ = try self.write_locks.getOrPut(allocator, address);
            } else {
                const entry = try self.readonly_locks.getOrPut(allocator, address);
                entry.value_ptr.* += 1;
            }
        }
    }

    /// Infallible function that guarantees all the provided accounts will be
    /// unlocked after it returns.
    ///
    /// Returns the number of items that were already unlocked and thus did not
    /// need to be unlocked. You can use this in a calling scope to assert that
    /// this struct is not being misused.
    pub fn unlock(self: *AccountLocks, accounts: []const struct { Pubkey, bool }) u64 {
        var already_unlocked: u64 = 0;
        for (accounts) |account| {
            const address, const write = account;
            if (write) {
                if (!self.write_locks.swapRemove(address)) already_unlocked += 1;
            } else {
                const index = self.readonly_locks.getIndex(address) orelse {
                    already_unlocked += 1;
                    continue;
                };
                const value = &self.readonly_locks.entries.slice().items(.value)[index];
                if (value.* == 0) {
                    // this means there is an internal bug within the unlock
                    // method, since the next block here should remove the item
                    // before this number would ever reach zero.
                    unreachable;
                } else if (value.* == 1) {
                    self.readonly_locks.swapRemoveAt(index);
                } else {
                    value.* -= 1;
                }
            }
        }
        return already_unlocked;
    }
};
