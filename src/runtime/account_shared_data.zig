const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/account.rs#L118
pub const AccountSharedData = struct {
    /// lamports in the account
    lamports: u64,
    /// data held in this account
    data: *std.ArrayListUnmanaged(u8),
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,

    pub fn resize(self: *AccountSharedData, allocator: std.mem.Allocator, new_size: usize) !void {
        try self.data.appendNTimes(allocator, 0, new_size - self.data.items.len);
    }

    pub fn equals(self: AccountSharedData, other: AccountSharedData) bool {
        return self.lamports == other.lamports and
            std.mem.eql(u8, self.data.items, other.data.items) and
            self.owner.equals(&other.owner) and
            self.executable == other.executable and
            self.rent_epoch == other.rent_epoch;
    }
};
