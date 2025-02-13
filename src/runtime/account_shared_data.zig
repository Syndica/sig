const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

/// `AccountSharedData` holds account information with a shared reference to the account data field
/// `AccountSharedData`'s are loaded from `accounts_db` during the transaction loading phase
///
/// TODO: move to `accounts_db`?
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/account.rs#L118
pub const AccountSharedData = struct {
    /// lamports in the account
    lamports: u64,
    /// data held in this account
    data: []u8,
    /// the program that owns this account. If executable, the program that loads this account.
    owner: Pubkey,
    /// this account's data contains a loaded program (and is now read-only)
    executable: bool,
    /// the epoch at which this account will next owe rent
    rent_epoch: Epoch,

    pub fn isZeroed(self: AccountSharedData) bool {
        // TODO: naive implementation
        for (self.data) |byte| if (byte != 0) return false;
        return true;
    }

    pub fn resize(self: *AccountSharedData, allocator: std.mem.Allocator, new_size: usize) !void {
        // TODO: naive implementation
        const new_memory = try allocator.alloc(u8, new_size);
        @memset(new_memory, 0);
        @memcpy(new_memory[0..self.data.len], self.data);
        allocator.free(self.data);
        self.data.ptr = new_memory.ptr;
        self.data.len = new_size;
    }
};
