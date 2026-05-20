const std = @import("std");
const sig = @import("../sig.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const TransactionError = sig.ledger.transaction_status.TransactionError;

pub const AccountLoadError = error{ OutOfMemory, AccountsDBError };

pub const AccountReader = struct {
    ctx: *const anyopaque,
    getFn: *const fn (
        *const anyopaque,
        std.mem.Allocator,
        Pubkey,
    ) AccountLoadError!?AccountSharedData,

    /// Returns caller-owned account data for a live account. The caller must
    /// deinitialize returned `AccountSharedData.data` with the same allocator.
    /// Missing accounts and dead accounts return null.
    pub fn get(
        self: AccountReader,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) AccountLoadError!?AccountSharedData {
        return self.getFn(self.ctx, allocator, pubkey);
    }
};

pub const StatusChecker = struct {
    ctx: *const anyopaque,
    checkFn: *const fn (
        *const anyopaque,
        *const Hash,
        *const Hash,
    ) ?TransactionError,

    pub fn check(
        self: StatusChecker,
        msg_hash: *const Hash,
        recent_blockhash: *const Hash,
    ) ?TransactionError {
        return self.checkFn(self.ctx, msg_hash, recent_blockhash);
    }
};
