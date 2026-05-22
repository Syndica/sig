const std = @import("std");
const sig = @import("../sig.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const TransactionError = sig.core.transaction_error.TransactionError;

pub const AccountLoadError = error{ OutOfMemory, AccountsDBError };

pub const AccountReader = struct {
    ctx: *const anyopaque,
    getFn: *const fn (
        *const anyopaque,
        std.mem.Allocator,
        Pubkey,
    ) AccountLoadError!?AccountSharedData,

    /// Returns caller-owned account data. The caller must deinitialize returned
    /// `AccountSharedData.data` with the same allocator. Missing accounts return null.
    pub fn get(
        self: AccountReader,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) AccountLoadError!?AccountSharedData {
        return self.getFn(self.ctx, allocator, pubkey);
    }
};

pub const EpochStakeReader = struct {
    ctx: *const anyopaque,
    totalStakeFn: *const fn (*const anyopaque) u64,
    stakeForVoteAccountFn: *const fn (*const anyopaque, Pubkey) u64,

    pub fn totalStake(self: EpochStakeReader) u64 {
        return self.totalStakeFn(self.ctx);
    }

    pub fn stakeForVoteAccount(self: EpochStakeReader, pubkey: Pubkey) u64 {
        return self.stakeForVoteAccountFn(self.ctx, pubkey);
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
