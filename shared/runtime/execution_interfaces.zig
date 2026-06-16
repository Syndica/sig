const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../lib.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const BlockhashQueue = sig.core.BlockhashQueue;
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

    const AccountMap = sig.utils.collections.PubkeyMap(AccountSharedData);

    /// Returns an account reader backed by an in-memory account map.
    /// The map must remain alive for the reader to be used.
    pub fn fromMap(accounts: *const AccountMap) AccountReader {
        const Reader = struct {
            fn get(
                ctx: *const anyopaque,
                allocator: std.mem.Allocator,
                pubkey: Pubkey,
            ) AccountLoadError!?AccountSharedData {
                const map: *const AccountMap = @ptrCast(@alignCast(ctx));
                const account = map.get(pubkey) orelse return null;
                return try account.clone(allocator);
            }
        };

        return .{ .ctx = accounts, .getFn = Reader.get };
    }

    pub fn noop() AccountReader {
        comptime std.debug.assert(builtin.is_test);

        const Reader = struct {
            const noop_context: u8 = 0;

            fn get(
                _: *const anyopaque,
                _: std.mem.Allocator,
                _: Pubkey,
            ) AccountLoadError!?AccountSharedData {
                return null;
            }
        };

        return .{ .ctx = &Reader.noop_context, .getFn = Reader.get };
    }
};

pub const RecentBlockhashChecker = struct {
    ctx: *const anyopaque,
    isRecentBlockhashValidFn: *const fn (*const anyopaque, Hash, u64) bool,

    pub fn isRecentBlockhashValid(
        self: RecentBlockhashChecker,
        blockhash: Hash,
        max_age: u64,
    ) bool {
        return self.isRecentBlockhashValidFn(self.ctx, blockhash, max_age);
    }

    pub fn fromBlockhashQueue(blockhash_queue: *const BlockhashQueue) RecentBlockhashChecker {
        const Checker = struct {
            fn isRecentBlockhashValid(
                ctx: *const anyopaque,
                blockhash: Hash,
                max_age: u64,
            ) bool {
                const queue: *const BlockhashQueue = @ptrCast(@alignCast(ctx));
                return queue.isHashValidForAge(blockhash, max_age);
            }
        };

        return .{
            .ctx = blockhash_queue,
            .isRecentBlockhashValidFn = Checker.isRecentBlockhashValid,
        };
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

pub const TestEpochStakeReaderContext = if (builtin.is_test) struct {
    pub const StakeParam = struct {
        pubkey: Pubkey,
        stake: u64,
    };

    stakes: []const StakeParam = &.{},

    pub fn totalStake(ctx: *const anyopaque) u64 {
        const self: *const TestEpochStakeReaderContext = @ptrCast(@alignCast(ctx));
        var total: u64 = 0;
        for (self.stakes) |stake| {
            total += stake.stake;
        }
        return total;
    }

    pub fn stakeForVoteAccount(ctx: *const anyopaque, pubkey: Pubkey) u64 {
        const self: *const TestEpochStakeReaderContext = @ptrCast(@alignCast(ctx));
        for (self.stakes) |stake| {
            if (stake.pubkey.equals(&pubkey)) return stake.stake;
        }
        return 0;
    }
} else struct {};
