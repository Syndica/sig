const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../lib.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

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
        ctx: *const anyopaque,
        msg_hash: *const Hash,
        recent_blockhash: *const Hash,
        max_age: u64,
    ) Result,

    pub const Result = enum {
        /// The transaction is recent, and has never been executed in the
        /// current fork, so it is legal to execute this in the current block.
        recent_and_unprocessed,
        /// The transaction was already executed in a recent block on the
        /// current fork, so it is not legal to include it in the current block.
        already_processed,
        /// The recent_blockhash count not be identified. It could not be
        /// determined whether the transaction already exists in a block. This
        /// means the recent_blockhash is too old or invalid, or the transaction
        /// uses a durable nonce.
        unknown_blockhash,
    };

    /// Checks recent blocks up to max_age to see a transaction it was already
    /// processed in any of these blocks.
    ///
    /// Does not locate transactions using a durable nonce. It will return
    /// "unknown_blockhash" for those.
    pub fn check(
        self: StatusChecker,
        msg_hash: *const Hash,
        recent_blockhash: *const Hash,
        max_age: u64,
    ) Result {
        return self.checkFn(self.ctx, msg_hash, recent_blockhash, max_age);
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
