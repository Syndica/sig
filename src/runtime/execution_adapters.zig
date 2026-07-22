const std = @import("std");
const sig = @import("../sig.zig");

const AccountReader = sig.runtime.execution_interfaces.AccountReader;
const AccountLoadError = sig.runtime.execution_interfaces.AccountLoadError;
const EpochStakeReader = sig.runtime.execution_interfaces.EpochStakeReader;
const account_conversions = sig.runtime.account_conversions;
const AccountSharedData = sig.runtime.AccountSharedData;
const Ancestors = sig.core.Ancestors;
const Hash = sig.core.Hash;
const EpochStakes = sig.core.EpochStakes;
const Pubkey = sig.core.Pubkey;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;
const StatusCache = sig.core.StatusCache;
const StatusChecker = sig.runtime.execution_interfaces.StatusChecker;

pub const SlotAccountReaderAdapter = struct {
    reader: SlotAccountReader,

    pub fn accountReader(self: *const SlotAccountReaderAdapter) AccountReader {
        return .{ .ctx = self, .getFn = get };
    }

    fn get(
        ctx: *const anyopaque,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) AccountLoadError!?AccountSharedData {
        const adapter: *const SlotAccountReaderAdapter = @ptrCast(@alignCast(ctx));
        const account = adapter.reader.get(allocator, pubkey) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.AccountsDBError,
        } orelse return null;
        defer account.deinit(allocator);

        return try account_conversions.fromAccount(allocator, &account);
    }
};

pub const EpochStakeReaderAdapter = struct {
    epoch_stakes: *const EpochStakes,

    pub fn epochStakeReader(self: *const EpochStakeReaderAdapter) EpochStakeReader {
        return .{
            .ctx = self.epoch_stakes,
            .totalStakeFn = totalStake,
            .stakeForVoteAccountFn = stakeForVoteAccount,
        };
    }

    fn totalStake(ctx: *const anyopaque) u64 {
        const epoch_stakes: *const EpochStakes = @ptrCast(@alignCast(ctx));
        return epoch_stakes.total_stake;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/runtime/src/bank.rs#L6140-L6145
    fn stakeForVoteAccount(ctx: *const anyopaque, pubkey: Pubkey) u64 {
        const epoch_stakes: *const EpochStakes = @ptrCast(@alignCast(ctx));
        return epoch_stakes.stakes.vote_accounts.getDelegatedStake(pubkey);
    }
};

pub const StatusCacheStatusCheckerAdapter = struct {
    ancestors: *const Ancestors,
    status_cache: *StatusCache,
    blockhash_queue: *const sig.core.BlockhashQueue,

    pub fn statusChecker(self: *const StatusCacheStatusCheckerAdapter) StatusChecker {
        return .{ .ctx = self, .checkFn = check };
    }

    /// [agave]
    // sig fmt: off
    /// https://github.com/firedancer-io/agave/blob/403d23b/runtime/src/bank/check_transactions.rs#L186
    // sig fmt: on
    fn check(
        ctx: *const anyopaque,
        msg_hash: *const Hash,
        recent_blockhash: *const Hash,
        max_age: u64,
    ) StatusChecker.Result {
        const adapter: *const StatusCacheStatusCheckerAdapter = @ptrCast(@alignCast(ctx));
        if (!adapter.blockhash_queue.isHashValidForAge(recent_blockhash.*, max_age)) {
            return .unknown_blockhash;
        }
        return switch (adapter.status_cache.getStatus(
            &msg_hash.data,
            recent_blockhash,
            adapter.ancestors,
        )) {
            .pending => .recent_and_unprocessed,
            .failed, .succeeded => .already_processed,
        };
    }
};

test "SlotAccountReaderAdapter preserves reader zero-lamport behavior" {
    const allocator = std.testing.allocator;
    const pubkey = Pubkey.ZEROES;

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData).empty;
    defer accounts.deinit(allocator);
    try accounts.put(allocator, pubkey, .{
        .lamports = 0,
        .data = &.{},
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .executable = false,
        .rent_epoch = 0,
    });

    const adapter = SlotAccountReaderAdapter{
        .reader = .{ .account_shared_data_map = &accounts },
    };
    const maybe_account = try adapter.accountReader().get(allocator, pubkey);
    defer if (maybe_account) |account| account.deinit(allocator);

    try std.testing.expect(maybe_account != null);
    try std.testing.expectEqual(0, maybe_account.?.lamports);
}

test "StatusCacheStatusCheckerAdapter" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ancestors = Ancestors{};
    defer ancestors.deinit(allocator);

    var status_cache: StatusCache = .DEFAULT;
    defer status_cache.deinit(allocator);

    const msg_hash = Hash.init("msg hash");
    const recent_blockhash = Hash.init("recent blockhash");
    const stale_blockhash = Hash.init("stale blockhash");
    const max_age: u64 = 5;

    var blockhash_queue: sig.core.BlockhashQueue =
        try .initWithSingleEntry(allocator, recent_blockhash, 5000);
    defer blockhash_queue.deinit(allocator);

    const adapter = StatusCacheStatusCheckerAdapter{
        .ancestors = &ancestors,
        .status_cache = &status_cache,
        .blockhash_queue = &blockhash_queue,
    };
    const status_checker = adapter.statusChecker();

    // recent_blockhash is in the queue, status cache empty.
    try std.testing.expectEqual(
        .recent_and_unprocessed,
        status_checker.check(&msg_hash, &recent_blockhash, max_age),
    );

    // A blockhash that isn't in the queue is too old to decide,
    // letting the caller fall through to the durable-nonce path.
    try std.testing.expectEqual(
        .unknown_blockhash,
        status_checker.check(&msg_hash, &stale_blockhash, max_age),
    );

    try ancestors.ancestors.put(allocator, 0, {});
    try status_cache.insert(allocator, prng.random(), &recent_blockhash, &msg_hash.data, 0, null);

    // Same (msg_hash, recent_blockhash) recorded in the cache.
    try std.testing.expectEqual(
        .already_processed,
        status_checker.check(&msg_hash, &recent_blockhash, max_age),
    );

    // The hash is in the status cache, but the blockhash is too old. This is
    // technically a corrupted state or an invalid input. The contract of the
    // status checker is that it only looks for transactions that specify their
    // blockhashes up to a max age, otherwise it's treated as unknown. Even if
    // we have more information about the transaction, we must return unknown
    // here.
    try std.testing.expectEqual(
        .unknown_blockhash,
        status_checker.check(&msg_hash, &stale_blockhash, max_age),
    );
}

test "EpochStakeReaderAdapter" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const vote_pubkey = Pubkey.initRandom(prng.random());
    const other_vote_pubkey = Pubkey.initRandom(prng.random());

    var epoch_stakes: EpochStakes = .{
        .stakes = .EMPTY,
        .total_stake = 246,
        .node_id_to_vote_accounts = .empty,
        .epoch_authorized_voters = .empty,
    };
    defer epoch_stakes.deinit(allocator);

    // Set up vote accounts with delegated stake (keyed by vote account pubkey).
    const VoteAccount = sig.core.stakes.VoteAccount;
    var vote_account_1: VoteAccount = try .initRandom(allocator, prng.random(), null);
    errdefer vote_account_1.deinit(allocator);
    var vote_account_2: VoteAccount = try .initRandom(allocator, prng.random(), null);
    errdefer vote_account_2.deinit(allocator);

    try epoch_stakes.stakes.vote_accounts.vote_accounts.put(allocator, vote_pubkey, .{
        .stake = 123,
        .account = vote_account_1,
    });
    try epoch_stakes.stakes.vote_accounts.vote_accounts.put(allocator, other_vote_pubkey, .{
        .stake = 123,
        .account = vote_account_2,
    });

    const adapter = EpochStakeReaderAdapter{ .epoch_stakes = &epoch_stakes };
    const reader = adapter.epochStakeReader();

    try std.testing.expectEqual(246, reader.totalStake());
    try std.testing.expectEqual(123, reader.stakeForVoteAccount(vote_pubkey));
    try std.testing.expectEqual(123, reader.stakeForVoteAccount(other_vote_pubkey));
    try std.testing.expectEqual(
        0,
        reader.stakeForVoteAccount(Pubkey.initRandom(prng.random())),
    );
}
