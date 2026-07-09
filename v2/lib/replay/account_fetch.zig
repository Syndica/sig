const lib = @import("../lib.zig");

const replay = lib.replay;
const accounts_db = lib.accounts_db;

const AccountPool = accounts_db.AccountPool;
const AccountRef = AccountPool.AccountRef;
const AccountLookups = accounts_db.AccountLookups;

const Unrooted = accounts_db.Unrooted;

pub const AccountFetch = struct {
    account_pool: *AccountPool,
    account_lookups: *AccountLookups,
    block_pool: *replay.BlockPool,
    unrooted: *accounts_db.Unrooted,

    pub const InitParams = struct {
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        block_pool: *replay.BlockPool,
        unrooted: *accounts_db.Unrooted,
    };

    pub fn init(params: InitParams) AccountFetch {
        return .{
            .account_pool = params.account_pool,
            .account_lookups = params.account_lookups,
            .block_pool = params.block_pool,
            .unrooted = params.unrooted,
        };
    }

    // TODO: in the future we would like to have a submitTransactionBatch method to
    // resolve a batch of transactions at once. A scheduler can take advantage of this to
    // resolve multiple transactions in parallel (but in the order they are in the batch),
    // specifically when the batch of transactions are non-conflicting with other batches.
    pub fn submitTransaction(
        self: *AccountFetch,
        block_ref: replay.BlockRef,
        tx_ref: replay.TransactionPool.ItemId,
        tx_bytes: []const u8,
    ) !void {
        _ = .{ self, block_ref, tx_ref, tx_bytes };
        @panic("AccountFetch.submitTransaction not implemented");
    }
};
