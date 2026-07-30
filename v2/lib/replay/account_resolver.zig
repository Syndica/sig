const std = @import("std");
const lib = @import("../lib.zig");

const Unrooted = lib.replay.Unrooted;
const AccountPool = lib.accounts_db.AccountPool;
const AccountLookups = lib.accounts_db.AccountLookups;
const BlockPool = lib.replay.BlockPool;
const BlockRef = lib.replay.BlockRef;
const TransactionPool = lib.replay.TransactionPool;
const VersionedTransaction = lib.replay.VersionedTransaction;

const TransactionRef = lib.replay.TransactionRef;

const account_fetcher = @import("account_fetcher.zig");

const AccountFetcher = account_fetcher.AccountFetcher;

pub const AccountResolver = struct {
    fetcher: AccountFetcher,

    pub fn init(
        allocator: std.mem.Allocator,
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        unrooted: *Unrooted,
        block_pool: *BlockPool,
    ) AccountResolver {
        return AccountResolver{
            .fetcher = AccountFetcher.init(
                allocator,
                account_pool,
                account_lookups,
                unrooted,
                block_pool,
            ),
        };
    }

    pub fn resolve(self: *AccountResolver, block_ref: BlockRef, tx: VersionedTransaction.View) void {

    };

    pub fn pollResolvedTransactions() void {};

};
