const lib = @import("../lib.zig");

const replay = lib.replay;
const accounts_db = lib.accounts_db;

const AccountPool = accounts_db.AccountPool;
const AccountRef = AccountPool.AccountRef;
const AccountLookups = accounts_db.AccountLookups;

const Unrooted = accounts_db.Unrooted;

/// Maximum number of accounts a transaction may load for execution.
/// TODO: citation needed, but should have something to do with that feature gate that raised this from 64.
pub const MAX_TX_ACCOUNTS = 128;

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

        // TODO: decode VersionedTransaction
        // TODO: extract static account_keys
        // TODO: for each key, fetch from unrooted, otherwise do the rooted lookup.
        // TODO: store pending state (if any)
    }

    pub fn poll(self: *AccountFetch) !void {
        _ = self;
        @panic("AccountFetch.poll not implemented");
    }

    pub fn nextCompletedTransaction(self: *AccountFetch) ?LoadedTransaction {
        _ = self;
        @panic("AccountFetch.nextCompletedTransaction not implemented");
    }
};

/// Result of resolving all accounts required to execute a submitted transaction.
pub const LoadedTransaction = extern struct {
    /// Block context for the submitted transaction. Used for ancestor walk in `Unrooted` and
    /// lets replay/exec associate the completed load result with the correct block.
    block_ref: replay.BlockRef,

    /// Reference to the transation bytes in `TransactionPool`.
    tx_ref: replay.TransactionPool.ItemId,

    /// The number of valid entries in `account_refs`.
    ///
    /// NOTE: For `status == .ready`, this is the full account count required
    /// by the transaction (including accounts loaded from ALTs).
    n_accounts: u8,

    /// The status of the account fetch operation.
    status: Status,

    // TODO: do we want explicit padding here due to this being an extern struct?

    /// Resolved account references for VM execution.
    ///
    /// NOTE: Valid entries are stored in `account_refs[0..n_accounts]` and are ordered
    /// as the transaction expects: static message accounts first, followed by any
    /// accounts loaded through address lookup tables.
    account_refs: [MAX_TX_ACCOUNTS]AccountRef,

    pub const Status = enum(u8) {
        ready,
        missing_account,
        invalid_alt,
        too_many_accounts,
        decode_error,
    };
};
