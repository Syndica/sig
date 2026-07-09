const lib = @import("../lib.zig");

const replay = lib.replay;
const accounts_db = lib.accounts_db;

const AccountPool = accounts_db.AccountPool;
const AccountRef = AccountPool.AccountRef;
const AccountLookups = accounts_db.AccountLookups;

/// Maximum number of accounts (static + ALT-expanded) per transaction. Matches
/// `ExecRequest.txn_exec.account_ref_buf` so the emitted refs can be copied
/// directly into an exec request.
pub const MAX_TX_ACCOUNTS = 128;

/// The output of `AccountFetch`.
///
/// Ownership: for each `i` in `account_refs[0..n_accounts]`, if `account_refs[i]`
/// is not `.invalid`, the `LoadedTransaction` owns one ref to that account. The
/// consumer must unref/free them once execution completes or the transaction is
/// dropped.
pub const LoadedTransaction = extern struct {
    block_ref: replay.BlockRef,
    tx_ref: replay.TransactionPool.ItemId,
    n_accounts: u8,
    status: Status,
    _pad: [2]u8 = @splat(0),
    /// Same logical order as the transaction's account keys:
    ///   static account keys
    /// + ALT-expanded writable keys (in address_table_lookups order)
    /// + ALT-expanded readonly keys (in address_table_lookups order)
    account_refs: [MAX_TX_ACCOUNTS]AccountRef,

    pub const Status = enum(u8) {
        ready,
        missing_account,
        invalid_alt,
        too_many_accounts,
        decode_error,
    };
};

pub const AccountFetch = struct {
    account_pool: *AccountPool,
    account_lookups: *AccountLookups,
    block_pool: *replay.BlockPool,

    pub const InitParams = struct {
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        block_pool: *replay.BlockPool,
    };

    pub fn init(params: InitParams) AccountFetch {
        return .{
            .account_pool = params.account_pool,
            .account_lookups = params.account_lookups,
            .block_pool = params.block_pool,
        };
    }

    pub fn deinit(self: *AccountFetch) void {
        self.* = undefined;
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
