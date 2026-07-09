const std = @import("std");

const lib = @import("../lib.zig");

const replay = lib.replay;
const accounts_db = lib.accounts_db;

const bincode = lib.solana.bincode;

const VersionedTransaction = lib.solana.transaction.VersionedTransaction;

const AccountPool = accounts_db.AccountPool;
const AccountRef = AccountPool.AccountRef;
const AccountLookups = accounts_db.AccountLookups;

const Unrooted = accounts_db.Unrooted;

/// Maximum number of accounts a transaction may load for execution.
/// TODO: citation needed, but should have something to do with that feature gate that raised this from 64.
pub const MAX_TX_ACCOUNTS = 128;

/// Maximum number of transactions that `AccountFetch` queues for resolution at any given time.
pub const MAX_PENDING_TXS = 256;


/// TODO: Not sure on where/which component with eventually "own" AccountFetch. For now, this was put together to be 
/// a drop in replacement for the existing blocking fetch for accounts being done in replay. We'll likely have an AccountFetch 
/// per exec-service, capable of handling batches of transactions, and cacheing accounts (?).
/// 
/// TODO: Program cache/read-only accounts need to live somewhere. It would be nice of all accounts 
/// involved for executing any and all transactions live in the same one place (here?).
/// 
/// TODO: in the future we would like to have a submitTransactionBatch method to
/// resolve a batch of transactions at once. A scheduler can take advantage of this to
/// resolve multiple transactions in parallel (but in the order they are in the batch),
/// specifically when the batch of transactions are non-conflicting with other batches.
/// Each non-conflicting batch can also be executed in parallel. So maybe we want an AccountFetch-per-exec service?
pub const AccountFetch = struct {
    account_pool: *AccountPool,
    account_lookups: *AccountLookups,
    block_pool: *replay.BlockPool,
    transaction_pool: *replay.TransactionPool,
    unrooted: *accounts_db.Unrooted,

    pending: [MAX_PENDING_TXS]PendingTransaction = @splat(PendingTransaction.empty()),
    pending_len: usize = 0,
    pending_tail: usize = 0,

    pub const Error = enum {
        /// The pending transaction queue is full and cannot accept new transactions.
        account_fetch_queue_full,
    };

    pub const InitParams = struct {
        account_pool: *AccountPool,
        account_lookups: *AccountLookups,
        block_pool: *replay.BlockPool,
        transaction_pool: *replay.TransactionPool,
        unrooted: *accounts_db.Unrooted,
    };

    pub fn init(params: InitParams) AccountFetch {
        return .{
            .account_pool = params.account_pool,
            .account_lookups = params.account_lookups,
            .block_pool = params.block_pool,
            .transaction_pool = params.transaction_pool,
            .unrooted = params.unrooted,

            .pending = @splat(PendingTransaction.empty()),
            .pending_len = 0,
            .pending_tail = 0,
        };
    }


    /// Submit a transaction by a stale tx_ref only. Reads transaction bytes from the TransactionPool.
    ///
    /// TODO: Double-check/make the TransactionPool thread-safe. It would be nice if a deserialized 
    /// transaction could be stored in the pool once, being made visible to all (participating) threads/services, 
    /// allowing for full zero-copy handling. For now, this function is written with the assumption that 
    /// this is indeed the case.
    pub fn submitTransaction(
        self: *AccountFetch,
        block_ref: replay.BlockRef,
        tx_ref: replay.TransactionPool.ItemId,
    ) Error!void {
        const pending_idx = try self.reservePending(block_ref, tx_ref);
        const pending_tx = self.getPendingMut(pending_idx);

        pending_tx.loaded.status = .loading;

        const tx_bytes: []const u8 = self.transaction_pool.indexToConstPtr(tx_ref);

        // TODO: walk the transaction bytes to iterate over static accounts 
        // and resolve them.

    };

    /// Reserves an entry in the pending transaction queue for a new transaction to be resolved.
    /// Returns the index of the reserved entry in the pending queue.
    fn reservePending(
        self: *AccountFetch,
        block_ref: replay.BlockRef,
        tx_ref: replay.TransactionPool.ItemId,
    ) Error!usize {
        // TODO: do we want to block instead?
        if (self.pending_len == MAX_PENDING_TXS) return Error.account_fetch_queue_full;

        // TODO: worth consolidating pending_tail and pending_len?
        const idx = self.pending_len;
        self.pending_tail = (self.pending_tail + 1) % MAX_PENDING_TXS;
        self.pending_len += 1;

        self.pending[idx] = .{
            .seq = self.next_submit_seq,
            .block_ref = block_ref,
            .tx_ref = tx_ref,
        };
        self.next_submit_seq += 1;

        return idx;
    }

    fn getPendingRef(self: *const AccountFetch, idx: usize) *const PendingTransaction {
        return &self.pending[idx];
    }

    fn getPendingMut(self: *AccountFetch, idx: usize) *PendingTransaction {
        return &self.pending[idx];
    }

    pub fn poll(self: *AccountFetch) !void {
        _ = self;
        @panic("AccountFetch.poll not implemented");
    }

    // TODO: Avoid the copy being made here to return LoadedTransaction.
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
        empty,
        ready,
        missing_account,
        invalid_alt,
        too_many_accounts,
        decode_error,
    };

    pub fn empty() LoadedTransaction {
        return .{
            .block_ref = .null,
            .tx_ref = .null,
            .n_accounts = 0,
            .status = .empty,
            .reserved = 0,
            .account_refs = undefined,
        };
    }
};

pub const PendingTransaction = extern struct {
    loaded: LoadedTransaction = .empty(),
    seq: u64 = 0,
    pending_reads: u16 = 0,
    completed: bool = false,

    pub fn empty() PendingTransaction {
        return .{
            .loaded = LoadedTransaction.empty(),
            .seq = 0,
            .pending_reads = 0,
            .completed = false,
        };
    }
};
