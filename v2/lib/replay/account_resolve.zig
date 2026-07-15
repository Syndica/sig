const lib = @import("../lib.zig");

const VersionedTransaction = lib.solana.transaction.VersionedTransaction;
const Pubkey = lib.solana.Pubkey;

pub const ResolveError = error{
    LookupTableNotFound,
    InvalidLookupTableOwner,
    InvalidLookupTableData,
    InvalidLookupTableIndex,
    DeactivatedLookupTable,
    AccountLoadedTwice,
};

pub const ResolvedTransaction = struct {
    block_ref: lib.replay.BlockRef,
    tx_ref: lib.replay.TransactionPool.ItemId,

    /// Writable addresses first, followed by readonly addresses.
    dynamic_addresses: [
        VersionedTransaction.MAX_ACCOUNT_ADDRESSES
    ]Pubkey,

    pub fn writableAddresses(
        self: *const ResolvedTransaction,
        transaction_pool: *const lib.replay.TransactionPool,
    ) []const Pubkey {
        const tx = self.tx_ref.constPtr(transaction_pool);
        const count: usize = tx.layout.loaded_writable_count;
        return self.dynamic_addresses[0..count];
    }

    pub fn readonlyAddresses(
        self: *const ResolvedTransaction,
        transaction_pool: *const lib.replay.TransactionPool,
    ) []const Pubkey {
        const tx = self.tx_ref.constPtr(transaction_pool);
        const writable_count: usize = tx.layout.loaded_writable_count;
        const readonly_count: usize = tx.layout.loaded_readonly_count;

        return self.dynamic_addresses[writable_count..][0..readonly_count];
    }
};
