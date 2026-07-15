//! TODO: Not sure on where/which component with eventually "own" AccountFetch. For now, this was put together to be
//! a drop in replacement for the existing blocking fetch for accounts being done in replay. We'll likely have an AccountFetch
//! per exec-service, capable of handling batches of transactions, and cacheing accounts (?).
//!
//! TODO: Program cache/read-only accounts need to live somewhere. It would be nice of all accounts
//! involved for executing any and all transactions live in the same one place (here?).
//!
//! TODO: in the future we would like to have a submitTransactionBatch method to
//! resolve a batch of transactions at once. A scheduler can take advantage of this to
//! resolve multiple transactions in parallel (but in the order they are in the batch),
//! specifically when the batch of transactions are non-conflicting with other batches.
//! Each non-conflicting batch can also be executed in parallel. So maybe we want an AccountFetch-per-exec service?
const std = @import("std");
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

/// TODO: citations for each check done in this method + unit tests.
fn resolveTableLookup(
    table_account: *const lib.accounts_db.AccountPool.Account,
    lookup: VersionedTransaction.View.AddressTableLookupIter.Item,
    current_slot: lib.solana.Slot,
    deactivation_slot_is_recent: bool,
    writable_out: []Pubkey,
    readonly_out: []Pubkey,
) ResolveError!void {
    if (!table_account.owner.equals(
        &lib.solana.address_lookup_table.PROGRAM_ID,
    )) {
        return error.InvalidLookupTableOwner;
    }

    const table = lib.solana.address_lookup_table.AddressLookupTable.deserialize(
        table_account.getData(),
    ) catch return error.InvalidLookupTableData;

    const meta = table.meta;

    const active = meta.deactivation_slot == std.math.maxInt(lib.solana.Slot) or
        meta.deactivation_slot == current_slot or
        deactivation_slot_is_recent;

    if (!active) return error.DeactivatedLookupTable;

    const active_len: usize = if (current_slot > meta.last_extended_slot)
        table.addresses.len
    else
        meta.last_extended_slot_start_index;

    if (active_len > table.addresses.len)
        return error.InvalidLookupTableData;

    if (writable_out.len != lookup.writable_indexes.len or
        readonly_out.len != lookup.readonly_indexes.len)
    {
        unreachable;
    }

    for (lookup.writable_indexes, writable_out) |index, *address| {
        if (index >= active_len)
            return error.InvalidLookupTableIndex;

        address.* = table.addresses[index];
    }

    for (lookup.readonly_indexes, readonly_out) |index, *address| {
        if (index >= active_len)
            return error.InvalidLookupTableIndex;

        address.* = table.addresses[index];
    }
}
