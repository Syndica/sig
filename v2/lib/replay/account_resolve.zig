//! TODO: Not sure on where/which component with eventually "own" AccountResolver. For now, this was put together to be
//! a drop in replacement for the existing blocking fetch for accounts being done in replay. We'll likely have an AccountResolver
//! per exec-service, capable of handling batches of transactions, and cacheing accounts (?).
//!
//! TODO: Program cache/read-only accounts need to live somewhere. It would be nice of all accounts
//! involved for executing any and all transactions live in the same one place (here?).
//!
//! TODO: in the future we would like to have a submitTransactionBatch method to
//! resolve a batch of transactions at once. A scheduler can take advantage of this to
//! resolve multiple transactions in parallel (but in the order they are in the batch),
//! specifically when the batch of transactions are non-conflicting with other batches.
//! Each non-conflicting batch can also be executed in parallel. So maybe we want an AccountResolver-per-exec service?
const std = @import("std");
const lib = @import("../lib.zig");

const alt = lib.solana.account_lookup_table;

const VersionedTransaction = lib.solana.transaction.VersionedTransaction;
const Pubkey = lib.solana.Pubkey;

const AccountLookups = lib.accounts_db.AccountLookups;

/// Maximum number of submitted transactions whose completions have not yet
/// been consumed.
///
/// This is also the range encoded by the pending index in future Rooted lookup
/// request user-data.
pub const MAX_PENDING_TRANSACTIONS: usize = 256;

pub const AccountResolver = struct {
    account_pool: *lib.accounts_db.AccountPool,
    account_lookups: *AccountLookups,
    block_pool: *lib.replay.BlockPool,
    transaction_pool: *lib.replay.TransactionPool,
    unrooted: *lib.accounts_db.Unrooted,

    // TODO: maybe we want a monotonically increasing id for each submission. This should let
    // us track out of order completions better, allowing us to report resolved transactions to the caller
    // even if they are not in submission order. This would be useful for a scheduler that wants
    // to execute non-conflicting transactions in parallel.

    pending_queue: [lib.accounts_db.AccountLookups.capacity]PendingTransaction,

    /// Index of the oldest submitted, unconsumed transaction in `pending`.
    pending_head: usize,

    /// Includes resolving entries and completed entries that are not yet popped.
    pending_count: usize,

    pub const InitParams = struct {
        account_pool: *lib.accounts_db.AccountPool,
        account_lookups: *AccountLookups,
        block_pool: *lib.replay.BlockPool,
        transaction_pool: *lib.replay.TransactionPool,
        unrooted: *lib.accounts_db.Unrooted,
    };

    pub const SubmitError = error{Full};

    pub fn init(params: InitParams) AccountResolver {
        return AccountResolver{
            .account_pool = params.account_pool,
            .account_lookups = params.account_lookups,
            .block_pool = params.block_pool,
            .transaction_pool = params.transaction_pool,
            .unrooted = params.unrooted,

            .pending_queue = @splat(.{}),
            .pending_head = 0,
            .pending_count = 0,
        };
    }

    /// Queues one transaction for ALT resolution.
    ///
    /// This function does not perform account reads. The caller is expected to call `poll()`
    /// to drive the resolution process.
    ///
    /// The caller must keep `tx_ref` alive in TransactionPool until the corresponding
    /// completion is popped via `popCompleted()`.
    pub fn submit(
        self: *AccountResolver,
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        // TODO: find a way to remove this.
        bank_context: BankContext,
    ) SubmitError!void {
        if (self.pending_count == self.pending_queue.len) {
            @branchHint(.unlikely);
            return error.Full;
        }

        const pending_index =
            (self.pending_head + self.pending_count) % self.pending_queue.len;

        const pending = &self.pending_queue[pending_index];
        std.debug.assert(pending.status == .free);

        const gen = nextGeneration(pending.gen);

        const transaction_record = tx_ref.constPtr(self.transaction_pool);
        const transaction = transaction_record.view();
        const has_lookups = transaction.hasAddressTableLookups();

        // TODO: if the transaction has no lookups we should skip the resolver entirely.
        if (!has_lookups) {
            std.debug.assert(transaction.loadedAddressCount() == 0);
        }

        pending.* = .{
            .gen = gen,
            .state = if (has_lookups) .resolving else .complete,
            .bank_context = bank_context,
            .next_lookup_index = 0,
            .in_flight_lookups = 0,
            .completion = .{
                .transaction = .{
                    .block_ref = block_ref,
                    .tx_ref = tx_ref,

                    // For transactions without ALTs, the valid dynamic slices both have length 0
                    // so this remains intentionnally uninitialized.
                    // TODO: do we want a safer way to represent this in the future?
                    .dynamic_addresses = undefined,
                },
            },
        };

        self.pending_count += 1;
    }

    /// Returns a pointer to the oldest submitted completion, preserving submission order.
    ///
    /// A later transaction may already be complete internally, but it remains
    /// hidden while an earlier transaction is unresolved.
    ///
    /// The returned pointer remains valid until popCompleted() is called.
    ///
    /// TODO: we should return a batch of completions instead of one at a time.
    pub fn peekCompleted(self: *AccountResolver) ?*const Completion {
        if (self.pending_count == 0) return null;

        const pending = &self.pending_queue[self.pending_head];
        std.debug.assert(pending.status != .free);

        if (pending.status != .complete) return null;

        return &pending.completion;
    }

    /// Consumes the completion returned by peekCompleted()
    ///
    /// This invalidates any pointer previously return for that completion.
    /// It does not destroy the TrnsactionPool.ItemId, ownership of `tx_ref` remains with the caller.
    pub fn popCompleted(self: *AccountResolver) void {
        std.debug.assert(self.pending_count > 0);

        const pending = &self.pending_queue[self.pending_head];
        std.debug.assert(pending.status == .complete);
        std.debug.assert(pending.in_flight_lookups == 0);

        pending.reset();

        self.pending_head = (self.pending_head + 1) % self.pending_queue.len;
        self.pending_count -= 1;
    }

    const LookupTicket = packed struct(u32) {
        pending_index: u8,
        lookup_index: u8,
        generation: u16,
    };

    /// Terminal result exposed to the caller.
    pub const Completion = struct {
        transaction: ResolvedTransaction,
        result: Result,

        pub const Result = union(enum) {
            resolved: void,
            failed: ResolveError,
        };
    };

    const PendingTransaction = struct {
        /// Incremented whenever this array position is reused.
        ///
        /// Rooted response tickets will carry this generation so stale responses
        /// cannot be associated with a newly submitted transaction.
        gen: u16,

        status: Status = .free,

        // TODO: can we remove this? why can't pending share the same slice?
        // TODO: look into how the bank info for ALT validity is stored in v1.
        bank_context: BankContext,

        /// First ALT descriptor which has not yet been submitted or processed.
        next_lookup_index: u8,

        /// Number of Rooted requests submitted but not yet resolved.
        in_flight_lookups: u8,

        /// Holds both the working output buffer and eventual public completion.
        completion: Completion = undefined,

        resolved: ResolvedTransaction = undefined,

        pub const Status = enum(u2) {
            free,
            /// More lookup descrriptors to submit.
            resolving,
            /// Resolution failed, but Rooted results still need to be drained and their AccountRefs released.
            draining_after_failure,
            /// Terminal result is available. This entry will be freed once the caller invokes `popCompleted()`
            complete,
        };

        pub fn reset(self: *PendingTransaction) void {
            // Preserve the generation across re-use.
            const gen = self.gen;
            self.* = .{
                .gen = gen,
            };
        }
    };

    inline fn nextGeneration(current: u16) u16 {
        var next = current +% 1;
        // 0 is reserved for uninitialized PendingTransaction entries, so we skip it.
        if (next == 0) next = 1;
        return next;
    }

    const LookupPosition = struct {
        lookup: VersionedTransaction.View.AddressTableLookupIter.Item,
        writable_offset: usize,
        readonly_offset: usize,
    };

    fn lookupAt(
        transaction: VersionedTransaction.View,
        target_index: u8,
    ) LookupPosition {
        var writable_offset: usize = 0;
        var readonly_offset: usize = 0;
        var iter = transaction.addressTableLookups();

        for (0..target_index + 1) |i| {
            const lookup = iter.next() orelse unreachable;

            if (i == target_index) {
                return LookupPosition{
                    .lookup = lookup,
                    .writable_offset = writable_offset,
                    .readonly_offset = readonly_offset,
                };
            }

            writable_offset += lookup.writable_indexes.len;
            readonly_offset += lookup.readonly_indexes.len;
        }

        unreachable; // target_index is guaranteed to be valid by the caller
    }
};

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

fn decodeLookupTableAccount(
    owner: *const Pubkey,
    data: []const u8,
) ResolveError!alt.AddressLookupTable {
    if (!owner.equals(&alt.ID))
        return error.InvalidLookupTableOwner;

    return alt.AddressLookupTable.deserialize(data) catch
        return error.InvalidLookupTableData;
}

/// TODO: citations for each check done in this method + unit tests.
fn resolveTableLookup(
    table: alt.AddressLookupTable,
    lookup: VersionedTransaction.View.AddressTableLookupIter.Item,
    current_slot: lib.solana.Slot,
    /// True only when `table.meta.deactivation_slot` is in the current
    /// bank's SlotHashes.
    deactivation_slot_is_recent: bool,
    writable_out: []Pubkey,
    readonly_out: []Pubkey,
) ResolveError!void {
    const active =
        table.meta.deactivation_slot == std.math.maxInt(lib.solana.Slot) or
        table.meta.deactivation_slot == current_slot or
        deactivation_slot_is_recent;

    if (!active) {
        @branchHint(.unlikely);
        // NOTE: this is what agave returns
        // TODO: document this.
        return error.LookupTableNotFound;
    }

    const active_len: usize = if (current_slot > table.meta.last_extended_slot)
        table.addresses.len
    else
        table.meta.last_extended_slot_start_index;

    if (active_len > table.addresses.len) {
        @branchHint(.unlikely);
        return error.InvalidLookupTableData;
    }

    std.debug.assert(writable_out.len == lookup.writable_indexes.len);
    std.debug.assert(readonly_out.len == lookup.readonly_indexes.len);

    for (lookup.writable_indexes, writable_out) |index, *address| {
        if (index >= active_len) {
            @branchHint(.unlikely);
            return error.InvalidLookupTableIndex;
        }

        address.* = table.addresses[index];
    }

    for (lookup.readonly_indexes, readonly_out) |index, *address| {
        if (index >= active_len) {
            @branchHint(.unlikely);
            return error.InvalidLookupTableIndex;
        }

        address.* = table.addresses[index];
    }
}

// NOTE: resolver needs the current slot and SlotHahes to determine if a
// deactivated alt remains usable. This should get replaced by something proper.
pub const BankContext = struct {
    current_slot: lib.solana.Slot,
    slot_hashes: []const SlotHash,

    pub const SlotHash = extern struct {
        slot: lib.solana.Slot,
        hash: lib.solana.Hash,
    };

    pub fn containsSlot(self: BankContext, slot: lib.solana.Slot) bool {
        for (self.slot_hashes) |entry| {
            if (entry.slot == slot) return true;
        }
        return false;
    }
};
