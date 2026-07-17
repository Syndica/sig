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
//!
//! TODO: Agave processes ALT descriptors in transaction order and retrn immedately on the first error (on first
//! descriptor that fails). Sig v1 does the same, Firedancer interpreter does the same (one table at a time, in order, and returns on first error).
const std = @import("std");
const lib = @import("../lib.zig");

const alt = lib.solana.account_lookup_table;

const VersionedTransaction = lib.solana.transaction.VersionedTransaction;
const Pubkey = lib.solana.Pubkey;

const AccountLookups = lib.accounts_db.AccountLookups;
const AccountPool = lib.accounts_db.AccountPool;

/// Maximum number of submitted transactions whose completions have not yet
/// been consumed.
///
/// This is also the range encoded by the pending index in future Rooted lookup
/// request user-data.
pub const MAX_PENDING_TRANSACTIONS: usize = AccountLookups.capacity;

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

    pending_queue: [MAX_PENDING_TRANSACTIONS]PendingTransaction,

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

            .pending_queue = @splat(.empty()),
            .pending_head = 0,
            .pending_count = 0,
        };
    }

    /// Queues one transaction for ALT resolution.
    ///
    /// This function does not perform account reads. The caller is expected to call `poll()`
    /// to drive the resolution process.
    ///
    /// Until the corresponding completion is popped via `popCompleted()`:
    /// - `tx_ref` must remain allocated in `TransactionPool`;
    /// - `block_ref` and its ancestor chain must remain allocated in `BlockPool`
    ///   (walked by `Unrooted.fetch` on every poll);
    /// - `bank_context.slot_hashes` storage AND contents must remain unchanged
    ///   (`containsSlot()` re-reads it on every poll).
    ///
    /// The bank's `current_slot` must equal the slot of `block_ref` in `BlockPool`;
    /// otherwise same-slot extension and deactivation checks silently use the
    /// wrong slot.
    ///
    /// TODO: The resolver should retain a bank/fork context reference rather than
    /// borrowing unrelated slices and pool IDs independently.
    pub fn submit(
        self: *AccountResolver,
        block_ref: lib.replay.BlockRef,
        tx_ref: lib.replay.TransactionPool.ItemId,
        bank_context: BankContext,
    ) SubmitError!void {
        if (self.pending_count == self.pending_queue.len) {
            @branchHint(.unlikely);
            return error.Full;
        }

        // Blocks older than the bootstrap root have `null` here and should not
        // be submitted for resolution.
        const block_slot = block_ref.constPtr(self.block_pool).slot.opt() orelse
            unreachable;
        std.debug.assert(block_slot == bank_context.current_slot);

        const pending_index =
            (self.pending_head + self.pending_count) % self.pending_queue.len;

        const pending = &self.pending_queue[pending_index];
        std.debug.assert(pending.status == .free);

        const gen = nextGeneration(pending.gen);

        const transaction_record = tx_ref.constPtr(self.transaction_pool);
        const transaction = transaction_record.view();
        const has_lookups = transaction.hasAddressTableLookups();

        pending.* = .{
            .gen = gen,
            .status = if (has_lookups) .resolving else .complete,
            .bank_context = bank_context,
            .next_lookup_index = 0,
            .in_flight_lookups = 0,
            .failure = null,
            .completion = .{
                .transaction = .{
                    .block_ref = block_ref,
                    .tx_ref = tx_ref,

                    // For transactions without ALTs, the valid dynamic slices both have length 0
                    // so this remains intentionnally uninitialized.
                    // TODO: do we want a safer way to represent this in the future?
                    .dynamic_addresses = undefined,
                },
                // TODO: need a pending result variant.
                .result = undefined,
            },
        };

        // TODO: if the transaction has no lookups we should skip the resolver entirely.
        if (!has_lookups) {
            std.debug.assert(transaction.loadedAddressCount() == 0);
            pending.completion.result = .{ .resolved = {} };
        }

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
    pub fn peekCompleted(self: *const AccountResolver) ?*const Completion {
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
        // Note: we use u8 here, but this must be larger if `MAX_PENDING_TRANSACTIONS` is increased beyond 256.
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

        /// Lowest-indexed failed lookup observer so far.
        failure: ?LookupFailure,

        /// Holds both the working output buffer and eventual public completion.
        completion: Completion = undefined,

        pub const Status = enum(u2) {
            free,
            /// More lookup descrriptors to submit.
            resolving,
            /// Resolution failed, but Rooted results still need to be drained and their AccountRefs released.
            draining_after_failure,
            /// Terminal result is available. This entry will be freed once the caller invokes `popCompleted()`
            complete,
        };

        const LookupFailure = struct {
            lookup_index: u8,
            err: ResolveError,
        };

        pub inline fn reset(self: *PendingTransaction) void {
            // Preserve the generation across re-use.
            const gen = self.gen;
            self.* = PendingTransaction.empty();
            self.gen = gen;
        }

        pub fn empty() PendingTransaction {
            return PendingTransaction{
                .gen = 0,
                .status = .free,
                .bank_context = BankContext{
                    .current_slot = 0,
                    .slot_hashes = &.{},
                },
                .next_lookup_index = 0,
                .in_flight_lookups = 0,
                .failure = null,
                .completion = undefined,
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

    // TODO: we should be able to track these up front and not have to perform this every time we get a response from Rooted.
    fn lookupAt(
        transaction: VersionedTransaction.View,
        target_index: u8,
    ) LookupPosition {
        std.debug.assert(
            target_index < transaction.layout.address_table_lookup_count,
        );

        var writable_offset: usize = 0;
        var readonly_offset: usize = 0;
        var iter = transaction.addressTableLookups();

        for (0..target_index + 1) |i| {
            const lookup = iter.next() catch unreachable orelse unreachable;

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

    pub fn poll(self: *AccountResolver) bool {
        const drained = self.drainRootedResults();
        const driven = self.drivePendingLookups();
        return drained or driven;
    }

    fn drainRootedResults(self: *AccountResolver) bool {
        var reader = self.account_lookups.out.get(.reader);
        var consumed: usize = 0;

        while (reader.next()) |result| {
            consumed += 1;
            self.processRootedResult(result.*);
        }

        if (consumed != 0) {
            reader.markUsed();
            return true;
        }

        return false;
    }

    fn drivePendingLookups(self: *AccountResolver) bool {
        // TODO: store writer on AccountResolver struct.
        var writer = self.account_lookups.in.get(.writer);

        var made_progress = false;
        var submitted_count: usize = 0;
        var rooted_queue_full = false;

        defer if (submitted_count != 0) writer.markUsed();

        for (0..self.pending_count) |i| {
            const pending_index = (self.pending_head + i) % self.pending_queue.len;
            const pending = &self.pending_queue[pending_index];

            if (pending.status != .resolving)
                continue;

            const transaction = pending.completion.transaction
                .tx_ref
                .constPtr(self.transaction_pool)
                .view();

            while (pending.status == .resolving and
                pending.next_lookup_index <
                    transaction.layout.address_table_lookup_count)
            {
                const lookup_index = pending.next_lookup_index;
                const position = lookupAt(transaction, lookup_index);

                // Check Unrooted first.
                const account_ref = self.unrooted.fetch(
                    position.lookup.account_key,
                    pending.completion.transaction.block_ref,
                    self.block_pool,
                    self.account_pool,
                );

                if (account_ref != .invalid) {
                    // This descriptor has now been consumed, regardless of
                    // whether semantic resolution succeeds.
                    pending.next_lookup_index += 1;

                    {
                        defer self.releaseAccount(account_ref);

                        self.resolveLookupAccount(
                            pending,
                            lookup_index,
                            account_ref,
                        ) catch |err| {
                            recordLookupFailure(
                                pending,
                                lookup_index,
                                err,
                            );
                        };
                    }

                    // This is always true because we just consumed a descriptor, but it makes the intent clearer.
                    // TODO: Maybe re-write this a bit
                    made_progress = true;
                    const completed = self.maybeCompletePending(pending);
                    made_progress = completed or made_progress;

                    continue;
                }

                // Once the Rooted ring is full, later transactions can still make
                // progress through Unrooted hits, but no more Rooted misses can
                // be submitted during this poll.
                // TODO: perhaps we want to limit batch sizes to limit poll times?
                if (rooted_queue_full)
                    break;

                const request = writer.next() orelse {
                    rooted_queue_full = true;
                    break;
                };

                const ticket: LookupTicket = .{
                    .pending_index = @intCast(pending_index),
                    .lookup_index = lookup_index,
                    .generation = pending.gen,
                };

                request.* = .{
                    .req_user_data = @bitCast(ticket),
                    .pubkey = position.lookup.account_key.*,
                };

                // Update correlation state before markUsed() publishes the request.
                pending.next_lookup_index += 1;
                pending.in_flight_lookups += 1;

                submitted_count += 1;
                made_progress = true;
            }

            made_progress =
                self.maybeCompletePending(pending) or
                made_progress;
        }

        return made_progress;
    }

    fn processRootedResult(
        self: *AccountResolver,
        result: AccountLookups.Result,
    ) void {
        const ticket: LookupTicket = @bitCast(result.req_user_data);
        const pending_index: usize = ticket.pending_index;

        if (pending_index >= self.pending_queue.len) {
            self.releaseAccount(result.account_index);
            return;
        }

        const pending = &self.pending_queue[pending_index];

        // A stale response belongs to a previous use of this queue position.
        if (pending.gen != ticket.generation or
            pending.status == .free or
            pending.status == .complete)
        {
            self.releaseAccount(result.account_index);
            return;
        }

        const transaction = pending.completion.transaction
            .tx_ref
            .constPtr(self.transaction_pool)
            .view();

        // The ticket was created internally from a submitted descriptor.
        std.debug.assert(
            ticket.lookup_index < pending.next_lookup_index,
        );
        std.debug.assert(
            ticket.lookup_index <
                transaction.layout.address_table_lookup_count,
        );

        // TODO: look into removing this somehow.
        const position = lookupAt(transaction, ticket.lookup_index);

        // NOTE: Rooted must echo the request pubkey unchanged. Firedancer treats a
        // mismatch between the expected table and supplied table as an internal
        // invariant violation rather than a transaction error.
        // TODO: Perhaps make this a runtime check?
        std.debug.assert(
            result.pubkey.equals(position.lookup.account_key),
        );

        std.debug.assert(pending.in_flight_lookups > 0);
        pending.in_flight_lookups -= 1;

        defer self.releaseAccount(result.account_index);
        defer _ = self.maybeCompletePending(pending);

        // If a lower-index failure is already known, this response cannot affect
        // the final result. It still has to be consumed and released.
        if (pending.failure) |failure| {
            if (ticket.lookup_index >= failure.lookup_index)
                return;
        }

        // TODO: re-write this bit
        const maybe_error: ?ResolveError =
            if (result.account_index == .invalid)
                error.LookupTableNotFound
            else blk: {
                self.resolveLookupAccount(
                    pending,
                    ticket.lookup_index,
                    result.account_index,
                ) catch |err| break :blk err;

                break :blk null;
            };

        if (maybe_error) |err| {
            recordLookupFailure(
                pending,
                ticket.lookup_index,
                err,
            );
        }
    }

    fn resolveLookupAccount(
        self: *AccountResolver,
        pending: *PendingTransaction,
        lookup_index: u8,
        account_ref: AccountPool.AccountRef,
    ) ResolveError!void {
        std.debug.assert(account_ref != .invalid);

        const resolved = &pending.completion.transaction;
        const transaction = resolved.tx_ref
            .constPtr(self.transaction_pool)
            .view();

        const position = lookupAt(transaction, lookup_index);
        const account = self.account_pool.getAccount(account_ref);

        // The storage lookup and ticket must identify the same table.
        std.debug.assert(
            account.pubkey.equals(position.lookup.account_key),
        );

        // Zero-lamport values are tombstones and shadow older Rooted versions.
        // Do not fall back to Rooted after finding one in Unrooted.
        if (account.lamports == 0)
            return error.LookupTableNotFound;

        const table = try decodeLookupTableAccount(
            &account.owner,
            account.getData(),
        );

        const writable_len = position.lookup.writable_indexes.len;
        const readonly_len = position.lookup.readonly_indexes.len;

        const loaded_writable_count: usize =
            transaction.layout.loaded_writable_count;

        const writable_start = position.writable_offset;
        const readonly_start =
            loaded_writable_count + position.readonly_offset;

        std.debug.assert(writable_start + writable_len <= loaded_writable_count);
        std.debug.assert(
            readonly_start + readonly_len <=
                transaction.loadedAddressCount(),
        );

        const writable_out =
            resolved.dynamic_addresses[writable_start..][0..writable_len];

        const readonly_out =
            resolved.dynamic_addresses[readonly_start..][0..readonly_len];

        const deactivation_slot_is_recent =
            pending.bank_context.containsSlot(
                table.meta.deactivation_slot,
            );

        try resolveTableLookup(
            table,
            position.lookup,
            pending.bank_context.current_slot,
            deactivation_slot_is_recent,
            writable_out,
            readonly_out,
        );
    }

    fn recordLookupFailure(
        pending: *PendingTransaction,
        lookup_index: u8,
        err: ResolveError,
    ) void {
        // NOTE: We track the lowest-index failure we've seen so far. This is to match
        // expected validator behavior.
        //
        // TODO: consider moving to linked-submissions strat where we batch submit all requests to rooted,
        // which uses io_uring linked ops to processes all lookups in order, erroring on the first it sees.
        if (pending.failure) |current| {
            if (lookup_index < current.lookup_index) {
                pending.failure = .{
                    .lookup_index = lookup_index,
                    .err = err,
                };
            }
        } else {
            pending.failure = .{
                .lookup_index = lookup_index,
                .err = err,
            };
        }

        pending.status = .draining_after_failure;
    }

    fn maybeCompletePending(
        self: *AccountResolver,
        pending: *PendingTransaction,
    ) bool {
        if (pending.in_flight_lookups != 0)
            return false;

        if (pending.failure) |failure| {
            std.debug.assert(pending.status == .draining_after_failure);

            pending.completion.result = .{ .failed = failure.err };
            pending.status = .complete;
            return true;
        }

        if (pending.status != .resolving)
            return false;

        const transaction = pending.completion.transaction
            .tx_ref
            .constPtr(self.transaction_pool)
            .view();

        // Some descriptors have not yet been submitted because the Rooted request
        // ring was full.
        if (pending.next_lookup_index !=
            transaction.layout.address_table_lookup_count)
        {
            return false;
        }

        // TODO: need to validate this.
        // TODO: document/link to agave/fd.
        validateNoDuplicateAccounts(
            transaction,
            &pending.completion.transaction,
        ) catch |err| {
            pending.completion.result = .{ .failed = err };
            pending.status = .complete;
            return true;
        };

        pending.completion.result = .{ .resolved = {} };
        pending.status = .complete;
        return true;
    }

    // TODO: gotta validate this. Agave uses HashSet, fd has it's own impl. We should do something custom here in the future.
    // Note: document that agave performs this check after lookups.
    fn validateNoDuplicateAccounts(
        transaction: VersionedTransaction.View,
        resolved: *const ResolvedTransaction,
    ) error{AccountLoadedTwice}!void {
        const static_keys = transaction.staticAccountKeys();
        const dynamic_keys = resolved.dynamic_addresses[0..transaction.loadedAddressCount()];

        for (static_keys, 0..) |*key, i| {
            for (static_keys[i + 1 ..]) |*other| {
                if (key.equals(other)) return error.AccountLoadedTwice;
            }

            for (dynamic_keys) |*other| {
                if (key.equals(other)) return error.AccountLoadedTwice;
            }
        }

        for (dynamic_keys, 0..) |*key, i| {
            for (dynamic_keys[i + 1 ..]) |*other| {
                if (key.equals(other)) return error.AccountLoadedTwice;
            }
        }
    }

    fn releaseAccount(
        self: *AccountResolver,
        account_ref: AccountPool.AccountRef,
    ) void {
        if (account_ref == .invalid)
            return;

        const account = self.account_pool.getAccount(account_ref);
        if (account.unref())
            self.account_pool.free(account_ref);
    }
};

pub const LookupError = error{
    LookupTableNotFound,
    InvalidLookupTableOwner,
    InvalidLookupTableData,
    InvalidLookupTableIndex,
};

pub const ResolveError = LookupError || error{AccountLoadedTwice};

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
