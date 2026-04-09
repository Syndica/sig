const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const jrpc_types = sig.rpc.jrpc_websockets.types;

const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger("replay.committer");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

const Account = sig.core.Account;
const LoadedAccount = sig.runtime.account_loader.LoadedAccount;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const LogCollector = sig.runtime.LogCollector;
const TransactionStatusMeta = sig.ledger.transaction_status.TransactionStatusMeta;
const TransactionStatusMetaBuilder = sig.ledger.transaction_status.TransactionStatusMetaBuilder;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const LoadedAddresses = sig.ledger.transaction_status.LoadedAddresses;
const Ledger = sig.ledger.Ledger;
const SlotAccountStore = sig.accounts_db.SlotAccountStore;
const spl_token = sig.runtime.spl_token;

const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const parseSanitizedVoteTransaction =
    sig.consensus.vote_listener.vote_parser.parseSanitizedVoteTransaction;

const Committer = @This();

logger: Logger,
slot_state: *sig.core.SlotState,
status_cache: *sig.core.StatusCache,
stakes_cache: *sig.core.StakesCache,
new_rate_activation_epoch: ?sig.core.Epoch,
replay_votes_sender: ?*Channel(ParsedVote),
event_sink: ?*jrpc_types.EventSink = null,
/// Ledger for persisting transaction status metadata (optional for backwards compatibility)
ledger: ?*Ledger,
/// Account store for looking up accounts (e.g. mint accounts for token balance resolution)
account_store: ?SlotAccountStore,
/// Cache for tracking per-slot prioritization fees for RPC queries
prioritization_fee_cache: ?*sig.rpc.hook_contexts.PrioritizationFeeCache = null,

pub fn commitTransactions(
    self: Committer,
    persistent_allocator: Allocator,
    temp_allocator: Allocator,
    slot: Slot,
    transactions: []const ResolvedTransaction,
    tx_results: []const struct { Hash, ProcessedTransaction },
    base_transaction_index: usize,
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "commitTransactions" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    var rng = std.Random.DefaultPrng.init(slot + transactions.len);

    var accounts_to_store = sig.utils.collections.PubkeyMap(LoadedAccount).empty;
    defer accounts_to_store.deinit(temp_allocator);

    var signature_count: usize = 0;
    var rent_collected: u64 = 0;

    var transaction_fees: u64 = 0;
    var priority_fees: u64 = 0;
    var non_vote_count: usize = 0;

    // When an event sink is present, build a rich transaction batch event.
    // The arena owns all TransactionEntry data; allocate from the event sink
    // so the receive side can free with its own (channel) allocator.
    const maybe_event_sink = self.event_sink;
    const batch_allocator = if (maybe_event_sink) |es| es.allocator() else persistent_allocator;
    var owns_batch_arena = maybe_event_sink != null;
    var batch_arena = std.heap.ArenaAllocator.init(batch_allocator);
    defer if (owns_batch_arena) batch_arena.deinit();
    var batch_entries: ArrayListUnmanaged(jrpc_types.TransactionEntry) = .{};

    for (transactions, tx_results, 0..) |transaction, *result, local_index| {
        // Expand per-batch starting index to per-transaction global index.
        // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/ledger/src/blockstore_processor.rs#L559
        const global_index = base_transaction_index + local_index;
        const message_hash = &result.@"0";
        const tx_result = &result.@"1";

        signature_count += transaction.transaction.signatures.len;

        for (tx_result.writes.constSlice()) |*account| {
            try accounts_to_store.put(temp_allocator, account.pubkey, account.*);
        }
        transaction_fees += tx_result.fees.transaction_fee;
        priority_fees += tx_result.fees.prioritization_fee;

        const is_simple_vote_tx = transaction.transaction.isSimpleVoteTransaction(
            transaction.instructions,
        );

        if (!is_simple_vote_tx) {
            non_vote_count += 1;
        }

        // Update prioritization fee cache for non-vote transactions
        if (self.prioritization_fee_cache) |cache| if (!is_simple_vote_tx) try cache.update(
            persistent_allocator,
            slot,
            tx_result.fees.compute_unit_price,
            transaction.accounts.items(.pubkey),
            transaction.accounts.items(.is_writable),
        );

        if (tx_result.outputs != null) {
            rent_collected += tx_result.rent;

            // Parse and forward vote transactions
            if (self.replay_votes_sender) |sender| {
                if (tx_result.err == null and is_simple_vote_tx) {
                    if (try parseSanitizedVoteTransaction(
                        persistent_allocator,
                        transaction,
                    )) |parsed| {
                        if (parsed.vote.lastVotedSlot() != null) {
                            sender.send(parsed) catch parsed.deinit(persistent_allocator);
                        } else {
                            parsed.deinit(persistent_allocator);
                        }
                    }
                }
            }
        }

        const recent_blockhash = &transaction.transaction.msg.recent_blockhash;
        const signature = transaction.transaction.signatures[0];
        {
            const z = tracy.Zone.init(@src(), .{
                .name = "status_cache.insert: message_hash.data",
            });
            defer z.deinit();
            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &message_hash.data,
                slot,
                tx_result.err,
            );
        }
        {
            const z = tracy.Zone.init(@src(), .{
                .name = "status_cache.insert: signature.toBytes()",
            });
            defer z.deinit();
            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &signature.toBytes(),
                slot,
                tx_result.err,
            );
        }

        // When subscribers are present, build a rich
        // TransactionEntry in the arena, then also use
        // it for the ledger write (avoiding duplicate
        // metadata computation).
        if (maybe_event_sink != null) {
            const arena_alloc = batch_arena.allocator();
            const entry = try buildTransactionEntry(
                arena_alloc,
                temp_allocator,
                transaction,
                tx_result.*,
                is_simple_vote_tx,
                global_index,
                self.account_store,
            );

            try batch_entries.append(arena_alloc, entry);

            // Write to ledger from the entry (borrows
            // arena data, no extra allocations).
            if (self.ledger) |ledger| {
                try writeTransactionStatusFromEntry(
                    temp_allocator,
                    ledger,
                    slot,
                    transaction,
                    &entry,
                    global_index,
                );
            }
        } else {
            // No subscribers, use the original
            // ledger-only path (no entry allocation).
            if (self.ledger) |ledger| {
                try writeTransactionStatus(
                    temp_allocator,
                    ledger,
                    slot,
                    transaction,
                    tx_result.*,
                    global_index,
                    self.account_store,
                );
            }
        }
    }

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
    _ = self.slot_state.non_vote_transaction_count.fetchAdd(non_vote_count, .monotonic);
    _ = self.slot_state.signature_count.fetchAdd(signature_count, .monotonic);
    _ = self.slot_state.collected_rent.fetchAdd(rent_collected, .monotonic);

    for (accounts_to_store.values()) |account| {
        try self.stakes_cache.checkAndStore(
            persistent_allocator,
            account.pubkey,
            account.account,
            self.new_rate_activation_epoch,
        );
    }

    if (maybe_event_sink) |event_sink| {
        const event: jrpc_types.InboundEvent = .{ .transaction_batch = .{
            .slot = slot,
            .entries = batch_entries.items,
            .arena_state = batch_arena.state,
        } };
        owns_batch_arena = false;
        errdefer event.deinit(event_sink.allocator());

        try event_sink.send(event);
    }
}

fn appendSlotTransactionLogsEntry(
    allocator: Allocator,
    batch_log_entries: *ArrayListUnmanaged(jrpc_types.TransactionLogsEntry),
    transaction: ResolvedTransaction,
    tx_err: ?TransactionError,
    maybe_log_collector: ?LogCollector,
    is_vote: bool,
) !void {
    const log_collector = maybe_log_collector orelse return;
    const log_messages = try cloneLogMessages(allocator, log_collector);
    errdefer {
        for (log_messages) |log_message| {
            allocator.free(log_message);
        }
        allocator.free(log_messages);
    }
    if (log_messages.len == 0) {
        return;
    }

    const mentioned_pubkeys = try allocator.dupe(Pubkey, transaction.accounts.items(.pubkey));
    errdefer allocator.free(mentioned_pubkeys);

    const cloned_err = if (tx_err) |err_value| try err_value.clone(allocator) else null;
    errdefer if (cloned_err) |err_value| err_value.deinit(allocator);

    try batch_log_entries.append(allocator, .{
        .signature = transaction.transaction.signatures[0],
        .err = cloned_err,
        .is_vote = is_vote,
        .logs = log_messages,
        .mentioned_pubkeys = mentioned_pubkeys,
    });
}

fn cloneLogMessages(
    allocator: Allocator,
    log_collector: LogCollector,
) ![]const []const u8 {
    var iterator = log_collector.iterator();
    const count = iterator.count();
    const log_messages = try allocator.alloc([]const u8, count);
    var copied: usize = 0;
    errdefer {
        for (log_messages[0..copied]) |log_message| {
            allocator.free(log_message);
        }
        allocator.free(log_messages);
    }

    while (iterator.next()) |message| {
        log_messages[copied] = try allocator.dupe(u8, message);
        copied += 1;
    }

    std.debug.assert(copied == log_messages.len);
    return log_messages;
}

/// Build and write TransactionStatusMeta to the ledger for a single transaction.
fn writeTransactionStatus(
    allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    transaction: ResolvedTransaction,
    tx_result: ProcessedTransaction,
    transaction_index: usize,
    account_store: ?SlotAccountStore,
) !void {
    const status_write_zone = tracy.Zone.init(@src(), .{ .name = "writeTransactionStatus" });
    defer status_write_zone.deinit();

    const signature = transaction.transaction.signatures[0];
    const num_accounts = transaction.accounts.len;

    // Use pre-balances captured during execution
    // If pre_balances is empty (account loading failed), use zeros
    const pre_balances = try allocator.alloc(u64, num_accounts);
    defer allocator.free(pre_balances);
    if (tx_result.pre_balances.len == num_accounts) {
        @memcpy(pre_balances, tx_result.pre_balances.constSlice());
    } else {
        // Account loading failed - pre-balances not available
        @memset(pre_balances, 0);
    }

    // Compute post-balances: start with pre-balances, then update from writes
    var post_balances = try allocator.alloc(u64, num_accounts);
    defer allocator.free(post_balances);
    @memcpy(post_balances, pre_balances);

    // Update post-balances with values from written accounts
    for (tx_result.writes.constSlice()) |*written_account| {
        // Find the index of this account in the transaction
        for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
            if (pubkey.equals(&written_account.pubkey)) {
                post_balances[idx] = written_account.account.lamports;
                break;
            }
        }
    }

    const num_static_addresses = transaction.transaction.msg.account_keys.len;

    // Count loaded addresses
    var num_loaded_writable: usize = 0;
    var num_loaded_readonly: usize = 0;
    for (transaction.transaction.msg.address_lookups) |lookup| {
        num_loaded_writable += lookup.writable_indexes.len;
        num_loaded_readonly += lookup.readonly_indexes.len;
    }

    // Populate loaded addresses and address_signatures index keys
    var writable_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        allocator,
        num_static_addresses + num_loaded_writable,
    );
    defer writable_keys.deinit(allocator);
    var readonly_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        allocator,
        num_static_addresses + num_loaded_readonly,
    );
    defer readonly_keys.deinit(allocator);
    var loaded_writable_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        allocator,
        num_loaded_writable,
    );
    defer loaded_writable_keys.deinit(allocator);
    var loaded_readonly_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        allocator,
        num_loaded_readonly,
    );
    defer loaded_readonly_keys.deinit(allocator);
    for (
        transaction.accounts.items(.pubkey),
        transaction.accounts.items(.is_writable),
        0..,
    ) |pubkey, is_writable, index| {
        const is_loaded = index >= num_static_addresses;

        if (is_writable) {
            writable_keys.appendAssumeCapacity(pubkey);
            if (is_loaded) loaded_writable_keys.appendAssumeCapacity(pubkey);
        } else {
            readonly_keys.appendAssumeCapacity(pubkey);
            if (is_loaded) loaded_readonly_keys.appendAssumeCapacity(pubkey);
        }
    }

    const loaded_addresses = LoadedAddresses{
        .writable = loaded_writable_keys.items,
        .readonly = loaded_readonly_keys.items,
    };

    // Collect token balances
    // Build a mint decimals cache from writes (for mints modified in this tx)
    var mint_cache = spl_token.MintDecimalsCache.init(allocator);
    defer mint_cache.deinit();

    // Populate cache with any mints found in the transaction writes
    for (tx_result.writes.constSlice()) |*written_account| {
        const acc = written_account.account;
        const pubkey = written_account.pubkey;
        if (acc.data.len >= spl_token.MINT_ACCOUNT_SIZE) {
            if (spl_token.ParsedMint.parse(acc.data[0..spl_token.MINT_ACCOUNT_SIZE])) |mint| {
                mint_cache.put(pubkey, mint.decimals) catch {};
            }
        }
    }

    // Resolve pre-token balances using FallbackAccountReader (writes first, then account store)
    const mint_reader = FallbackAccountReader{
        .writes = tx_result.writes.constSlice(),
        .account_store_reader = if (account_store) |store| store.reader() else null,
    };
    const pre_token_balances = spl_token.resolveTokenBalances(
        allocator,
        tx_result.pre_token_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    ) catch null;
    errdefer if (pre_token_balances) |balances| {
        for (balances) |b| b.deinit(allocator);
        allocator.free(balances);
    };

    // Compute post-token balances by reading all transaction accounts.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_processor.rs#L532-L533
    const post_raw_token_balances = try collectPostTokenBalances(
        allocator,
        transaction,
        tx_result.writes.constSlice(),
        if (account_store) |store| store.reader() else null,
    );
    const post_token_balances = spl_token.resolveTokenBalances(
        allocator,
        post_raw_token_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    ) catch null;
    errdefer if (post_token_balances) |balances| {
        for (balances) |b| b.deinit(allocator);
        allocator.free(balances);
    };

    // Build TransactionStatusMeta
    const status = try TransactionStatusMetaBuilder.build(
        allocator,
        tx_result,
        pre_balances,
        post_balances,
        loaded_addresses,
        pre_token_balances,
        post_token_balances,
    );
    defer status.deinit(allocator);

    // Write to ledger
    const result_writer = ledger.resultWriter();
    try result_writer.writeTransactionStatus(
        slot,
        signature,
        writable_keys.items,
        readonly_keys.items,
        status,
        transaction_index,
    );
}

/// Build a rich TransactionEntry in the given arena allocator.
///
/// Computes all the same metadata that `writeTransactionStatus`
/// does (balances, token balances, loaded addresses, inner
/// instructions, logs, return data) but stores them into a
/// `TransactionEntry` that can be cached and reused for both
/// ledger writes and notification construction.
fn buildTransactionEntry(
    arena: Allocator,
    temp_allocator: Allocator,
    transaction: ResolvedTransaction,
    tx_result: ProcessedTransaction,
    is_vote: bool,
    transaction_index: usize,
    account_store: ?SlotAccountStore,
) !jrpc_types.TransactionEntry {
    const zone = tracy.Zone.init(@src(), .{ .name = "buildTransactionEntry" });
    defer zone.deinit();

    const num_accounts = transaction.accounts.len;

    // Pre-balances
    const pre_balances = try arena.alloc(u64, num_accounts);
    if (tx_result.pre_balances.len == num_accounts) {
        @memcpy(pre_balances, tx_result.pre_balances.constSlice());
    } else {
        @memset(pre_balances, 0);
    }

    // Post-balances
    const post_balances = try arena.alloc(u64, num_accounts);
    @memcpy(post_balances, pre_balances);
    for (tx_result.writes.constSlice()) |*written| {
        for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
            if (pubkey.equals(&written.pubkey)) {
                post_balances[idx] = written.account.lamports;
                break;
            }
        }
    }

    // Loaded addresses
    const num_static = transaction.transaction.msg.account_keys.len;
    var num_loaded_w: usize = 0;
    var num_loaded_r: usize = 0;
    for (transaction.transaction.msg.address_lookups) |l| {
        num_loaded_w += l.writable_indexes.len;
        num_loaded_r += l.readonly_indexes.len;
    }
    var loaded_w = try ArrayListUnmanaged(Pubkey).initCapacity(arena, num_loaded_w);
    var loaded_r = try ArrayListUnmanaged(Pubkey).initCapacity(arena, num_loaded_r);
    for (
        transaction.accounts.items(.pubkey),
        transaction.accounts.items(.is_writable),
        0..,
    ) |pubkey, is_writable, index| {
        if (index >= num_static) {
            if (is_writable) {
                loaded_w.appendAssumeCapacity(pubkey);
            } else {
                loaded_r.appendAssumeCapacity(pubkey);
            }
        }
    }
    const loaded_addresses = LoadedAddresses{
        .writable = loaded_w.items,
        .readonly = loaded_r.items,
    };

    // Token balances
    var mint_cache = spl_token.MintDecimalsCache.init(temp_allocator);
    defer mint_cache.deinit();
    for (tx_result.writes.constSlice()) |*written| {
        if (written.account.data.len >= spl_token.MINT_ACCOUNT_SIZE) {
            if (spl_token.ParsedMint.parse(
                written.account.data[0..spl_token.MINT_ACCOUNT_SIZE],
            )) |mint| {
                try mint_cache.put(
                    written.pubkey,
                    mint.decimals,
                );
            }
        }
    }
    const mint_reader = FallbackAccountReader{
        .writes = tx_result.writes.constSlice(),
        .account_store_reader = if (account_store) |s| s.reader() else null,
    };
    const pre_token_balances = try spl_token.resolveTokenBalances(
        arena,
        tx_result.pre_token_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_processor.rs#L532-L533
    const post_raw = try collectPostTokenBalances(
        temp_allocator,
        transaction,
        tx_result.writes.constSlice(),
        if (account_store) |s| s.reader() else null,
    );
    const post_token_balances = try spl_token.resolveTokenBalances(
        arena,
        post_raw,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    );

    // Build TransactionStatusMeta for inner
    // instructions, logs, return data, compute
    // We use the arena allocator so that all the
    // converted data lives in the batch arena.
    const meta = try TransactionStatusMetaBuilder.build(
        arena,
        tx_result,
        pre_balances,
        post_balances,
        loaded_addresses,
        pre_token_balances,
        post_token_balances,
    );
    // Do NOT deinit `meta` the arena owns the data.

    // Clone transaction into arena
    const cloned_tx = try transaction.transaction.clone(arena);

    // Mentioned pubkeys
    const mentioned = try arena.dupe(Pubkey, transaction.accounts.items(.pubkey));

    // Error: clone into arena if it has heap data
    const cloned_err: ?TransactionError = if (tx_result.err) |err| try err.clone(arena) else null;

    return .{
        .signature = transaction.transaction.signatures[0],
        .transaction = cloned_tx,
        .is_vote = is_vote,
        .transaction_index = transaction_index,
        .err = cloned_err,
        .fee = meta.fee,
        .compute_units_consumed = meta.compute_units_consumed,
        .cost_units = tx_result.cost_units,
        .pre_balances = meta.pre_balances,
        .post_balances = meta.post_balances,
        .pre_token_balances = meta.pre_token_balances,
        .post_token_balances = meta.post_token_balances,
        .inner_instructions = meta.inner_instructions,
        .log_messages = meta.log_messages,
        .return_data = meta.return_data,
        .loaded_addresses = meta.loaded_addresses,
        .mentioned_pubkeys = mentioned,
    };
}

/// Write transaction status to the ledger using data from a previously built `TransactionEntry`. Constructs a
/// borrowing `TransactionStatusMeta` from the entry's arena-owned fields, no extra allocations needed for
/// the metadata itself.
fn writeTransactionStatusFromEntry(
    temp_allocator: Allocator,
    ledger: *Ledger,
    slot: Slot,
    transaction: ResolvedTransaction,
    entry: *const jrpc_types.TransactionEntry,
    transaction_index: usize,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "writeTransactionStatusFromEntry" });
    defer zone.deinit();

    // Classify keys into writable/readonly for the address-signatures index.
    var writable_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        temp_allocator,
        transaction.accounts.len,
    );
    defer writable_keys.deinit(temp_allocator);
    var readonly_keys = try ArrayListUnmanaged(Pubkey).initCapacity(
        temp_allocator,
        transaction.accounts.len,
    );
    defer readonly_keys.deinit(temp_allocator);

    for (
        transaction.accounts.items(.pubkey),
        transaction.accounts.items(.is_writable),
    ) |pubkey, is_writable| {
        if (is_writable) {
            writable_keys.appendAssumeCapacity(pubkey);
        } else {
            readonly_keys.appendAssumeCapacity(pubkey);
        }
    }

    // Build a borrowing TransactionStatusMeta that
    // points into the arena-owned entry data.
    const status = TransactionStatusMeta{
        .status = entry.err,
        .fee = entry.fee,
        .pre_balances = entry.pre_balances,
        .post_balances = entry.post_balances,
        .inner_instructions = entry.inner_instructions,
        .log_messages = entry.log_messages,
        .pre_token_balances = entry.pre_token_balances,
        .post_token_balances = entry.post_token_balances,
        // Per-transaction rewards are always empty in Agave.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/rpc/src/transaction_status_service.rs#L190
        .rewards = &.{},
        .loaded_addresses = entry.loaded_addresses,
        .return_data = entry.return_data,
        .compute_units_consumed = entry.compute_units_consumed,
        .cost_units = entry.cost_units,
    };
    // Do NOT defer status.deinit(), it borrows from the arena.

    const result_writer = ledger.resultWriter();
    try result_writer.writeTransactionStatus(
        slot,
        entry.signature,
        writable_keys.items,
        readonly_keys.items,
        status,
        transaction_index,
    );
}

/// Collects post-execution token balances for all transaction accounts.
///
/// Iterates every account key in the transaction (not just writes) and
/// reads each account's final state from the transaction writes first,
/// falling back to the account store for unmodified accounts. This
/// matches Agave's `collect_balances`, which reads through the
/// `AccountLoader` after it has been updated with execution results.
///
/// For failed transactions the writes only contain rollback accounts
/// (fee-payer and nonce), so token accounts that were not modified
/// still need to be read from the account store to populate
/// `postTokenBalances`.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_processor.rs#L532-L533
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L78-L110
fn collectPostTokenBalances(
    allocator: Allocator,
    transaction: ResolvedTransaction,
    writes: []const LoadedAccount,
    account_store_reader: ?sig.accounts_db.SlotAccountReader,
) !spl_token.RawTokenBalances {
    var result = spl_token.RawTokenBalances{};

    // Early exit when the transaction has no token program in its
    // account keys, no account can be a token account.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L86
    const has_token_program = for (transaction.accounts.items(.pubkey)) |pubkey| {
        if (spl_token.isTokenProgram(pubkey)) break true;
    } else false;
    if (!has_token_program) return result;

    // Iterate ALL account keys in transaction order.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L88
    for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
        // Skip token program IDs themselves since they are programs and not token accounts.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L98
        if (spl_token.isTokenProgram(pubkey)) continue;

        // Read the account's final state. Check transaction writes
        // first (updated/rolled-back accounts), then fall back to
        // the account store (unmodified accounts).
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/account_loader.rs#L237-L255
        var owner: ?Pubkey = null;
        var data_buf: [spl_token.TOKEN_ACCOUNT_SIZE]u8 = undefined;
        var have_data = false;

        if (findInWrites(writes, pubkey)) |written| {
            owner = written.account.owner;
            if (written.account.data.len >= spl_token.TOKEN_ACCOUNT_SIZE) {
                @memcpy(&data_buf, written.account.data[0..spl_token.TOKEN_ACCOUNT_SIZE]);
                have_data = true;
            }
        } else if (account_store_reader) |reader| {
            const account = try reader.get(allocator, pubkey) orelse continue;
            defer account.deinit(allocator);
            owner = account.owner;
            if (account.data.len() >= spl_token.TOKEN_ACCOUNT_SIZE) {
                _ = account.data.read(0, &data_buf);
                have_data = true;
            }
        } else continue;

        if (!have_data) continue;

        // The account's owner must be a known token program.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L99
        const owner_pubkey = owner orelse return error.MissingTokenAccountOwner;
        if (!spl_token.isTokenProgram(owner_pubkey)) continue;

        // Parse SPL Token account state.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L101-L105
        const parsed = spl_token.ParsedTokenAccount.parse(
            &data_buf,
        ) orelse continue;

        result.append(.{
            .account_index = @intCast(idx),
            .mint = parsed.mint,
            .owner = parsed.owner,
            .amount = parsed.amount,
            .program_id = owner_pubkey,
        }) catch unreachable; // BoundedArray full; can never happen because capacity == MAX_TX_ACCOUNT_LOCKS.
    }

    return result;
}

fn findInWrites(
    writes: []const LoadedAccount,
    pubkey: Pubkey,
) ?*const LoadedAccount {
    for (writes) |*written| {
        if (written.pubkey.equals(&pubkey)) return written;
    }
    return null;
}

/// Account reader that checks transaction writes first, then falls back to the
/// account store. This ensures mint accounts can be found even when they weren't
/// modified by the transaction (the common case for token transfers).
/// [agave] Agave uses account_loader.load_account() which has full store access.
pub const FallbackAccountReader = struct {
    writes: []const LoadedAccount,
    account_store_reader: ?sig.accounts_db.SlotAccountReader,

    /// Stub account type returned by this reader.
    /// Allocates and owns the data buffer.
    const StubAccount = struct {
        data: DataHandle,

        const DataHandle = struct {
            slice: []const u8,

            pub fn constSlice(self: DataHandle) []const u8 {
                return self.slice;
            }
        };

        pub fn deinit(self: StubAccount, allocator: Allocator) void {
            allocator.free(self.data.slice);
        }
    };

    pub fn get(self: FallbackAccountReader, allocator: Allocator, pubkey: Pubkey) !?StubAccount {
        // Check transaction writes first
        for (self.writes) |*account| {
            if (account.pubkey.equals(&pubkey)) {
                const data_copy = try allocator.dupe(u8, account.account.data);
                errdefer allocator.free(data_copy);
                return StubAccount{
                    .data = .{ .slice = data_copy },
                };
            }
        }

        // Fall back to account store (e.g. for mint accounts not modified in this tx)
        if (self.account_store_reader) |reader| {
            const account = try reader.get(allocator, pubkey) orelse return null;
            defer account.deinit(allocator);
            const data_copy = try account.data.readAllAllocate(allocator);
            errdefer allocator.free(data_copy);
            return StubAccount{ .data = .{
                .slice = data_copy,
            } };
        }

        return null;
    }
};

fn initResolvedTransaction(
    allocator: Allocator,
    random: std.Random,
) !ResolvedTransaction {
    var transaction = try sig.core.Transaction.initRandom(allocator, random, null);
    errdefer transaction.deinit(allocator);

    var resolved_accounts: std.MultiArrayList(sig.core.instruction.InstructionAccount) = .{};
    try resolved_accounts.ensureTotalCapacity(allocator, transaction.msg.account_keys.len);
    for (transaction.msg.account_keys, 0..) |pubkey, index| {
        resolved_accounts.appendAssumeCapacity(.{
            .pubkey = pubkey,
            .is_signer = index < transaction.signatures.len,
            .is_writable = index == 0,
        });
    }

    const resolved_instructions = try allocator.alloc(sig.runtime.InstructionInfo, 0);

    return .{
        .transaction = transaction,
        .accounts = resolved_accounts,
        .instructions = resolved_instructions,
    };
}

test "commitTransactions emits transaction logs batch with transaction metadata" {
    const allocator = std.testing.allocator;

    var test_state = try replay.execution.TestState.init(allocator);
    defer test_state.deinit(allocator);

    const event_sink = try jrpc_types.EventSink.create(allocator);
    defer event_sink.destroy();

    var committer = test_state.committer();
    committer.event_sink = event_sink;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var resolved_transactions = [_]ResolvedTransaction{
        try initResolvedTransaction(allocator, prng.random()),
        try initResolvedTransaction(allocator, prng.random()),
        try initResolvedTransaction(allocator, prng.random()),
    };
    defer {
        for (resolved_transactions) |resolved_transaction| {
            resolved_transaction.deinit(allocator);
            resolved_transaction.transaction.deinit(allocator);
        }
    }

    var log_collector_1 = try LogCollector.init(allocator, 10_000);
    try log_collector_1.log(allocator, "Program log: hello", .{});
    try log_collector_1.log(allocator, "Program log: world", .{});

    var log_collector_2 = try LogCollector.init(allocator, 10_000);
    try log_collector_2.log(allocator, "Program log: account missing", .{});

    var log_collector_3 = try LogCollector.init(allocator, 10_000);
    try log_collector_3.log(allocator, "Program log: success", .{});

    const borsh_io_error = try allocator.dupe(u8, "borsh io");
    defer allocator.free(borsh_io_error);

    var tx_results = [_]struct { Hash, ProcessedTransaction }{
        .{
            Hash.ZEROES,
            .{
                .fees = .{ .transaction_fee = 0, .prioritization_fee = 0, .compute_unit_price = 0 },
                .rent = 0,
                .writes = .{},
                .err = .{ .InstructionError = .{ 3, .{ .BorshIoError = borsh_io_error } } },
                .loaded_accounts_data_size = 0,
                .outputs = .{
                    .err = .{ .InstructionError = .{ 3, .{ .BorshIoError = borsh_io_error } } },
                    .log_collector = log_collector_1,
                    .instruction_trace = null,
                    .return_data = null,
                    .compute_limit = 0,
                    .compute_meter = 0,
                    .accounts_data_len_delta = 0,
                    .executed_units = 0,
                },
                .pre_balances = .{},
                .pre_token_balances = .{},
                .cost_units = 0,
            },
        },
        .{
            Hash.ZEROES,
            .{
                .fees = .{ .transaction_fee = 0, .prioritization_fee = 0, .compute_unit_price = 0 },
                .rent = 0,
                .writes = .{},
                .err = .AccountNotFound,
                .loaded_accounts_data_size = 0,
                .outputs = .{
                    .err = .AccountNotFound,
                    .log_collector = log_collector_2,
                    .instruction_trace = null,
                    .return_data = null,
                    .compute_limit = 0,
                    .compute_meter = 0,
                    .accounts_data_len_delta = 0,
                    .executed_units = 0,
                },
                .pre_balances = .{},
                .pre_token_balances = .{},
                .cost_units = 0,
            },
        },
        .{
            Hash.ZEROES,
            .{
                .fees = .{ .transaction_fee = 0, .prioritization_fee = 0, .compute_unit_price = 0 },
                .rent = 0,
                .writes = .{},
                .err = null,
                .loaded_accounts_data_size = 0,
                .outputs = .{
                    .err = null,
                    .log_collector = log_collector_3,
                    .instruction_trace = null,
                    .return_data = null,
                    .compute_limit = 0,
                    .compute_meter = 0,
                    .accounts_data_len_delta = 0,
                    .executed_units = 0,
                },
                .pre_balances = .{},
                .pre_token_balances = .{},
                .cost_units = 0,
            },
        },
    };
    defer {
        for (&tx_results) |*tx_result| {
            const hash, const processed = tx_result.*;
            _ = hash;
            processed.deinit(allocator);
        }
    }

    try committer.commitTransactions(
        allocator,
        allocator,
        42,
        resolved_transactions[0..],
        tx_results[0..],
        0,
    );

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);

    switch (event) {
        .transaction_batch => |batch_event| {
            try std.testing.expectEqual(42, batch_event.slot);
            try std.testing.expectEqual(3, batch_event.entries.len);

            const borsh_entry = batch_event.entries[0];
            try std.testing.expect(borsh_entry.signature.eql(
                &resolved_transactions[0].transaction.signatures[0],
            ));
            try std.testing.expect(borsh_entry.err != null);
            try std.testing.expect(borsh_entry.err.? == .InstructionError);
            const instruction_index, const err = borsh_entry.err.?.InstructionError;
            try std.testing.expectEqual(3, instruction_index);
            try std.testing.expect(err == .BorshIoError);
            try std.testing.expect(err.BorshIoError.ptr != borsh_io_error.ptr);
            try std.testing.expectEqualStrings("borsh io", err.BorshIoError);
            try std.testing.expect(!borsh_entry.is_vote);
            const logs_0 = borsh_entry.log_messages orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(2, logs_0.len);
            try std.testing.expectEqualStrings("Program log: hello", logs_0[0]);
            try std.testing.expectEqualStrings("Program log: world", logs_0[1]);
            try std.testing.expectEqual(
                resolved_transactions[0].accounts.items(.pubkey).len,
                borsh_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(borsh_entry.mentioned_pubkeys[0].equals(
                &resolved_transactions[0].accounts.items(.pubkey)[0],
            ));

            const anf_entry = batch_event.entries[1];
            try std.testing.expect(anf_entry.signature.eql(
                &resolved_transactions[1].transaction.signatures[0],
            ));
            try std.testing.expectEqual(.AccountNotFound, anf_entry.err);
            try std.testing.expect(!anf_entry.is_vote);
            const logs_1 = anf_entry.log_messages orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(1, logs_1.len);
            try std.testing.expectEqualStrings("Program log: account missing", logs_1[0]);
            try std.testing.expectEqual(
                resolved_transactions[1].accounts.items(.pubkey).len,
                anf_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(anf_entry.mentioned_pubkeys[0].equals(
                &resolved_transactions[1].accounts.items(.pubkey)[0],
            ));

            const ok_entry = batch_event.entries[2];
            try std.testing.expect(ok_entry.signature.eql(
                &resolved_transactions[2].transaction.signatures[0],
            ));
            try std.testing.expectEqual(null, ok_entry.err);
            try std.testing.expect(!ok_entry.is_vote);
            const logs_2 = ok_entry.log_messages orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(1, logs_2.len);
            try std.testing.expectEqualStrings("Program log: success", logs_2[0]);
            try std.testing.expectEqual(
                resolved_transactions[2].accounts.items(.pubkey).len,
                ok_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(ok_entry.mentioned_pubkeys[0].equals(
                &resolved_transactions[2].accounts.items(.pubkey)[0],
            ));
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(event_sink.channel.tryReceive() == null);
}

test "commitTransactions emits empty transaction logs batch when execution has no logs" {
    const allocator = std.testing.allocator;

    var test_state = try replay.execution.TestState.init(allocator);
    defer test_state.deinit(allocator);

    const event_sink = try jrpc_types.EventSink.create(allocator);
    defer event_sink.destroy();

    var committer = test_state.committer();
    committer.event_sink = event_sink;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var resolved_transaction = try initResolvedTransaction(allocator, prng.random());
    defer {
        resolved_transaction.deinit(allocator);
        resolved_transaction.transaction.deinit(allocator);
    }

    var tx_result: struct { Hash, ProcessedTransaction } = .{
        Hash.ZEROES,
        .{
            .fees = .{ .transaction_fee = 0, .prioritization_fee = 0, .compute_unit_price = 0 },
            .rent = 0,
            .writes = .{},
            .err = null,
            .loaded_accounts_data_size = 0,
            .outputs = .{
                .err = null,
                .log_collector = null,
                .instruction_trace = null,
                .return_data = null,
                .compute_limit = 0,
                .compute_meter = 0,
                .accounts_data_len_delta = 0,
                .executed_units = 0,
            },
            .pre_balances = .{},
            .pre_token_balances = .{},
            .cost_units = 0,
        },
    };
    defer {
        _, const processed = tx_result;
        processed.deinit(allocator);
    }

    try committer.commitTransactions(
        allocator,
        allocator,
        43,
        (&resolved_transaction)[0..1],
        (&tx_result)[0..1],
        0,
    );

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(allocator);

    switch (event) {
        .transaction_batch => |batch_event| {
            try std.testing.expectEqual(43, batch_event.slot);
            // One transaction was submitted, so we should get one entry
            // (even without logs, the entry carries balances etc.).
            try std.testing.expectEqual(1, batch_event.entries.len);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(event_sink.channel.tryReceive() == null);
}

test "collectPostTokenBalances: failed tx reads token account from account store" {
    // Regression test: for failed transactions, writes contain only
    // rollback accounts (fee payer / nonce). Token accounts that
    // were loaded but not modified must still appear in
    // postTokenBalances, read from the account store.
    //
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.2/svm/src/transaction_balances.rs#L88
    const allocator = std.testing.allocator;
    const ids = sig.runtime.ids;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const fee_payer = Pubkey.initRandom(random);
    const token_program = ids.TOKEN_PROGRAM_ID;
    const mint_pubkey = Pubkey.initRandom(random);
    const token_owner = Pubkey.initRandom(random);
    const token_account_key = Pubkey.initRandom(random);

    // Resolved accounts: [fee_payer, token_program, token_account]
    var resolved_accounts: std.MultiArrayList(
        sig.core.instruction.InstructionAccount,
    ) = .{};
    try resolved_accounts.ensureTotalCapacity(allocator, 3);
    defer resolved_accounts.deinit(allocator);

    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = fee_payer,
        .is_signer = true,
        .is_writable = true,
    });
    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = token_program,
        .is_signer = false,
        .is_writable = false,
    });
    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = token_account_key,
        .is_signer = false,
        .is_writable = true,
    });

    const transaction = ResolvedTransaction{
        .transaction = sig.core.Transaction.EMPTY,
        .accounts = resolved_accounts,
        .instructions = &.{},
    };

    // Build valid SPL token account data (165 bytes).
    var token_data = std.mem.zeroes(
        [spl_token.TOKEN_ACCOUNT_SIZE]u8,
    );
    @memcpy(token_data[0..32], &mint_pubkey.data);
    @memcpy(token_data[32..64], &token_owner.data);
    std.mem.writeInt(
        u64,
        token_data[64..72],
        1_000_000,
        .little,
    );
    token_data[108] = 1; // TokenAccountState.initialized

    // Failed tx: writes are empty (token account not modified).
    const writes: []const LoadedAccount = &.{};

    // Account store holds the token account.
    var account_map = sig.utils.collections.PubkeyMap(
        sig.runtime.AccountSharedData,
    ){};
    defer account_map.deinit(allocator);
    try account_map.put(allocator, token_account_key, .{
        .lamports = 1_000_000,
        .data = &token_data,
        .owner = token_program,
        .executable = false,
        .rent_epoch = 0,
    });

    const reader: sig.accounts_db.SlotAccountReader = .{
        .account_shared_data_map = &account_map,
    };

    const result = try collectPostTokenBalances(
        allocator,
        transaction,
        writes,
        reader,
    );

    // Token account at index 2 must be present.
    try std.testing.expectEqual(1, result.len);
    const entry = result.constSlice()[0];
    try std.testing.expectEqual(@as(u8, 2), entry.account_index);
    try std.testing.expect(entry.mint.equals(&mint_pubkey));
    try std.testing.expect(entry.owner.equals(&token_owner));
    try std.testing.expectEqual(
        @as(u64, 1_000_000),
        entry.amount,
    );
    try std.testing.expect(
        entry.program_id.equals(&token_program),
    );
}

test "collectPostTokenBalances: success tx reads token account from writes" {
    const allocator = std.testing.allocator;
    const ids = sig.runtime.ids;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const fee_payer = Pubkey.initRandom(random);
    const token_program = ids.TOKEN_PROGRAM_ID;
    const mint_pubkey = Pubkey.initRandom(random);
    const token_owner = Pubkey.initRandom(random);
    const token_account_key = Pubkey.initRandom(random);

    // Resolved accounts: [fee_payer, token_program, token_account]
    var resolved_accounts: std.MultiArrayList(
        sig.core.instruction.InstructionAccount,
    ) = .{};
    try resolved_accounts.ensureTotalCapacity(allocator, 3);
    defer resolved_accounts.deinit(allocator);

    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = fee_payer,
        .is_signer = true,
        .is_writable = true,
    });
    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = token_program,
        .is_signer = false,
        .is_writable = false,
    });
    resolved_accounts.appendAssumeCapacity(.{
        .pubkey = token_account_key,
        .is_signer = false,
        .is_writable = true,
    });

    const transaction = ResolvedTransaction{
        .transaction = sig.core.Transaction.EMPTY,
        .accounts = resolved_accounts,
        .instructions = &.{},
    };

    // Build valid SPL token account data.
    var token_data = std.mem.zeroes(
        [spl_token.TOKEN_ACCOUNT_SIZE]u8,
    );
    @memcpy(token_data[0..32], &mint_pubkey.data);
    @memcpy(token_data[32..64], &token_owner.data);
    std.mem.writeInt(
        u64,
        token_data[64..72],
        500_000,
        .little,
    );
    token_data[108] = 1; // TokenAccountState.initialized

    // Success tx: writes contain the token account.
    var writes_arr = [_]LoadedAccount{.{
        .pubkey = token_account_key,
        .account = .{
            .lamports = 1_000_000,
            .data = &token_data,
            .owner = token_program,
            .executable = false,
            .rent_epoch = 0,
        },
    }};

    const result = try collectPostTokenBalances(
        allocator,
        transaction,
        &writes_arr,
        null, // no account store needed
    );

    try std.testing.expectEqual(1, result.len);
    const entry = result.constSlice()[0];
    try std.testing.expectEqual(@as(u8, 2), entry.account_index);
    try std.testing.expect(entry.mint.equals(&mint_pubkey));
    try std.testing.expect(entry.owner.equals(&token_owner));
    try std.testing.expectEqual(@as(u64, 500_000), entry.amount);
    try std.testing.expect(
        entry.program_id.equals(&token_program),
    );
}
