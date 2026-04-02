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

    var maybe_logs_batch_event: ?jrpc_types.SlotTransactionLogs = null;
    defer if (maybe_logs_batch_event) |*logs_batch_event| {
        logs_batch_event.deinit();
    };
    var batch_log_entries: ArrayListUnmanaged(jrpc_types.TransactionLogsEntry) = .{};
    if (self.event_sink != null) {
        maybe_logs_batch_event = .{
            .slot = slot,
            .arena = std.heap.ArenaAllocator.init(persistent_allocator),
        };
    }

    for (transactions, tx_results, 0..) |transaction, *result, transaction_index| {
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

        // Update prioritization fee cache for non-vote transactions
        if (self.prioritization_fee_cache) |cache| if (!is_simple_vote_tx) try cache.update(
            persistent_allocator,
            slot,
            tx_result.fees.compute_unit_price,
            transaction.accounts.items(.pubkey),
            transaction.accounts.items(.is_writable),
        );

        // TODO: fix nesting, this sucks

        if (tx_result.outputs) |outputs| {
            rent_collected += tx_result.rent;

            if (maybe_logs_batch_event) |*logs_batch_event| {
                appendSlotTransactionLogsEntry(
                    logs_batch_event.arena.allocator(),
                    &batch_log_entries,
                    transaction,
                    tx_result.err,
                    outputs.log_collector,
                    is_simple_vote_tx,
                ) catch |err| {
                    self.logger.err().logf(
                        "failed to build transaction logs batch for slot {} transaction {}: {}",
                        .{ slot, transaction_index, err },
                    );
                };
            }

            // Skip non successful or non vote transactions.
            // Only send votes if consensus is enabled (sender exists)
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
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: message_hash.data" },
            );
            defer status_cache_zone.deinit();

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
            const status_cache_zone = tracy.Zone.init(
                @src(),
                .{ .name = "status_cache.insert: signature.toBytes()" },
            );
            defer status_cache_zone.deinit();

            try self.status_cache.insert(
                persistent_allocator,
                rng.random(),
                recent_blockhash,
                &signature.toBytes(),
                slot,
                tx_result.err,
            );
        }

        // Write transaction status to ledger for RPC (getBlock, getTransaction)
        if (self.ledger) |ledger| {
            try writeTransactionStatus(
                temp_allocator,
                ledger,
                slot,
                transaction,
                tx_result.*,
                transaction_index,
                self.account_store,
            );
        }
    }

    _ = self.slot_state.collected_transaction_fees.fetchAdd(transaction_fees, .monotonic);
    _ = self.slot_state.collected_priority_fees.fetchAdd(priority_fees, .monotonic);
    _ = self.slot_state.transaction_count.fetchAdd(tx_results.len, .monotonic);
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

    if (self.event_sink) |event_sink| {
        if (maybe_logs_batch_event) |*logs_batch_event| {
            // NOTE: it's fine to just assign the slice here since the arena allocator will free
            // everything, so we don't need to track actual capacity of the ArrayList
            logs_batch_event.entries = batch_log_entries.items;

            const event: jrpc_types.InboundEvent = .{ .logs = logs_batch_event.* };
            maybe_logs_batch_event = null;
            errdefer event.deinit();

            try event_sink.send(event);
        }
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
    if (log_messages.len == 0) {
        return;
    }
    errdefer {
        for (log_messages) |log_message| {
            allocator.free(log_message);
        }
        allocator.free(log_messages);
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
    if (count == 0) {
        return &.{};
    }

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

    // Compute post-token balances from writes
    const post_raw_token_balances = collectPostTokenBalances(transaction, tx_result);
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

/// Collect post-execution token balances from transaction writes.
fn collectPostTokenBalances(
    transaction: ResolvedTransaction,
    tx_result: ProcessedTransaction,
) spl_token.RawTokenBalances {
    var result = spl_token.RawTokenBalances{};

    for (tx_result.writes.constSlice()) |*written_account| {
        // Skip non-token accounts
        if (!spl_token.isTokenProgram(written_account.account.owner)) continue;

        // Skip if data is too short for a token account
        if (written_account.account.data.len < spl_token.TOKEN_ACCOUNT_SIZE) continue;

        // Try to parse as token account
        const parsed = spl_token.ParsedTokenAccount.parse(
            written_account.account.data[0..spl_token.TOKEN_ACCOUNT_SIZE],
        ) orelse continue;

        // Find the account index in the transaction
        var account_index: ?u8 = null;
        for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
            if (pubkey.equals(&written_account.pubkey)) {
                account_index = @intCast(idx);
                break;
            }
        }

        if (account_index) |idx| {
            result.append(.{
                .account_index = idx,
                .mint = parsed.mint,
                .owner = parsed.owner,
                .amount = parsed.amount,
                .program_id = written_account.account.owner,
            }) catch {}; // this is ok since tx_result.writes and result.len are the same
        }
    }

    return result;
}

/// Account reader that checks transaction writes first, then falls back to the
/// account store. This ensures mint accounts can be found even when they weren't
/// modified by the transaction (the common case for token transfers).
/// [agave] Agave uses account_loader.load_account() which has full store access.
const FallbackAccountReader = struct {
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
    );

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(event_sink.channel.allocator);

    switch (event) {
        .logs => |logs_event| {
            try std.testing.expectEqual(42, logs_event.slot);
            try std.testing.expectEqual(3, logs_event.entries.len);

            const borsh_entry = logs_event.entries[0];
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
            try std.testing.expectEqual(2, borsh_entry.logs.len);
            try std.testing.expectEqualStrings("Program log: hello", borsh_entry.logs[0]);
            try std.testing.expectEqualStrings("Program log: world", borsh_entry.logs[1]);
            try std.testing.expectEqual(
                resolved_transactions[0].accounts.items(.pubkey).len,
                borsh_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(borsh_entry.mentioned_pubkeys[0].equals(
                &resolved_transactions[0].accounts.items(.pubkey)[0],
            ));

            const account_not_found_entry = logs_event.entries[1];
            try std.testing.expect(account_not_found_entry.signature.eql(
                &resolved_transactions[1].transaction.signatures[0],
            ));
            try std.testing.expectEqual(.AccountNotFound, account_not_found_entry.err);
            try std.testing.expect(!account_not_found_entry.is_vote);
            try std.testing.expectEqual(1, account_not_found_entry.logs.len);
            try std.testing.expectEqualStrings(
                "Program log: account missing",
                account_not_found_entry.logs[0],
            );
            try std.testing.expectEqual(
                resolved_transactions[1].accounts.items(.pubkey).len,
                account_not_found_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(account_not_found_entry.mentioned_pubkeys[0].equals(
                &resolved_transactions[1].accounts.items(.pubkey)[0],
            ));

            const success_entry = logs_event.entries[2];
            try std.testing.expect(success_entry.signature.eql(
                &resolved_transactions[2].transaction.signatures[0],
            ));
            try std.testing.expectEqual(null, success_entry.err);
            try std.testing.expect(!success_entry.is_vote);
            try std.testing.expectEqual(1, success_entry.logs.len);
            try std.testing.expectEqualStrings("Program log: success", success_entry.logs[0]);
            try std.testing.expectEqual(
                resolved_transactions[2].accounts.items(.pubkey).len,
                success_entry.mentioned_pubkeys.len,
            );
            try std.testing.expect(success_entry.mentioned_pubkeys[0].equals(
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed + 1);
    var resolved_transactions = [_]ResolvedTransaction{
        try initResolvedTransaction(allocator, prng.random()),
    };
    defer {
        resolved_transactions[0].deinit(allocator);
        resolved_transactions[0].transaction.deinit(allocator);
    }

    var tx_results = [_]struct { Hash, ProcessedTransaction }{.{
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
            },
            .pre_balances = .{},
            .pre_token_balances = .{},
            .cost_units = 0,
        },
    }};
    defer {
        const hash, const processed = tx_results[0];
        _ = hash;
        processed.deinit(allocator);
    }

    try committer.commitTransactions(
        allocator,
        allocator,
        43,
        resolved_transactions[0..],
        tx_results[0..],
    );

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(event_sink.channel.allocator);

    switch (event) {
        .logs => |logs_event| {
            try std.testing.expectEqual(43, logs_event.slot);
            try std.testing.expectEqual(0, logs_event.entries.len);
        },
        else => return error.TestUnexpectedResult,
    }

    try std.testing.expect(event_sink.channel.tryReceive() == null);
}
