//! RPC hook context for transaction sending-related methods.
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const methods = @import("../methods.zig");

const Allocator = std.mem.Allocator;
const Base64Decoder = std.base64.standard.Decoder;
const Channel = sig.sync.Channel;
const CommitmentTracker = sig.replay.trackers.CommitmentTracker;
const EpochTracker = sig.core.EpochTracker;
const FallbackAccountReader = sig.replay.Committer.FallbackAccountReader;
const GetAccountInfo = methods.GetAccountInfo;
const GetBlock = methods.GetBlock;
const GetLatestBlockhashValue = methods.GetLatestBlockhash.Response.Value;
const Hash = sig.core.Hash;
const InnerInstructions = sig.ledger.transaction_status.InnerInstructions;
const Message = sig.core.transaction.Message;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const Pubkey = sig.core.Pubkey;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SendTransaction = methods.SendTransaction;
const SimulateTransaction = methods.SimulateTransaction;
const Slot = sig.core.Slot;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const SlotTracker = sig.replay.trackers.SlotTracker;
const StatusCache = sig.core.StatusCache;
const SvmGateway = sig.replay.svm_gateway.SvmGateway;
const Transaction = sig.core.Transaction;
const TransactionInfo = sig.TransactionSenderService.TransactionInfo;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const TransactionReturnData = sig.ledger.transaction_status.TransactionReturnData;

const encodeAccount = sig.rpc.account_codec.encodeAccount;
const computeBudgetExecute = sig.runtime.program.compute_budget.execute;
const getDurableNonce = sig.runtime.check_transactions.getDurableNonce;
const getSysvarFromAccount = sig.replay.update_sysvar.getSysvarFromAccount;
const resolveTransaction = sig.replay.resolve_lookup.resolveTransaction;
const executeTransaction = sig.replay.svm_gateway.executeTransaction;

/// Analogous to [MAX_BASE58_SIZE](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4341)
const MAX_BASE58_SIZE: usize = 1683;
/// Analogous to [MAX_BASE64_SIZE](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4341)
const MAX_BASE64_SIZE: usize = 1644;
const MAX_INSTRUCTION_TRACE_LENGTH = sig.runtime.transaction_context.MAX_INSTRUCTION_TRACE_LENGTH;
const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;

const SendTransactionHookContext = @This();

slot_tracker: *SlotTracker,
commitments: *CommitmentTracker,
account_store: sig.accounts_db.AccountStore,
epoch_tracker: *EpochTracker,
status_cache: *StatusCache,
tx_svc_channel: *Channel(TransactionInfo),

pub fn sendTransaction(
    self: SendTransactionHookContext,
    arena: Allocator,
    params: SendTransaction,
) !SendTransaction.Response {
    const config: SendTransaction.Config = params.config orelse .{};
    const encoding = config.resolveEncoding() orelse return error.UnsupportedEncoding;
    const skip_preflight = config.skipPreflight orelse false;

    const wire_transaction, const wire_len, const unsanitized_tx = try decodeAndDeserialize(
        arena,
        params.transaction,
        encoding,
    );

    const preflight_commitment = if (skip_preflight)
        .processed
    else
        config.preflightCommitment orelse .finalized;
    const preflight_slot = self.commitments.get(preflight_commitment);
    if (config.minContextSlot) |min_slot| {
        if (preflight_slot < min_slot) return error.RpcMinContextSlotNotMet;
    }
    const preflight_slot_ref = self.slot_tracker.get(preflight_slot) orelse return error.SlotNotFound;
    defer preflight_slot_ref.release();

    const transaction = try sanitizeTransaction(
        arena,
        unsanitized_tx,
        preflight_slot,
        &preflight_slot_ref,
        self.account_store.reader().forSlot(&preflight_slot_ref.constants().ancestors),
    );

    const durable_nonce_info: ?struct { Pubkey, Hash } = if (getDurableNonce(&transaction)) |nonce|
        .{ nonce, transaction.recent_blockhash }
    else
        null;

    const last_valid_block_height = blk: {
        const bq, var bq_lg = preflight_slot_ref.state().blockhash_queue.readWithLock();
        defer bq_lg.unlock();
        const block_height = preflight_slot_ref.constants().block_height;
        const value = bq.getLastValidBlockHeight(block_height, unsanitized_tx.msg.recent_blockhash);
        break :blk if (durable_nonce_info != null or (skip_preflight and value == null))
            block_height + sig.core.BlockhashQueue.MAX_PROCESSING_AGE
        else
            value orelse 0;
    };

    if (!skip_preflight) {
        const result: SimulateTransactionResult = blk: {
            unsanitized_tx.verify() catch break :blk .{ .err = .SignatureFailure };
            // TODO: Health Check
            // Agave json rpc config specifies a health check which checks node health before servicing requests.
            // We should consider the same.
            // [agave] https://github.com/anza-xyz/agave/blob/2a61a3ecd417b0515c0b2f322d0128394f20626b/rpc/src/rpc.rs#L3867-L3886
            break :blk try self.simulateRuntimeTransaction(
                arena,
                transaction,
                preflight_slot,
                &preflight_slot_ref,
            );
        };

        if (result.err) |err| {
            return .{ .preflight_failure = .{
                .err = err,
                .logs = result.logs,
                .units_consumed = result.units_consumed,
                .loaded_accounts_data_size = result.loaded_accounts_data_size,
            } };
        }
    }

    // NOTE: Agave returns the signature even if they fail to send the transaction to the pool for submission.
    // We intentially fail and return an RPC error instead.
    try self.tx_svc_channel.send(.initWithWire(
        unsanitized_tx,
        wire_transaction,
        wire_len,
        transaction.msg_hash,
        last_valid_block_height,
        durable_nonce_info,
        config.maxRetries,
    ));

    return .{ .signature = unsanitized_tx.signatures[0] };
}

pub fn simulateTransaction(
    self: SendTransactionHookContext,
    arena: Allocator,
    params: SimulateTransaction,
) !SimulateTransaction.Response {
    const config: SimulateTransaction.Config = params.config orelse .{};
    const encoding = config.resolveEncoding() orelse return error.UnsupportedEncoding;
    _, _, var unsanitized_tx = try decodeAndDeserialize(
        arena,
        params.transaction,
        encoding,
    );

    const commitment = config.commitment orelse .finalized;
    const slot = self.commitments.get(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }
    var slot_ref = self.slot_tracker.get(slot) orelse return error.SlotNotFound;
    defer slot_ref.release();

    const blockhash: ?GetLatestBlockhashValue = if (config.replaceRecentBlockhash) blk: {
        if (config.sigVerify) {
            // TODO: return a more helpful error here somehow
            return error.InvalidParams;
        }
        const recent_blockhash = last_bh: {
            const bq, var bq_lg = slot_ref.state().blockhash_queue.readWithLock();
            defer bq_lg.unlock();
            break :last_bh bq.last_hash orelse return error.SlotNotAvailable;
        };
        unsanitized_tx.msg.recent_blockhash = recent_blockhash;

        const last_valid_block_height = lvbh: {
            const bq, var bq_lg = slot_ref.state().blockhash_queue.readWithLock();
            defer bq_lg.unlock();
            break :lvbh bq.getLastValidBlockHeight(
                slot_ref.constants().block_height,
                unsanitized_tx.msg.recent_blockhash,
            ) orelse return error.NoLastValidBlockheight;
        };

        break :blk .{
            .blockhash = recent_blockhash,
            .lastValidBlockHeight = last_valid_block_height,
        };
    } else null;

    const slot_account_reader = self.account_store.reader().forSlot(&slot_ref.constants().ancestors);

    const transaction = try sanitizeTransaction(
        arena,
        unsanitized_tx,
        slot,
        &slot_ref,
        slot_account_reader,
    );

    const verification_error: ?TransactionError = if (config.sigVerify) blk: {
        unsanitized_tx.verify() catch break :blk .SignatureFailure;
        break :blk null;
    } else null;

    const simulation_result: SimulateTransactionResult = if (verification_error) |err|
        .{ .err = err }
    else
        try self.simulateRuntimeTransaction(arena, transaction, slot, &slot_ref);

    // Build accounts response if requested.
    // [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4030-L4074
    const accounts: ?[]const ?GetAccountInfo.Response.Value =
        if (config.accounts) |accounts_config| blk: {
            const accounts_encoding = accounts_config.encoding orelse .base64;
            if (accounts_encoding == .binary or accounts_encoding == .base58) {
                return error.InvalidParams;
            }

            if (accounts_config.addresses.len > transaction.accounts.len) {
                return error.InvalidParams;
            }

            // If simulation had an error, return null for each requested account.
            if (simulation_result.err != null) {
                const nulls = try arena.alloc(
                    ?GetAccountInfo.Response.Value,
                    accounts_config.addresses.len,
                );
                @memset(nulls, null);
                break :blk nulls;
            }

            const result = try arena.alloc(
                ?GetAccountInfo.Response.Value,
                accounts_config.addresses.len,
            );
            for (accounts_config.addresses, 0..) |address, i| {
                result[i] = try getSimulatedAccount(
                    arena,
                    address,
                    accounts_encoding,
                    simulation_result.post_simulation_accounts,
                    slot_account_reader,
                );
            }
            break :blk result;
        } else null;

    // Convert inner instructions if requested.
    // [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4076-L4080
    const inner_instructions = if (config.innerInstructions)
        if (simulation_result.inner_instructions) |iis|
            try GetBlock.Response.UiInnerInstructions.fromLedger(arena, iis)
        else
            null
    else
        null;

    // Convert return data to UI format (base64 encode).
    const return_data =
        if (simulation_result.return_data) |rd|
            try GetBlock.Response.UiTransactionReturnData.fromLedger(arena, rd)
        else
            null;

    // Resolve and convert token balances.
    // Uses a FallbackAccountReader that checks post-simulation writes first, then the bank.
    const pre_token_balances = try resolveAndConvertTokenBalances(
        arena,
        simulation_result.pre_token_balances,
        simulation_result.post_simulation_accounts,
        slot_account_reader,
    );
    const post_token_balances = try resolveAndConvertTokenBalances(
        arena,
        simulation_result.post_token_balances,
        simulation_result.post_simulation_accounts,
        slot_account_reader,
    );

    // Extract loaded addresses from the transaction (ALT-resolved accounts).
    const loaded_addresses = getLoadedAddresses(unsanitized_tx, transaction);

    return .{
        .context = .{ .slot = slot },
        .value = .{
            .err = simulation_result.err,
            .logs = simulation_result.logs,
            .accounts = accounts,
            .unitsConsumed = simulation_result.units_consumed,
            .loadedAccountsDataSize = simulation_result.loaded_accounts_data_size,
            .returnData = return_data,
            .innerInstructions = inner_instructions,
            .replacementBlockhash = blockhash,
            .fee = simulation_result.fee,
            .preBalances = simulation_result.pre_balances.constSlice(),
            .postBalances = simulation_result.post_balances.constSlice(),
            .preTokenBalances = pre_token_balances,
            .postTokenBalances = post_token_balances,
            .loadedAddresses = loaded_addresses,
        },
    };
}

/// Analogous to [decode_and_deserialize](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4343)
fn decodeAndDeserialize(
    arena: Allocator,
    encoded: []const u8,
    encoding: methods.common.TransactionBinaryEncoding,
) !struct { [PACKET_DATA_SIZE]u8, usize, Transaction } {
    var wire_transaction: [PACKET_DATA_SIZE]u8 = @splat(0);

    const wire_len: usize = switch (encoding) {
        .base58 => blk: {
            if (encoded.len > MAX_BASE58_SIZE) {
                // TODO: return a more helpful error here somehow
                return error.InvalidParams;
            }
            var decoded_buf: [base58.decodedMaxSize(MAX_BASE58_SIZE)]u8 = undefined;
            const decoded_len = base58.Table.BITCOIN.decode(&decoded_buf, encoded) catch {
                return error.InvalidParams;
            };
            if (decoded_len > PACKET_DATA_SIZE) return error.InvalidParams;
            @memcpy(wire_transaction[0..decoded_len], decoded_buf[0..decoded_len]);
            break :blk decoded_len;
        },
        .base64 => blk: {
            if (encoded.len > MAX_BASE64_SIZE) {
                // TODO: return a more helpful error here somehow
                return error.InvalidParams;
            }
            const decoded_len = Base64Decoder.calcSizeForSlice(encoded) catch {
                // TODO: return a more helpful error here somehow
                return error.InvalidParams;
            };
            if (decoded_len > PACKET_DATA_SIZE) return error.InvalidParams;
            Base64Decoder.decode(wire_transaction[0..decoded_len], encoded) catch {
                // TODO: return a more helpful error here somehow
                return error.InvalidParams;
            };
            break :blk decoded_len;
        },
    };
    const unsanitized_tx = sig.bincode.readFromSlice(
        arena,
        Transaction,
        wire_transaction[0..wire_len],
        .{ .allocation_limit = PACKET_DATA_SIZE, .int_encoding = .fixed },
    ) catch {
        // TODO: return a more helpful error here somehow
        return error.InvalidParams;
    };
    return .{ wire_transaction, wire_len, unsanitized_tx };
}

/// Analogous to [sanitize_transaction](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4405)
fn sanitizeTransaction(
    arena: Allocator,
    tx: Transaction,
    preflight_slot: Slot,
    preflight_slot_ref: *const SlotTracker.Reference,
    slot_account_reader: SlotAccountReader,
) !RuntimeTransaction {
    const enable_static_ixn_limit = preflight_slot_ref.constants().feature_set.active(
        .static_instruction_limit,
        preflight_slot,
    );
    if (enable_static_ixn_limit and tx.msg.instructions.len > MAX_INSTRUCTION_TRACE_LENGTH) {
        return error.SanitizeFailure;
    }

    try tx.validate();

    const slot_hashes = try getSysvarFromAccount(
        SlotHashes,
        arena,
        slot_account_reader,
    ) orelse SlotHashes.INIT;

    const resolved = try resolveTransaction(arena, tx, .{
        .slot = preflight_slot,
        .account_reader = slot_account_reader,
        .reserved_accounts = &preflight_slot_ref.constants().reserved_accounts,
        .slot_hashes = slot_hashes,
    });

    const compute_budget_instruction_details = switch (computeBudgetExecute(&tx.msg)) {
        .ok => |details| details,
        .err => return error.InvalidParams,
    };

    const msg_hash = Message.hash((try tx.msg.serializeBounded(tx.version)).constSlice());
    return .{
        .signature_count = tx.signatures.len,
        .fee_payer = tx.msg.account_keys[0],
        .msg_hash = msg_hash,
        .recent_blockhash = tx.msg.recent_blockhash,
        .instructions = resolved.instructions,
        .accounts = resolved.accounts,
        .compute_budget_instruction_details = compute_budget_instruction_details,
        .num_lookup_tables = tx.msg.address_lookups.len,
        .is_simple_vote_transaction = false,
    };
}

const SimulateTransactionResult = struct {
    err: ?TransactionError,
    logs: []const []const u8 = &[_][]const u8{},
    post_simulation_accounts: ProcessedTransaction.Writes = .{},
    units_consumed: u64 = 0,
    loaded_accounts_data_size: u32 = 0,
    return_data: ?TransactionReturnData = null,
    inner_instructions: ?[]const InnerInstructions = null,
    fee: ?u64 = null,
    pre_balances: ProcessedTransaction.PreBalances = .{},
    post_balances: ProcessedTransaction.PreBalances = .{},
    pre_token_balances: ProcessedTransaction.PreTokenBalances = .{},
    post_token_balances: ProcessedTransaction.PreTokenBalances = .{},
};

fn simulateRuntimeTransaction(
    self: *const SendTransactionHookContext,
    arena: Allocator,
    transaction: RuntimeTransaction,
    preflight_slot: Slot,
    preflight_slot_ref: *const SlotTracker.Reference,
    // TODO: enable_cpi_recording.
) !SimulateTransactionResult {
    const slot_state = preflight_slot_ref.state();
    const slot_constants = preflight_slot_ref.constants();

    const epoch_info = try self.epoch_tracker.getEpochInfo(preflight_slot);

    var svm_gateway = try SvmGateway.init(arena, .{
        .slot = preflight_slot,
        .max_age = sig.core.BlockhashQueue.MAX_PROCESSING_AGE / 2,
        .lamports_per_signature = slot_constants.fee_rate_governor.lamports_per_signature,
        .blockhash_queue = &slot_state.blockhash_queue,
        .account_store = self.account_store.forSlot(preflight_slot, &slot_constants.ancestors),
        .ancestors = &slot_constants.ancestors,
        .feature_set = slot_constants.feature_set,
        .rent_collector = &slot_constants.rent_collector,
        .epoch_stakes = &epoch_info.stakes,
        .status_cache = self.status_cache,
    });
    defer svm_gateway.deinit(arena);

    // For simulation/preflight, call loadAndExecuteTransaction directly
    // instead of executeTransaction, because we must NOT write results back
    // to the account store — the preflight slot may be finalized/rooted,
    // and writing to a rooted slot would fail with CannotWriteRootedSlot.
    const environment = try svm_gateway.environment();
    const processed_transaction =
        switch (try sig.runtime.transaction_execution.loadAndExecuteTransaction(
            arena,
            arena,
            &transaction,
            svm_gateway.params.account_store.reader(),
            &environment,
            &.{ .log = true, .log_messages_byte_limit = null },
            &svm_gateway.state.programs,
        )) {
            .ok => |processed_transaction| processed_transaction,
            .err => |err| return .{ .err = err },
        };

    const outputs = processed_transaction.outputs;

    const meta = sig.ledger.transaction_status.TransactionStatusMetaBuilder;
    return .{
        .err = processed_transaction.err,
        .logs = (try meta.extractLogMessages(arena, processed_transaction)) orelse &[_][]const u8{},
        .post_simulation_accounts = processed_transaction.writes,
        .units_consumed = if (outputs) |out| out.compute_limit - out.compute_meter else 0,
        .loaded_accounts_data_size = processed_transaction.loaded_accounts_data_size,
        .return_data = try meta.convertReturnData(arena, processed_transaction),
        .inner_instructions = try meta.convertInstructionTrace(arena, processed_transaction),
        .fee = processed_transaction.fees.total(),
        .pre_balances = processed_transaction.pre_balances,
        .post_balances = blk: {
            var post = processed_transaction.pre_balances;
            for (processed_transaction.writes.constSlice()) |*written_account| {
                for (transaction.accounts.items(.pubkey), 0..) |pubkey, idx| {
                    if (pubkey.equals(&written_account.pubkey)) {
                        post.set(idx, written_account.account.lamports);
                        break;
                    }
                }
            }
            break :blk post;
        },
        .pre_token_balances = processed_transaction.pre_token_balances,
        .post_token_balances = sig.runtime.spl_token.collectRawTokenBalances(
            processed_transaction.writes.constSlice(),
        ),
    };
}

/// Look up a post-simulation account by address, falling back to the bank state,
/// and encode it for the RPC response.
/// [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4042-L4072
fn getSimulatedAccount(
    arena: Allocator,
    address: Pubkey,
    encoding: methods.common.AccountEncoding,
    post_simulation_accounts: ProcessedTransaction.Writes,
    slot_reader: SlotAccountReader,
) !?GetAccountInfo.Response.Value {
    // Check post-simulation accounts first (these reflect state after simulation).
    for (post_simulation_accounts.constSlice()) |written| {
        if (!written.pubkey.equals(&address)) continue;
        const account: sig.core.Account = .{
            .lamports = written.account.lamports,
            .data = .{ .unowned_allocation = written.account.data },
            .owner = written.account.owner,
            .executable = written.account.executable,
            .rent_epoch = written.account.rent_epoch,
        };
        const data = try encodeAccount(
            arena,
            address,
            account,
            encoding,
            slot_reader,
            null,
        );
        return .from(account, data);
    }
    // Fall back to bank state.
    const account = try slot_reader.get(arena, address) orelse return null;
    const data = try encodeAccount(
        arena,
        address,
        account,
        encoding,
        slot_reader,
        null,
    );
    return .from(account, data);
}

/// Extract loaded addresses (ALT-resolved writable/readonly) from the resolved transaction.
/// The RuntimeTransaction accounts are ordered: [static keys] ++ [writable lookups] ++ [readonly lookups].
/// [agave] https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4102
fn getLoadedAddresses(
    unsanitized_tx: Transaction,
    transaction: RuntimeTransaction,
) GetBlock.Response.UiLoadedAddresses {
    const static_keys_len = unsanitized_tx.msg.account_keys.len;
    var writable_lookup_count: usize = 0;
    var readonly_lookup_count: usize = 0;
    for (unsanitized_tx.msg.address_lookups) |lookup| {
        writable_lookup_count += lookup.writable_indexes.len;
        readonly_lookup_count += lookup.readonly_indexes.len;
    }

    const pubkeys = transaction.accounts.items(.pubkey);
    const writable_start = static_keys_len;
    const readonly_start = writable_start + writable_lookup_count;

    return .{
        .writable = if (writable_lookup_count > 0)
            pubkeys[writable_start..readonly_start]
        else
            &.{},
        .readonly = if (readonly_lookup_count > 0)
            pubkeys[readonly_start .. readonly_start + readonly_lookup_count]
        else
            &.{},
    };
}

/// Resolve raw token balances (mint decimals lookup) and convert to UI format.
/// Uses a FallbackAccountReader that checks post-simulation writes first, then falls back
/// to the account store for mint accounts not modified by the transaction.
/// [reference] Committer.writeTransactionStatus uses the same FallbackAccountReader pattern.
fn resolveAndConvertTokenBalances(
    arena: Allocator,
    raw_balances: ProcessedTransaction.PreTokenBalances,
    post_simulation_accounts: ProcessedTransaction.Writes,
    slot_reader: SlotAccountReader,
) !?GetBlock.Response.UiTransactionTokenBalances {
    if (raw_balances.len == 0) return .{};

    const spl_token = sig.runtime.spl_token;

    var mint_cache = spl_token.MintDecimalsCache.init(arena);
    defer mint_cache.deinit();

    // Pre-populate cache with mints found in post-simulation writes.
    for (post_simulation_accounts.constSlice()) |*written_account| {
        const acc = written_account.account;
        if (acc.data.len >= spl_token.MINT_ACCOUNT_SIZE) {
            if (spl_token.ParsedMint.parse(acc.data[0..spl_token.MINT_ACCOUNT_SIZE])) |mint| {
                mint_cache.put(written_account.pubkey, mint.decimals) catch {};
            }
        }
    }

    const mint_reader = FallbackAccountReader{
        .writes = post_simulation_accounts.constSlice(),
        .account_store_reader = slot_reader,
    };

    const resolved = spl_token.resolveTokenBalances(
        arena,
        raw_balances,
        &mint_cache,
        FallbackAccountReader,
        mint_reader,
    ) catch return null;
    const balances = resolved orelse return null;

    return try GetBlock.Response.UiTransactionTokenBalances.fromLedger(arena, balances);
}

test "decodeAndDeserialize: base64 encoding succeeds" {
    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf: [std.base64.standard.Encoder.calcSize(tx_bytes.len)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encode_buf, &tx_bytes);

    const result = try decodeAndDeserialize(std.testing.allocator, encoded, .base64);
    const tx = result[2];
    defer tx.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), tx.signatures.len);
    try std.testing.expectEqual(.legacy, tx.version);
}

test "decodeAndDeserialize: base58 encoding succeeds" {
    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf: [base58.encodedMaxSize(tx_bytes.len)]u8 = undefined;
    const encoded_len = base58.Table.BITCOIN.encode(&encode_buf, &tx_bytes);
    const encoded = encode_buf[0..encoded_len];

    const result = try decodeAndDeserialize(std.testing.allocator, encoded, .base58);
    const tx = result[2];
    defer tx.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), tx.signatures.len);
    try std.testing.expectEqual(.legacy, tx.version);
}

test "decodeAndDeserialize: base64 too large returns InvalidParams" {
    const oversized = "A" ** (MAX_BASE64_SIZE + 1);
    try std.testing.expectError(
        error.InvalidParams,
        decodeAndDeserialize(std.testing.allocator, oversized, .base64),
    );
}

test "decodeAndDeserialize: base58 too large returns InvalidParams" {
    const oversized = "1" ** (MAX_BASE58_SIZE + 1);
    try std.testing.expectError(
        error.InvalidParams,
        decodeAndDeserialize(std.testing.allocator, oversized, .base58),
    );
}

test "decodeAndDeserialize: invalid base64 returns InvalidParams" {
    try std.testing.expectError(
        error.InvalidParams,
        decodeAndDeserialize(std.testing.allocator, "!!!invalid-base64!!!", .base64),
    );
}

test "decodeAndDeserialize: invalid base58 returns error" {
    // 'l' is not a valid base58 character
    try std.testing.expectError(
        error.InvalidParams,
        decodeAndDeserialize(std.testing.allocator, "lll", .base58),
    );
}

test "decodeAndDeserialize: base64 invalid transaction data returns InvalidParams" {
    // Valid base64 but not valid bincode transaction
    var encode_buf: [std.base64.standard.Encoder.calcSize(4)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(
        &encode_buf,
        &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF },
    );
    try std.testing.expectError(
        error.InvalidParams,
        decodeAndDeserialize(std.testing.allocator, encoded, .base64),
    );
}

test "decodeAndDeserialize: wire_transaction contains decoded bytes" {
    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf: [std.base64.standard.Encoder.calcSize(tx_bytes.len)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encode_buf, &tx_bytes);

    const result = try decodeAndDeserialize(std.testing.allocator, encoded, .base64);
    const wire_transaction = result[0];
    const tx = result[2];
    defer tx.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, &tx_bytes, wire_transaction[0..tx_bytes.len]);
    // Rest should be zero-filled
    for (wire_transaction[tx_bytes.len..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test sendTransaction {
    const allocator = std.testing.allocator;

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .constants = .{
            .parent_slot = 0,
            .parent_hash = .ZEROES,
            .parent_lt_hash = .IDENTITY,
            .block_height = 0,
            .collector_id = .ZEROES,
            .max_tick_height = 0,
            .fee_rate_governor = .DEFAULT,
            .ancestors = .{ .ancestors = .empty },
            .feature_set = .ALL_DISABLED,
            .reserved_accounts = .empty,
            .inflation = .DEFAULT,
            .rent_collector = .DEFAULT,
        },
        .state = .GENESIS,
        .allocator = allocator,
    });
    defer slot_tracker.deinit(allocator);

    const channel = try Channel(TransactionInfo).create(allocator);
    defer channel.destroy();

    var commitments = CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    var epoch_tracker = try EpochTracker.initForTest(allocator, std.crypto.random, 0, .INIT);
    defer epoch_tracker.deinit();

    var status_cache = StatusCache.DEFAULT;
    errdefer status_cache.deinit(allocator);

    const ctx: SendTransactionHookContext = .{
        .slot_tracker = &slot_tracker,
        .commitments = &commitments,
        .account_store = .noop,
        .epoch_tracker = &epoch_tracker,
        .status_cache = &status_cache,
        .tx_svc_channel = channel,
    };

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf_58: [base58.encodedMaxSize(tx_bytes.len)]u8 = undefined;
    const encoded_58_len = base58.Table.BITCOIN.encode(&encode_buf_58, &tx_bytes);
    const encoded_58 = encode_buf_58[0..encoded_58_len];

    { // Success
        var encode_buf_64: [std.base64.standard.Encoder.calcSize(tx_bytes.len)]u8 = undefined;
        const encoded_64 = std.base64.standard.Encoder.encode(&encode_buf_64, &tx_bytes);
        const result = try ctx.sendTransaction(arena, .{
            .transaction = encoded_64,
            .config = .{
                .skipPreflight = true,
                .encoding = .base64,
            },
        });
        const expected_sig = sig.core.transaction.transaction_legacy_example.as_struct.signatures[0];
        try std.testing.expect(expected_sig.eql(&result.signature));
        const txn_info = channel.tryReceive().?;
        try std.testing.expectEqual(expected_sig, txn_info.signature);
    }

    { // Unknown encoding
        try std.testing.expectError(
            error.UnsupportedEncoding,
            ctx.sendTransaction(arena, .{
                .transaction = "anything",
                .config = .{ .encoding = .json },
            }),
        );
    }

    { // Min context slot not met
        try std.testing.expectError(
            error.RpcMinContextSlotNotMet,
            ctx.sendTransaction(arena, .{
                .transaction = encoded_58,
                .config = .{ .minContextSlot = 1 },
            }),
        );
    }

    { // Slot not found
        commitments.finalized.store(1, .monotonic);
        commitments.confirmed.store(1, .monotonic);
        commitments.processed.store(1, .monotonic);
        defer {
            commitments.finalized.store(0, .monotonic);
            commitments.confirmed.store(0, .monotonic);
            commitments.processed.store(0, .monotonic);
        }

        try std.testing.expectError(
            error.SlotNotFound,
            ctx.sendTransaction(arena, .{
                .transaction = encoded_58,
                .config = .{ .preflightCommitment = .finalized },
            }),
        );
    }

    { // Preflight failure (skipPreflight = false, corrupted signature)
        var bad_tx_bytes = tx_bytes;
        bad_tx_bytes[1] ^= 0xFF; // Corrupt first byte of signature
        var encode_buf_64: [std.base64.standard.Encoder.calcSize(bad_tx_bytes.len)]u8 = undefined;
        const encoded_64 = std.base64.standard.Encoder.encode(&encode_buf_64, &bad_tx_bytes);
        const result = try ctx.sendTransaction(arena, .{
            .transaction = encoded_64,
            .config = .{
                .encoding = .base64,
                // skipPreflight defaults to false; verify() fails → preflight_failure
            },
        });
        try std.testing.expect(result == .preflight_failure);
        try std.testing.expectEqual(TransactionError.SignatureFailure, result.preflight_failure.err);
    }
}

test simulateTransaction {
    const allocator = std.testing.allocator;

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .constants = .{
            .parent_slot = 0,
            .parent_hash = .ZEROES,
            .parent_lt_hash = .IDENTITY,
            .block_height = 0,
            .collector_id = .ZEROES,
            .max_tick_height = 0,
            .fee_rate_governor = .DEFAULT,
            .ancestors = .{ .ancestors = .empty },
            .feature_set = .ALL_DISABLED,
            .reserved_accounts = .empty,
            .inflation = .DEFAULT,
            .rent_collector = .DEFAULT,
        },
        .state = .GENESIS,
        .allocator = allocator,
    });
    defer slot_tracker.deinit(allocator);

    const channel = try Channel(TransactionInfo).create(allocator);
    defer channel.destroy();

    var commitments = CommitmentTracker.init(allocator, 0);
    defer commitments.deinit(allocator);

    var epoch_tracker = try EpochTracker.initForTest(allocator, std.crypto.random, 0, .INIT);
    defer epoch_tracker.deinit();

    var status_cache = StatusCache.DEFAULT;
    errdefer status_cache.deinit(allocator);

    const ctx: SendTransactionHookContext = .{
        .slot_tracker = &slot_tracker,
        .commitments = &commitments,
        .account_store = .noop,
        .epoch_tracker = &epoch_tracker,
        .status_cache = &status_cache,
        .tx_svc_channel = channel,
    };

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf_58: [base58.encodedMaxSize(tx_bytes.len)]u8 = undefined;
    const encoded_58_len = base58.Table.BITCOIN.encode(&encode_buf_58, &tx_bytes);
    const encoded_58 = encode_buf_58[0..encoded_58_len];

    { // Unsupported encoding
        try std.testing.expectError(
            error.UnsupportedEncoding,
            ctx.simulateTransaction(arena, .{
                .transaction = "anything",
                .config = .{ .encoding = .json },
            }),
        );
    }

    { // Min context slot not met
        try std.testing.expectError(
            error.RpcMinContextSlotNotMet,
            ctx.simulateTransaction(arena, .{
                .transaction = encoded_58,
                .config = .{ .minContextSlot = 1 },
            }),
        );
    }

    { // Slot not found
        commitments.finalized.store(1, .monotonic);
        commitments.confirmed.store(1, .monotonic);
        commitments.processed.store(1, .monotonic);
        defer {
            commitments.finalized.store(0, .monotonic);
            commitments.confirmed.store(0, .monotonic);
            commitments.processed.store(0, .monotonic);
        }

        try std.testing.expectError(
            error.SlotNotFound,
            ctx.simulateTransaction(arena, .{
                .transaction = encoded_58,
                .config = .{ .commitment = .finalized },
            }),
        );
    }

    { // replaceRecentBlockhash + sigVerify conflict
        try std.testing.expectError(
            error.InvalidParams,
            ctx.simulateTransaction(arena, .{
                .transaction = encoded_58,
                .config = .{
                    .replaceRecentBlockhash = true,
                    .sigVerify = true,
                },
            }),
        );
    }

    // Corrupt the signature so verify() fails, allowing us to test the response
    // building code paths without needing a fully initialized runtime.
    var bad_tx_bytes = tx_bytes;
    bad_tx_bytes[1] ^= 0xFF;
    var encode_buf_64: [std.base64.standard.Encoder.calcSize(bad_tx_bytes.len)]u8 = undefined;
    const encoded_64 = std.base64.standard.Encoder.encode(&encode_buf_64, &bad_tx_bytes);

    { // sigVerify failure builds full response
        const result = try ctx.simulateTransaction(arena, .{
            .transaction = encoded_64,
            .config = .{
                .sigVerify = true,
                .encoding = .base64,
                .innerInstructions = true,
            },
        });
        try std.testing.expectEqual(@as(u64, 0), result.context.slot);
        try std.testing.expectEqual(TransactionError.SignatureFailure, result.value.err.?);
        try std.testing.expectEqual(@as(?u64, 0), result.value.unitsConsumed);
        try std.testing.expectEqual(@as(?u64, null), result.value.fee);
        try std.testing.expect(result.value.accounts == null);
        try std.testing.expect(result.value.innerInstructions == null);
        try std.testing.expect(result.value.returnData == null);
        try std.testing.expect(result.value.replacementBlockhash == null);
        // Loaded addresses should be empty for legacy tx (no ALTs)
        const la = result.value.loadedAddresses.?;
        try std.testing.expectEqual(@as(usize, 0), la.writable.len);
        try std.testing.expectEqual(@as(usize, 0), la.readonly.len);
    }

    { // sigVerify failure with accounts config returns nulls
        const result = try ctx.simulateTransaction(arena, .{
            .transaction = encoded_64,
            .config = .{
                .sigVerify = true,
                .encoding = .base64,
                .accounts = .{
                    .addresses = &.{Pubkey.ZEROES},
                },
            },
        });
        try std.testing.expect(result.value.err != null);
        const accounts = result.value.accounts.?;
        try std.testing.expectEqual(@as(usize, 1), accounts.len);
        try std.testing.expect(accounts[0] == null);
    }

    { // accounts config with base58 encoding returns InvalidParams
        try std.testing.expectError(
            error.InvalidParams,
            ctx.simulateTransaction(arena, .{
                .transaction = encoded_64,
                .config = .{
                    .sigVerify = true,
                    .encoding = .base64,
                    .accounts = .{
                        .encoding = .base58,
                        .addresses = &.{Pubkey.ZEROES},
                    },
                },
            }),
        );
    }

    { // accounts config with too many addresses returns InvalidParams
        const many_addresses = try arena.alloc(Pubkey, 200);
        @memset(many_addresses, Pubkey.ZEROES);
        try std.testing.expectError(
            error.InvalidParams,
            ctx.simulateTransaction(arena, .{
                .transaction = encoded_64,
                .config = .{
                    .sigVerify = true,
                    .encoding = .base64,
                    .accounts = .{
                        .addresses = many_addresses,
                    },
                },
            }),
        );
    }
}
