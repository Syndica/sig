//! RPC hook context for transaction sending-related methods.
//! Requires access to ... for ... .
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const methods = @import("../methods.zig");

const Allocator = std.mem.Allocator;
const Channel = sig.sync.Channel;
const Base64Decoder = std.base64.standard.Decoder;
const Hash = sig.core.Hash;
const Message = sig.core.transaction.Message;
const Pubkey = sig.core.Pubkey;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SendTransaction = methods.SendTransaction;
const Slot = sig.core.Slot;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const SlotTracker = sig.replay.trackers.SlotTracker;
const Transaction = sig.core.Transaction;
const TransactionInfo = sig.TransactionSenderService.TransactionInfo;

const computeBudgetExecute = sig.runtime.program.compute_budget.execute;
const getDurableNonce = sig.runtime.check_transactions.getDurableNonce;
const getSysvarFromAccount = sig.replay.update_sysvar.getSysvarFromAccount;
const resolveTransaction = sig.replay.resolve_lookup.resolveTransaction;

/// Analogous to [MAX_BASE58_SIZE](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4341)
const MAX_BASE58_SIZE: usize = 1683;
/// Analogous to [MAX_BASE64_SIZE](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4341)
const MAX_BASE64_SIZE: usize = 1644;
const MAX_INSTRUCTION_TRACE_LENGTH = sig.runtime.transaction_context.MAX_INSTRUCTION_TRACE_LENGTH;
const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;

const SendTransactionHookContext = @This();

slot_tracker: *SlotTracker,
account_reader: sig.accounts_db.AccountReader,
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
    const preflight_slot = self.slot_tracker.commitments.get(preflight_commitment);
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
        self.account_reader.forSlot(&preflight_slot_ref.constants().ancestors),
    );

    const durable_nonce_info: ?struct { Pubkey, Hash } = if (getDurableNonce(&transaction)) |nonce|
        .{ nonce, transaction.recent_blockhash }
    else
        null;

    const last_valid_block_height = blk: {
        const value = preflight_slot_ref.getBlockhashLastValidBlockHeight(
            unsanitized_tx.msg.recent_blockhash,
        );
        const block_height = preflight_slot_ref.constants().block_height;
        break :blk if (durable_nonce_info != null or (skip_preflight and value == null))
            block_height + sig.core.BlockhashQueue.MAX_PROCESSING_AGE
        else
            value orelse 0;
    };

    if (!skip_preflight) {
        @panic("TODO");
    }

    return try sendTransactionImpl(
        self.tx_svc_channel,
        unsanitized_tx,
        transaction.msg_hash,
        wire_transaction,
        wire_len,
        last_valid_block_height,
        durable_nonce_info,
        config.maxRetries,
    );
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
            const decoded_len = try base58.Table.BITCOIN.decode(&decoded_buf, encoded);
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

/// Analogous to [_send_transaction](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L2675)
fn sendTransactionImpl(
    transaction_sender: *Channel(TransactionInfo),
    transaction: Transaction,
    message_hash: Hash,
    wire_transaction: [PACKET_DATA_SIZE]u8,
    wire_transaction_size: usize,
    last_valid_block_height: u64,
    durable_nonce_info: ?struct { Pubkey, Hash },
    max_retries: ?usize,
) !SendTransaction.Response {
    const signature = transaction.signatures[0];
    const transaction_info: TransactionInfo = .initWithWire(
        transaction,
        wire_transaction,
        wire_transaction_size,
        message_hash,
        last_valid_block_height,
        durable_nonce_info,
        max_retries,
    );
    try transaction_sender.send(transaction_info);
    return signature;
}

/// Analagous to [sanitize_transaction](https://github.com/anza-xyz/agave/blob/765ee54adc4f574b1cd4f03a5500bf46c0af0817/rpc/src/rpc.rs#L4405)
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

    const slot_hashes = getSysvarFromAccount(
        SlotHashes,
        arena,
        slot_account_reader,
    ) catch null orelse SlotHashes.INIT;

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

test "decodeAndDeserialize: base64 encoding succeeds" {
    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf: [std.base64.standard.Encoder.calcSize(tx_bytes.len)]u8 = undefined;
    const encoded = std.base64.standard.Encoder.encode(&encode_buf, tx_bytes);

    const result = try decodeAndDeserialize(std.testing.allocator, encoded, .base64);
    const tx = result[1];

    try std.testing.expectEqual(@as(usize, 1), tx.signatures.len);
    try std.testing.expectEqual(.legacy, tx.version);
}

test "decodeAndDeserialize: base58 encoding succeeds" {
    const tx_bytes = sig.core.transaction.transaction_legacy_example.as_bytes;
    var encode_buf: [base58.encodedMaxSize(tx_bytes.len)]u8 = undefined;
    const encoded_len = base58.Table.BITCOIN.encode(&encode_buf, tx_bytes);
    const encoded = encode_buf[0..encoded_len];

    const result = try decodeAndDeserialize(std.testing.allocator, encoded, .base58);
    const tx = result[1];

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
        error.NonBase58Character,
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
    const encoded = std.base64.standard.Encoder.encode(&encode_buf, tx_bytes);

    const wire_transaction = (try decodeAndDeserialize(std.testing.allocator, encoded, .base64))[0];

    try std.testing.expectEqualSlices(u8, tx_bytes, wire_transaction[0..tx_bytes.len]);
    // Rest should be zero-filled
    for (wire_transaction[tx_bytes.len..]) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "sendTransactionImpl: sends transaction and returns signature" {
    const channel = try Channel(TransactionInfo).create(std.testing.allocator);
    defer channel.destroy();

    const tx = sig.core.transaction.transaction_legacy_example.as_struct;
    const wire: [PACKET_DATA_SIZE]u8 = @splat(0);
    const msg_hash = Hash.ZEROES;

    const result = try sendTransactionImpl(
        channel,
        tx,
        msg_hash,
        wire,
        1000,
        null,
        null,
    );

    // Should return the first signature
    try std.testing.expectEqualSlices(u8, &tx.signatures[0].data, &result.data);

    // Channel should have received the transaction info
    const received = channel.tryReceive().?;
    try std.testing.expectEqual(msg_hash, received.message_hash);
    try std.testing.expectEqual(@as(u64, 1000), received.last_valid_block_height);
    try std.testing.expectEqual(@as(?struct { Pubkey, Hash }, null), received.durable_nonce_info);
    try std.testing.expectEqual(std.math.maxInt(usize), received.max_retries);
}

test "sendTransactionImpl: with durable nonce info" {
    const channel = try Channel(TransactionInfo).create(std.testing.allocator);
    defer channel.destroy();

    const tx = sig.core.transaction.transaction_legacy_example.as_struct;
    const wire: [PACKET_DATA_SIZE]u8 = @splat(0);
    const nonce_pubkey = Pubkey.ZEROES;
    const nonce_hash = Hash.ZEROES;

    _ = try sendTransactionImpl(
        channel,
        tx,
        Hash.ZEROES,
        wire,
        500,
        .{ nonce_pubkey, nonce_hash },
        5,
    );

    const received = channel.tryReceive().?;
    try std.testing.expect(received.durable_nonce_info != null);
    try std.testing.expectEqual(@as(usize, 5), received.max_retries);
}
