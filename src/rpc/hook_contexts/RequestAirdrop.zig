//! RPC hook context for the requestAirdrop method.
//! Creates a system transfer transaction from a faucet account to a recipient.

const std = @import("std");
const sig = @import("../../sig.zig");
const methods = @import("../methods.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Allocator = std.mem.Allocator;
const Channel = sig.sync.Channel;
const Hash = sig.core.Hash;
const Message = sig.core.transaction.Message;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotTracker = sig.replay.trackers.SlotTracker;
const Transaction = sig.core.Transaction;
const TransactionInfo = sig.TransactionSenderService.TransactionInfo;

const RequestAirdrop = methods.RequestAirdrop;
const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;

const RequestAirdropHookContext = @This();

slot_tracker: *SlotTracker,
tx_svc_channel: *Channel(TransactionInfo),
faucet_keypair: *const KeyPair,

/// Requests an airdrop by creating and sending a system transfer transaction from the faucet account to the specified recipient.
/// Returns the signature of the submitted transaction on success.
/// NOTE: Rate limiting and faucet balance checks are not implemented. Consider implementing:
/// - ip whitelist
/// - ip max request count per time window
/// - recipient max request count per time window
/// - min/max lamports per request
pub fn requestAirdrop(
    self: RequestAirdropHookContext,
    arena: Allocator,
    params: RequestAirdrop,
) !RequestAirdrop.Response {
    const commitment = if (params.config) |config| config.commitment else .finalized;
    const airdrop_slot = self.slot_tracker.commitments.get(commitment);

    var slot_ref = self.slot_tracker.get(airdrop_slot) orelse return error.SlotNotAvailable;
    defer slot_ref.release();

    const blockhash = blk: {
        const bq, var bq_lg = slot_ref.state().blockhash_queue.readWithLock();
        defer bq_lg.unlock();
        break :blk bq.last_hash orelse return error.SlotNotAvailable;
    };

    const last_valid_block_height = slot_ref.getBlockhashLastValidBlockHeight(blockhash) orelse 0;

    const faucet_pubkey = Pubkey.fromPublicKey(&self.faucet_keypair.public_key);
    const instruction = try sig.runtime.program.system.transfer(
        arena,
        faucet_pubkey,
        params.pubkey,
        params.lamports,
    );
    defer instruction.deinit(arena);

    var message = try Message.initCompile(
        arena,
        &.{instruction},
        faucet_pubkey,
        blockhash,
        null,
    );
    errdefer message.deinit(arena);

    const transaction = try Transaction.initOwnedMessageWithSigningKeypairs(
        arena,
        .v0,
        message,
        &.{self.faucet_keypair.*},
    );

    var wire_transaction: [PACKET_DATA_SIZE]u8 = @splat(0);
    const wire_transaction_serialized = sig.bincode.writeToSlice(
        &wire_transaction,
        transaction,
        .{ .int_encoding = .fixed },
    ) catch |err| switch (err) {
        error.NoSpaceLeft => return error.TransactionTooLarge,
        else => return err,
    };

    const msg_hash = Message.hash(
        (try transaction.msg.serializeBounded(transaction.version)).constSlice(),
    );

    const transaction_info: TransactionInfo = .initWithWire(
        transaction,
        wire_transaction,
        wire_transaction_serialized.len,
        msg_hash,
        last_valid_block_height,
        null, // no durable nonce for airdrop
        null, // no max_retries for airdrop
    );
    try self.tx_svc_channel.send(transaction_info);

    return transaction.signatures[0];
}

fn testDummySlotConstants(slot: Slot, block_height: u64) sig.core.SlotConstants {
    return .{
        .parent_slot = slot -| 1,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = block_height,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

fn testDummySlotState(transaction_count: u64) sig.core.SlotState {
    var state: sig.core.SlotState = .GENESIS;
    state.transaction_count = .init(transaction_count);
    return state;
}

fn testSetupSlotTracker(
    root_slot: Slot,
    root_block_height: u64,
    root_tx_count: u64,
) !SlotTracker {
    return .init(std.testing.allocator, root_slot, .{
        .constants = testDummySlotConstants(root_slot, root_block_height),
        .state = testDummySlotState(root_tx_count),
        .allocator = std.testing.allocator,
    });
}

test "RequestAirdropHookContext.requestAirdrop - happy path" {
    const channel = try Channel(TransactionInfo).create(std.testing.allocator);
    defer channel.destroy();

    var state = testDummySlotState(0);
    const blockhash = Hash.ZEROES;
    {
        const bq, var bq_lock = state.blockhash_queue.writeWithLock();
        defer bq_lock.unlock();
        try bq.insertHash(std.testing.allocator, blockhash, 0);
    }

    var slot_tracker: SlotTracker = try .init(std.testing.allocator, 42, .{
        .constants = testDummySlotConstants(42, 100),
        .state = state,
        .allocator = std.testing.allocator,
    });
    defer slot_tracker.deinit(std.testing.allocator);

    const faucet_seed: [32]u8 = [_]u8{0} ** 32;
    const faucet_keypair = try KeyPair.generateDeterministic(faucet_seed);
    const ctx: RequestAirdropHookContext = .{
        .slot_tracker = &slot_tracker,
        .tx_svc_channel = channel,
        .faucet_keypair = &faucet_keypair,
    };

    const signature = try ctx.requestAirdrop(std.testing.allocator, .{
        .pubkey = Pubkey.ZEROES,
        .lamports = 123,
    });

    const info = channel.tryReceive().?;
    try std.testing.expectEqual(signature, info.signature);
    try std.testing.expectEqual(blockhash, info.recent_blockhash);
    try std.testing.expect(info.wire_transaction_size > 0);
    try std.testing.expect(channel.tryReceive() == null);

    const wire_tx = try sig.bincode.readFromSlice(
        std.testing.allocator,
        Transaction,
        info.wire_transaction[0..info.wire_transaction_size],
        .{},
    );
    defer wire_tx.deinit(std.testing.allocator);

    const expected_msg_hash = Message.hash(
        (try wire_tx.msg.serializeBounded(wire_tx.version)).constSlice(),
    );
    try std.testing.expectEqual(expected_msg_hash, info.message_hash);

    var slot_ref = slot_tracker.get(42).?;
    defer slot_ref.release();
    const expected_last_valid = slot_ref.getBlockhashLastValidBlockHeight(blockhash) orelse 0;
    try std.testing.expectEqual(expected_last_valid, info.last_valid_block_height);
}

test "RequestAirdropHookContext.requestAirdrop - slot missing" {
    const channel = try Channel(TransactionInfo).create(std.testing.allocator);
    defer channel.destroy();

    var slot_tracker: SlotTracker = try .initEmpty(std.testing.allocator, 10);
    defer slot_tracker.deinit(std.testing.allocator);

    const faucet_seed: [32]u8 = [_]u8{1} ** 32;
    const faucet_keypair = try KeyPair.generateDeterministic(faucet_seed);
    const ctx: RequestAirdropHookContext = .{
        .slot_tracker = &slot_tracker,
        .tx_svc_channel = channel,
        .faucet_keypair = &faucet_keypair,
    };

    try std.testing.expectError(
        error.SlotNotAvailable,
        ctx.requestAirdrop(std.testing.allocator, .{
            .pubkey = Pubkey.ZEROES,
            .lamports = 1,
        }),
    );
    try std.testing.expect(channel.tryReceive() == null);
}

test "RequestAirdropHookContext.requestAirdrop - blockhash missing" {
    const channel = try Channel(TransactionInfo).create(std.testing.allocator);
    defer channel.destroy();

    var slot_tracker = try testSetupSlotTracker(42, 100, 0);
    defer slot_tracker.deinit(std.testing.allocator);

    const faucet_seed: [32]u8 = [_]u8{2} ** 32;
    const faucet_keypair = try KeyPair.generateDeterministic(faucet_seed);
    const ctx: RequestAirdropHookContext = .{
        .slot_tracker = &slot_tracker,
        .tx_svc_channel = channel,
        .faucet_keypair = &faucet_keypair,
    };

    try std.testing.expectError(
        error.SlotNotAvailable,
        ctx.requestAirdrop(std.testing.allocator, .{
            .pubkey = Pubkey.ZEROES,
            .lamports = 1,
        }),
    );
    try std.testing.expect(channel.tryReceive() == null);
}
