const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;
const GeyserWriter = sig.geyser.GeyserWriter;
const TradeEventV1 = sig.geyser.core.TradeEventV1;
const VersionedAccountPayload = sig.geyser.core.VersionedAccountPayload;

const PUMPFUN_PROGRAM = Pubkey.parseRuntime("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P") catch unreachable;

const BUY_DISCRIMINATOR: [8]u8 = .{ 0x66, 0x06, 0x3d, 0x12, 0x01, 0xda, 0xeb, 0xea };
const SELL_DISCRIMINATOR: [8]u8 = .{ 0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad };

/// Parse PumpFun buy/sell instructions from a transaction and emit TradeEventV1
/// via the geyser writer. Called per-transaction in replayBatch before SVM execution.
/// Safe to call with null geyser_writer — returns immediately.
pub fn parseTransaction(
    tx: *const Transaction,
    slot: u64,
    geyser_writer: ?*GeyserWriter,
) void {
    const gw = geyser_writer orelse return;

    for (tx.msg.instructions) |instr| {
        if (instr.program_index >= tx.msg.account_keys.len) continue;
        const program_id = &tx.msg.account_keys[instr.program_index];
        if (!program_id.equals(&PUMPFUN_PROGRAM)) continue;

        const data = instr.data;
        if (data.len < 16) continue; // need 8 disc + 8 token_amount

        const disc = data[0..8];

        const direction: u8 = if (std.mem.eql(u8, disc, &BUY_DISCRIMINATOR))
            0
        else if (std.mem.eql(u8, disc, &SELL_DISCRIMINATOR))
            1
        else
            continue;

        // accounts[2] = mint, accounts[3] = bonding curve, accounts[6] = user wallet
        if (instr.account_indexes.len < 7) continue;
        const mint_idx = instr.account_indexes[2];
        const curve_idx = instr.account_indexes[3];
        const wallet_idx = instr.account_indexes[6];
        if (mint_idx >= tx.msg.account_keys.len) continue;
        if (curve_idx >= tx.msg.account_keys.len) continue;
        if (wallet_idx >= tx.msg.account_keys.len) continue;

        const mint_pubkey = tx.msg.account_keys[mint_idx];
        const curve_pubkey = tx.msg.account_keys[curve_idx];
        const wallet_pubkey = tx.msg.account_keys[wallet_idx];
        // Anchor IDL: buy(amount: u64, max_sol_cost: u64) — data[8..16] = token amount
        const token_amount = std.mem.readInt(u64, data[8..16], .little);

        const event = TradeEventV1{
            .slot = slot,
            .mint = mint_pubkey.data,
            .curve = curve_pubkey.data,
            .wallet = wallet_pubkey.data,
            .token_amount = token_amount,
            .direction = direction,
        };

        gw.writePayloadToPipe(.{ .TradeEventV1 = event }) catch {};
    }
}
