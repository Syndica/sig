const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;
const GeyserWriter = sig.geyser.GeyserWriter;
const PumpSwapPoolCreatedV1 = sig.geyser.core.PumpSwapPoolCreatedV1;
const PumpSwapTradeV1 = sig.geyser.core.PumpSwapTradeV1;

const PUMPSWAP_PROGRAM = Pubkey.parseRuntime("pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA") catch unreachable;

// Anchor discriminators (sha256("global:<name>")[0..8], little-endian)
const CREATE_POOL_DISCRIMINATOR: [8]u8 = .{ 0xe9, 0x92, 0xd1, 0x8e, 0xcf, 0x68, 0x40, 0xbc };
const BUY_DISCRIMINATOR: [8]u8    = .{ 0x66, 0x06, 0x3d, 0x12, 0x01, 0xda, 0xeb, 0xea };
const SELL_DISCRIMINATOR: [8]u8   = .{ 0x33, 0xe6, 0x85, 0xa4, 0x01, 0x7f, 0x83, 0xad };

/// Parse PumpSwap instructions from a transaction and emit pool/trade events.
/// Mirrors pumpfun_parser.parseTransaction — safe to call with null geyser_writer.
pub fn parseTransaction(
    tx: *const Transaction,
    slot: u64,
    geyser_writer: ?*GeyserWriter,
) void {
    const gw = geyser_writer orelse return;

    for (tx.msg.instructions) |instr| {
        if (instr.program_index >= tx.msg.account_keys.len) continue;
        const program_id = &tx.msg.account_keys[instr.program_index];
        if (!program_id.equals(&PUMPSWAP_PROGRAM)) continue;

        const data = instr.data;
        if (data.len < 8) continue;
        const disc = data[0..8];

        if (std.mem.eql(u8, disc, &CREATE_POOL_DISCRIMINATOR)) {
            // CreatePool args after discriminator: index(u16) + base_amount_in(u64) + quote_amount_in(u64)
            // Total needed: 8 + 2 + 8 + 8 = 26 bytes
            if (data.len < 26) continue;
            // accounts[0]=pool, accounts[9]=pool_base_token_account, accounts[10]=pool_quote_token_account
            if (instr.account_indexes.len < 1) continue;
            const pool_idx = instr.account_indexes[0];
            if (pool_idx >= tx.msg.account_keys.len) continue;

            const pool_pubkey = tx.msg.account_keys[pool_idx];
            // Skip index (u16) at data[8..10], read base at [10..18], quote at [18..26]
            const base_amount = std.mem.readInt(u64, data[10..18], .little);
            const quote_amount = std.mem.readInt(u64, data[18..26], .little);

            const event = PumpSwapPoolCreatedV1{
                .slot = slot,
                .pool = pool_pubkey.data,
                .base_amount = base_amount,
                .quote_amount = quote_amount,
            };
            gw.writePayloadToPipe(.{ .PumpSwapPoolCreatedV1 = event }) catch {};

        } else if (std.mem.eql(u8, disc, &BUY_DISCRIMINATOR)) {
            // Buy args: base_amount_out(u64) at data[8..16]
            if (data.len < 16) continue;
            // accounts[0]=pool, accounts[1]=user
            if (instr.account_indexes.len < 2) continue;
            const pool_idx = instr.account_indexes[0];
            const user_idx = instr.account_indexes[1];
            if (pool_idx >= tx.msg.account_keys.len) continue;
            if (user_idx >= tx.msg.account_keys.len) continue;

            const event = PumpSwapTradeV1{
                .slot = slot,
                .pool = tx.msg.account_keys[pool_idx].data,
                .user = tx.msg.account_keys[user_idx].data,
                .base_amount = std.mem.readInt(u64, data[8..16], .little),
                .direction = 0,
            };
            gw.writePayloadToPipe(.{ .PumpSwapTradeV1 = event }) catch {};

        } else if (std.mem.eql(u8, disc, &SELL_DISCRIMINATOR)) {
            // Sell args: base_amount_in(u64) at data[8..16]
            if (data.len < 16) continue;
            if (instr.account_indexes.len < 2) continue;
            const pool_idx = instr.account_indexes[0];
            const user_idx = instr.account_indexes[1];
            if (pool_idx >= tx.msg.account_keys.len) continue;
            if (user_idx >= tx.msg.account_keys.len) continue;

            const event = PumpSwapTradeV1{
                .slot = slot,
                .pool = tx.msg.account_keys[pool_idx].data,
                .user = tx.msg.account_keys[user_idx].data,
                .base_amount = std.mem.readInt(u64, data[8..16], .little),
                .direction = 1,
            };
            gw.writePayloadToPipe(.{ .PumpSwapTradeV1 = event }) catch {};
        }
    }
}
