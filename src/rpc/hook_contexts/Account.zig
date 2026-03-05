//! The Account RPC hook context. Contains references to the necessary state in the validator required for reading out account data and for serving RPC.

const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;

const GetAccountInfo = sig.rpc.methods.GetAccountInfo;
const GetBalance = sig.rpc.methods.GetBalance;
const GetTokenAccountBalance = sig.rpc.methods.GetTokenAccountBalance;

const AccountEncoding = account_codec.AccountEncoding;
const CommitmentSlotConfig = sig.rpc.methods.common.CommitmentSlotConfig;

slot_tracker: *sig.replay.trackers.SlotTracker,
account_reader: sig.accounts_db.AccountReader,

pub fn getAccountInfo(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetAccountInfo,
) !GetAccountInfo.Response {
    const config = params.config orelse GetAccountInfo.Config{};
    // [agave] Default commitment is finalized:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
    const commitment = config.commitment orelse .finalized;
    // [agave] Default encoding in Agave is `Binary` (legacy base58):
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L545
    // Despite the fact that `Binary` is deprecated and `Base64` is better for performance.
    const encoding = config.encoding orelse AccountEncoding.binary;

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
    const account = try slot_reader.get(arena, params.pubkey) orelse return .{
        .context = .{ .slot = slot },
        .value = null,
    };
    defer account.deinit(arena);

    const data: account_codec.AccountData = if (encoding == .jsonParsed)
        try account_codec.encodeJsonParsed(
            arena,
            params.pubkey,
            account,
            slot_reader,
            config.dataSlice,
        )
    else
        // TODO: [agave conformance] When base58 encoding is requested and account data exceeds
        // 128 bytes, Agave returns JSON-RPC error code -32600 (InvalidRequest) with the message:
        // "Encoded binary (base 58) data should be less than 128 bytes, please use Base64 encoding."
        // Currently, `error.Base58DataTooLarge` propagates to hooks.zig's generic error mapper,
        // which produces a non-deterministic positive error code via `@intFromError` and the raw
        // error name as the message.
        try account_codec.encodeStandard(arena, account, encoding, config.dataSlice);

    return .{
        .context = .{ .slot = slot },
        .value = .{
            .data = data,
            .executable = account.executable,
            .lamports = account.lamports,
            .owner = account.owner,
            .rentEpoch = account.rent_epoch,
            .space = account.data.len(),
        },
    };
}

pub fn getBalance(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetBalance,
) !GetBalance.Response {
    const config = params.config orelse CommitmentSlotConfig{};
    // [agave] Default commitment is finalized:
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L348
    const commitment = config.commitment orelse .finalized;

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    // Get slot reference to access ancestors
    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);

    // Look up account
    const maybe_account = try slot_reader.get(arena, params.pubkey);

    const lamports: u64 = if (maybe_account) |account| blk: {
        defer account.deinit(arena);
        break :blk account.lamports;
    } else 0;

    return .{
        .context = .{
            .slot = slot,
        },
        .value = lamports,
    };
}

pub fn getTokenAccountBalance(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetTokenAccountBalance,
) !GetTokenAccountBalance.Response {
    const config: GetTokenAccountBalance.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = self.slot_tracker.getSlotForCommitment(commitment);

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotFound;
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
    const maybe_account = try slot_reader.get(arena, params.pubkey);

    const account = maybe_account orelse return error.RpcAccountNotFound;
    defer account.deinit(arena);

    // Validate that this is a token account (owned by SPL Token or Token-2022)
    const is_token_program = account.owner.equals(&sig.runtime.ids.TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return error.RpcNotATokenAccount;

    // Read account data and unpack the token account
    var data_buf: [account_codec.parse_token.TokenAccount.LEN]u8 = undefined;
    var data_iter = account.data.iterator();
    const bytes_read = data_iter.readBytes(&data_buf) catch return error.RpcNotATokenAccount;
    if (bytes_read < account_codec.parse_token.TokenAccount.LEN)
        return error.RpcNotATokenAccount;

    const token_account = account_codec.parse_token.TokenAccount.unpack(&data_buf) catch
        return error.RpcNotATokenAccount;
    if (token_account.state == .uninitialized) return error.RpcNotATokenAccount;

    // Build SplTokenAdditionalData for mint decimals and extension configs
    const is_native_mint = token_account.mint.equals(&sig.runtime.ids.NATIVE_MINT_ID);
    const spl_token_data: account_codec.parse_token.SplTokenAdditionalData = if (is_native_mint)
        // Native mint (wrapped SOL): decimals=9, no extensions
        // TODO: document agave conformance.
        .{ .decimals = 9 }
    else
        // Look up the mint account for decimals and extension configs
        account_codec.getMintAdditionalData(
            arena,
            token_account.mint,
            slot_reader,
        ) orelse return error.RpcMintNotFound;

    const ui_token_amount = account_codec.parse_token.UiTokenAmount.init(
        token_account.amount,
        spl_token_data,
    );

    return .{
        .context = .{ .slot = slot },
        .value = ui_token_amount,
    };
}
