//! The Account RPC hook context. Contains references to the necessary state in the validator required for reading out account data and for serving RPC.

const std = @import("std");
const tracy = @import("tracy");

const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const parse_token = account_codec.parse_token;

const GetAccountInfo = sig.rpc.methods.GetAccountInfo;
const GetBalance = sig.rpc.methods.GetBalance;
const GetTokenAccountBalance = sig.rpc.methods.GetTokenAccountBalance;
const GetTokenSupply = sig.rpc.methods.GetTokenSupply;
const GetProgramAccounts = sig.rpc.methods.GetProgramAccounts;

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
    // [agave] Default encoding in AGave is `Binary` (legacy base58):
    // https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L545
    // However, `Binary` is deprecated and `Base64` is preferred for performance.
    // We default to base64 as it's more efficient and the recommended encoding.
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

    // TODO: [agave conformance] When base58 encoding is requested and account data exceeds
    // 128 bytes, Agave returns JSON-RPC error code -32600 (InvalidRequest) with the message:
    // "Encoded binary (base 58) data should be less than 128 bytes, please use Base64 encoding."
    // Currently, `error.Base58DataTooLarge` propagates to hooks.zig's generic error mapper,
    // which produces a non-deterministic positive error code via `@intFromError` and the raw
    // error name as the message.
    const data = try account_codec.encodeAccount(
        arena,
        params.pubkey,
        account,
        encoding,
        slot_reader,
        config.dataSlice,
    );

    return .{
        .context = .{ .slot = slot },
        .value = .from(account, data),
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

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);
    const maybe_account = try slot_reader.get(arena, params.pubkey);

    const account = maybe_account orelse return error.RpcAccountNotFound;

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

pub fn getTokenSupply(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetTokenSupply,
) !GetTokenSupply.Response {
    const config: GetTokenSupply.Config = params.config orelse .{};
    const commitment = config.commitment orelse .finalized;

    const slot = self.slot_tracker.getSlotForCommitment(commitment);

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    const slot_reader = self.account_reader.forSlot(&ref.constants().ancestors);

    // Fetch mint account
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1989-L1991
    const maybe_account = try slot_reader.get(arena, params.mint);
    const account = maybe_account orelse return error.RpcAccountNotFound;

    // Validate that this is owned by a token program
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1992-L1996
    const is_token_program = account.owner.equals(&sig.runtime.ids.TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return error.RpcNotATokenAccount;

    // Read account data into contiguous buffer for mint parsing and extension extraction
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1997-L2009
    const data_len = account.data.len();
    const mint_data = try arena.alloc(u8, data_len);
    var data_iter = account.data.iterator();
    _ = data_iter.readBytes(mint_data) catch return error.RpcMintUnpackFailed;

    // Validate this is actually a mint account, not a token account or multisig.
    // Without this, a token account's garbage bytes at the decimals offset can cause
    // a panic in formatTokenAmount. Agave performs similar validation.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L1997
    const detected = parse_token.DetectedType.parse(mint_data) orelse
        return error.RpcMintUnpackFailed;
    if (detected != .mint) return error.RpcMintUnpackFailed;

    // Parse mint to get supply
    const mint = parse_token.Mint.unpack(mint_data) catch return error.RpcMintUnpackFailed;
    if (!mint.is_initialized) return error.RpcMintUnpackFailed;

    // Extract decimals, extension configs, and clock timestamp from the raw mint data
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2011-L2019
    const spl_token_data = account_codec.parseMintAdditionalData(
        arena,
        mint_data,
        slot_reader,
    ) orelse return error.RpcMintUnpackFailed;

    const ui_token_amount = parse_token.UiTokenAmount.init(
        mint.supply,
        spl_token_data,
    );

    return .{
        .context = .{ .slot = slot },
        .value = ui_token_amount,
    };
}

pub fn getProgramAccounts(
    self: @This(),
    arena: std.mem.Allocator,
    params: GetProgramAccounts,
) !GetProgramAccounts.Response {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.gPA" });
    defer zone.deinit();

    const config = params.config orelse GetProgramAccounts.Config{};
    const commitment = config.commitment orelse .finalized;
    const encoding = config.encoding orelse .base64;
    const f = config.filters orelse &.{};
    try sig.rpc.filters.verifyFilters(f);

    const slot = self.slot_tracker.getSlotForCommitment(commitment);
    if (config.minContextSlot) |min_slot| {
        if (slot < min_slot) return error.RpcMinContextSlotNotMet;
    }

    const ref = self.slot_tracker.get(slot) orelse return error.SlotNotAvailable;
    const ancestors = &ref.constants().ancestors;
    const slot_reader = self.account_reader.forSlot(ancestors);

    var iter = blk: {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gPA.ownerQuery" });
        defer z.deinit();
        break :blk try slot_reader.getByOwner(arena, &params.program_id);
    };
    defer iter.deinit();

    var results = std.ArrayListUnmanaged(GetProgramAccounts.Value){};
    defer {
        for (results.items) |v| v.account.data.deinit(arena);
        results.deinit(arena);
    }

    while (try iter.next()) |entry| {
        const pubkey, const account = entry;
        defer account.deinit(arena);
        if (account.lamports == 0) continue;
        const data_slice: []const u8 = switch (account.data) {
            .unowned_allocation => |d| d,
            .owned_allocation => |d| d,
            else => @panic("gPA: unexpected AccountDataHandle variant"),
        };
        if (!sig.rpc.filters.filtersAllow(f, data_slice)) continue;

        const data = try account_codec.encodeAccount(
            arena,
            pubkey,
            account,
            encoding,
            slot_reader,
            config.dataSlice,
        );
        errdefer data.deinit(arena);
        try results.append(arena, .{
            .pubkey = pubkey,
            .account = .from(account, data),
        });
    }

    if (config.sortResults orelse false) {
        const z = tracy.Zone.init(@src(), .{ .name = "rpc.gPA.sort" });
        defer z.deinit();
        std.mem.sortUnstable(GetProgramAccounts.Value, results.items, {}, struct {
            fn lessThan(_: void, a: GetProgramAccounts.Value, b: GetProgramAccounts.Value) bool {
                return std.mem.order(u8, &a.pubkey.data, &b.pubkey.data) == .lt;
            }
        }.lessThan);
    }
    const values = try results.toOwnedSlice(arena);
    if (config.withContext orelse false) {
        return .{ .context = .{ .context = .{ .slot = slot }, .value = values } };
    }
    return .{ .list = values };
}
