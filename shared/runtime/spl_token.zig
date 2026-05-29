//! SPL Token account parsing for token balance extraction.
//!
//! This module provides parsing of SPL Token and Token-2022 account data
//! to extract token balances for transaction metadata (preTokenBalances/postTokenBalances).
//!
//! References:
//! - SPL Token: https://github.com/solana-labs/solana-program-library/tree/master/token/program
//! - Token-2022: https://github.com/solana-labs/solana-program-library/tree/master/token/program-2022

const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;

const Pubkey = sig.core.Pubkey;

const ids = sig.runtime.ids;

pub const SPL_MEMO_V1_ID: Pubkey = .parse("Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo");
pub const SPL_MEMO_V3_ID: Pubkey = .parse("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

// SPL Token account layout constants
pub const TOKEN_ACCOUNT_SIZE: usize = 165;
pub const MINT_ACCOUNT_SIZE: usize = 82;

// Token account layout offsets
const MINT_OFFSET: usize = 0;
const OWNER_OFFSET: usize = 32;
const AMOUNT_OFFSET: usize = 64;
const STATE_OFFSET: usize = 108;

// Mint account layout offsets
const MINT_DECIMALS_OFFSET: usize = 44;
const MINT_IS_INITIALIZED_OFFSET: usize = 45;

/// Token account state enum
pub const TokenAccountState = enum(u8) {
    uninitialized = 0,
    initialized = 1,
    frozen = 2,
};

/// Parsed SPL Token account data
pub const ParsedTokenAccount = struct {
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    state: TokenAccountState,

    /// Parse a token account from raw account data.
    /// Returns null if the data is invalid or the account is not initialized.
    pub fn parse(data: []const u8) ?ParsedTokenAccount {
        if (data.len < TOKEN_ACCOUNT_SIZE) return null;

        // Check state - must be initialized or frozen
        const state_byte = data[STATE_OFFSET];
        const state: TokenAccountState = std.meta.intToEnum(
            TokenAccountState,
            state_byte,
        ) catch return null;
        if (state == .uninitialized) return null;

        return .{
            .mint = Pubkey{ .data = data[MINT_OFFSET..][0..32].* },
            .owner = Pubkey{ .data = data[OWNER_OFFSET..][0..32].* },
            .amount = std.mem.readInt(u64, data[AMOUNT_OFFSET..][0..8], .little),
            .state = state,
        };
    }
};

/// Parsed SPL Token mint data
pub const ParsedMint = struct {
    decimals: u8,
    is_initialized: bool,

    /// Parse a mint account from raw account data.
    /// Returns null if the data is invalid or the mint is not initialized.
    pub fn parse(data: []const u8) ?ParsedMint {
        if (data.len < MINT_ACCOUNT_SIZE) return null;

        const is_initialized = data[MINT_IS_INITIALIZED_OFFSET] != 0;
        if (!is_initialized) return null;

        return .{
            .decimals = data[MINT_DECIMALS_OFFSET],
            .is_initialized = true,
        };
    }
};

/// Check if the given program ID is a token program (SPL Token or Token-2022)
pub fn isTokenProgram(program_id: Pubkey) bool {
    return program_id.equals(&ids.TOKEN_PROGRAM_ID) or
        program_id.equals(&ids.TOKEN_2022_PROGRAM_ID);
}

/// Raw token balance data captured during transaction execution.
/// This struct stores the essential token account information without
/// requiring mint decimals lookup, which can be deferred to later processing.
pub const RawTokenBalance = struct {
    account_index: u8,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    program_id: Pubkey,
};

/// Bounded array type for storing raw token balances during execution.
/// Uses the same max size as account locks since each account can have at most one token balance.
pub const RawTokenBalances = std14.BoundedArray(
    RawTokenBalance,
    account_loader.MAX_TX_ACCOUNT_LOCKS,
);

/// Collect raw token balance data from loaded accounts.
/// This is used during transaction execution to capture pre-execution token balances.
/// Unlike collectTokenBalances, this doesn't require mint decimals lookup.
///
/// Arguments:
/// - accounts: Slice of loaded accounts to scan for token accounts
///
/// Returns a bounded array of RawTokenBalance entries.
pub fn collectRawTokenBalances(
    accounts: []const sig.runtime.account_loader.LoadedAccount,
) RawTokenBalances {
    var result = RawTokenBalances{};

    for (accounts, 0..) |account, idx| {
        // Skip non-token accounts
        if (!isTokenProgram(account.account.owner)) continue;

        // Skip if data is too short for a token account
        if (account.account.data.len < TOKEN_ACCOUNT_SIZE) continue;

        // Try to parse as token account
        const parsed = ParsedTokenAccount.parse(
            account.account.data[0..TOKEN_ACCOUNT_SIZE],
        ) orelse continue;

        // Add to result (won't fail since we can't have more token accounts than total accounts)
        result.append(.{
            .account_index = @intCast(idx),
            .mint = parsed.mint,
            .owner = parsed.owner,
            .amount = parsed.amount,
            .program_id = account.account.owner,
        }) catch unreachable;
    }

    return result;
}

// Tests
test "runtime.spl_token.ParsedTokenAccount.parse" {
    const testing = std.testing;

    // Create a valid token account data blob
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    // Set mint (first 32 bytes)
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);

    // Set owner (next 32 bytes)
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);

    // Set amount (8 bytes at offset 64)
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], 1_000_000, .little);

    // Set state to initialized (byte at offset 108)
    data[STATE_OFFSET] = 1;

    const parsed = ParsedTokenAccount.parse(&data);
    try testing.expect(parsed != null);
    try testing.expectEqual(mint, parsed.?.mint);
    try testing.expectEqual(owner, parsed.?.owner);
    try testing.expectEqual(@as(u64, 1_000_000), parsed.?.amount);
    try testing.expectEqual(TokenAccountState.initialized, parsed.?.state);
}

test "runtime.spl_token.ParsedTokenAccount.parse rejects uninitialized" {
    const testing = std.testing;

    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    // State = 0 (uninitialized)
    data[STATE_OFFSET] = 0;

    const parsed = ParsedTokenAccount.parse(&data);
    try testing.expect(parsed == null);
}

test "runtime.spl_token.ParsedTokenAccount.parse rejects short data" {
    const testing = std.testing;

    // Test with data that's too short - parse should return null
    var data: [100]u8 = undefined; // Too short (TOKEN_ACCOUNT_SIZE is 165)
    @memset(&data, 0);

    const parsed = ParsedTokenAccount.parse(&data);
    try testing.expect(parsed == null);
}

test "runtime.spl_token.ParsedMint.parse" {
    const testing = std.testing;

    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    // Set decimals
    data[MINT_DECIMALS_OFFSET] = 6;
    // Set is_initialized
    data[MINT_IS_INITIALIZED_OFFSET] = 1;

    const parsed = ParsedMint.parse(&data);
    try testing.expect(parsed != null);
    try testing.expectEqual(@as(u8, 6), parsed.?.decimals);
    try testing.expectEqual(true, parsed.?.is_initialized);
}

test "runtime.spl_token.isTokenProgram" {
    const testing = std.testing;

    try testing.expect(isTokenProgram(ids.TOKEN_PROGRAM_ID));
    try testing.expect(isTokenProgram(ids.TOKEN_2022_PROGRAM_ID));
    try testing.expect(!isTokenProgram(Pubkey.ZEROES));
    try testing.expect(!isTokenProgram(sig.runtime.program.system.ID));
}

test "runtime.spl_token.ParsedMint.parse: uninitialized returns null" {
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 0; // uninitialized

    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "runtime.spl_token.ParsedMint.parse: short data returns null" {
    var data: [50]u8 = undefined;
    @memset(&data, 0);
    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "runtime.spl_token.ParsedTokenAccount.parse: frozen state" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);
    const owner = Pubkey{ .data = [_]u8{2} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], 500, .little);
    data[STATE_OFFSET] = 2; // frozen

    const parsed = ParsedTokenAccount.parse(&data);
    try std.testing.expect(parsed != null);
    try std.testing.expectEqual(TokenAccountState.frozen, parsed.?.state);
    try std.testing.expectEqual(@as(u64, 500), parsed.?.amount);
}

test "runtime.spl_token.ParsedTokenAccount.parse: invalid state byte rejects" {
    // State byte = 3 is not a valid TokenAccountState variant
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 3;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);

    // State byte = 255 is also invalid
    data[STATE_OFFSET] = 255;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);
}

test "runtime.spl_token.ParsedTokenAccount.parse: max amount (u64 max)" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    const mint = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);
    const owner = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], std.math.maxInt(u64), .little);
    data[STATE_OFFSET] = 1; // initialized

    const parsed = ParsedTokenAccount.parse(&data).?;
    try std.testing.expectEqual(std.math.maxInt(u64), parsed.amount);
    try std.testing.expectEqual(mint, parsed.mint);
    try std.testing.expectEqual(owner, parsed.owner);
}

test "runtime.spl_token.ParsedTokenAccount.parse: data exactly TOKEN_ACCOUNT_SIZE" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    try std.testing.expect(ParsedTokenAccount.parse(&data) != null);
}

test "runtime.spl_token.ParsedTokenAccount.parse: data larger than Token-2022 with extensions" {
    // Token-2022 accounts can be larger than 165 bytes with extensions
    var data: [TOKEN_ACCOUNT_SIZE + 100]u8 = undefined;
    @memset(&data, 0);

    const mint = Pubkey{ .data = [_]u8{0xCC} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);
    const owner = Pubkey{ .data = [_]u8{0xDD} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], 42, .little);
    data[STATE_OFFSET] = 1;

    const parsed = ParsedTokenAccount.parse(&data).?;
    try std.testing.expectEqual(@as(u64, 42), parsed.amount);
    try std.testing.expectEqual(mint, parsed.mint);
}

test "runtime.spl_token.ParsedTokenAccount.parse: data one byte too short" {
    var data: [TOKEN_ACCOUNT_SIZE - 1]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);
}

test "runtime.spl_token.ParsedTokenAccount.parse: zero amount initialized" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    // Amount is already 0 from @memset

    const parsed = ParsedTokenAccount.parse(&data).?;
    try std.testing.expectEqual(@as(u64, 0), parsed.amount);
    try std.testing.expectEqual(TokenAccountState.initialized, parsed.state);
}

test "runtime.spl_token.ParsedMint.parse: various decimal values" {
    const test_decimals = [_]u8{ 0, 1, 6, 9, 18, 255 };
    for (test_decimals) |dec| {
        var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
        @memset(&data, 0);
        data[MINT_DECIMALS_OFFSET] = dec;
        data[MINT_IS_INITIALIZED_OFFSET] = 1;

        const parsed = ParsedMint.parse(&data).?;
        try std.testing.expectEqual(dec, parsed.decimals);
    }
}

test "runtime.spl_token.ParsedMint.parse: data exactly MINT_ACCOUNT_SIZE" {
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 9;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;
    try std.testing.expect(ParsedMint.parse(&data) != null);
}

test "runtime.spl_token.ParsedMint.parse: data larger than Token-2022 mint with extensions" {
    var data: [MINT_ACCOUNT_SIZE + 200]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 18;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;

    const parsed = ParsedMint.parse(&data).?;
    try std.testing.expectEqual(@as(u8, 18), parsed.decimals);
}

test "runtime.spl_token.ParsedMint.parse: data one byte too short" {
    var data: [MINT_ACCOUNT_SIZE - 1]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;
    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "runtime.spl_token.ParsedMint.parse: non-zero is_initialized byte" {
    // Any non-zero value should count as initialized (Agave uses bool)
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 255; // any non-zero

    const parsed = ParsedMint.parse(&data);
    try std.testing.expect(parsed != null);
}

test "runtime.spl_token.TokenAccountState: all enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(TokenAccountState.uninitialized));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(TokenAccountState.initialized));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(TokenAccountState.frozen));
}

test "runtime.spl_token.collectRawTokenBalances: empty accounts" {
    const accounts: []const account_loader.LoadedAccount = &.{};
    const result = collectRawTokenBalances(accounts);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "runtime.spl_token.collectRawTokenBalances: non-token accounts skipped" {
    // Create accounts owned by the system program (not a token program)
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;

    const accounts = [_]account_loader.LoadedAccount{.{
        .pubkey = Pubkey.ZEROES,
        .account = .{
            .lamports = 1_000_000,
            .data = &data,
            .owner = sig.runtime.program.system.ID, // not a token program
            .executable = false,
            .rent_epoch = 0,
        },
    }};
    const result = collectRawTokenBalances(&accounts);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "runtime.spl_token.collectRawTokenBalances: token account collected" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    const mint = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);
    const owner = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], 5_000_000, .little);
    data[STATE_OFFSET] = 1;

    const accounts = [_]account_loader.LoadedAccount{.{
        .pubkey = Pubkey.ZEROES,
        .account = .{
            .lamports = 1_000_000,
            .data = &data,
            .owner = ids.TOKEN_PROGRAM_ID,
            .executable = false,
            .rent_epoch = 0,
        },
    }};
    const result = collectRawTokenBalances(&accounts);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u8, 0), result.constSlice()[0].account_index);
    try std.testing.expectEqual(mint, result.constSlice()[0].mint);
    try std.testing.expectEqual(owner, result.constSlice()[0].owner);
    try std.testing.expectEqual(@as(u64, 5_000_000), result.constSlice()[0].amount);
    try std.testing.expectEqual(ids.TOKEN_PROGRAM_ID, result.constSlice()[0].program_id);
}

test "runtime.spl_token.collectRawTokenBalances: Token-2022 account collected" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);

    const mint = Pubkey{ .data = [_]u8{0x11} ** 32 };
    @memcpy(data[MINT_OFFSET..][0..32], &mint.data);
    const owner = Pubkey{ .data = [_]u8{0x22} ** 32 };
    @memcpy(data[OWNER_OFFSET..][0..32], &owner.data);
    std.mem.writeInt(u64, data[AMOUNT_OFFSET..][0..8], 100, .little);
    data[STATE_OFFSET] = 1;

    const accounts = [_]account_loader.LoadedAccount{.{
        .pubkey = Pubkey.ZEROES,
        .account = .{
            .lamports = 1_000_000,
            .data = &data,
            .owner = ids.TOKEN_2022_PROGRAM_ID,
            .executable = false,
            .rent_epoch = 0,
        },
    }};
    const result = collectRawTokenBalances(&accounts);
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(ids.TOKEN_2022_PROGRAM_ID, result.constSlice()[0].program_id);
}

test "runtime.spl_token.collectRawTokenBalances: mixed token and non-token accounts" {
    // Account 0: system program (not token): should be skipped
    var system_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&system_data, 0);
    system_data[STATE_OFFSET] = 1;

    // Account 1: SPL Token account: should be collected
    var token_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&token_data, 0);
    const mint1 = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    @memcpy(token_data[MINT_OFFSET..][0..32], &mint1.data);
    const owner1 = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    @memcpy(token_data[OWNER_OFFSET..][0..32], &owner1.data);
    std.mem.writeInt(u64, token_data[AMOUNT_OFFSET..][0..8], 1000, .little);
    token_data[STATE_OFFSET] = 1;

    // Account 2: Token-2022 account: should be collected
    var token2022_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&token2022_data, 0);
    const mint2 = Pubkey{ .data = [_]u8{0xCC} ** 32 };
    @memcpy(token2022_data[MINT_OFFSET..][0..32], &mint2.data);
    const owner2 = Pubkey{ .data = [_]u8{0xDD} ** 32 };
    @memcpy(token2022_data[OWNER_OFFSET..][0..32], &owner2.data);
    std.mem.writeInt(u64, token2022_data[AMOUNT_OFFSET..][0..8], 2000, .little);
    token2022_data[STATE_OFFSET] = 2; // frozen

    // Account 3: uninitialized token account: should be skipped
    var uninit_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&uninit_data, 0);
    uninit_data[STATE_OFFSET] = 0; // uninitialized

    const accounts = [_]account_loader.LoadedAccount{
        .{
            .pubkey = Pubkey.ZEROES,
            .account = .{
                .lamports = 1_000_000,
                .data = &system_data,
                .owner = sig.runtime.program.system.ID,
                .executable = false,
                .rent_epoch = 0,
            },
        },
        .{
            .pubkey = Pubkey.ZEROES,
            .account = .{
                .lamports = 1_000_000,
                .data = &token_data,
                .owner = ids.TOKEN_PROGRAM_ID,
                .executable = false,
                .rent_epoch = 0,
            },
        },
        .{
            .pubkey = Pubkey.ZEROES,
            .account = .{
                .lamports = 1_000_000,
                .data = &token2022_data,
                .owner = ids.TOKEN_2022_PROGRAM_ID,
                .executable = false,
                .rent_epoch = 0,
            },
        },
        .{
            .pubkey = Pubkey.ZEROES,
            .account = .{
                .lamports = 1_000_000,
                .data = &uninit_data,
                .owner = ids.TOKEN_PROGRAM_ID,
                .executable = false,
                .rent_epoch = 0,
            },
        },
    };

    const result = collectRawTokenBalances(&accounts);
    // Only accounts 1 and 2 should be collected (system skipped, uninitialized skipped)
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u8, 1), result.constSlice()[0].account_index);
    try std.testing.expectEqual(@as(u8, 2), result.constSlice()[1].account_index);
    try std.testing.expectEqual(@as(u64, 1000), result.constSlice()[0].amount);
    try std.testing.expectEqual(@as(u64, 2000), result.constSlice()[1].amount);
    try std.testing.expectEqual(ids.TOKEN_PROGRAM_ID, result.constSlice()[0].program_id);
    try std.testing.expectEqual(ids.TOKEN_2022_PROGRAM_ID, result.constSlice()[1].program_id);
}

test "runtime.spl_token.collectRawTokenBalances: short data account skipped" {
    // Token program owner but data too short
    var short_data: [100]u8 = undefined;
    @memset(&short_data, 0);

    const accounts = [_]account_loader.LoadedAccount{.{
        .pubkey = Pubkey.ZEROES,
        .account = .{
            .lamports = 1_000_000,
            .data = &short_data,
            .owner = ids.TOKEN_PROGRAM_ID,
            .executable = false,
            .rent_epoch = 0,
        },
    }};
    const result = collectRawTokenBalances(&accounts);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "runtime.spl_token.isTokenProgram: distinct pubkeys" {
    // Verify TOKEN_PROGRAM_ID and TOKEN_2022_PROGRAM_ID are different
    try std.testing.expect(!ids.TOKEN_PROGRAM_ID.equals(&ids.TOKEN_2022_PROGRAM_ID));

    // Random pubkeys should not be token programs
    const random_key = Pubkey{ .data = [_]u8{0xDE} ** 32 };
    try std.testing.expect(!isTokenProgram(random_key));
}

test "runtime.spl_token.RawTokenBalance struct layout" {
    // Verify RawTokenBalance fields are properly accessible
    const balance = RawTokenBalance{
        .account_index = 5,
        .mint = Pubkey{ .data = [_]u8{1} ** 32 },
        .owner = Pubkey{ .data = [_]u8{2} ** 32 },
        .amount = 999_999,
        .program_id = ids.TOKEN_PROGRAM_ID,
    };
    try std.testing.expectEqual(@as(u8, 5), balance.account_index);
    try std.testing.expectEqual(@as(u64, 999_999), balance.amount);
}
