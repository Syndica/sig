//! SPL Token account parsing for token balance extraction.
//!
//! This module provides parsing of SPL Token and Token-2022 account data
//! to extract token balances for transaction metadata (preTokenBalances/postTokenBalances).
//!
//! References:
//! - SPL Token: https://github.com/solana-labs/solana-program-library/tree/master/token/program
//! - Token-2022: https://github.com/solana-labs/solana-program-library/tree/master/token/program-2022

const std = @import("std");
const sig = @import("../sig.zig");

const account_loader = sig.runtime.account_loader;

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;

const ids = sig.runtime.ids;
const TransactionTokenBalance = sig.ledger.transaction_status.TransactionTokenBalance;
const UiTokenAmount = sig.ledger.transaction_status.UiTokenAmount;

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
        const state: TokenAccountState = std.meta.intToEnum(TokenAccountState, state_byte) catch return null;
        if (state == .uninitialized) return null;

        return ParsedTokenAccount{
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

        return ParsedMint{
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
pub const RawTokenBalances = std.BoundedArray(RawTokenBalance, account_loader.MAX_TX_ACCOUNT_LOCKS);

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
        const parsed = ParsedTokenAccount.parse(account.account.data[0..TOKEN_ACCOUNT_SIZE]) orelse continue;

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

/// Convert RawTokenBalances to TransactionTokenBalance slice for RPC responses.
/// This resolves mint decimals using the provided account reader.
///
/// Arguments:
/// - allocator: Used for allocating the result
/// - raw_balances: Raw token balances captured during execution
/// - mint_decimals_cache: Cache for mint decimals
/// - account_reader: Reader to fetch mint accounts for decimals lookup
///
/// Returns a slice of TransactionTokenBalance that must be freed by the caller.
/// Returns null if any mint lookup fails (graceful degradation).
pub fn resolveTokenBalances(
    allocator: Allocator,
    raw_balances: RawTokenBalances,
    mint_decimals_cache: *MintDecimalsCache,
    comptime AccountReaderType: type,
    account_reader: AccountReaderType,
) ?[]TransactionTokenBalance {
    if (raw_balances.len == 0) return null;

    var result = std.ArrayList(TransactionTokenBalance).init(allocator);
    errdefer {
        for (result.items) |item| item.deinit(allocator);
        result.deinit();
    }

    for (raw_balances.constSlice()) |raw| {
        // Get decimals for this mint (skip if not found)
        const decimals = getMintDecimals(
            allocator,
            mint_decimals_cache,
            AccountReaderType,
            account_reader,
            raw.mint,
        ) catch continue; // Skip tokens with missing mints

        // Format the token amount
        const ui_token_amount = formatTokenAmount(allocator, raw.amount, decimals) catch return null;
        errdefer ui_token_amount.deinit(allocator);

        // Create the token balance entry
        const mint_str = allocator.dupe(u8, &raw.mint.data) catch return null;
        errdefer allocator.free(mint_str);

        const owner_str = allocator.dupe(u8, &raw.owner.data) catch return null;
        errdefer allocator.free(owner_str);

        const program_id_str = allocator.dupe(u8, &raw.program_id.data) catch return null;
        errdefer allocator.free(program_id_str);

        result.append(.{
            .account_index = raw.account_index,
            .mint = mint_str,
            .owner = owner_str,
            .program_id = program_id_str,
            .ui_token_amount = ui_token_amount,
        }) catch return null;
    }

    return result.toOwnedSlice() catch return null;
}

/// Cache for mint decimals to avoid repeated lookups
pub const MintDecimalsCache = struct {
    map: std.AutoHashMap(Pubkey, u8),
    allocator: Allocator,

    pub fn init(allocator: Allocator) MintDecimalsCache {
        return .{
            .map = std.AutoHashMap(Pubkey, u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *MintDecimalsCache) void {
        self.map.deinit();
    }

    pub fn get(self: *MintDecimalsCache, mint: Pubkey) ?u8 {
        return self.map.get(mint);
    }

    pub fn put(self: *MintDecimalsCache, mint: Pubkey, decimals: u8) !void {
        try self.map.put(mint, decimals);
    }
};

/// Format a token amount as UiTokenAmount for RPC responses.
pub fn formatTokenAmount(
    allocator: Allocator,
    amount: u64,
    decimals: u8,
) error{OutOfMemory}!UiTokenAmount {
    // Convert amount to string
    const amount_str = try std.fmt.allocPrint(allocator, "{d}", .{amount});
    errdefer allocator.free(amount_str);

    // Calculate UI amount
    const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
    const ui_amount: f64 = @as(f64, @floatFromInt(amount)) / divisor;

    // Format UI amount string with proper decimal places
    const ui_amount_string = try formatUiAmountString(allocator, ui_amount, decimals);
    errdefer allocator.free(ui_amount_string);

    return UiTokenAmount{
        .ui_amount = ui_amount,
        .decimals = decimals,
        .amount = amount_str,
        .ui_amount_string = ui_amount_string,
    };
}

/// Format the UI amount string with the correct number of decimal places.
fn formatUiAmountString(
    allocator: Allocator,
    ui_amount: f64,
    decimals: u8,
) error{OutOfMemory}![]const u8 {
    // For integer amounts (decimals == 0), don't show decimal point
    if (decimals == 0) {
        return try std.fmt.allocPrint(allocator, "{d}", .{@as(u64, @intFromFloat(ui_amount))});
    }

    // Format with all decimal places, then trim trailing zeros but keep at least one
    var buf: [64]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{d:.9}", .{ui_amount}) catch {
        // Fallback for very large numbers
        return try std.fmt.allocPrint(allocator, "{d}", .{ui_amount});
    };

    // Find the decimal point
    const dot_pos = std.mem.indexOf(u8, formatted, ".") orelse {
        return try allocator.dupe(u8, formatted);
    };

    // Trim trailing zeros, but keep at least one decimal place
    var end = formatted.len;
    while (end > dot_pos + 2 and formatted[end - 1] == '0') {
        end -= 1;
    }

    return try allocator.dupe(u8, formatted[0..end]);
}

/// Collect token balances from a list of loaded accounts.
///
/// This function scans the accounts for SPL Token accounts, parses them,
/// and returns token balance information for RPC responses.
///
/// Arguments:
/// - allocator: Used for allocating the result
/// - accounts: List of (pubkey, owner, data) tuples to scan
/// - account_reader: Reader to fetch mint accounts for decimals lookup
///
/// Returns a slice of TransactionTokenBalance that must be freed by the caller.
pub fn collectTokenBalances(
    allocator: Allocator,
    account_pubkeys: []const Pubkey,
    account_owners: []const Pubkey,
    account_datas: []const []const u8,
    mint_decimals_cache: *MintDecimalsCache,
    comptime AccountReaderType: type,
    account_reader: AccountReaderType,
) error{ OutOfMemory, MintNotFound }![]TransactionTokenBalance {
    std.debug.assert(account_pubkeys.len == account_owners.len);
    std.debug.assert(account_pubkeys.len == account_datas.len);

    var result = std.ArrayList(TransactionTokenBalance).init(allocator);
    errdefer {
        for (result.items) |item| item.deinit(allocator);
        result.deinit();
    }

    for (account_pubkeys, account_owners, account_datas, 0..) |_, owner, data, idx| {
        // Skip non-token accounts
        if (!isTokenProgram(owner)) continue;

        // Try to parse as token account
        const parsed = ParsedTokenAccount.parse(data) orelse continue;

        // Get decimals for this mint
        const decimals = try getMintDecimals(
            allocator,
            mint_decimals_cache,
            AccountReaderType,
            account_reader,
            parsed.mint,
        );

        // Format the token amount
        const ui_token_amount = try formatTokenAmount(allocator, parsed.amount, decimals);
        errdefer ui_token_amount.deinit(allocator);

        // Create the token balance entry
        const mint_str = try allocator.dupe(u8, &parsed.mint.data);
        errdefer allocator.free(mint_str);

        const owner_str = try allocator.dupe(u8, &parsed.owner.data);
        errdefer allocator.free(owner_str);

        const program_id_str = try allocator.dupe(u8, &owner.data);
        errdefer allocator.free(program_id_str);

        try result.append(.{
            .account_index = @intCast(idx),
            .mint = mint_str,
            .owner = owner_str,
            .program_id = program_id_str,
            .ui_token_amount = ui_token_amount,
        });
    }

    return try result.toOwnedSlice();
}

/// Get decimals for a mint, using cache or fetching from account reader.
fn getMintDecimals(
    allocator: Allocator,
    cache: *MintDecimalsCache,
    comptime AccountReaderType: type,
    account_reader: AccountReaderType,
    mint: Pubkey,
) error{ OutOfMemory, MintNotFound }!u8 {
    // Check cache first
    if (cache.get(mint)) |decimals| {
        return decimals;
    }

    // Fetch mint account
    const mint_account = account_reader.get(mint, allocator) catch {
        return error.MintNotFound;
    };
    defer if (mint_account) |acct| acct.deinit(allocator);

    if (mint_account) |acct| {
        const data = acct.data.constSlice();
        const parsed_mint = ParsedMint.parse(data) orelse {
            return error.MintNotFound;
        };

        // Cache the result
        try cache.put(mint, parsed_mint.decimals);
        return parsed_mint.decimals;
    }

    return error.MintNotFound;
}

// Tests
test "ParsedTokenAccount.parse" {
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

test "ParsedTokenAccount.parse rejects uninitialized" {
    const testing = std.testing;

    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    // State = 0 (uninitialized)
    data[STATE_OFFSET] = 0;

    const parsed = ParsedTokenAccount.parse(&data);
    try testing.expect(parsed == null);
}

test "ParsedTokenAccount.parse rejects short data" {
    const testing = std.testing;

    // Test with data that's too short - parse should return null
    var data: [100]u8 = undefined; // Too short (TOKEN_ACCOUNT_SIZE is 165)
    @memset(&data, 0);

    const parsed = ParsedTokenAccount.parse(&data);
    try testing.expect(parsed == null);
}

test "ParsedMint.parse" {
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

test "formatTokenAmount" {
    const testing = std.testing;
    const allocator = testing.allocator;

    // Test with 6 decimals (like USDC)
    {
        const result = try formatTokenAmount(allocator, 1_000_000, 6);
        defer result.deinit(allocator);

        try testing.expectEqualStrings("1000000", result.amount);
        try testing.expectEqual(@as(u8, 6), result.decimals);
        try testing.expectApproxEqRel(@as(f64, 1.0), result.ui_amount.?, 0.0001);
    }

    // Test with 9 decimals (like SOL)
    {
        const result = try formatTokenAmount(allocator, 1_500_000_000, 9);
        defer result.deinit(allocator);

        try testing.expectEqualStrings("1500000000", result.amount);
        try testing.expectEqual(@as(u8, 9), result.decimals);
        try testing.expectApproxEqRel(@as(f64, 1.5), result.ui_amount.?, 0.0001);
    }

    // Test with 0 decimals
    {
        const result = try formatTokenAmount(allocator, 42, 0);
        defer result.deinit(allocator);

        try testing.expectEqualStrings("42", result.amount);
        try testing.expectEqual(@as(u8, 0), result.decimals);
        try testing.expectApproxEqRel(@as(f64, 42.0), result.ui_amount.?, 0.0001);
    }
}

test "isTokenProgram" {
    const testing = std.testing;

    try testing.expect(isTokenProgram(ids.TOKEN_PROGRAM_ID));
    try testing.expect(isTokenProgram(ids.TOKEN_2022_PROGRAM_ID));
    try testing.expect(!isTokenProgram(Pubkey.ZEROES));
    try testing.expect(!isTokenProgram(sig.runtime.program.system.ID));
}
