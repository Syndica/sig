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
        const state: TokenAccountState = std.meta.intToEnum(
            TokenAccountState,
            state_byte,
        ) catch return null;
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
pub const RawTokenBalances = std14.BoundedArray(RawTokenBalance, account_loader.MAX_TX_ACCOUNT_LOCKS);

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

    var result = std.ArrayList(TransactionTokenBalance).initCapacity(
        allocator,
        raw_balances.len,
    ) catch return null;
    errdefer {
        for (result.items) |item| item.deinit(allocator);
        result.deinit(allocator);
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
        const ui_token_amount = formatTokenAmount(
            allocator,
            raw.amount,
            decimals,
        ) catch return null;
        errdefer ui_token_amount.deinit(allocator);

        result.append(allocator, .{
            .account_index = raw.account_index,
            .mint = raw.mint,
            .owner = raw.owner,
            .program_id = raw.program_id,
            .ui_token_amount = ui_token_amount,
        }) catch return null;
    }

    return result.toOwnedSlice(allocator) catch return null;
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

    // Format UI amount string with proper decimal places (using integer math for full precision)
    const ui_amount_string = try realNumberStringTrimmed(allocator, amount, decimals);
    errdefer allocator.free(ui_amount_string);

    return UiTokenAmount{
        .ui_amount = ui_amount,
        .decimals = decimals,
        .amount = amount_str,
        .ui_amount_string = ui_amount_string,
    };
}

/// Format an integer token amount as a decimal string with full precision.
/// Matches Agave's `real_number_string` from account-decoder-client-types/src/token.rs.
///
/// Examples (amount, decimals) -> result:
///   (1_000_000_000, 9) -> "1.000000000"
///   (1_234_567_890, 3) -> "1234567.890"
///   (42, 0) -> "42"
fn realNumberString(allocator: Allocator, amount: u64, decimals: u8) error{OutOfMemory}![]const u8 {
    if (decimals == 0) {
        return try std.fmt.allocPrint(allocator, "{d}", .{amount});
    }

    // Format amount as string, left-padded with zeros to at least decimals+1 digits
    const dec: usize = @intCast(decimals);
    const raw = try std.fmt.allocPrint(allocator, "{d}", .{amount});
    defer allocator.free(raw);

    // Pad with leading zeros if needed so we have at least decimals+1 chars
    const min_len = dec + 1;
    const padded = if (raw.len < min_len) blk: {
        const buf = try allocator.alloc(u8, min_len);
        const pad_count = min_len - raw.len;
        @memset(buf[0..pad_count], '0');
        @memcpy(buf[pad_count..], raw);
        break :blk buf;
    } else try allocator.dupe(u8, raw);
    defer allocator.free(padded);

    // Insert decimal point at position len - decimals
    const dot_pos = padded.len - dec;
    const result = try allocator.alloc(u8, padded.len + 1);
    @memcpy(result[0..dot_pos], padded[0..dot_pos]);
    result[dot_pos] = '.';
    @memcpy(result[dot_pos + 1 ..], padded[dot_pos..]);

    return result;
}

/// Format an integer token amount as a trimmed decimal string with full precision.
/// Matches Agave's `real_number_string_trimmed` from account-decoder-client-types/src/token.rs.
///
/// Examples (amount, decimals) -> result:
///   (1_000_000_000, 9) -> "1"
///   (1_234_567_890, 3) -> "1234567.89"
///   (600010892365405206, 9) -> "600010892.365405206"
pub fn realNumberStringTrimmed(
    allocator: Allocator,
    amount: u64,
    decimals: u8,
) error{OutOfMemory}![]const u8 {
    const s = try realNumberString(allocator, amount, decimals);

    if (decimals == 0) return s;

    // Trim trailing zeros, then trailing dot
    var end = s.len;
    while (end > 0 and s[end - 1] == '0') {
        end -= 1;
    }
    if (end > 0 and s[end - 1] == '.') {
        end -= 1;
    }

    if (end == s.len) return s;

    const trimmed = try allocator.dupe(u8, s[0..end]);
    allocator.free(s);
    return trimmed;
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

test "realNumberString - zero decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 42, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "realNumberString - 9 decimals with exact SOL" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.000000000", result);
}

test "realNumberString - 3 decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.890", result);
}

test "realNumberString - amount smaller than decimals requires padding" {
    const allocator = std.testing.allocator;
    // amount=42, decimals=6 -> "0.000042"
    const result = try realNumberString(allocator, 42, 6);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000042", result);
}

test "realNumberString - zero amount with decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 0, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000000", result);
}

test "realNumberStringTrimmed - trims trailing zeros" {
    const allocator = std.testing.allocator;
    // 1 SOL = 1_000_000_000 with 9 decimals -> "1" (all trailing zeros trimmed including dot)
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "realNumberStringTrimmed - partial trailing zeros" {
    const allocator = std.testing.allocator;
    // 1_234_567_890 with 3 decimals -> "1234567.89" (one trailing zero trimmed)
    const result = try realNumberStringTrimmed(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.89", result);
}

test "realNumberStringTrimmed - no trailing zeros" {
    const allocator = std.testing.allocator;
    // Agave example: 600010892365405206, 9 -> "600010892.365405206"
    const result = try realNumberStringTrimmed(allocator, 600010892365405206, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("600010892.365405206", result);
}

test "realNumberStringTrimmed - zero decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 42, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "realNumberStringTrimmed - zero amount" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 0, 6);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0", result);
}

test "formatTokenAmount - ui_amount_string uses trimmed format" {
    const allocator = std.testing.allocator;
    // 1.5 SOL -> ui_amount_string should be "1.5", not "1.500000000"
    const result = try formatTokenAmount(allocator, 1_500_000_000, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1500000000", result.amount);
    try std.testing.expectEqualStrings("1.5", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 9), result.decimals);
}

test "formatTokenAmount - small fractional amount" {
    const allocator = std.testing.allocator;
    // 1 lamport = 0.000000001 SOL -> trimmed to "0.000000001"
    const result = try formatTokenAmount(allocator, 1, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1", result.amount);
    try std.testing.expectEqualStrings("0.000000001", result.ui_amount_string);
}

test "ParsedMint.parse - uninitialized returns null" {
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 0; // uninitialized

    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "ParsedMint.parse - short data returns null" {
    var data: [50]u8 = undefined;
    @memset(&data, 0);
    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "ParsedTokenAccount.parse - frozen state" {
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

test "MintDecimalsCache - basic usage" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    try std.testing.expectEqual(@as(?u8, null), cache.get(mint));

    try cache.put(mint, 6);
    try std.testing.expectEqual(@as(?u8, 6), cache.get(mint));
}

test "ParsedTokenAccount.parse - invalid state byte rejects" {
    // State byte = 3 is not a valid TokenAccountState variant
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 3;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);

    // State byte = 255 is also invalid
    data[STATE_OFFSET] = 255;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);
}

test "ParsedTokenAccount.parse - max amount (u64 max)" {
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

test "ParsedTokenAccount.parse - data exactly TOKEN_ACCOUNT_SIZE" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    try std.testing.expect(ParsedTokenAccount.parse(&data) != null);
}

test "ParsedTokenAccount.parse - data larger than TOKEN_ACCOUNT_SIZE (Token-2022 with extensions)" {
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

test "ParsedTokenAccount.parse - data one byte too short" {
    var data: [TOKEN_ACCOUNT_SIZE - 1]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    try std.testing.expect(ParsedTokenAccount.parse(&data) == null);
}

test "ParsedTokenAccount.parse - zero amount initialized" {
    var data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[STATE_OFFSET] = 1;
    // Amount is already 0 from @memset

    const parsed = ParsedTokenAccount.parse(&data).?;
    try std.testing.expectEqual(@as(u64, 0), parsed.amount);
    try std.testing.expectEqual(TokenAccountState.initialized, parsed.state);
}

test "ParsedMint.parse - various decimal values" {
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

test "ParsedMint.parse - data exactly MINT_ACCOUNT_SIZE" {
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 9;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;
    try std.testing.expect(ParsedMint.parse(&data) != null);
}

test "ParsedMint.parse - data larger than MINT_ACCOUNT_SIZE (Token-2022 mint with extensions)" {
    var data: [MINT_ACCOUNT_SIZE + 200]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 18;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;

    const parsed = ParsedMint.parse(&data).?;
    try std.testing.expectEqual(@as(u8, 18), parsed.decimals);
}

test "ParsedMint.parse - data one byte too short" {
    var data: [MINT_ACCOUNT_SIZE - 1]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 1;
    try std.testing.expect(ParsedMint.parse(&data) == null);
}

test "ParsedMint.parse - non-zero is_initialized byte" {
    // Any non-zero value should count as initialized (Agave uses bool)
    var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
    @memset(&data, 0);
    data[MINT_DECIMALS_OFFSET] = 6;
    data[MINT_IS_INITIALIZED_OFFSET] = 255; // any non-zero

    const parsed = ParsedMint.parse(&data);
    try std.testing.expect(parsed != null);
}

test "realNumberString - single digit amount with many decimals" {
    const allocator = std.testing.allocator;
    // Agave test case: amount=1, decimals=9 -> "0.000000001"
    const result = try realNumberString(allocator, 1, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000001", result);
}

test "realNumberString - large amount (u64 max)" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, std.math.maxInt(u64), 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073709551615", result);
}

test "realNumberString - large amount with decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, std.math.maxInt(u64), 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073.709551615", result);
}

test "realNumberString - 1 decimal" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 15, 1);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.5", result);
}

test "realNumberString - amount exactly equals decimals digits" {
    const allocator = std.testing.allocator;
    // amount=123, decimals=3 -> "0.123"
    const result = try realNumberString(allocator, 123, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.123", result);
}

test "realNumberStringTrimmed - single lamport (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: amount=1, decimals=9 -> "0.000000001"
    const result = try realNumberStringTrimmed(allocator, 1, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000001", result);
}

test "realNumberStringTrimmed - exact round number (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: amount=1_000_000_000, decimals=9 -> "1"
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "realNumberStringTrimmed - large amount with high precision (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: 1_234_567_890 with 3 decimals -> "1234567.89"
    const result = try realNumberStringTrimmed(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.89", result);
}

test "realNumberStringTrimmed - u64 max with 9 decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, std.math.maxInt(u64), 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073.709551615", result);
}

test "formatTokenAmount - zero amount zero decimals" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, 0, 0);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("0", result.amount);
    try std.testing.expectEqualStrings("0", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 0), result.decimals);
    try std.testing.expectApproxEqRel(@as(f64, 0.0), result.ui_amount.?, 0.0001);
}

test "formatTokenAmount - zero amount 9 decimals" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, 0, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("0", result.amount);
    try std.testing.expectEqualStrings("0", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 9), result.decimals);
}

test "formatTokenAmount - USDC style (6 decimals, 1 million)" {
    const allocator = std.testing.allocator;
    // 1 USDC = 1_000_000 with 6 decimals
    const result = try formatTokenAmount(allocator, 1_000_000, 6);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1000000", result.amount);
    try std.testing.expectEqualStrings("1", result.ui_amount_string);
    try std.testing.expectApproxEqRel(@as(f64, 1.0), result.ui_amount.?, 0.0001);
}

test "formatTokenAmount - max u64 amount" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, std.math.maxInt(u64), 0);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("18446744073709551615", result.amount);
    try std.testing.expectEqualStrings("18446744073709551615", result.ui_amount_string);
}

test "formatTokenAmount - ui_amount precision (Agave pattern)" {
    const allocator = std.testing.allocator;
    // 1.234567890 SOL
    const result = try formatTokenAmount(allocator, 1_234_567_890, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1234567890", result.amount);
    try std.testing.expectApproxEqRel(@as(f64, 1.23456789), result.ui_amount.?, 0.0001);
    // Trimmed string should not have trailing zero
    try std.testing.expectEqualStrings("1.23456789", result.ui_amount_string);
}

test "MintDecimalsCache - multiple mints" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const mint1 = Pubkey{ .data = [_]u8{1} ** 32 };
    const mint2 = Pubkey{ .data = [_]u8{2} ** 32 };
    const mint3 = Pubkey{ .data = [_]u8{3} ** 32 };

    try cache.put(mint1, 6);
    try cache.put(mint2, 9);
    try cache.put(mint3, 0);

    try std.testing.expectEqual(@as(?u8, 6), cache.get(mint1));
    try std.testing.expectEqual(@as(?u8, 9), cache.get(mint2));
    try std.testing.expectEqual(@as(?u8, 0), cache.get(mint3));
}

test "MintDecimalsCache - overwrite existing entry" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    try cache.put(mint, 6);
    try std.testing.expectEqual(@as(?u8, 6), cache.get(mint));

    // Overwrite with new value
    try cache.put(mint, 9);
    try std.testing.expectEqual(@as(?u8, 9), cache.get(mint));
}

test "MintDecimalsCache - unknown mint returns null" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const unknown = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    try std.testing.expectEqual(@as(?u8, null), cache.get(unknown));
}

test "TokenAccountState - all enum values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(TokenAccountState.uninitialized));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(TokenAccountState.initialized));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(TokenAccountState.frozen));
}

test "collectRawTokenBalances - empty accounts" {
    const accounts: []const account_loader.LoadedAccount = &.{};
    const result = collectRawTokenBalances(accounts);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "collectRawTokenBalances - non-token accounts skipped" {
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

test "collectRawTokenBalances - token account collected" {
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

test "collectRawTokenBalances - Token-2022 account collected" {
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

test "collectRawTokenBalances - mixed token and non-token accounts" {
    // Account 0: system program (not token) - should be skipped
    var system_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&system_data, 0);
    system_data[STATE_OFFSET] = 1;

    // Account 1: SPL Token account - should be collected
    var token_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&token_data, 0);
    const mint1 = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    @memcpy(token_data[MINT_OFFSET..][0..32], &mint1.data);
    const owner1 = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    @memcpy(token_data[OWNER_OFFSET..][0..32], &owner1.data);
    std.mem.writeInt(u64, token_data[AMOUNT_OFFSET..][0..8], 1000, .little);
    token_data[STATE_OFFSET] = 1;

    // Account 2: Token-2022 account - should be collected
    var token2022_data: [TOKEN_ACCOUNT_SIZE]u8 = undefined;
    @memset(&token2022_data, 0);
    const mint2 = Pubkey{ .data = [_]u8{0xCC} ** 32 };
    @memcpy(token2022_data[MINT_OFFSET..][0..32], &mint2.data);
    const owner2 = Pubkey{ .data = [_]u8{0xDD} ** 32 };
    @memcpy(token2022_data[OWNER_OFFSET..][0..32], &owner2.data);
    std.mem.writeInt(u64, token2022_data[AMOUNT_OFFSET..][0..8], 2000, .little);
    token2022_data[STATE_OFFSET] = 2; // frozen

    // Account 3: uninitialized token account - should be skipped
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

test "collectRawTokenBalances - short data account skipped" {
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

test "isTokenProgram - distinct pubkeys" {
    // Verify TOKEN_PROGRAM_ID and TOKEN_2022_PROGRAM_ID are different
    try std.testing.expect(!ids.TOKEN_PROGRAM_ID.equals(&ids.TOKEN_2022_PROGRAM_ID));

    // Random pubkeys should not be token programs
    const random_key = Pubkey{ .data = [_]u8{0xDE} ** 32 };
    try std.testing.expect(!isTokenProgram(random_key));
}

test "RawTokenBalance struct layout" {
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

test "realNumberString - 2 decimals (Agave USDC-like)" {
    const allocator = std.testing.allocator;
    // Agave tests token amounts with 2 decimals
    const result = try realNumberString(allocator, 4200, 2);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42.00", result);
}

test "realNumberString - 18 decimals (high precision token)" {
    const allocator = std.testing.allocator;
    // Some tokens use 18 decimals (like ETH-bridged tokens)
    const result = try realNumberString(allocator, 1_000_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.000000000000000000", result);
}

test "realNumberStringTrimmed - 2 decimals trims" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 4200, 2);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "realNumberStringTrimmed - 18 decimals large amount" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "realNumberStringTrimmed - 18 decimals with fractional" {
    const allocator = std.testing.allocator;
    // 1.5 in 18 decimals
    const result = try realNumberStringTrimmed(allocator, 1_500_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.5", result);
}

test "formatTokenAmount - all fields consistent" {
    const allocator = std.testing.allocator;
    // 42.5 USDC (6 decimals)
    const result = try formatTokenAmount(allocator, 42_500_000, 6);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("42500000", result.amount);
    try std.testing.expectEqual(@as(u8, 6), result.decimals);
    try std.testing.expectApproxEqRel(@as(f64, 42.5), result.ui_amount.?, 0.0001);
    try std.testing.expectEqualStrings("42.5", result.ui_amount_string);
}

/// Mock account reader for testing getMintDecimals and resolveTokenBalances.
/// Mimics the interface of FallbackAccountReader used in production.
const MockAccountReader = struct {
    mint_data: std.AutoHashMap(Pubkey, [MINT_ACCOUNT_SIZE]u8),

    const MockAccount = struct {
        data: DataHandle,

        const DataHandle = struct {
            slice: []const u8,
            pub fn constSlice(self: DataHandle) []const u8 {
                return self.slice;
            }
        };

        pub fn deinit(self: MockAccount, allocator: Allocator) void {
            allocator.free(self.data.slice);
        }
    };

    fn init(allocator: Allocator) MockAccountReader {
        return .{ .mint_data = std.AutoHashMap(Pubkey, [MINT_ACCOUNT_SIZE]u8).init(allocator) };
    }

    fn deinit(self: *MockAccountReader) void {
        self.mint_data.deinit();
    }

    /// Register a mint with the given decimals.
    fn addMint(self: *MockAccountReader, mint: Pubkey, decimals: u8) !void {
        var data: [MINT_ACCOUNT_SIZE]u8 = undefined;
        @memset(&data, 0);
        data[MINT_DECIMALS_OFFSET] = decimals;
        data[MINT_IS_INITIALIZED_OFFSET] = 1;
        try self.mint_data.put(mint, data);
    }

    pub fn get(self: MockAccountReader, pubkey: Pubkey, allocator: Allocator) !?MockAccount {
        const data = self.mint_data.get(pubkey) orelse return null;
        return MockAccount{
            .data = .{ .slice = try allocator.dupe(u8, &data) },
        };
    }
};

test "getMintDecimals - cache hit" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const mint = Pubkey{ .data = [_]u8{0x01} ** 32 };
    try cache.put(mint, 9);

    // Should return cached value without hitting the reader
    const decimals = try getMintDecimals(allocator, &cache, MockAccountReader, reader, mint);
    try std.testing.expectEqual(@as(u8, 9), decimals);
}

test "getMintDecimals - cache miss fetches from reader" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const mint = Pubkey{ .data = [_]u8{0x02} ** 32 };
    try reader.addMint(mint, 6);

    const decimals = try getMintDecimals(allocator, &cache, MockAccountReader, reader, mint);
    try std.testing.expectEqual(@as(u8, 6), decimals);

    // Should now be cached
    try std.testing.expectEqual(@as(?u8, 6), cache.get(mint));
}

test "getMintDecimals - unknown mint returns MintNotFound" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const unknown_mint = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    const result = getMintDecimals(allocator, &cache, MockAccountReader, reader, unknown_mint);
    try std.testing.expectError(error.MintNotFound, result);
}

test "resolveTokenBalances - empty raw balances returns null" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const raw = RawTokenBalances{};
    const result = resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader);
    try std.testing.expectEqual(@as(?[]TransactionTokenBalance, null), result);
}

test "resolveTokenBalances - resolves token balances with mint lookup" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const mint1 = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const mint2 = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    try reader.addMint(mint1, 6);
    try reader.addMint(mint2, 9);

    var raw = RawTokenBalances{};
    raw.appendAssumeCapacity(.{
        .account_index = 1,
        .mint = mint1,
        .owner = Pubkey{ .data = [_]u8{0x11} ** 32 },
        .amount = 1_000_000, // 1.0 with 6 decimals
        .program_id = ids.TOKEN_PROGRAM_ID,
    });
    raw.appendAssumeCapacity(.{
        .account_index = 3,
        .mint = mint2,
        .owner = Pubkey{ .data = [_]u8{0x22} ** 32 },
        .amount = 1_500_000_000, // 1.5 with 9 decimals
        .program_id = ids.TOKEN_2022_PROGRAM_ID,
    });

    const result = resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader).?;
    defer {
        for (result) |item| item.deinit(allocator);
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 2), result.len);

    // First token balance
    try std.testing.expectEqual(@as(u8, 1), result[0].account_index);
    try std.testing.expectEqual(mint1, result[0].mint);
    try std.testing.expectEqual(@as(u8, 6), result[0].ui_token_amount.decimals);
    try std.testing.expectEqualStrings("1000000", result[0].ui_token_amount.amount);
    try std.testing.expectEqualStrings("1", result[0].ui_token_amount.ui_amount_string);

    // Second token balance
    try std.testing.expectEqual(@as(u8, 3), result[1].account_index);
    try std.testing.expectEqual(mint2, result[1].mint);
    try std.testing.expectEqual(@as(u8, 9), result[1].ui_token_amount.decimals);
    try std.testing.expectEqualStrings("1500000000", result[1].ui_token_amount.amount);
    try std.testing.expectEqualStrings("1.5", result[1].ui_token_amount.ui_amount_string);
}

test "resolveTokenBalances - skips tokens with missing mints" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const known_mint = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const unknown_mint = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    try reader.addMint(known_mint, 6);
    // unknown_mint is NOT added to reader

    var raw = RawTokenBalances{};
    raw.appendAssumeCapacity(.{
        .account_index = 0,
        .mint = unknown_mint, // This one will be skipped
        .owner = Pubkey{ .data = [_]u8{0x11} ** 32 },
        .amount = 100,
        .program_id = ids.TOKEN_PROGRAM_ID,
    });
    raw.appendAssumeCapacity(.{
        .account_index = 2,
        .mint = known_mint, // This one will succeed
        .owner = Pubkey{ .data = [_]u8{0x22} ** 32 },
        .amount = 500_000,
        .program_id = ids.TOKEN_PROGRAM_ID,
    });

    const result = resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader).?;
    defer {
        for (result) |item| item.deinit(allocator);
        allocator.free(result);
    }

    // Only the known mint should be in the result (unknown is skipped via catch continue)
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u8, 2), result[0].account_index);
    try std.testing.expectEqual(known_mint, result[0].mint);
}
