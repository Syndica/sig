//! Ledger and RPC token balance formatting.
//!
//! Runtime records raw token balances without mint metadata. This module resolves
//! mint decimals and formats raw balances into transaction status types.

const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const TransactionTokenBalance = sig.ledger.transaction_status.TransactionTokenBalance;
const UiTokenAmount = sig.ledger.transaction_status.UiTokenAmount;
const ids = sig.runtime.ids;
const spl_token = sig.runtime.spl_token;

/// Convert spl_token.RawTokenBalances to TransactionTokenBalance slice for RPC responses.
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
    raw_balances: spl_token.RawTokenBalances,
    mint_decimals_cache: *MintDecimalsCache,
    comptime AccountReaderType: type,
    account_reader: AccountReaderType,
) error{OutOfMemory}!?[]TransactionTokenBalance {
    if (raw_balances.len == 0) return null;

    var result = try std.ArrayList(TransactionTokenBalance).initCapacity(
        allocator,
        raw_balances.len,
    );
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
        const ui_token_amount = try formatTokenAmount(
            allocator,
            raw.amount,
            decimals,
        );
        errdefer ui_token_amount.deinit(allocator);

        result.appendAssumeCapacity(.{
            .account_index = raw.account_index,
            .mint = raw.mint,
            .owner = raw.owner,
            .program_id = raw.program_id,
            .ui_token_amount = ui_token_amount,
        });
    }

    return try result.toOwnedSlice(allocator);
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

    return .{
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
        if (!spl_token.isTokenProgram(owner)) continue;

        // Try to parse as token account
        const parsed = spl_token.ParsedTokenAccount.parse(data) orelse continue;

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
    if (cache.get(mint)) |decimals| return decimals;

    // Fetch mint account
    const mint_account = account_reader.get(allocator, mint) catch return error.MintNotFound;
    defer if (mint_account) |acct| acct.deinit(allocator);

    if (mint_account) |acct| {
        const data = acct.data.constSlice();
        const parsed_mint = spl_token.ParsedMint.parse(data) orelse return error.MintNotFound;

        // Cache the result
        try cache.put(mint, parsed_mint.decimals);
        return parsed_mint.decimals;
    }

    return error.MintNotFound;
}

// Tests
/// Mock account reader for testing getMintDecimals and resolveTokenBalances.
/// Mimics the interface of FallbackAccountReader used in production.
const MockAccountReader = struct {
    mint_data: std.AutoHashMap(Pubkey, [spl_token.MINT_ACCOUNT_SIZE]u8),

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
        return .{
            .mint_data = std.AutoHashMap(
                Pubkey,
                [spl_token.MINT_ACCOUNT_SIZE]u8,
            ).init(allocator),
        };
    }

    fn deinit(self: *MockAccountReader) void {
        self.mint_data.deinit();
    }

    /// Register a mint with the given decimals.
    fn addMint(self: *MockAccountReader, mint: Pubkey, decimals: u8) !void {
        var data: [spl_token.MINT_ACCOUNT_SIZE]u8 = undefined;
        @memset(&data, 0);
        data[44] = decimals;
        data[45] = 1;
        try self.mint_data.put(mint, data);
    }

    pub fn get(self: MockAccountReader, allocator: Allocator, pubkey: Pubkey) !?MockAccount {
        const data = self.mint_data.get(pubkey) orelse return null;
        return MockAccount{
            .data = .{ .slice = try allocator.dupe(u8, &data) },
        };
    }
};

test "runtime.spl_token.formatTokenAmount" {
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

test "runtime.spl_token.realNumberString: zero decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 42, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "runtime.spl_token.realNumberString: 9 decimals with exact SOL" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.000000000", result);
}

test "runtime.spl_token.realNumberString: 3 decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.890", result);
}

test "runtime.spl_token.realNumberString: amount smaller than decimals requires padding" {
    const allocator = std.testing.allocator;
    // amount=42, decimals=6 -> "0.000042"
    const result = try realNumberString(allocator, 42, 6);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000042", result);
}

test "runtime.spl_token.realNumberString: zero amount with decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 0, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000000", result);
}

test "runtime.spl_token.realNumberStringTrimmed: trims trailing zeros" {
    const allocator = std.testing.allocator;
    // 1 SOL = 1_000_000_000 with 9 decimals -> "1" (all trailing zeros trimmed including dot)
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "runtime.spl_token.realNumberStringTrimmed: partial trailing zeros" {
    const allocator = std.testing.allocator;
    // 1_234_567_890 with 3 decimals -> "1234567.89" (one trailing zero trimmed)
    const result = try realNumberStringTrimmed(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.89", result);
}

test "runtime.spl_token.realNumberStringTrimmed: no trailing zeros" {
    const allocator = std.testing.allocator;
    // Agave example: 600010892365405206, 9 -> "600010892.365405206"
    const result = try realNumberStringTrimmed(allocator, 600010892365405206, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("600010892.365405206", result);
}

test "runtime.spl_token.realNumberStringTrimmed: zero decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 42, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "runtime.spl_token.realNumberStringTrimmed: zero amount" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 0, 6);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0", result);
}

test "runtime.spl_token.formatTokenAmount: ui_amount_string uses trimmed format" {
    const allocator = std.testing.allocator;
    // 1.5 SOL -> ui_amount_string should be "1.5", not "1.500000000"
    const result = try formatTokenAmount(allocator, 1_500_000_000, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1500000000", result.amount);
    try std.testing.expectEqualStrings("1.5", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 9), result.decimals);
}

test "runtime.spl_token.formatTokenAmount: small fractional amount" {
    const allocator = std.testing.allocator;
    // 1 lamport = 0.000000001 SOL -> trimmed to "0.000000001"
    const result = try formatTokenAmount(allocator, 1, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1", result.amount);
    try std.testing.expectEqualStrings("0.000000001", result.ui_amount_string);
}

test "runtime.spl_token.MintDecimalsCache: basic usage" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    try std.testing.expectEqual(@as(?u8, null), cache.get(mint));

    try cache.put(mint, 6);
    try std.testing.expectEqual(@as(?u8, 6), cache.get(mint));
}

test "runtime.spl_token.realNumberString: single digit amount with many decimals" {
    const allocator = std.testing.allocator;
    // Agave test case: amount=1, decimals=9 -> "0.000000001"
    const result = try realNumberString(allocator, 1, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000001", result);
}

test "runtime.spl_token.realNumberString: large amount (u64 max)" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, std.math.maxInt(u64), 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073709551615", result);
}

test "runtime.spl_token.realNumberString: large amount with decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, std.math.maxInt(u64), 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073.709551615", result);
}

test "runtime.spl_token.realNumberString: 1 decimal" {
    const allocator = std.testing.allocator;
    const result = try realNumberString(allocator, 15, 1);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.5", result);
}

test "runtime.spl_token.realNumberString: amount exactly equals decimals digits" {
    const allocator = std.testing.allocator;
    // amount=123, decimals=3 -> "0.123"
    const result = try realNumberString(allocator, 123, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.123", result);
}

test "runtime.spl_token.realNumberStringTrimmed: single lamport (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: amount=1, decimals=9 -> "0.000000001"
    const result = try realNumberStringTrimmed(allocator, 1, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("0.000000001", result);
}

test "runtime.spl_token.realNumberStringTrimmed: exact round number (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: amount=1_000_000_000, decimals=9 -> "1"
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000, 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "runtime.spl_token.realNumberStringTrimmed: large amount with high precision (Agave test)" {
    const allocator = std.testing.allocator;
    // Agave test: 1_234_567_890 with 3 decimals -> "1234567.89"
    const result = try realNumberStringTrimmed(allocator, 1_234_567_890, 3);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1234567.89", result);
}

test "runtime.spl_token.realNumberStringTrimmed: u64 max with 9 decimals" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, std.math.maxInt(u64), 9);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("18446744073.709551615", result);
}

test "runtime.spl_token.formatTokenAmount: zero amount zero decimals" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, 0, 0);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("0", result.amount);
    try std.testing.expectEqualStrings("0", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 0), result.decimals);
    try std.testing.expectApproxEqRel(@as(f64, 0.0), result.ui_amount.?, 0.0001);
}

test "runtime.spl_token.formatTokenAmount: zero amount 9 decimals" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, 0, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("0", result.amount);
    try std.testing.expectEqualStrings("0", result.ui_amount_string);
    try std.testing.expectEqual(@as(u8, 9), result.decimals);
}

test "runtime.spl_token.formatTokenAmount: USDC style (6 decimals, 1 million)" {
    const allocator = std.testing.allocator;
    // 1 USDC = 1_000_000 with 6 decimals
    const result = try formatTokenAmount(allocator, 1_000_000, 6);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1000000", result.amount);
    try std.testing.expectEqualStrings("1", result.ui_amount_string);
    try std.testing.expectApproxEqRel(@as(f64, 1.0), result.ui_amount.?, 0.0001);
}

test "runtime.spl_token.formatTokenAmount: max u64 amount" {
    const allocator = std.testing.allocator;
    const result = try formatTokenAmount(allocator, std.math.maxInt(u64), 0);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("18446744073709551615", result.amount);
    try std.testing.expectEqualStrings("18446744073709551615", result.ui_amount_string);
}

test "runtime.spl_token.formatTokenAmount: ui_amount precision (Agave pattern)" {
    const allocator = std.testing.allocator;
    // 1.234567890 SOL
    const result = try formatTokenAmount(allocator, 1_234_567_890, 9);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("1234567890", result.amount);
    try std.testing.expectApproxEqRel(@as(f64, 1.23456789), result.ui_amount.?, 0.0001);
    // Trimmed string should not have trailing zero
    try std.testing.expectEqualStrings("1.23456789", result.ui_amount_string);
}

test "runtime.spl_token.MintDecimalsCache: multiple mints" {
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

test "runtime.spl_token.MintDecimalsCache: overwrite existing entry" {
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

test "runtime.spl_token.MintDecimalsCache: unknown mint returns null" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();

    const unknown = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    try std.testing.expectEqual(@as(?u8, null), cache.get(unknown));
}

test "runtime.spl_token.realNumberString: 2 decimals (Agave USDC-like)" {
    const allocator = std.testing.allocator;
    // Agave tests token amounts with 2 decimals
    const result = try realNumberString(allocator, 4200, 2);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42.00", result);
}

test "runtime.spl_token.realNumberString: 18 decimals (high precision token)" {
    const allocator = std.testing.allocator;
    // Some tokens use 18 decimals (like ETH-bridged tokens)
    const result = try realNumberString(allocator, 1_000_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.000000000000000000", result);
}

test "runtime.spl_token.realNumberStringTrimmed: 2 decimals trims" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 4200, 2);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("42", result);
}

test "runtime.spl_token.realNumberStringTrimmed: 18 decimals large amount" {
    const allocator = std.testing.allocator;
    const result = try realNumberStringTrimmed(allocator, 1_000_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1", result);
}

test "runtime.spl_token.realNumberStringTrimmed: 18 decimals with fractional" {
    const allocator = std.testing.allocator;
    // 1.5 in 18 decimals
    const result = try realNumberStringTrimmed(allocator, 1_500_000_000_000_000_000, 18);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1.5", result);
}

test "runtime.spl_token.formatTokenAmount: all fields consistent" {
    const allocator = std.testing.allocator;
    // 42.5 USDC (6 decimals)
    const result = try formatTokenAmount(allocator, 42_500_000, 6);
    defer result.deinit(allocator);

    try std.testing.expectEqualStrings("42500000", result.amount);
    try std.testing.expectEqual(@as(u8, 6), result.decimals);
    try std.testing.expectApproxEqRel(@as(f64, 42.5), result.ui_amount.?, 0.0001);
    try std.testing.expectEqualStrings("42.5", result.ui_amount_string);
}

test "runtime.spl_token.getMintDecimals: cache hit" {
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

test "runtime.spl_token.getMintDecimals: cache miss fetches from reader" {
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

test "runtime.spl_token.getMintDecimals: unknown mint returns MintNotFound" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const unknown_mint = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    const result = getMintDecimals(allocator, &cache, MockAccountReader, reader, unknown_mint);
    try std.testing.expectError(error.MintNotFound, result);
}

test "runtime.spl_token.resolveTokenBalances: empty raw balances returns null" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const raw = spl_token.RawTokenBalances{};
    const result = try resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader);
    try std.testing.expectEqual(@as(?[]TransactionTokenBalance, null), result);
}

test "runtime.spl_token.resolveTokenBalances: resolves token balances with mint lookup" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const mint1 = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const mint2 = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    try reader.addMint(mint1, 6);
    try reader.addMint(mint2, 9);

    var raw = spl_token.RawTokenBalances{};
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

    const result = (try resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader)).?;
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

test "runtime.spl_token.resolveTokenBalances: skips tokens with missing mints" {
    const allocator = std.testing.allocator;
    var cache = MintDecimalsCache.init(allocator);
    defer cache.deinit();
    var reader = MockAccountReader.init(allocator);
    defer reader.deinit();

    const known_mint = Pubkey{ .data = [_]u8{0xAA} ** 32 };
    const unknown_mint = Pubkey{ .data = [_]u8{0xFF} ** 32 };
    try reader.addMint(known_mint, 6);
    // unknown_mint is NOT added to reader

    var raw = spl_token.RawTokenBalances{};
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

    const result = (try resolveTokenBalances(allocator, raw, &cache, MockAccountReader, reader)).?;
    defer {
        for (result) |item| item.deinit(allocator);
        allocator.free(result);
    }

    // Only the known mint should be in the result (unknown is skipped via catch continue)
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(@as(u8, 2), result[0].account_index);
    try std.testing.expectEqual(known_mint, result[0].mint);
}
