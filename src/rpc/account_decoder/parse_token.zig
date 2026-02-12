/// Types for parsing SPL Token accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");
const parse_token_extension = @import("parse_token_extension.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const ParseError = account_decoder.ParseError;
const AccountState = account_decoder.AccountState;

const UiExtension = parse_token_extension.UiExtension;
const MAX_EXTENSIONS = parse_token_extension.MAX_EXTENSIONS;
const parseExtensions = parse_token_extension.parseExtensions;

/// Index of the account state byte (108 = offset of `state` field in TokenAccount)
// TODO: document offset form Agave.
const ACCOUNT_INITIALIZED_INDEX: usize = 108;

/// Parse an SPL Token account.
/// Returns null if:
/// - Data doesn't match any known token account type
/// - Token account provided without decimals (additional_data)
/// - Account is uninitialized
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L37-L80
pub fn parseToken(
    data: []const u8,
    additional_data: ?*const SplTokenAdditionalData,
) ParseError!?TokenAccountType {
    const account_type = DetectedType.parse(data) orelse return null;

    return switch (account_type) {
        .token_account => parseAsTokenAccount(data, additional_data),
        .mint => parseAsMint(data),
        .multisig => parseAsMultisig(data),
    };
}

/// Token-2022 account type discriminator (placed at TokenAccount.LEN for extended accounts)
// TODO: document
const AccountTypeDiscriminator = enum(u8) {
    uninitialized = 0,
    mint = 1,
    account = 2,
};

const DetectedType = union(enum) {
    token_account,
    mint,
    multisig,

    fn parse(data: []const u8) ?DetectedType {
        // Multisig: exactly 355 bytes (never has extensions)
        if (data.len == Multisig.LEN) return .multisig;
        // Check for Token-2022 Mint first (discriminator at offset 82)
        // Mint with extensions: len > 82
        if (data.len > Mint.LEN) {
            if (data[Mint.LEN] == @intFromEnum(AccountTypeDiscriminator.mint)) {
                return .mint;
            }
        }
        // Check for Token-2022 TokenAccount (discriminator at offset 165)
        // TokenAccount with extensions: len > 165
        if (data.len > TokenAccount.LEN) {
            if (data[TokenAccount.LEN] == @intFromEnum(AccountTypeDiscriminator.account)) {
                return .token_account;
            }
        }
        // SPL Token v1: exact lengths (no extensions)
        if (data.len == TokenAccount.LEN) return .token_account;
        if (data.len == Mint.LEN) return .mint;
        return null;
    }
};

fn parseAsTokenAccount(
    data: []const u8,
    additional_data: ?*const SplTokenAdditionalData,
) ?TokenAccountType {
    const account = TokenAccount.unpack(data) catch return null;
    if (account.state == .uninitialized) return null;

    const decimals = (additional_data orelse return null).decimals;
    const is_native = account.is_native != null;
    return .{ .account = .{
        .mint = account.mint.base58String(),
        .owner = account.owner.base58String(),
        .token_amount = UiTokenAmount.init(account.amount, decimals),
        .delegate = if (account.delegate) |d| d.base58String() else null,
        .state = account.state,
        .is_native = is_native,
        .rent_exempt_reserve = if (account.is_native) |r| UiTokenAmount.init(r, decimals) else null,
        .delegated_amount = if (account.delegate != null and account.delegated_amount > 0)
            UiTokenAmount.init(account.delegated_amount, decimals)
        else
            null,
        .close_authority = if (account.close_authority) |c| c.base58String() else null,
        .extensions = parseExtensions(data[TokenAccount.LEN..]),
    } };
}

fn parseAsMint(data: []const u8) ?TokenAccountType {
    const mint = Mint.unpack(data) catch return null;
    if (!mint.is_initialized) return null;
    return .{ .mint = .{
        .mint_authority = if (mint.mint_authority) |a| a.base58String() else null,
        .supply = mint.supply,
        .decimals = mint.decimals,
        .is_initialized = mint.is_initialized,
        .freeze_authority = if (mint.freeze_authority) |a| a.base58String() else null,
        .extensions = parseExtensions(data[Mint.LEN..]),
    } };
}

fn parseAsMultisig(data: []const u8) ?TokenAccountType {
    const multisig = Multisig.unpack(data) catch return null;
    if (!multisig.is_initialized) return null;
    // Collect non-zero signers up to n valid signers
    var signers: std.BoundedArray(Pubkey.Base58String, Multisig.MAX_SIGNERS) = .{};
    for (multisig.signers[0..multisig.n]) |signer| {
        if (!signer.isZeroed()) {
            signers.appendAssumeCapacity(signer.base58String());
        }
    }
    return .{ .multisig = .{
        .num_required_signers = multisig.m,
        .num_valid_signers = multisig.n,
        .is_initialized = multisig.is_initialized,
        .signers = signers,
    } };
}

/// Get the mint pubkey from token account data if valid.
/// Returns null if data is not a valid initialized token account.
/// Used by RPC layer to look up decimals from the mint account.
/// [agave] get_token_account_mint in account-decoder/src/parse_token.rs
pub fn getTokenAccountMint(data: []const u8) ?Pubkey {
    if (!isValidTokenAccountData(data)) return null;
    return Pubkey{ .data = data[0..32].* };
}

/// Get the owner pubkey from token account data if valid.
/// Returns null if data is not a valid initialized token account.
/// [spl] Account::unpack_account_owner in spl-token-2022 interface
pub fn getTokenAccountOwner(data: []const u8) ?Pubkey {
    if (!isValidTokenAccountData(data)) return null;
    return Pubkey{ .data = data[32..64].* };
}

/// Check if the account data represents a valid, initialized token account.
/// Handles both standard SPL Token (165 bytes) and Token-2022 extended accounts.
/// [spl] Account::valid_account_data in spl-token-2022 interface/src/state.rs
fn isValidTokenAccountData(data: []const u8) bool {
    // Standard token account: exactly 165 bytes and initialized
    if (data.len == TokenAccount.LEN) {
        return isInitializedAccount(data);
    }
    // Token-2022 extended account: >165 bytes, NOT multisig size (355),
    // and has AccountTypeDiscriminator.account at offset 165
    if (data.len > TokenAccount.LEN and data.len != Multisig.LEN) {
        if (data[TokenAccount.LEN] == @intFromEnum(AccountTypeDiscriminator.account)) {
            return isInitializedAccount(data);
        }
    }
    return false;
}

/// Check if the state byte at ACCOUNT_INITIALIZED_INDEX indicates initialized or frozen.
/// [spl] is_initialized_account in generic_token_account.rs
fn isInitializedAccount(data: []const u8) bool {
    if (data.len <= ACCOUNT_INITIALIZED_INDEX) return false;
    const state = data[ACCOUNT_INITIALIZED_INDEX];
    return state == @intFromEnum(AccountState.initialized) or
        state == @intFromEnum(AccountState.frozen);
}

/// Additional data needed for token account parsing (from mint lookup).
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L30-L35
pub const SplTokenAdditionalData = struct {
    decimals: u8,
    // Token-2022 extension data
    interest_bearing_config: ?InterestBearingConfigData = null,
    scaled_ui_amount_config: ?ScaledUiAmountConfigData = null,
};

/// Subset of InterestBearingConfig needed for amount calculations.
pub const InterestBearingConfigData = struct {
    rate_authority: ?Pubkey,
    initialization_timestamp: i64,
    pre_update_average_rate: i16,
    last_update_timestamp: i64,
    current_rate: i16,
};

/// Subset of ScaledUiAmountConfig needed for amount calculations.
pub const ScaledUiAmountConfigData = struct {
    multiplier: f64,
    new_multiplier_effective_timestamp: i64,
    new_multiplier: f64,
};

/// SPL Token Mint account layout (82 bytes).
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/state.rs#L49-L94
pub const Mint = struct {
    pub const LEN: usize = 82;
    mint_authority: ?Pubkey,
    supply: u64,
    decimals: u8,
    is_initialized: bool,
    freeze_authority: ?Pubkey,
    pub fn unpack(data: []const u8) ParseError!Mint {
        if (data.len < LEN) return ParseError.InvalidAccountData;
        return Mint{
            .mint_authority = readCOptionPubkey(data[0..36]),
            .supply = std.mem.readInt(u64, data[36..44], .little),
            .decimals = data[44],
            .is_initialized = data[45] != 0,
            .freeze_authority = readCOptionPubkey(data[46..82]),
        };
    }
};

/// SPL Token Account layout (165 bytes).
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/state.rs#L146-L195
pub const TokenAccount = struct {
    pub const LEN: usize = 165;
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
    delegate: ?Pubkey,
    state: AccountState,
    is_native: ?u64,
    delegated_amount: u64,
    close_authority: ?Pubkey,

    pub fn unpack(data: []const u8) ParseError!TokenAccount {
        if (data.len < LEN) return ParseError.InvalidAccountData;
        const state_byte = data[108];
        if (state_byte > 2) return ParseError.InvalidAccountData;
        return TokenAccount{
            .mint = Pubkey{ .data = data[0..32].* },
            .owner = Pubkey{ .data = data[32..64].* },
            .amount = std.mem.readInt(u64, data[64..72], .little),
            .delegate = readCOptionPubkey(data[72..108]),
            .state = @enumFromInt(state_byte),
            .is_native = readCOptionU64(data[109..121]),
            .delegated_amount = std.mem.readInt(u64, data[121..129], .little),
            .close_authority = readCOptionPubkey(data[129..165]),
        };
    }
};

/// SPL Token Multisig layout (355 bytes).
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/state.rs#L235-L270
pub const Multisig = struct {
    pub const LEN: usize = 355;
    pub const MAX_SIGNERS: usize = 11;
    m: u8,
    n: u8,
    is_initialized: bool,
    signers: [MAX_SIGNERS]Pubkey,
    pub fn unpack(data: []const u8) ParseError!Multisig {
        if (data.len != LEN) return ParseError.InvalidAccountData;
        var signers: [MAX_SIGNERS]Pubkey = undefined;
        for (0..MAX_SIGNERS) |i| {
            const start = 3 + i * 32;
            signers[i] = Pubkey{ .data = data[start..][0..32].* };
        }
        return Multisig{
            .m = data[0],
            .n = data[1],
            .is_initialized = data[2] != 0,
            .signers = signers,
        };
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L86-L93
pub const TokenAccountType = union(enum) {
    account: UiTokenAccount,
    mint: UiMint,
    multisig: UiMultisig,

    pub fn jsonStringify(self: TokenAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            .account => |v| {
                try jw.write("account");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .mint => |v| {
                try jw.write("mint");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
            .multisig => |v| {
                try jw.write("multisig");
                try jw.objectField("info");
                try v.jsonStringify(jw);
            },
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L53-L64
pub const UiTokenAccount = struct {
    mint: Pubkey.Base58String,
    owner: Pubkey.Base58String,
    token_amount: UiTokenAmount,
    delegate: ?Pubkey.Base58String,
    state: AccountState,
    is_native: bool,
    rent_exempt_reserve: ?UiTokenAmount,
    delegated_amount: ?UiTokenAmount,
    close_authority: ?Pubkey.Base58String,
    // Token-2022.
    extensions: std.BoundedArray(UiExtension, MAX_EXTENSIONS),

    pub fn jsonStringify(self: UiTokenAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("mint");
        try jw.write(self.mint.slice());
        try jw.objectField("owner");
        try jw.write(self.owner.slice());
        try jw.objectField("tokenAmount");
        try self.token_amount.jsonStringify(jw);
        try jw.objectField("delegate");
        if (self.delegate) |d| try jw.write(d.slice()) else try jw.write(null);
        try jw.objectField("state");
        try jw.write(switch (self.state) {
            .uninitialized => "uninitialized",
            .initialized => "initialized",
            .frozen => "frozen",
        });
        try jw.objectField("isNative");
        try jw.write(self.is_native);
        try jw.objectField("rentExemptReserve");
        if (self.rent_exempt_reserve) |r| try r.jsonStringify(jw) else try jw.write(null);
        try jw.objectField("delegatedAmount");
        if (self.delegated_amount) |d| try d.jsonStringify(jw) else try jw.write(null);
        try jw.objectField("closeAuthority");
        if (self.close_authority) |c| try jw.write(c.slice()) else try jw.write(null);
        if (self.extensions.len > 0) {
            try jw.objectField("extensions");
            try jw.beginArray();
            for (self.extensions) |ext| {
                try ext.jsonStringify(jw);
            }
            try jw.endArray();
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L66-L75
pub const UiMint = struct {
    mint_authority: ?Pubkey.Base58String,
    supply: u64,
    decimals: u8,
    is_initialized: bool,
    freeze_authority: ?Pubkey.Base58String,
    // Token-2022.
    extensions: std.BoundedArray(UiExtension, MAX_EXTENSIONS),

    pub fn jsonStringify(self: UiMint, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("mintAuthority");
        if (self.mint_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("supply");
        try jw.print("\"{d}\"", .{self.supply});
        try jw.objectField("decimals");
        try jw.write(self.decimals);
        try jw.objectField("isInitialized");
        try jw.write(self.is_initialized);
        try jw.objectField("freezeAuthority");
        if (self.freeze_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        if (self.extensions.len > 0) {
            try jw.objectField("extensions");
            try jw.beginArray();
            for (self.extensions) |ext| {
                try ext.jsonStringify(jw);
            }
            try jw.endArray();
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L77-L84
pub const UiMultisig = struct {
    num_required_signers: u8,
    num_valid_signers: u8,
    is_initialized: bool,
    signers: std.BoundedArray(Pubkey.Base58String, Multisig.MAX_SIGNERS),

    pub fn jsonStringify(self: UiMultisig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("numRequiredSigners");
        try jw.write(self.num_required_signers);
        try jw.objectField("numValidSigners");
        try jw.write(self.num_valid_signers);
        try jw.objectField("isInitialized");
        try jw.write(self.is_initialized);
        try jw.objectField("signers");
        try jw.beginArray();
        for (self.signers.constSlice()) |s| {
            try jw.write(s.slice());
        }
        try jw.endArray();
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L27-L37
pub const UiTokenAmount = struct {
    ui_amount: ?f64,
    decimals: u8,
    amount: u64,
    // max u64 digits + decimal point + null
    ui_amount_string: std.BoundedArray(u8, 40),

    /// Create a UiTokenAmount from raw amount and decimals.
    /// Formats the amount with proper decimal placement and trims trailing zeros.
    fn init(amount: u64, decimals: u8) UiTokenAmount {
        // Calculate ui_amount as f64 (may lose precision for large values)
        const ui_amount: ?f64 = if (decimals <= 20) blk: {
            const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
            break :blk @as(f64, @floatFromInt(amount)) / divisor;
        } else null;
        return UiTokenAmount{
            .ui_amount = ui_amount,
            .decimals = decimals,
            .amount = amount,
            .ui_amount_string = formatTokenAmount(amount, decimals),
        };
    }

    pub fn jsonStringify(self: UiTokenAmount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("uiAmount");
        if (self.ui_amount) |a| try jw.write(a) else try jw.write(null);
        try jw.objectField("decimals");
        try jw.write(self.decimals);
        try jw.objectField("amount");
        try jw.print("\"{d}\"", .{self.amount});
        try jw.objectField("uiAmountString");
        try jw.write(self.ui_amount_string.constSlice());
        try jw.endObject();
    }
};

/// Format amount with decimal point, trimming trailing zeros.
/// Examples:
///   formatTokenAmount(1000000, 6) → "1"
///   formatTokenAmount(1500000, 6) → "1.5"
///   formatTokenAmount(123, 6) → "0.000123"
///   formatTokenAmount(0, 6) → "0"
fn formatTokenAmount(amount: u64, decimals: u8) std.BoundedArray(u8, 40) {
    var buf: std.BoundedArray(u8, 40) = .{};

    if (decimals == 0) {
        const written = std.fmt.bufPrint(&buf.buffer, "{d}", .{amount}) catch unreachable;
        buf.len = @intCast(written.len);
        return buf;
    }

    // Format amount as string, left-padded with zeros to (decimals + 1) chars minimum
    // e.g., amount=123, decimals=6 → "0000123" → "0.000123"
    const min_len = decimals + 1;
    const written = std.fmt.bufPrint(&buf.buffer, "{d:0>[1]}", .{ amount, min_len }) catch unreachable;
    buf.len = @intCast(written.len);

    // Insert decimal point at position (len - decimals)
    const decimal_pos = buf.len - decimals;
    // Shift right to make room for decimal point
    std.mem.copyBackwards(u8, buf.buffer[decimal_pos + 1 .. buf.len + 1], buf.buffer[decimal_pos..buf.len]);
    buf.buffer[decimal_pos] = '.';
    buf.len += 1;

    // Trim trailing zeros
    while (buf.len > 0 and buf.buffer[buf.len - 1] == '0') {
        buf.len -= 1;
    }
    // Trim trailing decimal point
    if (buf.len > 0 and buf.buffer[buf.len - 1] == '.') {
        buf.len -= 1;
    }

    return buf;
}

// SPL Token uses fixed-offset binary layout (Pack trait), not bincode.
// TODO: COption crate layout might be binary compatible with zig more directly?
fn readCOptionPubkey(data: *const [36]u8) ?Pubkey {
    const tag = std.mem.readInt(u32, data[0..4], .little);
    if (tag == 0) return null;
    return Pubkey{ .data = data[4..36].* };
}

// COption<T> = 4-byte tag (0=None, 1=Some) + T
// TODO: COption crate layout might be binary compatible with zig more directly?
fn readCOptionU64(data: *const [12]u8) ?u64 {
    const tag = std.mem.readInt(u32, data[0..4], .little);
    if (tag == 0) return null;
    return std.mem.readInt(u64, data[4..12], .little);
}

test "rpc.account_decoder.parse_token: basic token account parsing" {
    const TEST_MINT_AUTHORITY = Pubkey{ .data = [_]u8{1} ** 32 };
    const TEST_FREEZE_AUTHORITY = Pubkey{ .data = [_]u8{2} ** 32 };

    const TEST_MINT = Mint{
        .mint_authority = TEST_MINT_AUTHORITY,
        .supply = 42,
        .decimals = 7,
        .is_initialized = true,
        .freeze_authority = TEST_FREEZE_AUTHORITY,
    };

    const TEST_MINT_SLICE: [Mint.LEN]u8 = .{
        1, 0, 0, 0, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 42, 0, 0, 0, 0, 0, 0, 0, 7, 1, 1, 0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, 2,  2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    };

    const TEST_ACCOUNT = TokenAccount{
        .mint = Pubkey{ .data = [_]u8{1} ** 32 },
        .owner = Pubkey{ .data = [_]u8{2} ** 32 },
        .amount = 3,
        .delegate = Pubkey{ .data = [_]u8{4} ** 32 },
        .state = .frozen,
        .is_native = 5,
        .delegated_amount = 6,
        .close_authority = Pubkey{ .data = [_]u8{7} ** 32 },
    };

    const TEST_ACCOUNT_SLICE: [TokenAccount.LEN]u8 = .{
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 1, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0,
        0, 6, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    };

    const TEST_MULTISIG = Multisig{
        .m = 1,
        .n = 11,
        .is_initialized = true,
        .signers = .{
            Pubkey{ .data = [_]u8{1} ** 32 },
            Pubkey{ .data = [_]u8{2} ** 32 },
            Pubkey{ .data = [_]u8{3} ** 32 },
            Pubkey{ .data = [_]u8{4} ** 32 },
            Pubkey{ .data = [_]u8{5} ** 32 },
            Pubkey{ .data = [_]u8{6} ** 32 },
            Pubkey{ .data = [_]u8{7} ** 32 },
            Pubkey{ .data = [_]u8{8} ** 32 },
            Pubkey{ .data = [_]u8{9} ** 32 },
            Pubkey{ .data = [_]u8{10} ** 32 },
            Pubkey{ .data = [_]u8{11} ** 32 },
        },
    };

    const TEST_MULTISIG_SLICE: [Multisig.LEN]u8 = .{
        1,  11, 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
        2,  2,  2,  2,  2,  2,  2,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
        3,  3,  3,  3,  3,  3,  3,  3,  3,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,
        4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
        5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
        6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
        8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
        9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    };

    // Mint - unpack from known bytes
    {
        const unpacked = try Mint.unpack(&TEST_MINT_SLICE);
        try std.testing.expect(unpacked.mint_authority != null);
        try std.testing.expectEqual(TEST_MINT_AUTHORITY, unpacked.mint_authority.?);
        try std.testing.expectEqual(@as(u64, 42), unpacked.supply);
        try std.testing.expectEqual(@as(u8, 7), unpacked.decimals);
        try std.testing.expect(unpacked.is_initialized);
        try std.testing.expect(unpacked.freeze_authority != null);
        try std.testing.expectEqual(TEST_FREEZE_AUTHORITY, unpacked.freeze_authority.?);
    }

    // Mint - too short should fail
    {
        const short_data: [Mint.LEN - 1]u8 = TEST_MINT_SLICE[0 .. Mint.LEN - 1].*;
        const result = Mint.unpack(&short_data);
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // Mint - unpack back to known struct
    {
        const unpacked = try Mint.unpack(&TEST_MINT_SLICE);
        try std.testing.expectEqual(TEST_MINT, unpacked);
    }

    // Account - unpack from known bytes
    {
        const unpacked = try TokenAccount.unpack(&TEST_ACCOUNT_SLICE);
        try std.testing.expectEqual(Pubkey{ .data = [_]u8{1} ** 32 }, unpacked.mint);
        try std.testing.expectEqual(Pubkey{ .data = [_]u8{2} ** 32 }, unpacked.owner);
        try std.testing.expectEqual(@as(u64, 3), unpacked.amount);
        try std.testing.expect(unpacked.delegate != null);
        try std.testing.expectEqual(Pubkey{ .data = [_]u8{4} ** 32 }, unpacked.delegate.?);
        try std.testing.expectEqual(AccountState.frozen, unpacked.state);
        try std.testing.expect(unpacked.is_native != null);
        try std.testing.expectEqual(@as(u64, 5), unpacked.is_native.?);
        try std.testing.expectEqual(@as(u64, 6), unpacked.delegated_amount);
        try std.testing.expect(unpacked.close_authority != null);
        try std.testing.expectEqual(Pubkey{ .data = [_]u8{7} ** 32 }, unpacked.close_authority.?);
    }

    // Account - too short should fail
    {
        const short_data: [TokenAccount.LEN - 1]u8 = TEST_ACCOUNT_SLICE[0 .. TokenAccount.LEN - 1].*;
        const result = TokenAccount.unpack(&short_data);
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // Account - unpack from known bytes
    {
        const unpacked = try TokenAccount.unpack(&TEST_ACCOUNT_SLICE);
        try std.testing.expectEqual(TEST_ACCOUNT, unpacked);
    }

    // Multisig - unpack from known bytes
    {
        const unpacked = try Multisig.unpack(&TEST_MULTISIG_SLICE);
        try std.testing.expectEqual(@as(u8, 1), unpacked.m);
        try std.testing.expectEqual(@as(u8, 11), unpacked.n);
        try std.testing.expect(unpacked.is_initialized);
        for (0..11) |i| {
            const expected_byte: u8 = @intCast(i + 1);
            try std.testing.expectEqual(Pubkey{ .data = [_]u8{expected_byte} ** 32 }, unpacked.signers[i]);
        }
    }

    // Multisig - wrong size should fail (too short)
    {
        const short_data: [Multisig.LEN - 1]u8 = TEST_MULTISIG_SLICE[0 .. Multisig.LEN - 1].*;
        const result = Multisig.unpack(&short_data);
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // Multisig - wrong size should fail (too long)
    {
        var long_data: [Multisig.LEN + 1]u8 = undefined;
        @memcpy(long_data[0..Multisig.LEN], &TEST_MULTISIG_SLICE);
        long_data[Multisig.LEN] = 0;
        const result = Multisig.unpack(&long_data);
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // Multisig - unpack from known bytes
    {
        const unpacked = try Multisig.unpack(&TEST_MULTISIG_SLICE);
        try std.testing.expectEqual(TEST_MULTISIG, unpacked);
    }

    // [agave] https://github.com/solana-program/token-2022/blob/v3.1.8/interface/src/state.rs#L398
    // Account data length < Account::LEN, unpack will not return a key
    {
        const src: [12]u8 = [_]u8{0} ** 12;
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result == null);
    }

    // The right account data size and initialized, unpack will return some key
    {
        var src: [TokenAccount.LEN]u8 = [_]u8{0} ** TokenAccount.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result != null);
    }

    // The right account data size and frozen, unpack will return some key
    {
        var src: [TokenAccount.LEN]u8 = [_]u8{0} ** TokenAccount.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.frozen);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result != null);
    }

    // Account data length > account data size, but not a valid extension,
    // unpack will not return a key
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result == null);
    }

    // Account data length > account data size with a valid extension and
    // initialized, expect some key returned
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result != null);
    }

    // Account data length > account data size with a valid extension but
    // uninitialized, expect None
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.uninitialized);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result == null);
    }

    // Account data length is multi-sig data size with a valid extension and
    // initialized, expect none
    {
        var src: [Multisig.LEN]u8 = [_]u8{0} ** Multisig.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        const result = getTokenAccountOwner(&src);
        try std.testing.expect(result == null);
    }

    // [agave] https://github.com/solana-program/token-2022/blob/v3.1.8/interface/src/state.rs#L505
    // Account data length < Account::LEN, unpack will not return a key
    {
        const src: [12]u8 = [_]u8{0} ** 12;
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result == null);
    }

    // The right account data size and initialized, unpack will return some key
    {
        var src: [TokenAccount.LEN]u8 = [_]u8{0} ** TokenAccount.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result != null);
    }

    // The right account data size and frozen, unpack will return some key
    {
        var src: [TokenAccount.LEN]u8 = [_]u8{0} ** TokenAccount.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.frozen);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result != null);
    }

    // Account data length > account data size, but not a valid extension,
    // unpack will not return a key
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result == null);
    }

    // Account data length > account data size with a valid extension and
    // initialized, expect some key returned
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result != null);
    }

    // Account data length > account data size with a valid extension but
    // uninitialized, expect none
    {
        var src: [TokenAccount.LEN + 5]u8 = [_]u8{0} ** (TokenAccount.LEN + 5);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.uninitialized);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result == null);
    }

    // Account data length is multi-sig data size with a valid extension and
    // initialized, expect none
    {
        var src: [Multisig.LEN]u8 = [_]u8{0} ** Multisig.LEN;
        src[ACCOUNT_INITIALIZED_INDEX] = @intFromEnum(AccountState.initialized);
        src[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);
        const result = getTokenAccountMint(&src);
        try std.testing.expect(result == null);
    }
}

test "rpc.account_decoder.parse_token: basic extension parsing" {
    // Test TLV parsing with marker extension
    {
        // make a minimal Token-2022 account with ImmutableOwner extension
        // Layout: [165 bytes base][1 byte discriminator][4 byte TLV header][0 bytes value][2 byte terminator]
        var data: [172]u8 = undefined;
        @memset(&data, 0);

        // Account type discriminator at offset 165
        data[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);

        // TLV entry: type=7 (ImmutableOwner), length=0
        // ExtensionType.immutable_owner (low byte)
        data[166] = 7;
        // (high byte)
        data[167] = 0;
        // Length (low byte)
        data[168] = 0;
        // Length (high byte)
        data[169] = 0;

        // Terminator: type=0 (Uninitialized)
        data[170] = 0;
        data[171] = 0;

        const extensions = parseExtensions(data[TokenAccount.LEN..]);
        try std.testing.expectEqual(1, extensions.len);
        try std.testing.expectEqual(UiExtension.immutable_owner, extensions.get(0));
    }

    // Test multiple extensions
    {
        var data: [180]u8 = undefined;
        @memset(&data, 0);

        data[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);

        // Extension 1: ImmutableOwner (type=7, len=0)
        data[166] = 7;
        data[167] = 0;
        data[168] = 0;
        data[169] = 0;

        // Extension 2: MemoTransfer (type=8, len=1, value=1)
        data[170] = 8;
        data[171] = 0;
        data[172] = 1;
        data[173] = 0;
        // require_incoming_transfer_memos = true
        data[174] = 1;

        // Terminator
        data[175] = 0;
        data[176] = 0;

        const extensions = parseExtensions(data[TokenAccount.LEN..]);
        try std.testing.expectEqual(2, extensions.len);
        try std.testing.expectEqual(UiExtension.immutable_owner, extensions.get(0));

        const memo = extensions.get(1);
        switch (memo) {
            .memo_transfer => |m| {
                try std.testing.expect(m.require_incoming_transfer_memos);
            },
            else => try std.testing.expect(false),
        }
    }

    // Test unknown extension type returns unparseable
    {
        var data: [174]u8 = undefined;
        @memset(&data, 0);

        data[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.account);

        // Unknown extension type (255)
        data[166] = 255;
        data[167] = 0;
        data[168] = 0;
        data[169] = 0;

        // Terminator
        data[170] = 0;
        data[171] = 0;

        const extensions = parseExtensions(data[TokenAccount.LEN..]);
        try std.testing.expectEqual(1, extensions.len);
        try std.testing.expectEqual(UiExtension.unparseable_extension, extensions.get(0));
    }

    // Test insufficient data returns null
    {
        const data: [1]u8 = .{0};
        const extensions = parseExtensions(&data);
        try std.testing.expect(extensions.len == 0);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L484
test "rpc.account_decoder.parse_token: token account with extensions" {
    const mint_pubkey = Pubkey{ .data = [_]u8{2} ** 32 };
    const owner_pubkey = Pubkey{ .data = [_]u8{3} ** 32 };
    // Build token account data manually (165 bytes)
    // Layout: mint(32) + owner(32) + amount(8) + delegate(36) + state(1) + is_native(12) + delegated_amount(8) + close_authority(36)
    var account_data: [TokenAccount.LEN]u8 = [_]u8{0} ** TokenAccount.LEN;
    // mint (bytes 0-31)
    @memcpy(account_data[0..32], &mint_pubkey.data);
    // owner (bytes 32-63)
    @memcpy(account_data[32..64], &owner_pubkey.data);
    // amount = 42 (bytes 64-71)
    std.mem.writeInt(u64, account_data[64..72], 42, .little);
    // delegate = None (COption: tag=0) (bytes 72-107)
    std.mem.writeInt(u32, account_data[72..76], 0, .little);
    // state = Initialized (byte 108)
    account_data[108] = @intFromEnum(AccountState.initialized);
    // is_native = None (COption: tag=0) (bytes 109-120)
    std.mem.writeInt(u32, account_data[109..113], 0, .little);
    // delegated_amount = 0 (bytes 121-128)
    std.mem.writeInt(u64, account_data[121..129], 0, .little);
    // close_authority = Some(owner_pubkey) (bytes 129-164)
    std.mem.writeInt(u32, account_data[129..133], 1, .little);
    @memcpy(account_data[133..165], &owner_pubkey.data);

    // Test: parsing without decimals returns null (token accounts require decimals)
    {
        const result = try parseToken(&account_data, null);
        try std.testing.expect(result == null);
    }

    // Test: parsing with decimals succeeds
    {
        const additional_data = SplTokenAdditionalData{ .decimals = 2 };
        const result = try parseToken(&account_data, &additional_data);
        try std.testing.expect(result != null);
        switch (result.?) {
            .account => |ui_account| {
                try std.testing.expectEqualStrings(mint_pubkey.base58String().slice(), ui_account.mint.slice());
                try std.testing.expectEqualStrings(owner_pubkey.base58String().slice(), ui_account.owner.slice());
                try std.testing.expectEqual(@as(u64, 42), ui_account.token_amount.amount);
                try std.testing.expectEqual(@as(u8, 2), ui_account.token_amount.decimals);
                try std.testing.expect(ui_account.token_amount.ui_amount != null);
                try std.testing.expect(@abs(ui_account.token_amount.ui_amount.? - 0.42) < 0.001);
                try std.testing.expectEqualStrings("0.42", ui_account.token_amount.ui_amount_string.constSlice());
                try std.testing.expect(ui_account.delegate == null);
                try std.testing.expectEqual(AccountState.initialized, ui_account.state);
                try std.testing.expect(!ui_account.is_native);
                try std.testing.expect(ui_account.rent_exempt_reserve == null);
                try std.testing.expect(ui_account.delegated_amount == null);
                try std.testing.expect(ui_account.close_authority != null);
                try std.testing.expectEqualStrings(owner_pubkey.base58String().slice(), ui_account.close_authority.?.slice());
            },
            else => try std.testing.expect(false),
        }
    }

    // Test: mint parsing (82 bytes)
    var mint_data: [Mint.LEN]u8 = [_]u8{0} ** Mint.LEN;
    // mint_authority = Some(owner_pubkey) (bytes 0-35)
    std.mem.writeInt(u32, mint_data[0..4], 1, .little);
    @memcpy(mint_data[4..36], &owner_pubkey.data);
    // supply = 42 (bytes 36-43)
    std.mem.writeInt(u64, mint_data[36..44], 42, .little);
    // decimals = 3 (byte 44)
    mint_data[44] = 3;
    // is_initialized = true (byte 45)
    mint_data[45] = 1;
    // freeze_authority = Some(owner_pubkey) (bytes 46-81)
    std.mem.writeInt(u32, mint_data[46..50], 1, .little);
    @memcpy(mint_data[50..82], &owner_pubkey.data);
    {
        const result = try parseToken(&mint_data, null);
        try std.testing.expect(result != null);
        switch (result.?) {
            .mint => |ui_mint| {
                try std.testing.expect(ui_mint.mint_authority != null);
                try std.testing.expectEqualStrings(owner_pubkey.base58String().slice(), ui_mint.mint_authority.?.slice());
                try std.testing.expectEqual(@as(u64, 42), ui_mint.supply);
                try std.testing.expectEqual(@as(u8, 3), ui_mint.decimals);
                try std.testing.expect(ui_mint.is_initialized);
                try std.testing.expect(ui_mint.freeze_authority != null);
                try std.testing.expectEqualStrings(owner_pubkey.base58String().slice(), ui_mint.freeze_authority.?.slice());
            },
            else => try std.testing.expect(false),
        }
    }

    // Test: multisig parsing (355 bytes)
    const signer1 = Pubkey{ .data = [_]u8{1} ** 32 };
    const signer2 = Pubkey{ .data = [_]u8{2} ** 32 };
    const signer3 = Pubkey{ .data = [_]u8{3} ** 32 };
    var multisig_data: [Multisig.LEN]u8 = [_]u8{0} ** Multisig.LEN;
    multisig_data[0] = 2; // m (required signers)
    multisig_data[1] = 3; // n (valid signers)
    multisig_data[2] = 1; // is_initialized
    @memcpy(multisig_data[3..35], &signer1.data);
    @memcpy(multisig_data[35..67], &signer2.data);
    @memcpy(multisig_data[67..99], &signer3.data);
    {
        const result = try parseToken(&multisig_data, null);
        try std.testing.expect(result != null);
        switch (result.?) {
            .multisig => |ui_multisig| {
                try std.testing.expectEqual(@as(u8, 2), ui_multisig.num_required_signers);
                try std.testing.expectEqual(@as(u8, 3), ui_multisig.num_valid_signers);
                try std.testing.expect(ui_multisig.is_initialized);
                try std.testing.expectEqual(@as(usize, 3), ui_multisig.signers.len);
                try std.testing.expectEqualStrings(signer1.base58String().slice(), ui_multisig.signers.get(0).slice());
                try std.testing.expectEqualStrings(signer2.base58String().slice(), ui_multisig.signers.get(1).slice());
                try std.testing.expectEqualStrings(signer3.base58String().slice(), ui_multisig.signers.get(2).slice());
            },
            else => try std.testing.expect(false),
        }
    }

    // Test: bad data returns null
    {
        const bad_data: [4]u8 = [_]u8{0} ** 4;
        const result = try parseToken(&bad_data, null);
        try std.testing.expect(result == null);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L300
test "rpc.account_decoder.parse_token: formatTokenAmount conformance" {

    // Basic integers
    try std.testing.expectEqualStrings("1", formatTokenAmount(1, 0).constSlice());
    try std.testing.expectEqualStrings("10", formatTokenAmount(10, 0).constSlice());

    // Small amounts with decimals
    try std.testing.expectEqualStrings("0.000000001", formatTokenAmount(1, 9).constSlice());

    // Whole numbers that trim to clean result
    try std.testing.expectEqualStrings("1", formatTokenAmount(1_000_000_000, 9).constSlice());

    // Partial decimal trimming (trailing zero removed)
    try std.testing.expectEqualStrings("1234567.89", formatTokenAmount(1_234_567_890, 3).constSlice());

    // Large decimals (25 places) - tests precision
    try std.testing.expectEqualStrings("0.000000000000000123456789", formatTokenAmount(1_234_567_890, 25).constSlice());

    // Zero amounts
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 0).constSlice());
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 9).constSlice());
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 25).constSlice());
}

test "rpc.account_decoder.parse_token: UiTokenAmount.init ui_amount" {
    // ui_amount is Some when decimals <= 20
    {
        const t = UiTokenAmount.init(1, 0);
        try std.testing.expectEqual(@as(?f64, 1.0), t.ui_amount);
    }
    {
        const t = UiTokenAmount.init(1_000_000_000, 9);
        try std.testing.expectEqual(@as(?f64, 1.0), t.ui_amount);
    }
    // ui_amount is None when decimals > 20
    {
        const t = UiTokenAmount.init(1_234_567_890, 25);
        try std.testing.expect(t.ui_amount == null);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L484
test "rpc.account_decoder.parse_token: token account with extensions conformance" {
    const mint_pubkey = Pubkey{ .data = [_]u8{2} ** 32 };
    const owner_pubkey = Pubkey{ .data = [_]u8{3} ** 32 };
    // Calculate account size: base(165) + discriminator(1) + extensions
    // ImmutableOwner: 4 header + 0 value = 4
    // MemoTransfer: 4 header + 1 value = 5
    // Total: 165 + 1 + 4 + 5 = 175 bytes
    const ACCOUNT_SIZE = TokenAccount.LEN + 1 + 4 + 5;
    var account_data: [ACCOUNT_SIZE]u8 = [_]u8{0} ** ACCOUNT_SIZE;
    // Build base account (same as existing test)
    @memcpy(account_data[0..32], &mint_pubkey.data);
    @memcpy(account_data[32..64], &owner_pubkey.data);
    std.mem.writeInt(u64, account_data[64..72], 42, .little);
    std.mem.writeInt(u32, account_data[72..76], 0, .little); // delegate = None
    account_data[108] = @intFromEnum(AccountState.initialized);
    std.mem.writeInt(u32, account_data[109..113], 0, .little); // is_native = None
    std.mem.writeInt(u64, account_data[121..129], 0, .little);
    std.mem.writeInt(u32, account_data[129..133], 1, .little); // close_authority = Some
    @memcpy(account_data[133..165], &owner_pubkey.data);
    // Account type discriminator
    account_data[165] = @intFromEnum(AccountTypeDiscriminator.account);
    // Extension 1: ImmutableOwner (type=7, len=0)
    std.mem.writeInt(u16, account_data[166..168], 7, .little);
    std.mem.writeInt(u16, account_data[168..170], 0, .little);
    // Extension 2: MemoTransfer (type=8, len=1, value=1)
    std.mem.writeInt(u16, account_data[170..172], 8, .little);
    std.mem.writeInt(u16, account_data[172..174], 1, .little);
    account_data[174] = 1; // require_incoming_transfer_memos = true

    // Parse and verify
    const additional_data = SplTokenAdditionalData{ .decimals = 2 };
    const result = try parseToken(&account_data, &additional_data);
    try std.testing.expect(result != null);
    switch (result.?) {
        .account => |ui_account| {
            // Verify base fields (same assertions as before)
            try std.testing.expectEqualStrings(mint_pubkey.base58String().slice(), ui_account.mint.slice());
            try std.testing.expectEqualStrings(owner_pubkey.base58String().slice(), ui_account.owner.slice());
            try std.testing.expectEqual(@as(u64, 42), ui_account.token_amount.amount);
            try std.testing.expectEqual(AccountState.initialized, ui_account.state);
            // Verify extensions
            try std.testing.expectEqual(@as(usize, 2), ui_account.extensions.len);
            try std.testing.expectEqual(UiExtension.immutable_owner, ui_account.extensions.get(0));

            switch (ui_account.extensions.get(1)) {
                .memo_transfer => |m| {
                    try std.testing.expect(m.require_incoming_transfer_memos);
                },
                else => try std.testing.expect(false),
            }
        },
        else => try std.testing.expect(false),
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L584
test "rpc.account_decoder.parse_token: mint with extensions conformance" {
    const owner_pubkey = Pubkey{ .data = [_]u8{3} ** 32 };
    // Size: 82 base + 1 discriminator + 4 TLV header + 32 value = 119
    const MINT_SIZE = Mint.LEN + 1 + 4 + 32;
    var mint_data: [MINT_SIZE]u8 = [_]u8{0} ** MINT_SIZE;
    // Build base mint
    std.mem.writeInt(u32, mint_data[0..4], 1, .little); // mint_authority = Some
    @memcpy(mint_data[4..36], &owner_pubkey.data);
    std.mem.writeInt(u64, mint_data[36..44], 42, .little); // supply
    mint_data[44] = 3; // decimals
    mint_data[45] = 1; // is_initialized
    std.mem.writeInt(u32, mint_data[46..50], 1, .little); // freeze_authority = Some
    @memcpy(mint_data[50..82], &owner_pubkey.data);
    // Account type discriminator
    mint_data[82] = @intFromEnum(AccountTypeDiscriminator.mint);
    // Extension: MintCloseAuthority (type=3, len=32)
    std.mem.writeInt(u16, mint_data[83..85], 3, .little);
    std.mem.writeInt(u16, mint_data[85..87], 32, .little);
    @memcpy(mint_data[87..119], &owner_pubkey.data);
    // Parse and verify
    const result = try parseToken(&mint_data, null);
    try std.testing.expect(result != null);
    switch (result.?) {
        .mint => |ui_mint| {
            try std.testing.expect(ui_mint.mint_authority != null);
            try std.testing.expectEqual(@as(u64, 42), ui_mint.supply);
            try std.testing.expectEqual(@as(u8, 3), ui_mint.decimals);
            try std.testing.expect(ui_mint.is_initialized);
            // Verify extension
            try std.testing.expectEqual(@as(usize, 1), ui_mint.extensions.len);
            switch (ui_mint.extensions.get(0)) {
                .mint_close_authority => |mca| {
                    try std.testing.expect(mca.close_authority != null);
                    try std.testing.expectEqualStrings(
                        owner_pubkey.base58String().slice(),
                        mca.close_authority.?.slice(),
                    );
                },
                else => try std.testing.expect(false),
            }
        },
        else => try std.testing.expect(false),
    }
}
