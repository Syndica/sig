/// Types for parsing SPL Token accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_codec = @import("lib.zig");
const parse_token_extension = @import("parse_token_extension.zig");

const Pubkey = sig.core.Pubkey;
const ParseError = account_codec.ParseError;
const AccountState = account_codec.AccountState;
const JsonArray = account_codec.JsonArray;
const JsonString = account_codec.JsonString;

const UiExtension = parse_token_extension.UiExtension;
const InterestBearingConfigData = parse_token_extension.InterestBearingConfigData;
const ScaledUiAmountConfigData = parse_token_extension.ScaledUiAmountConfigData;

const MAX_EXTENSIONS = parse_token_extension.MAX_EXTENSIONS;
const parseExtensions = parse_token_extension.parseExtensions;

/// Index of the account state byte in TokenAccount.
/// Offset 108 = mint(32) + owner(32) + amount(8) + delegate(36) = 108
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/generic_token_account.rs#L56
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

/// Token-2022 account type discriminator (placed after base account data for extended accounts).
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L1038-L1047
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
        // Token-2022 extended accounts: discriminator is ALWAYS at offset 165 (TokenAccount.LEN)
        // regardless of whether it's a mint or token account. Mints are padded with zeros
        // from offset 82 to 165 to achieve this uniform layout.
        // [spl] https://github.com/solana-program/token-2022/blob/main/program/src/extension/mod.rs
        if (data.len > TokenAccount.LEN) {
            return switch (data[TokenAccount.LEN]) {
                @intFromEnum(AccountTypeDiscriminator.mint) => .mint,
                @intFromEnum(AccountTypeDiscriminator.account) => .token_account,
                else => null,
            };
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

    const add_data = additional_data orelse return null;
    const is_native = account.is_native != null;
    return .{ .account = .{
        .mint = account.mint,
        .owner = account.owner,
        .tokenAmount = UiTokenAmount.init(account.amount, add_data.*),
        .delegate = account.delegate,
        .state = account.state,
        .isNative = is_native,
        .rentExemptReserve = if (account.is_native) |r|
            UiTokenAmount.init(r, add_data.*)
        else
            null,
        .delegatedAmount = if (account.delegate != null and account.delegated_amount > 0)
            UiTokenAmount.init(account.delegated_amount, add_data.*)
        else
            null,
        .closeAuthority = account.close_authority,
        .extensions = parseExtensions(data[TokenAccount.LEN..]),
    } };
}

fn parseAsMint(data: []const u8) ?TokenAccountType {
    const mint = Mint.unpack(data) catch return null;
    if (!mint.is_initialized) return null;
    // For Token-2022 mints with extensions, TLV data starts at offset 165 (TokenAccount.LEN).
    // The discriminator is at offset 165, and TLV entries start at offset 166.
    // For standard SPL Token mints (82 bytes), there are no extensions.
    const extension_data = if (data.len > TokenAccount.LEN) data[TokenAccount.LEN..] else &[_]u8{};
    return .{ .mint = .{
        .mintAuthority = mint.mint_authority,
        .supply = account_codec.Stringified(u64).init(mint.supply),
        .decimals = mint.decimals,
        .isInitialized = mint.is_initialized,
        .freezeAuthority = mint.freeze_authority,
        .extensions = parseExtensions(extension_data),
    } };
}

fn parseAsMultisig(data: []const u8) ?TokenAccountType {
    const multisig = Multisig.unpack(data) catch return null;
    if (!multisig.is_initialized) return null;
    // Collect non-zero signers up to n valid signers
    var signers: JsonArray(Pubkey, Multisig.MAX_SIGNERS) = .{};
    for (multisig.signers) |signer| {
        if (!signer.isZeroed()) {
            signers.appendAssumeCapacity(signer);
        }
    }
    return .{ .multisig = .{
        .numRequiredSigners = multisig.m,
        .numValidSigners = multisig.n,
        .isInitialized = multisig.is_initialized,
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
    unix_timestamp: i64 = 0, // From bank clock sysvar, used for interest/scaled calculations
    // Token-2022 extension data
    interest_bearing_config: ?InterestBearingConfigData = null,
    scaled_ui_amount_config: ?ScaledUiAmountConfigData = null,
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
            inline else => |v, tag| {
                try jw.write(@tagName(tag));
                try jw.objectField("info");
                try jw.write(v);
            },
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L53-L64
pub const UiTokenAccount = struct {
    mint: Pubkey,
    owner: Pubkey,
    tokenAmount: UiTokenAmount,
    delegate: ?Pubkey,
    state: AccountState,
    isNative: bool,
    rentExemptReserve: ?UiTokenAmount,
    delegatedAmount: ?UiTokenAmount,
    closeAuthority: ?Pubkey,
    // Token-2022.
    extensions: JsonArray(UiExtension, MAX_EXTENSIONS),

    pub fn jsonStringify(self: UiTokenAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        // Omit delegate when null (matches Agave's skip_serializing_if = "Option::is_none")
        if (self.delegate) |d| {
            try jw.objectField("delegate");
            try jw.write(d);
        }
        try jw.objectField("isNative");
        try jw.write(self.isNative);
        try jw.objectField("mint");
        try jw.write(self.mint);
        try jw.objectField("owner");
        try jw.write(self.owner);
        try jw.objectField("state");
        try jw.write(switch (self.state) {
            .uninitialized => "uninitialized",
            .initialized => "initialized",
            .frozen => "frozen",
        });
        try jw.objectField("tokenAmount");
        try jw.write(self.tokenAmount);
        // Omit closeAuthority when null (matches Agave's skip_serializing_if)
        if (self.closeAuthority) |c| {
            try jw.objectField("closeAuthority");
            try jw.write(c);
        }
        // Omit delegatedAmount when null (matches Agave's skip_serializing_if)
        if (self.delegatedAmount) |d| {
            try jw.objectField("delegatedAmount");
            try jw.write(d);
        }
        // Omit rentExemptReserve when null (matches Agave's skip_serializing_if)
        if (self.rentExemptReserve) |r| {
            try jw.objectField("rentExemptReserve");
            try jw.write(r);
        }
        if (self.extensions.len() > 0) {
            try jw.objectField("extensions");
            try jw.write(self.extensions);
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L66-L75
pub const UiMint = struct {
    mintAuthority: ?Pubkey,
    supply: account_codec.Stringified(u64),
    decimals: u8,
    isInitialized: bool,
    freezeAuthority: ?Pubkey,
    // Token-2022.
    extensions: JsonArray(UiExtension, MAX_EXTENSIONS),

    pub fn jsonStringify(self: UiMint, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("mintAuthority");
        try jw.write(self.mintAuthority);
        try jw.objectField("supply");
        try jw.write(self.supply);
        try jw.objectField("decimals");
        try jw.write(self.decimals);
        try jw.objectField("isInitialized");
        try jw.write(self.isInitialized);
        try jw.objectField("freezeAuthority");
        try jw.write(self.freezeAuthority);
        if (self.extensions.len() > 0) {
            try jw.objectField("extensions");
            try jw.write(self.extensions);
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L77-L84
pub const UiMultisig = struct {
    numRequiredSigners: u8,
    numValidSigners: u8,
    isInitialized: bool,
    signers: JsonArray(Pubkey, Multisig.MAX_SIGNERS),
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs#L27-L37
pub const UiTokenAmount = struct {
    ui_amount: ?f64,
    decimals: u8,
    amount: u64,
    // max u64 digits + decimal point + null
    ui_amount_string: JsonString(40),

    /// Create a UiTokenAmount from raw amount and additional data.
    /// Handles interest-bearing and scaled UI amount calculations if configured.
    /// Priority: interest-bearing > scaled > simple
    fn init(amount: u64, additional_data: SplTokenAdditionalData) UiTokenAmount {
        const decimals = additional_data.decimals;

        // Priority 1: Interest-bearing config
        if (additional_data.interest_bearing_config) |config| {
            if (interestBearingAmountToUi(
                amount,
                decimals,
                config,
                additional_data.unix_timestamp,
            )) |result| {
                return .{
                    .ui_amount = result.ui_amount,
                    .decimals = decimals,
                    .amount = amount,
                    .ui_amount_string = result.ui_amount_string,
                };
            }
        }

        // Priority 2: Scaled UI amount config
        if (additional_data.scaled_ui_amount_config) |config| {
            const result = scaledAmountToUi(
                amount,
                decimals,
                config,
                additional_data.unix_timestamp,
            );
            return .{
                .ui_amount = result.ui_amount,
                .decimals = decimals,
                .amount = amount,
                .ui_amount_string = result.ui_amount_string,
            };
        }

        // Default: Simple calculation
        const ui_amount: ?f64 = if (decimals <= 20) blk: {
            const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
            break :blk @as(f64, @floatFromInt(amount)) / divisor;
        } else null;

        return .{
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
        try jw.write(self.ui_amount_string);
        try jw.endObject();
    }
};

/// Format amount with decimal point, trimming trailing zeros.
/// Examples:
///   formatTokenAmount(1000000, 6) → "1"
///   formatTokenAmount(1500000, 6) → "1.5"
///   formatTokenAmount(123, 6) → "0.000123"
///   formatTokenAmount(0, 6) → "0"
fn formatTokenAmount(amount: u64, decimals: u8) JsonString(40) {
    var buf: JsonString(40) = .{ .inner = .{} };

    if (decimals == 0) {
        const written = std.fmt.bufPrint(&buf.inner.buffer, "{d}", .{amount}) catch unreachable;
        buf.inner.len = @intCast(written.len);
        return buf;
    }

    // Format amount as string, left-padded with zeros to (decimals + 1) chars minimum
    // e.g., amount=123, decimals=6 → "0000123" → "0.000123"
    const min_len = decimals + 1;
    const written = std.fmt.bufPrint(
        &buf.inner.buffer,
        "{d:0>[1]}",
        .{ amount, min_len },
    ) catch unreachable;
    buf.inner.len = @intCast(written.len);

    // Insert decimal point at position (len - decimals)
    const decimal_pos = buf.inner.len - decimals;
    // Shift right to make room for decimal point
    const src = buf.inner.buffer[decimal_pos..buf.inner.len];
    const dst = buf.inner.buffer[decimal_pos + 1 .. buf.inner.len + 1];
    std.mem.copyBackwards(u8, dst, src);
    buf.inner.buffer[decimal_pos] = '.';
    buf.inner.len += 1;

    // Trim trailing zeros
    while (buf.inner.len > 0 and buf.inner.buffer[buf.inner.len - 1] == '0') {
        buf.inner.len -= 1;
    }
    // Trim trailing decimal point
    if (buf.inner.len > 0 and buf.inner.buffer[buf.inner.len - 1] == '.') {
        buf.inner.len -= 1;
    }

    return buf;
}

// Constants for interest-bearing calculations
// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/interest_bearing_mint/mod.rs
const SECONDS_PER_YEAR: f64 = 31_556_736.0; // 60 * 60 * 24 * 365.24
const ONE_IN_BASIS_POINTS: f64 = 10_000.0;

/// Calculate UI amount for interest-bearing tokens using compound interest.
/// Returns null if timestamps are invalid (e.g., negative timespans).
fn interestBearingAmountToUi(
    amount: u64,
    decimals: u8,
    config: InterestBearingConfigData,
    unix_timestamp: i64,
) ?struct { ui_amount: ?f64, ui_amount_string: JsonString(40) } {
    // pre_update_timespan = last_update_timestamp - initialization_timestamp
    const pre_timespan = config.last_update_timestamp - config.initialization_timestamp;
    if (pre_timespan < 0) return null;

    // post_update_timespan = current_timestamp - last_update_timestamp
    const post_timespan = unix_timestamp - config.last_update_timestamp;
    if (post_timespan < 0) return null;

    // pre_update_exp = exp(rate * time / SECONDS_PER_YEAR / 10000)
    const pre_rate: f64 = @floatFromInt(config.pre_update_average_rate);
    const pre_ts: f64 = @floatFromInt(pre_timespan);
    const pre_exponent = pre_rate * pre_ts / SECONDS_PER_YEAR / ONE_IN_BASIS_POINTS;
    const pre_exp = @exp(pre_exponent);

    // post_update_exp
    const post_rate: f64 = @floatFromInt(config.current_rate);
    const post_ts: f64 = @floatFromInt(post_timespan);
    const post_exponent = post_rate * post_ts / SECONDS_PER_YEAR / ONE_IN_BASIS_POINTS;
    const post_exp = @exp(post_exponent);

    // total_scale = pre_exp * post_exp / 10^decimals
    const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
    const total_scale = pre_exp * post_exp / divisor;

    // scaled amount
    const scaled_amount = @as(f64, @floatFromInt(amount)) * total_scale;

    // Format with decimals precision, then trim
    var buf: JsonString(40) = .{ .inner = .{} };
    if (std.math.isInf(scaled_amount)) {
        buf.inner.appendSliceAssumeCapacity("inf");
    } else {
        // Format with fixed decimals precision
        const written = std.fmt.bufPrint(
            &buf.inner.buffer,
            "{d:.[1]}",
            .{ scaled_amount, decimals },
        ) catch return null;
        buf.inner.len = @intCast(written.len);
        trimUiAmountStringInPlace(&buf.inner, decimals);
    }

    // ui_amount as f64
    const ui_amount: ?f64 = if (std.math.isInf(scaled_amount))
        scaled_amount
    else
        std.fmt.parseFloat(f64, buf.constSlice()) catch null;

    return .{ .ui_amount = ui_amount, .ui_amount_string = buf };
}

/// Calculate UI amount for scaled tokens using multiplier.
/// Truncates toward zero before applying decimals (Agave behavior).
fn scaledAmountToUi(
    amount: u64,
    decimals: u8,
    config: ScaledUiAmountConfigData,
    unix_timestamp: i64,
) struct { ui_amount: ?f64, ui_amount_string: JsonString(40) } {
    // Pick current or new multiplier based on timestamp
    const multiplier = if (unix_timestamp >= config.new_multiplier_effective_timestamp)
        config.new_multiplier
    else
        config.multiplier;

    // scaled_amount = amount * multiplier
    const scaled_amount = @as(f64, @floatFromInt(amount)) * multiplier;

    // TRUNCATE toward zero BEFORE applying decimals
    const truncated = @trunc(scaled_amount);

    // Apply decimals
    const divisor = std.math.pow(f64, 10.0, @floatFromInt(decimals));
    const ui_value = truncated / divisor;

    // Format
    var buf: JsonString(40) = .{ .inner = .{} };
    if (std.math.isInf(ui_value)) {
        buf.inner.appendSliceAssumeCapacity("inf");
    } else {
        const written = std.fmt.bufPrint(
            &buf.inner.buffer,
            "{d:.[1]}",
            .{ ui_value, decimals },
        ) catch unreachable;
        buf.inner.len = @intCast(written.len);
        trimUiAmountStringInPlace(&buf.inner, decimals);
    }

    return .{
        .ui_amount = if (std.math.isInf(ui_value))
            ui_value
        else
            std.fmt.parseFloat(f64, buf.constSlice()) catch null,
        .ui_amount_string = buf,
    };
}

/// Trim trailing zeros and decimal point from a formatted number string.
fn trimUiAmountStringInPlace(buf: *std.BoundedArray(u8, 40), decimals: u8) void {
    if (decimals == 0) return;
    // Trim trailing zeros
    while (buf.len > 0 and buf.buffer[buf.len - 1] == '0') {
        buf.len -= 1;
    }
    // Trim trailing decimal point
    if (buf.len > 0 and buf.buffer[buf.len - 1] == '.') {
        buf.len -= 1;
    }
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

test "rpc.account_codec.parse_token: basic token account parsing" {
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

    // zig fmt: off
    const TEST_MULTISIG_SLICE: [Multisig.LEN]u8 = .{
        1,  11, 1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,
        1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  2,
        2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,
        2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  2,  3,  3,  3,  3,  3,
        3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,  3,
        3,  3,  3,  3,  3,  3,  3,  3,  3,  4,  4,  4,  4,  4,  4,  4,  4,  4,
        4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,  4,
        4,  4,  4,  4,  4,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
        5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
        5,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
        6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
        7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  8,  8,  8,  8,  8,  8,  8,
        8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
        8,  8,  8,  8,  8,  8,  8,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
        9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,  9,
        9,  9,  9,  10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10,
        10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 11,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
        11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
    };
    // zig fmt: on

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
            try std.testing.expectEqual(
                Pubkey{ .data = [_]u8{expected_byte} ** 32 },
                unpacked.signers[i],
            );
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

    // Some additional tests
    {
        var account_data: [TokenAccount.LEN]u8 = undefined;
        @memset(&account_data, 0);

        // Set mint pubkey (first 32 bytes)
        const expected_mint = Pubkey.parse("So11111111111111111111111111111111111111112");
        @memcpy(account_data[0..32], &expected_mint.data);

        // Set state to initialized (byte 108)
        account_data[108] = 1;

        const result = getTokenAccountMint(&account_data);
        try std.testing.expect(result != null);
        try std.testing.expectEqual(expected_mint, result.?);
    }
}

test "rpc.account_codec.parse_token: basic extension parsing" {
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
        try std.testing.expectEqual(1, extensions.len());
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
        try std.testing.expectEqual(2, extensions.len());
        try std.testing.expectEqual(UiExtension.immutable_owner, extensions.get(0));

        const memo = extensions.get(1);
        switch (memo) {
            .memo_transfer => |m| {
                try std.testing.expect(m.requireIncomingTransferMemos);
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
        try std.testing.expectEqual(1, extensions.len());
        try std.testing.expectEqual(UiExtension.unparseable_extension, extensions.get(0));
    }

    // Test insufficient data returns null
    {
        const data: [1]u8 = .{0};
        const extensions = parseExtensions(&data);
        try std.testing.expect(extensions.len() == 0);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L484
test "rpc.account_codec.parse_token: token account with extensions" {
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
                const mint_str = mint_pubkey.base58String().constSlice();
                const owner_str = owner_pubkey.base58String().constSlice();
                const acc_mint = ui_account.mint.base58String().constSlice();
                try std.testing.expectEqualStrings(mint_str, acc_mint);
                const acc_owner = ui_account.owner.base58String().constSlice();
                try std.testing.expectEqualStrings(owner_str, acc_owner);
                try std.testing.expectEqual(@as(u64, 42), ui_account.tokenAmount.amount);
                try std.testing.expectEqual(@as(u8, 2), ui_account.tokenAmount.decimals);
                try std.testing.expect(ui_account.tokenAmount.ui_amount != null);
                try std.testing.expect(@abs(ui_account.tokenAmount.ui_amount.? - 0.42) < 0.001);
                const ui_str = ui_account.tokenAmount.ui_amount_string.constSlice();
                try std.testing.expectEqualStrings("0.42", ui_str);
                try std.testing.expect(ui_account.delegate == null);
                try std.testing.expectEqual(AccountState.initialized, ui_account.state);
                try std.testing.expect(!ui_account.isNative);
                try std.testing.expect(ui_account.rentExemptReserve == null);
                try std.testing.expect(ui_account.delegatedAmount == null);
                try std.testing.expect(ui_account.closeAuthority != null);
                const close_auth = ui_account.closeAuthority.?.base58String().constSlice();
                try std.testing.expectEqualStrings(owner_str, close_auth);
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
                const owner_str = owner_pubkey.base58String().constSlice();
                try std.testing.expect(ui_mint.mintAuthority != null);
                const mint_auth = ui_mint.mintAuthority.?.base58String().constSlice();
                try std.testing.expectEqualStrings(owner_str, mint_auth);
                try std.testing.expectEqual(@as(u64, 42), ui_mint.supply.value);
                try std.testing.expectEqual(@as(u8, 3), ui_mint.decimals);
                try std.testing.expect(ui_mint.isInitialized);
                try std.testing.expect(ui_mint.freezeAuthority != null);
                const freeze_auth = ui_mint.freezeAuthority.?.base58String().constSlice();
                try std.testing.expectEqualStrings(owner_str, freeze_auth);
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
                try std.testing.expectEqual(@as(u8, 2), ui_multisig.numRequiredSigners);
                try std.testing.expectEqual(@as(u8, 3), ui_multisig.numValidSigners);
                try std.testing.expect(ui_multisig.isInitialized);
                try std.testing.expectEqual(@as(usize, 3), ui_multisig.signers.len());
                const s1_str = signer1.base58String().constSlice();
                const s2_str = signer2.base58String().constSlice();
                const s3_str = signer3.base58String().constSlice();
                const sig0 = ui_multisig.signers.get(0).base58String().constSlice();
                try std.testing.expectEqualStrings(s1_str, sig0);
                const sig1 = ui_multisig.signers.get(1).base58String().constSlice();
                try std.testing.expectEqualStrings(s2_str, sig1);
                const sig2 = ui_multisig.signers.get(2).base58String().constSlice();
                try std.testing.expectEqualStrings(s3_str, sig2);
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
test "rpc.account_codec.parse_token: formatTokenAmount conformance" {

    // Basic integers
    try std.testing.expectEqualStrings("1", formatTokenAmount(1, 0).constSlice());
    try std.testing.expectEqualStrings("10", formatTokenAmount(10, 0).constSlice());

    // Small amounts with decimals
    try std.testing.expectEqualStrings("0.000000001", formatTokenAmount(1, 9).constSlice());

    // Whole numbers that trim to clean result
    try std.testing.expectEqualStrings("1", formatTokenAmount(1_000_000_000, 9).constSlice());

    // Partial decimal trimming (trailing zero removed)
    try std.testing.expectEqualStrings(
        "1234567.89",
        formatTokenAmount(1_234_567_890, 3).constSlice(),
    );

    // Large decimals (25 places) - tests precision
    try std.testing.expectEqualStrings(
        "0.000000000000000123456789",
        formatTokenAmount(1_234_567_890, 25).constSlice(),
    );

    // Zero amounts
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 0).constSlice());
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 9).constSlice());
    try std.testing.expectEqualStrings("0", formatTokenAmount(0, 25).constSlice());
}

test "rpc.account_codec.parse_token: UiTokenAmount.init ui_amount" {
    // ui_amount is Some when decimals <= 20
    {
        const t = UiTokenAmount.init(1, .{ .decimals = 0 });
        try std.testing.expectEqual(@as(?f64, 1.0), t.ui_amount);
    }
    {
        const t = UiTokenAmount.init(1_000_000_000, .{ .decimals = 9 });
        try std.testing.expectEqual(@as(?f64, 1.0), t.ui_amount);
    }
    // ui_amount is None when decimals > 20
    {
        const t = UiTokenAmount.init(1_234_567_890, .{ .decimals = 25 });
        try std.testing.expect(t.ui_amount == null);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L484
test "rpc.account_codec.parse_token: token account with extensions conformance" {
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
            const mint_str = mint_pubkey.base58String().constSlice();
            const owner_str = owner_pubkey.base58String().constSlice();
            const acc_mint = ui_account.mint.base58String().constSlice();
            try std.testing.expectEqualStrings(mint_str, acc_mint);
            const acc_owner = ui_account.owner.base58String().constSlice();
            try std.testing.expectEqualStrings(owner_str, acc_owner);
            try std.testing.expectEqual(@as(u64, 42), ui_account.tokenAmount.amount);
            try std.testing.expectEqual(AccountState.initialized, ui_account.state);
            // Verify extensions
            try std.testing.expectEqual(@as(usize, 2), ui_account.extensions.len());
            try std.testing.expectEqual(UiExtension.immutable_owner, ui_account.extensions.get(0));

            switch (ui_account.extensions.get(1)) {
                .memo_transfer => |m| {
                    try std.testing.expect(m.requireIncomingTransferMemos);
                },
                else => try std.testing.expect(false),
            }
        },
        else => try std.testing.expect(false),
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L584
test "rpc.account_codec.parse_token: mint with extensions conformance" {
    const owner_pubkey = Pubkey{ .data = [_]u8{3} ** 32 };
    // Token-2022 layout: mint is padded to 165 bytes (TokenAccount.LEN), then discriminator at 165,
    // then TLV extensions starting at 166.
    // Size: 165 (padded mint) + 1 discriminator + 4 TLV header + 32 value = 202
    const MINT_SIZE = TokenAccount.LEN + 1 + 4 + 32;
    var mint_data: [MINT_SIZE]u8 = [_]u8{0} ** MINT_SIZE;
    // Build base mint (first 82 bytes)
    std.mem.writeInt(u32, mint_data[0..4], 1, .little); // mint_authority = Some
    @memcpy(mint_data[4..36], &owner_pubkey.data);
    std.mem.writeInt(u64, mint_data[36..44], 42, .little); // supply
    mint_data[44] = 3; // decimals
    mint_data[45] = 1; // is_initialized
    std.mem.writeInt(u32, mint_data[46..50], 1, .little); // freeze_authority = Some
    @memcpy(mint_data[50..82], &owner_pubkey.data);
    // Bytes 82-164 are padding (zeros) - already initialized
    // Account type discriminator at offset 165 (TokenAccount.LEN)
    mint_data[TokenAccount.LEN] = @intFromEnum(AccountTypeDiscriminator.mint);
    // Extension: MintCloseAuthority (type=3, len=32) starting at offset 166
    std.mem.writeInt(u16, mint_data[166..168], 3, .little);
    std.mem.writeInt(u16, mint_data[168..170], 32, .little);
    @memcpy(mint_data[170..202], &owner_pubkey.data);
    // Parse and verify
    const result = try parseToken(&mint_data, null);
    try std.testing.expect(result != null);
    switch (result.?) {
        .mint => |ui_mint| {
            try std.testing.expect(ui_mint.mintAuthority != null);
            try std.testing.expectEqual(@as(u64, 42), ui_mint.supply.value);
            try std.testing.expectEqual(@as(u8, 3), ui_mint.decimals);
            try std.testing.expect(ui_mint.isInitialized);
            // Verify extension
            try std.testing.expectEqual(@as(usize, 1), ui_mint.extensions.len());
            switch (ui_mint.extensions.get(0)) {
                .mint_close_authority => |mca| {
                    try std.testing.expect(mca.closeAuthority != null);
                    try std.testing.expectEqual(owner_pubkey, mca.closeAuthority.?);
                },
                else => try std.testing.expect(false),
            }
        },
        else => try std.testing.expect(false),
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L368-L396
test "rpc.account_codec.parse_token: interest-bearing 5% rate" {
    const INT_SECONDS_PER_YEAR: i64 = 31_556_736; // 6 * 6 * 24 * 36524
    const ONE: u64 = 1_000_000_000_000_000_000; // 1e18

    // Constant 5% rate for 1 year
    const config = InterestBearingConfigData{
        .rate_authority = null,
        .initialization_timestamp = 0,
        .pre_update_average_rate = 500, // 5% = 500 basis points
        .last_update_timestamp = INT_SECONDS_PER_YEAR,
        .current_rate = 500,
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 18,
        .unix_timestamp = INT_SECONDS_PER_YEAR,
        .interest_bearing_config = config,
    };

    const t = UiTokenAmount.init(ONE, additional_data);

    // exp(0.05) ≈ 1.051271096376024
    try std.testing.expect(t.ui_amount != null);
    const ui_str = t.ui_amount_string.constSlice();
    try std.testing.expect(std.mem.startsWith(u8, ui_str, "1.051271096376024"));
    // Check ui_amount is close to expected
    try std.testing.expect(@abs(t.ui_amount.? - 1.051271096376024) < 0.000001);
}

test "rpc.account_codec.parse_token: interest-bearing infinity case" {
    const INT_SECONDS_PER_YEAR: i64 = 31_556_736;

    // Max rate for 1000 years with max amount
    const config = InterestBearingConfigData{
        .rate_authority = null,
        .initialization_timestamp = 0,
        .pre_update_average_rate = 32767, // max i16
        .last_update_timestamp = 0,
        .current_rate = 32767,
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 0,
        .unix_timestamp = INT_SECONDS_PER_YEAR * 1000, // 1000 years
        .interest_bearing_config = config,
    };

    const t = UiTokenAmount.init(std.math.maxInt(u64), additional_data);

    try std.testing.expect(t.ui_amount != null);
    try std.testing.expect(std.math.isInf(t.ui_amount.?));
    try std.testing.expectEqualStrings("inf", t.ui_amount_string.constSlice());
}

test "rpc.account_codec.parse_token: interest-bearing negative rate" {
    const INT_SECONDS_PER_YEAR: i64 = 31_556_736;
    const ONE: u64 = 1_000_000_000_000_000_000;

    // -5% rate for 1 year
    const config = InterestBearingConfigData{
        .rate_authority = null,
        .initialization_timestamp = 0,
        .pre_update_average_rate = -500, // -5%
        .last_update_timestamp = INT_SECONDS_PER_YEAR,
        .current_rate = -500,
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 18,
        .unix_timestamp = INT_SECONDS_PER_YEAR,
        .interest_bearing_config = config,
    };

    const t = UiTokenAmount.init(ONE, additional_data);

    // exp(-0.05) ≈ 0.951229424500714
    try std.testing.expect(t.ui_amount != null);
    try std.testing.expect(@abs(t.ui_amount.? - 0.951229424500714) < 0.000001);
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs#L398-L413
test "rpc.account_codec.parse_token: scaled UI 2x multiplier" {
    const ONE: u64 = 1_000_000_000_000_000_000; // 1e18

    const config = ScaledUiAmountConfigData{
        .multiplier = 2.0,
        .new_multiplier_effective_timestamp = 0,
        .new_multiplier = 2.0,
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 18,
        .unix_timestamp = 0,
        .scaled_ui_amount_config = config,
    };

    const t = UiTokenAmount.init(ONE, additional_data);

    try std.testing.expectEqualStrings("2", t.ui_amount_string.constSlice());
    try std.testing.expect(t.ui_amount != null);
    try std.testing.expect(@abs(t.ui_amount.? - 2.0) < 0.000001);
}

test "rpc.account_codec.parse_token: scaled UI infinity case" {
    const config = ScaledUiAmountConfigData{
        .multiplier = std.math.inf(f64),
        .new_multiplier_effective_timestamp = 0,
        .new_multiplier = std.math.inf(f64),
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 0,
        .unix_timestamp = 0,
        .scaled_ui_amount_config = config,
    };

    const t = UiTokenAmount.init(std.math.maxInt(u64), additional_data);

    try std.testing.expect(t.ui_amount != null);
    try std.testing.expect(std.math.isInf(t.ui_amount.?));
    try std.testing.expectEqualStrings("inf", t.ui_amount_string.constSlice());
}

test "rpc.account_codec.parse_token: scaled UI multiplier switch at timestamp" {
    // 1e9
    const ONE: u64 = 1_000_000_000;

    // Before timestamp: use old multiplier (1x)
    // At/after timestamp: use new multiplier (3x)
    const config = ScaledUiAmountConfigData{
        .multiplier = 1.0,
        .new_multiplier_effective_timestamp = 100,
        .new_multiplier = 3.0,
    };

    // Before effective timestamp
    {
        const additional_data = SplTokenAdditionalData{
            .decimals = 9,
            .unix_timestamp = 99,
            .scaled_ui_amount_config = config,
        };
        const t = UiTokenAmount.init(ONE, additional_data);
        try std.testing.expectEqualStrings("1", t.ui_amount_string.constSlice());
    }

    // At effective timestamp
    {
        const additional_data = SplTokenAdditionalData{
            .decimals = 9,
            .unix_timestamp = 100,
            .scaled_ui_amount_config = config,
        };
        const t = UiTokenAmount.init(ONE, additional_data);
        try std.testing.expectEqualStrings("3", t.ui_amount_string.constSlice());
    }

    // After effective timestamp
    {
        const additional_data = SplTokenAdditionalData{
            .decimals = 9,
            .unix_timestamp = 200,
            .scaled_ui_amount_config = config,
        };
        const t = UiTokenAmount.init(ONE, additional_data);
        try std.testing.expectEqualStrings("3", t.ui_amount_string.constSlice());
    }
}

test "rpc.account_codec.parse_token: interest-bearing takes priority over scaled" {
    const INT_SECONDS_PER_YEAR: i64 = 31_556_736;
    const ONE: u64 = 1_000_000_000_000_000_000;

    // Both configs present - interest-bearing should take priority
    const interest_config = InterestBearingConfigData{
        .rate_authority = null,
        .initialization_timestamp = 0,
        .pre_update_average_rate = 500,
        .last_update_timestamp = INT_SECONDS_PER_YEAR,
        .current_rate = 500,
    };

    const scaled_config = ScaledUiAmountConfigData{
        .multiplier = 10.0, // Would give 10.0 if used
        .new_multiplier_effective_timestamp = 0,
        .new_multiplier = 10.0,
    };

    const additional_data = SplTokenAdditionalData{
        .decimals = 18,
        .unix_timestamp = INT_SECONDS_PER_YEAR,
        .interest_bearing_config = interest_config,
        .scaled_ui_amount_config = scaled_config,
    };

    const t = UiTokenAmount.init(ONE, additional_data);

    // Should use interest-bearing result (~1.05), not scaled (10.0)
    try std.testing.expect(t.ui_amount != null);
    // Interest-bearing gives ~1.05
    try std.testing.expect(t.ui_amount.? < 2.0);
    try std.testing.expect(std.mem.startsWith(u8, t.ui_amount_string.constSlice(), "1.05"));
}
