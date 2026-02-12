/// Types for parsing SPL Token accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");
const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const ParseError = account_decoder.ParseError;

// Index of the account state byte (108 = offset of `state` field in TokenAccount)
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
    // Try Token Account first (most common, 165+ bytes)
    // Token-2022 accounts may be larger due to extensions
    if (data.len >= TokenAccount.LEN) {
        if (TokenAccount.unpack(data)) |account| {
            if (account.state == .uninitialized) {
                return null; // Uninitialized account
            }
            // Token accounts REQUIRE decimals from mint
            const decimals = if (additional_data) |ad| ad.decimals else {
                return null; // No decimals provided - fallback to base64
            };
            return TokenAccountType{
                .account = buildUiTokenAccount(account, decimals),
            };
        } else |_| {}
    }

    // Try Mint (82+ bytes, Token-2022 may be larger)
    if (data.len >= Mint.LEN) {
        if (Mint.unpack(data)) |mint| {
            if (!mint.is_initialized) {
                return null;
            }
            return TokenAccountType{
                .mint = buildUiMint(mint),
            };
        } else |_| {}
    }

    // Try Multisig (exactly 355 bytes, no extensions)
    if (data.len == Multisig.LEN) {
        if (Multisig.unpack(data)) |multisig| {
            if (!multisig.is_initialized) {
                return null;
            }
            return TokenAccountType{
                .multisig = buildUiMultisig(multisig),
            };
        } else |_| {}
    }

    // TODO: token 22.

    return null;
}

fn buildUiTokenAccount(account: TokenAccount, decimals: u8) UiTokenAccount {
    const is_native = account.is_native != null;

    return UiTokenAccount{
        .mint = account.mint.base58String(),
        .owner = account.owner.base58String(),
        .token_amount = .init(account.amount, decimals),
        .delegate = if (account.delegate) |d| d.base58String() else null,
        .state = account.state,
        .is_native = is_native,
        .rent_exempt_reserve = if (account.is_native) |reserve|
            .init(reserve, decimals)
        else
            null,
        .delegated_amount = if (account.delegate != null and account.delegated_amount > 0)
            UiTokenAmount.init(account.delegated_amount, decimals)
        else
            null,
        .close_authority = if (account.close_authority) |c| c.base58String() else null,
    };
}

fn buildUiMint(mint: Mint) UiMint {
    return UiMint{
        .mint_authority = if (mint.mint_authority) |a| a.base58String() else null,
        .supply = mint.supply,
        .decimals = mint.decimals,
        .is_initialized = mint.is_initialized,
        .freeze_authority = if (mint.freeze_authority) |a| a.base58String() else null,
    };
}

fn buildUiMultisig(multisig: Multisig) UiMultisig {
    var signers: std.BoundedArray(Pubkey.Base58String, Multisig.MAX_SIGNERS) = .{};
    // Only include non-default pubkeys up to n valid signers
    for (0..multisig.n) |i| {
        const signer = multisig.signers[i];
        // Skip default (zero) pubkeys
        if (!signer.isZeroed()) {
            signers.appendAssumeCapacity(signer.base58String());
        }
    }
    return UiMultisig{
        .num_required_signers = multisig.m,
        .num_valid_signers = multisig.n,
        .is_initialized = multisig.is_initialized,
        .signers = signers,
    };
}

// Token-2022 account type discriminator (placed at TokenAccount.LEN for extended accounts)
const AccountTypeDiscriminator = enum(u8) {
    uninitialized = 0,
    mint = 1,
    account = 2,
};

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
    // TODO Token-2022 fields:
    // interest_bearing_config: ?InterestBearingConfig,
    // scaled_ui_amount_config: ?ScaledUiAmountConfig,
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

/// SPL Token Account state enum.
pub const AccountState = enum(u8) {
    uninitialized = 0,
    initialized = 1,
    frozen = 2,
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
        // No decimal point needed
        _ = std.fmt.bufPrint(buf.slice(), "{d}", .{amount}) catch unreachable;
        buf.len = @intCast(std.mem.indexOfScalar(u8, buf.slice(), 0) orelse buf.len);
        return buf;
    }

    const divisor = std.math.pow(u64, 10, decimals);
    const whole = amount / divisor;
    const frac = amount % divisor;

    if (frac == 0) {
        // No fractional part
        const written = std.fmt.bufPrint(&buf.buffer, "{d}", .{whole}) catch unreachable;
        buf.len = @intCast(written.len);
    } else {
        // Format with fractional part, then trim trailing zeros
        const written = std.fmt.bufPrint(&buf.buffer, "{d}.{d:0>[2]}", .{
            whole,
            frac,
            decimals,
        }) catch unreachable;
        buf.len = @intCast(written.len);

        // Trim trailing zeros (but keep at least one digit after decimal)
        while (buf.len > 0 and buf.buffer[buf.len - 1] == '0') {
            buf.len -= 1;
        }
        // Don't leave trailing decimal point
        if (buf.len > 0 and buf.buffer[buf.len - 1] == '.') {
            buf.len -= 1;
        }
    }

    return buf;
}

// SPL Token uses fixed-offset binary layout (Pack trait), not bincode.
fn readCOptionPubkey(data: *const [36]u8) ?Pubkey {
    const tag = std.mem.readInt(u32, data[0..4], .little);
    if (tag == 0) return null;
    return Pubkey{ .data = data[4..36].* };
}

// COption<T> = 4-byte tag (0=None, 1=Some) + T
fn readCOptionU64(data: *const [12]u8) ?u64 {
    const tag = std.mem.readInt(u32, data[0..4], .little);
    if (tag == 0) return null;
    return std.mem.readInt(u64, data[4..12], .little);
}

test "rpc.account_decoder.parseToken" {
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
