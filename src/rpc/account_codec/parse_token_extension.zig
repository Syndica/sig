//! Token-2022 extension parsing and UI representation for account decoder.
//! [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token_extension.rs#L22
const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const base64 = std.base64.standard;

const AccountState = account_codec.AccountState;
const Base64Encoded = account_codec.Base64Encoded;
const JsonArray = account_codec.JsonArray;
const JsonString = account_codec.JsonString;
const Pubkey = sig.core.Pubkey;

/// TLV parsing constants for Token-2022 extensions.
/// TLV layout: 2 bytes type (ExtensionType as u16) + 2 bytes length (Length as u16) + value
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L93-L99
const TLV_HEADER_SIZE: usize = 4;
/// Implementation limit for extension parsing (not a protocol limit).
pub const MAX_EXTENSIONS: usize = 16;

/// Token-2022 extension type discriminants.
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L1055-L1130
pub const ExtensionType = enum(u16) {
    uninitialized = 0,
    transfer_fee_config = 1,
    transfer_fee_amount = 2,
    mint_close_authority = 3,
    confidential_transfer_mint = 4,
    confidential_transfer_account = 5,
    default_account_state = 6,
    immutable_owner = 7,
    memo_transfer = 8,
    non_transferable = 9,
    interest_bearing_config = 10,
    cpi_guard = 11,
    permanent_delegate = 12,
    non_transferable_account = 13,
    transfer_hook = 14,
    transfer_hook_account = 15,
    confidential_transfer_fee_config = 16,
    confidential_transfer_fee_amount = 17,
    metadata_pointer = 18,
    token_metadata = 19,
    group_pointer = 20,
    token_group = 21,
    group_member_pointer = 22,
    token_group_member = 23,
    confidential_mint_burn = 24,
    scaled_ui_amount_config = 25,
    pausable_config = 26,
    pausable_account = 27,
    _,

    /// Expected size of extension data (excluding TLV header).
    /// Returns null for variable-length extensions (TokenMetadata).
    /// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L1167-L1212
    pub fn expectedSize(self: ExtensionType) ?usize {
        return switch (self) {
            .uninitialized => 0,
            .immutable_owner => 0,
            .non_transferable => 0,
            .non_transferable_account => 0,
            .pausable_account => 0,
            .default_account_state => 1,
            .memo_transfer => 1,
            .cpi_guard => 1,
            .transfer_hook_account => 1,
            .transfer_fee_amount => 8,
            .mint_close_authority => 32,
            .permanent_delegate => 32,
            .pausable_config => 33,
            .interest_bearing_config => 52,
            .scaled_ui_amount_config => 56,
            .metadata_pointer => 64,
            .group_pointer => 64,
            .group_member_pointer => 64,
            .transfer_hook => 64,
            .confidential_transfer_fee_amount => 64,
            .confidential_transfer_mint => 65,
            .token_group_member => 72,
            .token_group => 80,
            .transfer_fee_config => 108,
            .confidential_transfer_fee_config => 129,
            .confidential_mint_burn => 196,
            .confidential_transfer_account => 295,
            // NOTE: TokenMetadata uses borsh serialization, so length can be variable.
            .token_metadata => null,
            _ => null,
        };
    }

    /// Check if this is a mint extension (vs account extension).
    /// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L1255-L1295
    pub fn isMintExtension(self: ExtensionType) bool {
        return switch (self) {
            .transfer_fee_config,
            .mint_close_authority,
            .confidential_transfer_mint,
            .default_account_state,
            .non_transferable,
            .interest_bearing_config,
            .permanent_delegate,
            .transfer_hook,
            .confidential_transfer_fee_config,
            .metadata_pointer,
            .token_metadata,
            .group_pointer,
            .token_group,
            .group_member_pointer,
            .token_group_member,
            .confidential_mint_burn,
            .scaled_ui_amount_config,
            .pausable_config,
            => true,
            else => false,
        };
    }
};

/// UI representation of a Token-2022 extension for JSON output.
/// Serializes as: {"extension": "extensionName", "state": {...}}
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder-client-types/src/token.rs
pub const UiExtension = union(enum) {
    uninitialized,
    immutable_owner,
    non_transferable,
    non_transferable_account,
    pausable_account,

    // Special: unparseable fallback
    unparseable_extension,

    default_account_state: UiDefaultAccountState,
    memo_transfer: UiMemoTransfer,
    cpi_guard: UiCpiGuard,
    transfer_hook_account: UiTransferHookAccount,
    transfer_fee_amount: UiTransferFeeAmount,
    mint_close_authority: UiMintCloseAuthority,
    permanent_delegate: UiPermanentDelegate,
    pausable_config: UiPausableConfig,
    interest_bearing_config: UiInterestBearingConfig,
    scaled_ui_amount_config: UiScaledUiAmountConfig,
    metadata_pointer: UiMetadataPointer,
    group_pointer: UiGroupPointer,
    group_member_pointer: UiGroupMemberPointer,
    transfer_hook: UiTransferHook,
    confidential_transfer_fee_amount: UiConfidentialTransferFeeAmount,
    confidential_transfer_mint: UiConfidentialTransferMint,
    token_group_member: UiTokenGroupMember,
    token_group: UiTokenGroup,
    transfer_fee_config: UiTransferFeeConfig,
    confidential_transfer_fee_config: UiConfidentialTransferFeeConfig,
    confidential_mint_burn: UiConfidentialMintBurn,
    confidential_transfer_account: UiConfidentialTransferAccount,
    token_metadata: UiTokenMetadata,

    pub fn jsonStringify(self: UiExtension, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("extension");
        switch (self) {
            inline else => |v, tag| {
                try jw.write(typeNameFromTag(tag));
                if (@TypeOf(v) != void) {
                    try jw.objectField("state");
                    try jw.write(v);
                }
            },
        }
        try jw.endObject();
    }

    fn typeNameFromTag(comptime tag: std.meta.Tag(UiExtension)) []const u8 {
        return switch (tag) {
            .uninitialized => "uninitialized",
            .immutable_owner => "immutableOwner",
            .non_transferable => "nonTransferable",
            .non_transferable_account => "nonTransferableAccount",
            .pausable_account => "pausableAccount",
            .unparseable_extension => "unparseableExtension",
            .default_account_state => "defaultAccountState",
            .memo_transfer => "memoTransfer",
            .cpi_guard => "cpiGuard",
            .transfer_hook_account => "transferHookAccount",
            .transfer_fee_amount => "transferFeeAmount",
            .mint_close_authority => "mintCloseAuthority",
            .permanent_delegate => "permanentDelegate",
            .pausable_config => "pausableConfig",
            .interest_bearing_config => "interestBearingConfig",
            .scaled_ui_amount_config => "scaledUiAmountConfig",
            .metadata_pointer => "metadataPointer",
            .group_pointer => "groupPointer",
            .group_member_pointer => "groupMemberPointer",
            .transfer_hook => "transferHook",
            .confidential_transfer_fee_amount => "confidentialTransferFeeAmount",
            .confidential_transfer_mint => "confidentialTransferMint",
            .token_group_member => "tokenGroupMember",
            .token_group => "tokenGroup",
            .transfer_fee_config => "transferFeeConfig",
            .confidential_transfer_fee_config => "confidentialTransferFeeConfig",
            .confidential_mint_burn => "confidentialMintBurn",
            .confidential_transfer_account => "confidentialTransferAccount",
            .token_metadata => "tokenMetadata",
        };
    }
};

/// Parse Token-2022 TLV extensions from account data.
/// Returns an empty array if data doesn't contain valid extensions.
/// Uses similar iteration logic to spl-token-2022's get_tlv_data_info.
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/mod.rs#L203-L245
pub fn parseExtensions(data: []const u8) JsonArray(UiExtension, MAX_EXTENSIONS) {
    var extensions: JsonArray(UiExtension, MAX_EXTENSIONS) = .{};

    // data[0] is discriminator, TLV starts at data[1].
    // Need at least discriminator + one TLV header to have any extensions.
    if (data.len <= 1) return extensions;

    var offset: usize = 1;
    while (offset + TLV_HEADER_SIZE <= data.len) {
        // Read extension type (2 bytes, little-endian)
        const ext_type_raw = std.mem.readInt(u16, data[offset..][0..2], .little);
        const ext_type: ExtensionType = @enumFromInt(ext_type_raw);

        // Uninitialized (0x0000) marks end of extensions
        if (ext_type == .uninitialized) break;

        // Read length (2 bytes, little-endian)
        const length = std.mem.readInt(u16, data[offset + 2 ..][0..2], .little);
        offset += TLV_HEADER_SIZE;

        // Bounds check for value
        if (offset + length > data.len) {
            // Malformed TLV - return what we have so far. AGave's get_tlv_data_info returns
            // Err(InvalidAccountData) here, but parse_extension gracefully degrades with
            // UnparseableExtension, so we follow that pattern for UI display.
            break;
        }

        const value = data[offset..][0..length];

        // Parse extension or fall back to unparseable
        const parsed = parseExtension(ext_type, value) orelse .unparseable_extension;
        extensions.append(parsed) catch {
            // Too many extensions - stop parsing
            break;
        };

        offset += length;
    }

    return extensions;
}

// Parse a single extension from its value bytes.
/// Returns null if parsing fails (caller should use unparseable_extension).
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_token_extension.rs#L22-L148
fn parseExtension(ext_type: ExtensionType, value: []const u8) ?UiExtension {
    // Validate size for fixed-length extensions. AGave's get_extension uses pod_from_bytes
    // which fails on size mismatch, returning UnparseableExtension via unwrap_or.
    if (ext_type.expectedSize()) |expected| {
        if (value.len != expected) return null;
    }

    return switch (ext_type) {
        .uninitialized => .uninitialized,
        .immutable_owner => .immutable_owner,
        .non_transferable => .non_transferable,
        .non_transferable_account => .non_transferable_account,
        .pausable_account => .pausable_account,
        .default_account_state => UiDefaultAccountState.parse(value),
        .memo_transfer => UiMemoTransfer.parse(value),
        .cpi_guard => UiCpiGuard.parse(value),
        .transfer_hook_account => UiTransferHookAccount.parse(value),
        .transfer_fee_amount => UiTransferFeeAmount.parse(value),
        .mint_close_authority => UiMintCloseAuthority.parse(value),
        .permanent_delegate => UiPermanentDelegate.parse(value),
        .pausable_config => UiPausableConfig.parse(value),
        .interest_bearing_config => UiInterestBearingConfig.parse(value),
        .scaled_ui_amount_config => UiScaledUiAmountConfig.parse(value),
        .metadata_pointer => UiMetadataPointer.parse(value),
        .group_pointer => UiGroupPointer.parse(value),
        .group_member_pointer => UiGroupMemberPointer.parse(value),
        .transfer_hook => UiTransferHook.parse(value),
        .confidential_transfer_fee_amount => UiConfidentialTransferFeeAmount.parse(value),
        .confidential_transfer_mint => UiConfidentialTransferMint.parse(value),
        .token_group_member => UiTokenGroupMember.parse(value),
        .token_group => UiTokenGroup.parse(value),
        .transfer_fee_config => UiTransferFeeConfig.parse(value),
        .confidential_transfer_fee_config => UiConfidentialTransferFeeConfig.parse(value),
        .confidential_mint_burn => UiConfidentialMintBurn.parse(value),
        .confidential_transfer_account => UiConfidentialTransferAccount.parse(value),
        .token_metadata => UiTokenMetadata.parse(value),
        _ => null,
    };
}

/// Subset of InterestBearingConfig needed for amount calculations.
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension/interest_bearing_mint/mod.rs
pub const InterestBearingConfigData = struct {
    rate_authority: ?Pubkey,
    initialization_timestamp: i64,
    pre_update_average_rate: i16,
    last_update_timestamp: i64,
    current_rate: i16,

    /// Extract InterestBearingConfig data from mint extensions for calculations.
    /// Returns null if extension not present or data invalid.
    pub fn extractFromMint(mint_data: []const u8) ?InterestBearingConfigData {
        const MINT_LEN = 82; // parse_token.Mint.LEN
        if (mint_data.len <= MINT_LEN) return null;

        const ext_data = mint_data[MINT_LEN..];
        if (ext_data.len <= 1) return null;

        var offset: usize = 1; // Skip discriminator
        while (offset + TLV_HEADER_SIZE <= ext_data.len) {
            const ext_type_raw = std.mem.readInt(u16, ext_data[offset..][0..2], .little);
            const length = std.mem.readInt(u16, ext_data[offset + 2 ..][0..2], .little);
            offset += TLV_HEADER_SIZE;

            if (offset + length > ext_data.len or ext_type_raw == 0) break;

            const interest_bearing = @intFromEnum(ExtensionType.interest_bearing_config);
            const is_interest_bearing = ext_type_raw == interest_bearing;
            if (is_interest_bearing and length == 52) {
                const value = ext_data[offset..][0..52];
                const pubkey = readOptionalNonZeroPubkey(value[0..32]);
                return .{
                    .rate_authority = pubkey,
                    .initialization_timestamp = std.mem.readInt(i64, value[32..40], .little),
                    .pre_update_average_rate = std.mem.readInt(i16, value[40..42], .little),
                    .last_update_timestamp = std.mem.readInt(i64, value[42..50], .little),
                    .current_rate = std.mem.readInt(i16, value[50..52], .little),
                };
            }

            offset += length;
        }
        return null;
    }
};

/// Subset of ScaledUiAmountConfig needed for amount calculations.
pub const ScaledUiAmountConfigData = struct {
    multiplier: f64,
    new_multiplier_effective_timestamp: i64,
    new_multiplier: f64,

    /// Extract ScaledUiAmountConfig data from mint extensions for calculations.
    /// Returns null if extension not present or data invalid.
    pub fn extractFromMint(mint_data: []const u8) ?ScaledUiAmountConfigData {
        const MINT_LEN = 82; // parse_token.Mint.LEN
        if (mint_data.len <= MINT_LEN) return null;

        const ext_data = mint_data[MINT_LEN..];
        if (ext_data.len <= 1) return null;

        var offset: usize = 1; // Skip discriminator
        while (offset + TLV_HEADER_SIZE <= ext_data.len) {
            const ext_type_raw = std.mem.readInt(u16, ext_data[offset..][0..2], .little);
            const length = std.mem.readInt(u16, ext_data[offset + 2 ..][0..2], .little);
            offset += TLV_HEADER_SIZE;

            if (offset + length > ext_data.len or ext_type_raw == 0) break;

            const is_scaled_ui = ext_type_raw == @intFromEnum(ExtensionType.scaled_ui_amount_config);
            if (is_scaled_ui and length == 56) {
                const value = ext_data[offset..][0..56];
                const ts = std.mem.readInt(i64, value[40..48], .little);
                return .{
                    .multiplier = @bitCast(std.mem.readInt(u64, value[32..40], .little)),
                    .new_multiplier_effective_timestamp = ts,
                    .new_multiplier = @bitCast(std.mem.readInt(u64, value[48..56], .little)),
                };
            }

            offset += length;
        }
        return null;
    }
};

/// DefaultAccountState (1 byte) - sets the default state for new token accounts.
pub const UiDefaultAccountState = struct {
    accountState: AccountState,

    pub fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        const state_byte = value[0];
        if (state_byte > 2) return null;
        return .{ .default_account_state = .{
            .accountState = @enumFromInt(state_byte),
        } };
    }

    pub fn jsonStringify(self: UiDefaultAccountState, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("accountState");
        try jw.write(switch (self.accountState) {
            .uninitialized => "uninitialized",
            .initialized => "initialized",
            .frozen => "frozen",
        });
        try jw.endObject();
    }
};

/// MemoTransfer (1 byte) - Requires memos on incoming transfers.
pub const UiMemoTransfer = struct {
    requireIncomingTransferMemos: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        return .{ .memo_transfer = .{
            .requireIncomingTransferMemos = value[0] != 0,
        } };
    }
};

/// CpiGuard (1 byte) - Restricts certain CPI operations.
pub const UiCpiGuard = struct {
    lockCpi: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        return .{ .cpi_guard = .{
            .lockCpi = value[0] != 0,
        } };
    }
};

/// TransferHookAccount (1 byte) - Transfer hook execution state.
pub const UiTransferHookAccount = struct {
    transferring: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        return .{ .transfer_hook_account = .{
            .transferring = value[0] != 0,
        } };
    }
};

/// TransferFeeAmount (8 bytes) - Withheld transfer fees on account.
pub const UiTransferFeeAmount = struct {
    withheldAmount: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 8) return null;
        return .{ .transfer_fee_amount = .{
            .withheldAmount = std.mem.readInt(u64, value[0..8], .little),
        } };
    }
};

/// MintCloseAuthority (32 bytes) - Authority that can close the mint.
pub const UiMintCloseAuthority = struct {
    closeAuthority: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 32) return null;
        return .{ .mint_close_authority = .{
            .closeAuthority = readOptionalNonZeroPubkey(value[0..32]),
        } };
    }
};

/// PermanentDelegate (32 bytes) - Permanent delegate authority.
pub const UiPermanentDelegate = struct {
    delegate: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 32) return null;
        return .{ .permanent_delegate = .{
            .delegate = readOptionalNonZeroPubkey(value[0..32]),
        } };
    }
};

/// PausableConfig (33 bytes) - Pause authority and state.
pub const UiPausableConfig = struct {
    authority: ?Pubkey,
    paused: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 33) return null;
        return .{ .pausable_config = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .paused = value[32] != 0,
        } };
    }
};

/// InterestBearingConfig (52 bytes) - Interest-bearing token configuration.
pub const UiInterestBearingConfig = struct {
    rateAuthority: ?Pubkey,
    initializationTimestamp: i64,
    preUpdateAverageRate: i16,
    lastUpdateTimestamp: i64,
    currentRate: i16,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 52) return null;
        return .{ .interest_bearing_config = .{
            .rateAuthority = readOptionalNonZeroPubkey(value[0..32]),
            .initializationTimestamp = std.mem.readInt(i64, value[32..40], .little),
            .preUpdateAverageRate = std.mem.readInt(i16, value[40..42], .little),
            .lastUpdateTimestamp = std.mem.readInt(i64, value[42..50], .little),
            .currentRate = std.mem.readInt(i16, value[50..52], .little),
        } };
    }
};

/// ScaledUiAmountConfig (56 bytes) - UI amount scaling configuration.
pub const UiScaledUiAmountConfig = struct {
    authority: ?Pubkey,
    multiplier: f64,
    newMultiplierEffectiveTimestamp: i64,
    newMultiplier: f64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 56) return null;
        return .{ .scaled_ui_amount_config = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .multiplier = @bitCast(std.mem.readInt(u64, value[32..40], .little)),
            .newMultiplierEffectiveTimestamp = std.mem.readInt(i64, value[40..48], .little),
            .newMultiplier = @bitCast(std.mem.readInt(u64, value[48..56], .little)),
        } };
    }

    pub fn jsonStringify(self: UiScaledUiAmountConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        try jw.write(self.authority);
        try jw.objectField("multiplier");
        try jw.print("\"{d}\"", .{self.multiplier});
        try jw.objectField("newMultiplierEffectiveTimestamp");
        try jw.write(self.newMultiplierEffectiveTimestamp);
        try jw.objectField("newMultiplier");
        try jw.print("\"{d}\"", .{self.newMultiplier});
        try jw.endObject();
    }
};

/// MetadataPointer (64 bytes) - Pointer to token metadata.
pub const UiMetadataPointer = struct {
    authority: ?Pubkey,
    metadataAddress: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .metadata_pointer = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .metadataAddress = readOptionalNonZeroPubkey(value[32..64]),
        } };
    }
};

/// GroupPointer (64 bytes) - Pointer to token group data.
pub const UiGroupPointer = struct {
    authority: ?Pubkey,
    groupAddress: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .group_pointer = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .groupAddress = readOptionalNonZeroPubkey(value[32..64]),
        } };
    }
};

/// GroupMemberPointer (64 bytes) - Pointer to group member data.
pub const UiGroupMemberPointer = struct {
    authority: ?Pubkey,
    memberAddress: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .group_member_pointer = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .memberAddress = readOptionalNonZeroPubkey(value[32..64]),
        } };
    }
};

/// TransferHook (64 bytes) - Transfer hook program configuration.
pub const UiTransferHook = struct {
    authority: ?Pubkey,
    programId: ?Pubkey,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .transfer_hook = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .programId = readOptionalNonZeroPubkey(value[32..64]),
        } };
    }
};

/// ConfidentialTransferFeeAmount (64 bytes) - Encrypted withheld fees.
pub const UiConfidentialTransferFeeAmount = struct {
    withheldAmount: Base64Encoded(64),

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .confidential_transfer_fee_amount = .{
            .withheldAmount = Base64Encoded(64).init(value[0..64]),
        } };
    }
};

/// ConfidentialTransferMint (65 bytes) - Confidential transfer mint configuration.
pub const UiConfidentialTransferMint = struct {
    authority: ?Pubkey,
    autoApproveNewAccounts: bool,
    auditorElgamalPubkey: ?Base64Encoded(32),

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 65) return null;
        const auditor = readOptionalNonZeroBytes(value[33..65]);
        return .{ .confidential_transfer_mint = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .autoApproveNewAccounts = value[32] != 0,
            .auditorElgamalPubkey = if (auditor) |bytes|
                Base64Encoded(32).init(bytes[0..32])
            else
                null,
        } };
    }
};

/// TokenGroupMember (72 bytes) - Token group membership.
pub const UiTokenGroupMember = struct {
    mint: Pubkey,
    group: Pubkey,
    memberNumber: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 72) return null;
        return .{ .token_group_member = .{
            .mint = Pubkey{ .data = value[0..32].* },
            .group = Pubkey{ .data = value[32..64].* },
            .memberNumber = std.mem.readInt(u64, value[64..72], .little),
        } };
    }
};

/// TokenGroup (80 bytes) - Token group (collection) definition.
pub const UiTokenGroup = struct {
    updateAuthority: ?Pubkey,
    mint: Pubkey,
    size: u64,
    maxSize: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 80) return null;
        return .{ .token_group = .{
            .updateAuthority = readOptionalNonZeroPubkey(value[0..32]),
            .mint = Pubkey{ .data = value[32..64].* },
            .size = std.mem.readInt(u64, value[64..72], .little),
            .maxSize = std.mem.readInt(u64, value[72..80], .little),
        } };
    }
};

/// TransferFee - shared struct for older/newer fees.
pub const UiTransferFee = struct {
    epoch: u64,
    maximumFee: u64,
    transferFeeBasisPoints: u16,
};

/// TransferFeeConfig (108 bytes) - Transfer fee configuration.
pub const UiTransferFeeConfig = struct {
    transferFeeConfigAuthority: ?Pubkey,
    withdrawWithheldAuthority: ?Pubkey,
    withheldAmount: u64,
    olderTransferFee: UiTransferFee,
    newerTransferFee: UiTransferFee,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 108) return null;
        return .{ .transfer_fee_config = .{
            .transferFeeConfigAuthority = readOptionalNonZeroPubkey(value[0..32]),
            .withdrawWithheldAuthority = readOptionalNonZeroPubkey(value[32..64]),
            .withheldAmount = std.mem.readInt(u64, value[64..72], .little),
            .olderTransferFee = .{
                .epoch = std.mem.readInt(u64, value[72..80], .little),
                .maximumFee = std.mem.readInt(u64, value[80..88], .little),
                .transferFeeBasisPoints = std.mem.readInt(u16, value[88..90], .little),
            },
            .newerTransferFee = .{
                .epoch = std.mem.readInt(u64, value[90..98], .little),
                .maximumFee = std.mem.readInt(u64, value[98..106], .little),
                .transferFeeBasisPoints = std.mem.readInt(u16, value[106..108], .little),
            },
        } };
    }
};

/// ConfidentialTransferFeeConfig (129 bytes) - Confidential transfer fee configuration.
pub const UiConfidentialTransferFeeConfig = struct {
    authority: ?Pubkey,
    withdrawWithheldAuthorityElgamalPubkey: Base64Encoded(32),
    harvestToMintEnabled: bool,
    withheldAmount: Base64Encoded(64),

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 129) return null;
        return .{ .confidential_transfer_fee_config = .{
            .authority = readOptionalNonZeroPubkey(value[0..32]),
            .withdrawWithheldAuthorityElgamalPubkey = Base64Encoded(32).init(value[32..64]),
            .harvestToMintEnabled = value[64] != 0,
            .withheldAmount = Base64Encoded(64).init(value[65..129]),
        } };
    }
};

/// ConfidentialMintBurn (196 bytes) - Confidential minting and burning.
pub const UiConfidentialMintBurn = struct {
    confidentialSupply: Base64Encoded(64),
    decryptableSupply: Base64Encoded(36),
    supplyElgamalPubkey: Base64Encoded(32),
    pendingBurn: Base64Encoded(64),

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 196) return null;
        return .{ .confidential_mint_burn = .{
            .confidentialSupply = Base64Encoded(64).init(value[0..64]),
            .decryptableSupply = Base64Encoded(36).init(value[64..100]),
            .supplyElgamalPubkey = Base64Encoded(32).init(value[100..132]),
            .pendingBurn = Base64Encoded(64).init(value[132..196]),
        } };
    }
};

/// ConfidentialTransferAccount (295 bytes) - Confidential transfer account state.
pub const UiConfidentialTransferAccount = struct {
    approved: bool,
    elgamalPubkey: Base64Encoded(32),
    pendingBalanceLo: Base64Encoded(64),
    pendingBalanceHi: Base64Encoded(64),
    availableBalance: Base64Encoded(64),
    decryptableAvailableBalance: Base64Encoded(36),
    allowConfidentialCredits: bool,
    allowNonConfidentialCredits: bool,
    pendingBalanceCreditCounter: u64,
    maximumPendingBalanceCreditCounter: u64,
    expectedPendingBalanceCreditCounter: u64,
    actualPendingBalanceCreditCounter: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 295) return null;
        return .{ .confidential_transfer_account = .{
            .approved = value[0] != 0,
            .elgamalPubkey = Base64Encoded(32).init(value[1..33]),
            .pendingBalanceLo = Base64Encoded(64).init(value[33..97]),
            .pendingBalanceHi = Base64Encoded(64).init(value[97..161]),
            .availableBalance = Base64Encoded(64).init(value[161..225]),
            .decryptableAvailableBalance = Base64Encoded(36).init(value[225..261]),
            .allowConfidentialCredits = value[261] != 0,
            .allowNonConfidentialCredits = value[262] != 0,
            .pendingBalanceCreditCounter = std.mem.readInt(u64, value[263..271], .little),
            .maximumPendingBalanceCreditCounter = std.mem.readInt(u64, value[271..279], .little),
            .expectedPendingBalanceCreditCounter = std.mem.readInt(u64, value[279..287], .little),
            .actualPendingBalanceCreditCounter = std.mem.readInt(u64, value[287..295], .little),
        } };
    }
};

/// Key-value pair for TokenMetadata additional_metadata.
/// Serializes as a JSON array: ["key", "value"]
const KeyValuePair = struct {
    key: JsonString(64),
    value: JsonString(256),

    pub fn jsonStringify(self: KeyValuePair, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        try jw.write(self.key.constSlice());
        try jw.write(self.value.constSlice());
        try jw.endArray();
    }
};

/// TokenMetadata (variable length, Borsh serialized).
/// NOTE: Strings are stored inline in the struct's bounded arrays.
pub const UiTokenMetadata = struct {
    updateAuthority: ?Pubkey,
    mint: Pubkey,
    name: JsonString(128),
    symbol: JsonString(32),
    uri: JsonString(256),
    additionalMetadata: JsonArray(KeyValuePair, 32),

    /// Parse TokenMetadata from Borsh-serialized bytes.
    /// Borsh format: OptionalNonZeroPubkey(32) + Pubkey(32) + String(4+len) * 3 + Vec<(String,String)>
    /// [spl] https://github.com/solana-program/token-metadata/blob/main/interface/src/state.rs
    fn parse(value: []const u8) ?UiExtension {
        var offset: usize = 0;

        // update_authority: OptionalNonZeroPubkey (32 bytes)
        if (offset + 32 > value.len) return null;
        const authority = readOptionalNonZeroPubkey(value[offset..][0..32]);
        offset += 32;

        // mint: Pubkey (32 bytes)
        if (offset + 32 > value.len) return null;
        const mint = Pubkey{ .data = value[offset..][0..32].* };
        offset += 32;

        // name: String (4-byte len + UTF-8)
        const name = readBorshString(value, &offset, 128) orelse return null;

        // symbol: String (4-byte len + UTF-8)
        const symbol = readBorshString(value, &offset, 32) orelse return null;

        // uri: String (4-byte len + UTF-8)
        const uri = readBorshString(value, &offset, 256) orelse return null;

        // additional_metadata: Vec<(String, String)>
        // Return null (-> unparseable_extension) if limits exceeded
        if (offset + 4 > value.len) return null;
        const count = std.mem.readInt(u32, value[offset..][0..4], .little);
        offset += 4;

        if (count > 32) return null; // Too many pairs

        var additional_metadata: JsonArray(KeyValuePair, 32) = .{};
        for (0..count) |_| {
            const key = readBorshString(value, &offset, 64) orelse return null;
            const val = readBorshString(value, &offset, 256) orelse return null;
            additional_metadata.append(.{
                .key = key,
                .value = val,
            }) catch return null;
        }

        return .{ .token_metadata = .{
            .updateAuthority = authority,
            .mint = mint,
            .name = name,
            .symbol = symbol,
            .uri = uri,
            .additionalMetadata = additional_metadata,
        } };
    }
};

/// Read a Borsh-encoded string: 4-byte little-endian length + UTF-8 bytes.
/// Returns a JsonString wrapper directly to avoid intermediate copies.
fn readBorshString(
    data: []const u8,
    offset: *usize,
    comptime max_len: usize,
) ?JsonString(max_len) {
    if (offset.* + 4 > data.len) return null;
    const str_len = std.mem.readInt(u32, data[offset.*..][0..4], .little);
    offset.* += 4;

    if (offset.* + str_len > data.len) return null;
    if (str_len > max_len) return null;

    const result: JsonString(max_len) = .fromSlice(data[offset.*..][0..str_len]);
    offset.* += str_len;

    return result;
}

/// Read an OptionalNonZeroPubkey (32 bytes, zero = None).
fn readOptionalNonZeroPubkey(data: *const [32]u8) ?Pubkey {
    const pubkey = Pubkey{ .data = data.* };
    if (pubkey.isZeroed()) return null;
    return pubkey;
}

/// Check if bytes are all zero (for optional crypto types).
fn readOptionalNonZeroBytes(data: []const u8) ?[]const u8 {
    for (data) |b| {
        if (b != 0) return data;
    }
    return null;
}

/// Helper to build Borsh-encoded TokenMetadata bytes for testing.
fn buildTokenMetadataBytes(
    update_authority: ?Pubkey,
    mint: Pubkey,
    name: []const u8,
    symbol: []const u8,
    uri: []const u8,
    additional_metadata: []const struct { key: []const u8, value: []const u8 },
) JsonString(4096) {
    var buf: JsonString(4096) = .init();

    // update_authority: OptionalNonZeroPubkey (32 bytes)
    if (update_authority) |auth| {
        buf.appendSliceAssumeCapacity(&auth.data);
    } else {
        buf.appendNTimesAssumeCapacity(0, 32);
    }

    // mint: Pubkey (32 bytes)
    buf.appendSliceAssumeCapacity(&mint.data);

    // name: Borsh string
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(name.len))));
    buf.appendSliceAssumeCapacity(name);

    // symbol: Borsh string
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(symbol.len))));
    buf.appendSliceAssumeCapacity(symbol);

    // uri: Borsh string
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(uri.len))));
    buf.appendSliceAssumeCapacity(uri);

    // additional_metadata: Vec<(String, String)>
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(additional_metadata.len))));
    for (additional_metadata) |pair| {
        buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(pair.key.len))));
        buf.appendSliceAssumeCapacity(pair.key);
        buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(pair.value.len))));
        buf.appendSliceAssumeCapacity(pair.value);
    }

    return buf;
}

test "rpc.account_codec.parse_token_extension: token_metadata empty additional_metadata" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const authority = Pubkey{ .data = [_]u8{2} ** 32 };

    const bytes = buildTokenMetadataBytes(
        authority,
        mint,
        "Test Token",
        "TEST",
        "https://example.com/token.json",
        &.{}, // empty additional_metadata
    );

    const result = UiTokenMetadata.parse(bytes.constSlice());
    try std.testing.expect(result != null);

    switch (result.?) {
        .token_metadata => |tm| {
            try std.testing.expectEqualStrings("Test Token", tm.name.constSlice());
            try std.testing.expectEqualStrings("TEST", tm.symbol.constSlice());
            try std.testing.expectEqualStrings("https://example.com/token.json", tm.uri.constSlice());
            try std.testing.expectEqual(@as(usize, 0), tm.additionalMetadata.len);
        },
        else => try std.testing.expect(false),
    }
}

test "rpc.account_codec.parse_token_extension: token_metadata single pair" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };

    const bytes = buildTokenMetadataBytes(
        null, // no update authority
        mint,
        "NFT",
        "NFT",
        "https://example.com/nft.json",
        &.{.{ .key = "trait_type", .value = "Background" }},
    );

    const result = UiTokenMetadata.parse(bytes.constSlice());
    try std.testing.expect(result != null);

    switch (result.?) {
        .token_metadata => |tm| {
            try std.testing.expect(tm.updateAuthority == null);
            try std.testing.expectEqual(@as(usize, 1), tm.additionalMetadata.len);
            const pair = tm.additionalMetadata.get(0);
            try std.testing.expectEqualStrings("trait_type", pair.key.constSlice());
            try std.testing.expectEqualStrings("Background", pair.value.constSlice());
        },
        else => try std.testing.expect(false),
    }
}

test "rpc.account_codec.parse_token_extension: token_metadata multiple pairs" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };
    const authority = Pubkey{ .data = [_]u8{2} ** 32 };

    const bytes = buildTokenMetadataBytes(
        authority,
        mint,
        "Cool NFT",
        "CNFT",
        "https://example.com/cool.json",
        &.{
            .{ .key = "trait_type", .value = "Background" },
            .{ .key = "value", .value = "Blue" },
            .{ .key = "rarity", .value = "Legendary" },
        },
    );

    const result = UiTokenMetadata.parse(bytes.constSlice());
    try std.testing.expect(result != null);

    switch (result.?) {
        .token_metadata => |tm| {
            try std.testing.expectEqual(@as(usize, 3), tm.additionalMetadata.len);
            const meta = tm.additionalMetadata;
            try std.testing.expectEqualStrings("trait_type", meta.get(0).key.constSlice());
            try std.testing.expectEqualStrings("Background", meta.get(0).value.constSlice());
            try std.testing.expectEqualStrings("value", meta.get(1).key.constSlice());
            try std.testing.expectEqualStrings("Blue", meta.get(1).value.constSlice());
            try std.testing.expectEqualStrings("rarity", meta.get(2).key.constSlice());
            try std.testing.expectEqualStrings("Legendary", meta.get(2).value.constSlice());
        },
        else => try std.testing.expect(false),
    }
}

test "rpc.account_codec.parse_token_extension: token_metadata too many pairs returns null" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };

    // Build bytes with 33 pairs (exceeds limit of 32)
    var buf: JsonString(8192) = .{};

    // update_authority: 32 zero bytes
    buf.appendNTimesAssumeCapacity(0, 32);
    // mint
    buf.appendSliceAssumeCapacity(&mint.data);
    // name
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("Test");
    // symbol
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("TEST");
    // uri
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("http");
    // additional_metadata count: 33
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 33)));
    // Add 33 pairs
    for (0..33) |i| {
        var key_buf: [8]u8 = undefined;
        const key_len = std.fmt.bufPrint(&key_buf, "key{d}", .{i}) catch unreachable;
        buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, @intCast(key_len.len))));
        buf.appendSliceAssumeCapacity(key_len);
        buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 5)));
        buf.appendSliceAssumeCapacity("value");
    }

    const result = UiTokenMetadata.parse(buf.constSlice());
    // Should fail due to too many pairs
    try std.testing.expect(result == null);
}

test "rpc.account_codec.parse_token_extension: token_metadata key too long returns null" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };

    var buf: JsonString(4096) = .{};

    // update_authority: 32 zero bytes
    buf.appendNTimesAssumeCapacity(0, 32);
    // mint
    buf.appendSliceAssumeCapacity(&mint.data);
    // name
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("Test");
    // symbol
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("TEST");
    // uri
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("http");
    // additional_metadata count: 1
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 1)));
    // Key with 65 bytes (exceeds 64 limit)
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 65)));
    buf.appendNTimesAssumeCapacity('x', 65);
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 5)));
    buf.appendSliceAssumeCapacity("value");

    const result = UiTokenMetadata.parse(buf.constSlice());
    // Should fail due to key too long
    try std.testing.expect(result == null);
}

test "rpc.account_codec.parse_token_extension: token_metadata value too long returns null" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };

    var buf: JsonString(4096) = .{};

    // update_authority: 32 zero bytes
    buf.appendNTimesAssumeCapacity(0, 32);
    // mint
    buf.appendSliceAssumeCapacity(&mint.data);
    // name
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("Test");
    // symbol
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("TEST");
    // uri
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 4)));
    buf.appendSliceAssumeCapacity("http");
    // additional_metadata count: 1
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 1)));
    // Key (valid)
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 3)));
    buf.appendSliceAssumeCapacity("key");
    // Value with 257 bytes (exceeds 256 limit)
    buf.appendSliceAssumeCapacity(&std.mem.toBytes(@as(u32, 257)));
    buf.appendNTimesAssumeCapacity('v', 257);

    const result = UiTokenMetadata.parse(buf.constSlice());
    try std.testing.expect(result == null); // Should fail due to value too long
}

test "rpc.account_codec.parse_token_extension: token_metadata JSON output" {
    const mint = Pubkey{ .data = [_]u8{1} ** 32 };

    const bytes = buildTokenMetadataBytes(
        null,
        mint,
        "Test",
        "TST",
        "https://x.com",
        &.{
            .{ .key = "trait_type", .value = "Background" },
            .{ .key = "value", .value = "Blue" },
        },
    );

    const result = UiTokenMetadata.parse(bytes.constSlice());
    try std.testing.expect(result != null);

    switch (result.?) {
        .token_metadata => |tm| {
            var json_buf: [2048]u8 = undefined;
            var out: std.io.Writer = .fixed(&json_buf);
            var jw: std.json.Stringify = .{ .writer = &out };

            try jw.write(tm);

            const json_output = out.buffered();
            // Verify JSON contains expected structure
            const expected = "\"additionalMetadata\":[[\"trait_type\",\"Background\"]" ++
                ",[\"value\",\"Blue\"]]";
            try std.testing.expect(std.mem.indexOf(u8, json_output, expected) != null);
        },
        else => try std.testing.expect(false),
    }
}

test "rpc.account_codec.parse_token_extension: parseExtensions TLV iteration" {
    // Test empty data
    {
        const empty: []const u8 = &.{};
        const result = parseExtensions(empty);
        try std.testing.expectEqual(@as(usize, 0), result.len);
    }

    // Test data with only discriminator (no extensions)
    {
        const disc_only: []const u8 = &.{0x01}; // discriminator byte
        const result = parseExtensions(disc_only);
        try std.testing.expectEqual(@as(usize, 0), result.len);
    }

    // Test single extension: MintCloseAuthority (type=3, len=32)
    {
        var data: [1 + 4 + 32]u8 = undefined;
        data[0] = 0x01; // discriminator
        std.mem.writeInt(u16, data[1..3], 3, .little); // type = mint_close_authority
        std.mem.writeInt(u16, data[3..5], 32, .little); // length
        @memset(data[5..37], 0xAA); // pubkey bytes
        const result = parseExtensions(&data);
        try std.testing.expectEqual(@as(usize, 1), result.len);
        switch (result.get(0)) {
            .mint_close_authority => |mca| try std.testing.expect(mca.closeAuthority != null),
            else => try std.testing.expect(false),
        }
    }

    // Test multiple extensions
    {
        var data: [1 + 4 + 32 + 4 + 1]u8 = undefined;
        data[0] = 0x01; // discriminator
        // Extension 1: MintCloseAuthority (type=3, len=32)
        std.mem.writeInt(u16, data[1..3], 3, .little);
        std.mem.writeInt(u16, data[3..5], 32, .little);
        @memset(data[5..37], 0xBB);
        // Extension 2: DefaultAccountState (type=6, len=1)
        std.mem.writeInt(u16, data[37..39], 6, .little);
        std.mem.writeInt(u16, data[39..41], 1, .little);
        data[41] = 1; // initialized state
        const result = parseExtensions(&data);
        try std.testing.expectEqual(@as(usize, 2), result.len);
    }

    // Test uninitialized extension type (0) stops parsing
    {
        var data: [1 + 4 + 4]u8 = undefined;
        data[0] = 0x01;
        std.mem.writeInt(u16, data[1..3], 0, .little); // uninitialized = stop
        std.mem.writeInt(u16, data[3..5], 0, .little);
        // More data that should be ignored
        std.mem.writeInt(u16, data[5..7], 3, .little);
        std.mem.writeInt(u16, data[7..9], 0, .little);
        const result = parseExtensions(&data);
        try std.testing.expectEqual(@as(usize, 0), result.len);
    }

    // Test malformed TLV (length exceeds data) - graceful degradation
    {
        var data: [1 + 4]u8 = undefined;
        data[0] = 0x01;
        std.mem.writeInt(u16, data[1..3], 3, .little); // type
        std.mem.writeInt(u16, data[3..5], 100, .little); // length > remaining
        const result = parseExtensions(&data);
        try std.testing.expectEqual(@as(usize, 0), result.len);
    }

    // Test unknown extension type -> unparseable_extension
    {
        var data: [1 + 4 + 4]u8 = undefined;
        data[0] = 0x01;
        std.mem.writeInt(u16, data[1..3], 999, .little); // unknown type
        std.mem.writeInt(u16, data[3..5], 4, .little);
        @memset(data[5..9], 0x00);
        const result = parseExtensions(&data);
        try std.testing.expectEqual(@as(usize, 1), result.len);
        try std.testing.expect(result.get(0) == .unparseable_extension);
    }
}

test "rpc.account_codec.parse_token_extension: simple extensions" {
    // DefaultAccountState (type=6, 1 byte)
    {
        const result = UiDefaultAccountState.parse(&.{1}); // initialized
        try std.testing.expect(result != null);
        try std.testing.expect(result.?.default_account_state.accountState == .initialized);

        const frozen = UiDefaultAccountState.parse(&.{2});
        try std.testing.expect(frozen.?.default_account_state.accountState == .frozen);

        // Invalid state
        try std.testing.expect(UiDefaultAccountState.parse(&.{3}) == null);
        // Wrong size
        try std.testing.expect(UiDefaultAccountState.parse(&.{ 1, 2 }) == null);
    }

    // MemoTransfer (type=8, 1 byte)
    {
        const enabled = UiMemoTransfer.parse(&.{1});
        try std.testing.expect(enabled.?.memo_transfer.requireIncomingTransferMemos == true);

        const disabled = UiMemoTransfer.parse(&.{0});
        try std.testing.expect(disabled.?.memo_transfer.requireIncomingTransferMemos == false);
    }

    // CpiGuard (type=11, 1 byte)
    {
        const locked = UiCpiGuard.parse(&.{1});
        try std.testing.expect(locked.?.cpi_guard.lockCpi == true);
    }

    // TransferHookAccount (type=15, 1 byte)
    {
        const result = UiTransferHookAccount.parse(&.{1});
        try std.testing.expect(result.?.transfer_hook_account.transferring == true);
    }

    // TransferFeeAmount (type=2, 8 bytes)
    {
        var data: [8]u8 = undefined;
        std.mem.writeInt(u64, &data, 12345, .little);
        const result = UiTransferFeeAmount.parse(&data);
        try std.testing.expectEqual(@as(u64, 12345), result.?.transfer_fee_amount.withheldAmount);
    }

    // MintCloseAuthority (type=3, 32 bytes)
    {
        var pubkey_bytes: [32]u8 = undefined;
        @memset(&pubkey_bytes, 0xAA);
        const result = UiMintCloseAuthority.parse(&pubkey_bytes);
        try std.testing.expect(result.?.mint_close_authority.closeAuthority != null);

        // Zero pubkey = null authority
        const zero_result = UiMintCloseAuthority.parse(&([_]u8{0} ** 32));
        try std.testing.expect(zero_result.?.mint_close_authority.closeAuthority == null);
    }

    // PermanentDelegate (type=12, 32 bytes)
    {
        var pubkey_bytes: [32]u8 = undefined;
        @memset(&pubkey_bytes, 0xBB);
        const result = UiPermanentDelegate.parse(&pubkey_bytes);
        try std.testing.expect(result.?.permanent_delegate.delegate != null);
    }

    // PausableConfig (type=26, 33 bytes)
    {
        var data: [33]u8 = undefined;
        @memset(data[0..32], 0xCC);
        data[32] = 1; // paused = true
        const result = UiPausableConfig.parse(&data);
        try std.testing.expect(result.?.pausable_config.authority != null);
        try std.testing.expect(result.?.pausable_config.paused == true);
    }
}

test "rpc.account_codec.parse_token_extension: pointer extensions (64 bytes)" {
    const authority_bytes: [32]u8 = [_]u8{0xAA} ** 32;
    const address_bytes: [32]u8 = [_]u8{0xBB} ** 32;

    // MetadataPointer (type=18)
    {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &authority_bytes);
        @memcpy(data[32..64], &address_bytes);
        const result = UiMetadataPointer.parse(&data);
        try std.testing.expect(result.?.metadata_pointer.authority != null);
        try std.testing.expect(result.?.metadata_pointer.metadataAddress != null);
    }

    // GroupPointer (type=20)
    {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &authority_bytes);
        @memcpy(data[32..64], &address_bytes);
        const result = UiGroupPointer.parse(&data);
        try std.testing.expect(result.?.group_pointer.authority != null);
        try std.testing.expect(result.?.group_pointer.groupAddress != null);
    }

    // GroupMemberPointer (type=22)
    {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &authority_bytes);
        @memcpy(data[32..64], &address_bytes);
        const result = UiGroupMemberPointer.parse(&data);
        try std.testing.expect(result.?.group_member_pointer.authority != null);
        try std.testing.expect(result.?.group_member_pointer.memberAddress != null);
    }

    // TransferHook (type=14)
    {
        var data: [64]u8 = undefined;
        @memcpy(data[0..32], &authority_bytes);
        @memcpy(data[32..64], &address_bytes);
        const result = UiTransferHook.parse(&data);
        try std.testing.expect(result.?.transfer_hook.authority != null);
        try std.testing.expect(result.?.transfer_hook.programId != null);
    }

    // Wrong size returns null
    {
        const short: [63]u8 = [_]u8{0} ** 63;
        try std.testing.expect(UiMetadataPointer.parse(&short) == null);
    }
}

test "rpc.account_codec.parse_token_extension: InterestBearingConfig" {
    // UiInterestBearingConfig.parse (52 bytes)
    {
        var data: [52]u8 = undefined;
        @memset(data[0..32], 0xAA); // rate_authority
        std.mem.writeInt(i64, data[32..40], 1000000, .little); // init_timestamp
        std.mem.writeInt(i16, data[40..42], 500, .little); // pre_update_rate
        std.mem.writeInt(i64, data[42..50], 2000000, .little); // last_update_ts
        std.mem.writeInt(i16, data[50..52], 600, .little); // current_rate

        const result = UiInterestBearingConfig.parse(&data);
        try std.testing.expect(result != null);
        const config = result.?.interest_bearing_config;
        try std.testing.expect(config.rateAuthority != null);
        try std.testing.expectEqual(@as(i64, 1000000), config.initializationTimestamp);
        try std.testing.expectEqual(@as(i16, 500), config.preUpdateAverageRate);
        try std.testing.expectEqual(@as(i64, 2000000), config.lastUpdateTimestamp);
        try std.testing.expectEqual(@as(i16, 600), config.currentRate);
    }
    // Wrong size
    {
        const short: [51]u8 = [_]u8{0} ** 51;
        try std.testing.expect(UiInterestBearingConfig.parse(&short) == null);
    }
}

test "rpc.account_codec.parse_token_extension: ScaledUiAmountConfig" {
    // 56 bytes
    var data: [56]u8 = undefined;
    @memset(data[0..32], 0xBB); // authority
    std.mem.writeInt(u64, data[32..40], @as(u64, @bitCast(@as(f64, 1.5))), .little); // multiplier
    std.mem.writeInt(i64, data[40..48], 999999, .little); // new_multiplier_effective_ts
    std.mem.writeInt(u64, data[48..56], @as(u64, @bitCast(@as(f64, 2.0))), .little); // new_multiplier

    const result = UiScaledUiAmountConfig.parse(&data);
    try std.testing.expect(result != null);
    const config = result.?.scaled_ui_amount_config;
    try std.testing.expect(config.authority != null);
    try std.testing.expectEqual(@as(f64, 1.5), config.multiplier);
    try std.testing.expectEqual(@as(i64, 999999), config.newMultiplierEffectiveTimestamp);
    try std.testing.expectEqual(@as(f64, 2.0), config.newMultiplier);
}

test "rpc.account_codec.parse_token_extension: TransferFeeConfig" {
    // 108 bytes
    var data: [108]u8 = undefined;
    @memset(data[0..32], 0xAA); // config_authority
    @memset(data[32..64], 0xBB); // withdraw_authority
    std.mem.writeInt(u64, data[64..72], 5000, .little); // withheld_amount
    // older_transfer_fee
    std.mem.writeInt(u64, data[72..80], 100, .little); // epoch
    std.mem.writeInt(u64, data[80..88], 1000000, .little); // max_fee
    std.mem.writeInt(u16, data[88..90], 250, .little); // basis_points
    // newer_transfer_fee
    std.mem.writeInt(u64, data[90..98], 101, .little); // epoch
    std.mem.writeInt(u64, data[98..106], 2000000, .little); // max_fee
    std.mem.writeInt(u16, data[106..108], 300, .little); // basis_points

    const result = UiTransferFeeConfig.parse(&data);
    try std.testing.expect(result != null);
    const config = result.?.transfer_fee_config;
    try std.testing.expect(config.transferFeeConfigAuthority != null);
    try std.testing.expect(config.withdrawWithheldAuthority != null);
    try std.testing.expectEqual(@as(u64, 5000), config.withheldAmount);
    try std.testing.expectEqual(@as(u64, 100), config.olderTransferFee.epoch);
    try std.testing.expectEqual(@as(u16, 250), config.olderTransferFee.transferFeeBasisPoints);
    try std.testing.expectEqual(@as(u64, 101), config.newerTransferFee.epoch);
    try std.testing.expectEqual(@as(u16, 300), config.newerTransferFee.transferFeeBasisPoints);
}

test "rpc.account_codec.parse_token_extension: TokenGroup and TokenGroupMember" {
    // TokenGroup (80 bytes)
    {
        var data: [80]u8 = undefined;
        @memset(data[0..32], 0xAA); // update_authority
        @memset(data[32..64], 0xBB); // mint
        std.mem.writeInt(u64, data[64..72], 10, .little); // size
        std.mem.writeInt(u64, data[72..80], 100, .little); // max_size

        const result = UiTokenGroup.parse(&data);
        try std.testing.expect(result != null);
        const group = result.?.token_group;
        try std.testing.expect(group.updateAuthority != null);
        try std.testing.expectEqual(@as(u64, 10), group.size);
        try std.testing.expectEqual(@as(u64, 100), group.maxSize);
    }

    // TokenGroupMember (72 bytes)
    {
        var data: [72]u8 = undefined;
        @memset(data[0..32], 0xCC); // mint
        @memset(data[32..64], 0xDD); // group
        std.mem.writeInt(u64, data[64..72], 5, .little); // member_number

        const result = UiTokenGroupMember.parse(&data);
        try std.testing.expect(result != null);
        const member = result.?.token_group_member;
        try std.testing.expectEqual(@as(u64, 5), member.memberNumber);
    }
}

test "rpc.account_codec.parse_token_extension: confidential extensions" {
    // ConfidentialTransferMint (65 bytes)
    {
        var data: [65]u8 = undefined;
        @memset(data[0..32], 0xAA); // authority
        data[32] = 1; // auto_approve = true
        @memset(data[33..65], 0xBB); // auditor_elgamal_pubkey

        const result = UiConfidentialTransferMint.parse(&data);
        try std.testing.expect(result != null);
        const mint = result.?.confidential_transfer_mint;
        try std.testing.expect(mint.authority != null);
        try std.testing.expect(mint.autoApproveNewAccounts == true);
        try std.testing.expect(mint.auditorElgamalPubkey != null);
    }

    // ConfidentialTransferFeeAmount (64 bytes)
    {
        var data: [64]u8 = undefined;
        @memset(&data, 0xCC);
        const result = UiConfidentialTransferFeeAmount.parse(&data);
        try std.testing.expect(result != null);
    }

    // ConfidentialTransferFeeConfig (129 bytes)
    {
        var data: [129]u8 = undefined;
        @memset(data[0..32], 0xAA); // authority
        @memset(data[32..64], 0xBB); // elgamal_pubkey
        data[64] = 1; // harvest_enabled
        @memset(data[65..129], 0xCC); // withheld_amount

        const result = UiConfidentialTransferFeeConfig.parse(&data);
        try std.testing.expect(result != null);
        const config = result.?.confidential_transfer_fee_config;
        try std.testing.expect(config.authority != null);
        try std.testing.expect(config.harvestToMintEnabled == true);
    }

    // ConfidentialMintBurn (196 bytes)
    {
        var data: [196]u8 = undefined;
        @memset(data[0..64], 0xAA); // confidential_supply
        @memset(data[64..100], 0xBB); // decryptable_supply
        @memset(data[100..132], 0xCC); // supply_elgamal_pubkey
        @memset(data[132..196], 0xDD); // pending_burn

        const result = UiConfidentialMintBurn.parse(&data);
        try std.testing.expect(result != null);
    }

    // ConfidentialTransferAccount (295 bytes)
    {
        var data: [295]u8 = undefined;
        data[0] = 1; // approved
        @memset(data[1..33], 0xAA); // elgamal_pubkey
        @memset(data[33..97], 0xBB); // pending_balance_lo
        @memset(data[97..161], 0xCC); // pending_balance_hi
        @memset(data[161..225], 0xDD); // available_balance
        @memset(data[225..261], 0xEE); // decryptable_available_balance
        data[261] = 1; // allow_confidential_credits
        data[262] = 0; // allow_non_confidential_credits
        std.mem.writeInt(u64, data[263..271], 10, .little);
        std.mem.writeInt(u64, data[271..279], 20, .little);
        std.mem.writeInt(u64, data[279..287], 30, .little);
        std.mem.writeInt(u64, data[287..295], 40, .little);

        const result = UiConfidentialTransferAccount.parse(&data);
        try std.testing.expect(result != null);
        const account = result.?.confidential_transfer_account;
        try std.testing.expect(account.approved == true);
        try std.testing.expect(account.allowConfidentialCredits == true);
        try std.testing.expect(account.allowNonConfidentialCredits == false);
        try std.testing.expectEqual(@as(u64, 10), account.pendingBalanceCreditCounter);
    }
}

test "rpc.account_codec.parse_token_extension: extractFromMint helpers" {
    const MINT_LEN = 82;
    // InterestBearingConfigData.extractFromMint
    {
        // Build mint data with interest bearing extension at offset 82+
        var data: [MINT_LEN + 1 + 4 + 52]u8 = undefined;
        @memset(data[0..MINT_LEN], 0); // base mint data
        data[MINT_LEN] = 0x01; // discriminator
        std.mem.writeInt(u16, data[MINT_LEN + 1 ..][0..2], 10, .little); // type=interest_bearing_config
        std.mem.writeInt(u16, data[MINT_LEN + 3 ..][0..2], 52, .little); // length
        // Extension value (52 bytes)
        const ext_start = MINT_LEN + 5;
        @memset(data[ext_start..][0..32], 0xAA); // rate_authority
        std.mem.writeInt(i64, data[ext_start + 32 ..][0..8], 1234567, .little);
        std.mem.writeInt(i16, data[ext_start + 40 ..][0..2], 500, .little);
        std.mem.writeInt(i64, data[ext_start + 42 ..][0..8], 7654321, .little);
        std.mem.writeInt(i16, data[ext_start + 50 ..][0..2], 600, .little);

        const result = InterestBearingConfigData.extractFromMint(&data);
        try std.testing.expect(result != null);
        try std.testing.expect(result.?.rate_authority != null);
        try std.testing.expectEqual(@as(i64, 1234567), result.?.initialization_timestamp);
        try std.testing.expectEqual(@as(i16, 500), result.?.pre_update_average_rate);
        try std.testing.expectEqual(@as(i16, 600), result.?.current_rate);
    }

    // No extension present
    {
        var data: [MINT_LEN]u8 = undefined;
        @memset(&data, 0);
        const result = InterestBearingConfigData.extractFromMint(&data);
        try std.testing.expect(result == null);
    }

    // ScaledUiAmountConfigData.extractFromMint
    {
        var data: [MINT_LEN + 1 + 4 + 56]u8 = undefined;
        @memset(data[0..MINT_LEN], 0);
        data[MINT_LEN] = 0x01;
        std.mem.writeInt(u16, data[MINT_LEN + 1 ..][0..2], 25, .little); // type=scaled_ui_amount_config
        std.mem.writeInt(u16, data[MINT_LEN + 3 ..][0..2], 56, .little);
        const ext_start = MINT_LEN + 5;
        @memset(data[ext_start..][0..32], 0xBB); // authority
        const mult_bits = @as(u64, @bitCast(@as(f64, 1.25)));
        std.mem.writeInt(u64, data[ext_start + 32 ..][0..8], mult_bits, .little);
        std.mem.writeInt(i64, data[ext_start + 40 ..][0..8], 999, .little);
        const new_mult_bits = @as(u64, @bitCast(@as(f64, 2.5)));
        std.mem.writeInt(u64, data[ext_start + 48 ..][0..8], new_mult_bits, .little);

        const result = ScaledUiAmountConfigData.extractFromMint(&data);
        try std.testing.expect(result != null);
        try std.testing.expectEqual(@as(f64, 1.25), result.?.multiplier);
        try std.testing.expectEqual(@as(i64, 999), result.?.new_multiplier_effective_timestamp);
        try std.testing.expectEqual(@as(f64, 2.5), result.?.new_multiplier);
    }
}

test "rpc.account_codec.parse_token_extension: UiExtension jsonStringify" {
    var json_buf: [4096]u8 = undefined;
    var out: std.io.Writer = .fixed(&json_buf);
    var jw: std.json.Stringify = .{ .writer = &out };

    // Test unit variants
    {
        const ext: UiExtension = .immutable_owner;
        try ext.jsonStringify(&jw);
        const output = out.buffered();
        const needle = "\"extension\":\"immutableOwner\"";
        try std.testing.expect(std.mem.indexOf(u8, output, needle) != null);
    }

    // Reset buffer
    out.end = 0;
    jw = .{ .writer = &out };
    {
        const ext: UiExtension = .non_transferable;
        try ext.jsonStringify(&jw);
        const output = out.buffered();
        const needle = "\"extension\":\"nonTransferable\"";
        try std.testing.expect(std.mem.indexOf(u8, output, needle) != null);
    }

    // Test extension with state
    out.end = 0;
    jw = .{ .writer = &out };
    {
        const ext: UiExtension = .{ .default_account_state = .{ .accountState = .frozen } };
        try ext.jsonStringify(&jw);
        const output = out.buffered();
        const ext_needle = "\"extension\":\"defaultAccountState\"";
        try std.testing.expect(std.mem.indexOf(u8, output, ext_needle) != null);
        const state_needle = "\"accountState\":\"frozen\"";
        try std.testing.expect(std.mem.indexOf(u8, output, state_needle) != null);
    }

    // Test transfer_fee_config JSON
    out.end = 0;
    jw = .{ .writer = &out };
    {
        const ext: UiExtension = .{ .transfer_fee_config = .{
            .transferFeeConfigAuthority = null,
            .withdrawWithheldAuthority = null,
            .withheldAmount = 1000,
            .olderTransferFee = .{ .epoch = 10, .maximumFee = 500, .transferFeeBasisPoints = 100 },
            .newerTransferFee = .{ .epoch = 11, .maximumFee = 600, .transferFeeBasisPoints = 150 },
        } };
        try ext.jsonStringify(&jw);
        const output = out.buffered();
        const ext_needle = "\"extension\":\"transferFeeConfig\"";
        try std.testing.expect(std.mem.indexOf(u8, output, ext_needle) != null);
        const amt_needle = "\"withheldAmount\":1000";
        try std.testing.expect(std.mem.indexOf(u8, output, amt_needle) != null);
        const fee_needle = "\"transferFeeBasisPoints\":100";
        try std.testing.expect(std.mem.indexOf(u8, output, fee_needle) != null);
    }

    // Test confidential extension with base64 fields
    out.end = 0;
    jw = .{ .writer = &out };
    {
        const withheld_bytes = [_]u8{0xAA} ** 64;
        const ext: UiExtension = .{ .confidential_transfer_fee_amount = .{
            .withheldAmount = Base64Encoded(64).init(&withheld_bytes),
        } };
        try ext.jsonStringify(&jw);
        const output = out.buffered();
        const ext_needle = "\"extension\":\"confidentialTransferFeeAmount\"";
        try std.testing.expect(std.mem.indexOf(u8, output, ext_needle) != null);
        const amt_needle = "\"withheldAmount\":";
        try std.testing.expect(std.mem.indexOf(u8, output, amt_needle) != null);
    }
}
