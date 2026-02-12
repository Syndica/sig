/// Token-2022 extension parsing and UI representation for account decoder.
/// TODO: [agave] ...
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");
const base64 = std.base64.standard;

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const ParseError = account_decoder.ParseError;
const AccountState = account_decoder.AccountState;

/// TLV parsing constants for Token-2022 extensions.
// TODO: document offset form Agave.
/// TLV layout: 2 bytes type + 2 bytes length + value
const TLV_HEADER_SIZE: usize = 4;
// TODO: document offset form Agave.
/// Maximum expected size of all extensions (for sanity checking, not protocol limit)
pub const MAX_EXTENSIONS: usize = 16;

/// Token-2022 extension type discriminants.
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/extension.rs
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
    // TODO: document from agave.
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
    // TODO: document from agave.
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
            .uninitialized => try jw.write("uninitialized"),
            .immutable_owner => try jw.write("immutableOwner"),
            .non_transferable => try jw.write("nonTransferable"),
            .non_transferable_account => try jw.write("nonTransferableAccount"),
            .pausable_account => try jw.write("pausableAccount"),
            .unparseable_extension => try jw.write("unparseableExtension"),
            .default_account_state => |v| {
                try jw.write("defaultAccountState");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .memo_transfer => |v| {
                try jw.write("memoTransfer");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .cpi_guard => |v| {
                try jw.write("cpiGuard");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .transfer_hook_account => |v| {
                try jw.write("transferHookAccount");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .transfer_fee_amount => |v| {
                try jw.write("transferFeeAmount");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .mint_close_authority => |v| {
                try jw.write("mintCloseAuthority");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .permanent_delegate => |v| {
                try jw.write("permanentDelegate");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .pausable_config => |v| {
                try jw.write("pausableConfig");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .interest_bearing_config => |v| {
                try jw.write("interestBearingConfig");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .scaled_ui_amount_config => |v| {
                try jw.write("scaledUiAmountConfig");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .metadata_pointer => |v| {
                try jw.write("metadataPointer");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .group_pointer => |v| {
                try jw.write("groupPointer");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .group_member_pointer => |v| {
                try jw.write("groupMemberPointer");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .transfer_hook => |v| {
                try jw.write("transferHook");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .confidential_transfer_fee_amount => |v| {
                try jw.write("confidentialTransferFeeAmount");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .confidential_transfer_mint => |v| {
                try jw.write("confidentialTransferMint");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .token_group_member => |v| {
                try jw.write("tokenGroupMember");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .token_group => |v| {
                try jw.write("tokenGroup");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .transfer_fee_config => |v| {
                try jw.write("transferFeeConfig");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .confidential_transfer_fee_config => |v| {
                try jw.write("confidentialTransferFeeConfig");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .confidential_mint_burn => |v| {
                try jw.write("confidentialMintBurn");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .confidential_transfer_account => |v| {
                try jw.write("confidentialTransferAccount");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
            .token_metadata => |v| {
                try jw.write("tokenMetadata");
                try jw.objectField("state");
                try v.jsonStringify(jw);
            },
        }

        try jw.endObject();
    }
};

/// Parse Token-2022 TLV extensions from account data.
/// Returns null if data doesn't contain valid extensions.
/// TODO: [agave] Uses similar iteration logic to spl-token-2022's get_tlv_data_info
pub fn parseExtensions(data: []const u8) std.BoundedArray(UiExtension, MAX_EXTENSIONS) {
    var extensions: std.BoundedArray(UiExtension, MAX_EXTENSIONS) = .{};

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
            // Malformed TLV - return what we have so far
            // TODO: should we be returning an error instead?
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
fn parseExtension(ext_type: ExtensionType, value: []const u8) ?UiExtension {
    // Validate size for fixed-length extensions
    // TODO: check if this early exit is same logic in agave.
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

// TODO: for all parse fns, use defined constants for offsets and expected sizes, and document from agave.

/// DefaultAccountState (1 byte) - sets the default state for new token accounts.
pub const UiDefaultAccountState = struct {
    account_state: AccountState,

    pub fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        const state_byte = value[0];
        if (state_byte > 2) return null;
        return .{ .default_account_state = .{
            .account_state = @enumFromInt(state_byte),
        } };
    }

    pub fn jsonStringify(self: UiDefaultAccountState, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("accountState");
        try jw.write(switch (self.account_state) {
            .uninitialized => "uninitialized",
            .initialized => "initialized",
            .frozen => "frozen",
        });
        try jw.endObject();
    }
};

/// MemoTransfer (1 byte) - Requires memos on incoming transfers.
pub const UiMemoTransfer = struct {
    require_incoming_transfer_memos: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        return .{ .memo_transfer = .{
            .require_incoming_transfer_memos = value[0] != 0,
        } };
    }

    pub fn jsonStringify(self: UiMemoTransfer, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("requireIncomingTransferMemos");
        try jw.write(self.require_incoming_transfer_memos);
        try jw.endObject();
    }
};

/// CpiGuard (1 byte) - Restricts certain CPI operations.
pub const UiCpiGuard = struct {
    lock_cpi: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 1) return null;
        return .{ .cpi_guard = .{
            .lock_cpi = value[0] != 0,
        } };
    }

    pub fn jsonStringify(self: UiCpiGuard, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("lockCpi");
        try jw.write(self.lock_cpi);
        try jw.endObject();
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

    pub fn jsonStringify(self: UiTransferHookAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("transferring");
        try jw.write(self.transferring);
        try jw.endObject();
    }
};

/// TransferFeeAmount (8 bytes) - Withheld transfer fees on account.
pub const UiTransferFeeAmount = struct {
    withheld_amount: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 8) return null;
        return .{ .transfer_fee_amount = .{
            .withheld_amount = std.mem.readInt(u64, value[0..8], .little),
        } };
    }

    pub fn jsonStringify(self: UiTransferFeeAmount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("withheldAmount");
        try jw.write(self.withheld_amount);
        try jw.endObject();
    }
};

/// MintCloseAuthority (32 bytes) - Authority that can close the mint.
pub const UiMintCloseAuthority = struct {
    close_authority: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 32) return null;
        const pubkey = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .mint_close_authority = .{
            .close_authority = if (pubkey) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiMintCloseAuthority, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("closeAuthority");
        if (self.close_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// PermanentDelegate (32 bytes) - Permanent delegate authority.
pub const UiPermanentDelegate = struct {
    delegate: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 32) return null;
        const pubkey = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .permanent_delegate = .{
            .delegate = if (pubkey) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiPermanentDelegate, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("delegate");
        if (self.delegate) |d| try jw.write(d.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// PausableConfig (33 bytes) - Pause authority and state.
pub const UiPausableConfig = struct {
    authority: ?Pubkey.Base58String,
    paused: bool,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 33) return null;
        const pubkey = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .pausable_config = .{
            .authority = if (pubkey) |p| p.base58String() else null,
            .paused = value[32] != 0,
        } };
    }

    pub fn jsonStringify(self: UiPausableConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("paused");
        try jw.write(self.paused);
        try jw.endObject();
    }
};

/// InterestBearingConfig (52 bytes) - Interest-bearing token configuration.
pub const UiInterestBearingConfig = struct {
    rate_authority: ?Pubkey.Base58String,
    initialization_timestamp: i64,
    pre_update_average_rate: i16,
    last_update_timestamp: i64,
    current_rate: i16,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 52) return null;
        const pubkey = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .interest_bearing_config = .{
            .rate_authority = if (pubkey) |p| p.base58String() else null,
            .initialization_timestamp = std.mem.readInt(i64, value[32..40], .little),
            .pre_update_average_rate = std.mem.readInt(i16, value[40..42], .little),
            .last_update_timestamp = std.mem.readInt(i64, value[42..50], .little),
            .current_rate = std.mem.readInt(i16, value[50..52], .little),
        } };
    }

    pub fn jsonStringify(self: UiInterestBearingConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("rateAuthority");
        if (self.rate_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("initializationTimestamp");
        try jw.write(self.initialization_timestamp);
        try jw.objectField("preUpdateAverageRate");
        try jw.write(self.pre_update_average_rate);
        try jw.objectField("lastUpdateTimestamp");
        try jw.write(self.last_update_timestamp);
        try jw.objectField("currentRate");
        try jw.write(self.current_rate);
        try jw.endObject();
    }
};

/// ScaledUiAmountConfig (56 bytes) - UI amount scaling configuration.
pub const UiScaledUiAmountConfig = struct {
    authority: ?Pubkey.Base58String,
    multiplier: f64,
    new_multiplier_effective_timestamp: i64,
    new_multiplier: f64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 56) return null;
        const pubkey = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .scaled_ui_amount_config = .{
            .authority = if (pubkey) |p| p.base58String() else null,
            .multiplier = @bitCast(std.mem.readInt(u64, value[32..40], .little)),
            .new_multiplier_effective_timestamp = std.mem.readInt(i64, value[40..48], .little),
            .new_multiplier = @bitCast(std.mem.readInt(u64, value[48..56], .little)),
        } };
    }

    pub fn jsonStringify(self: UiScaledUiAmountConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("multiplier");
        try jw.write(self.multiplier);
        try jw.objectField("newMultiplierEffectiveTimestamp");
        try jw.write(self.new_multiplier_effective_timestamp);
        try jw.objectField("newMultiplier");
        try jw.write(self.new_multiplier);
        try jw.endObject();
    }
};

/// MetadataPointer (64 bytes) - Pointer to token metadata.
pub const UiMetadataPointer = struct {
    authority: ?Pubkey.Base58String,
    metadata_address: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        const metadata = readOptionalNonZeroPubkey(value[32..64]);
        return .{ .metadata_pointer = .{
            .authority = if (authority) |p| p.base58String() else null,
            .metadata_address = if (metadata) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiMetadataPointer, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("metadataAddress");
        if (self.metadata_address) |m| try jw.write(m.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// GroupPointer (64 bytes) - Pointer to token group data.
pub const UiGroupPointer = struct {
    authority: ?Pubkey.Base58String,
    group_address: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        const group = readOptionalNonZeroPubkey(value[32..64]);
        return .{ .group_pointer = .{
            .authority = if (authority) |p| p.base58String() else null,
            .group_address = if (group) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiGroupPointer, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("groupAddress");
        if (self.group_address) |g| try jw.write(g.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// GroupMemberPointer (64 bytes) - Pointer to group member data.
pub const UiGroupMemberPointer = struct {
    authority: ?Pubkey.Base58String,
    member_address: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        const member = readOptionalNonZeroPubkey(value[32..64]);
        return .{ .group_member_pointer = .{
            .authority = if (authority) |p| p.base58String() else null,
            .member_address = if (member) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiGroupMemberPointer, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("memberAddress");
        if (self.member_address) |m| try jw.write(m.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// TransferHook (64 bytes) - Transfer hook program configuration.
pub const UiTransferHook = struct {
    authority: ?Pubkey.Base58String,
    program_id: ?Pubkey.Base58String,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        const program = readOptionalNonZeroPubkey(value[32..64]);
        return .{ .transfer_hook = .{
            .authority = if (authority) |p| p.base58String() else null,
            .program_id = if (program) |p| p.base58String() else null,
        } };
    }

    pub fn jsonStringify(self: UiTransferHook, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("programId");
        if (self.program_id) |p| try jw.write(p.slice()) else try jw.write(null);
        try jw.endObject();
    }
};

/// ConfidentialTransferFeeAmount (64 bytes) - Encrypted withheld fees.
pub const UiConfidentialTransferFeeAmount = struct {
    withheld_amount: [64]u8,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 64) return null;
        return .{ .confidential_transfer_fee_amount = .{
            .withheld_amount = value[0..64].*,
        } };
    }

    pub fn jsonStringify(self: UiConfidentialTransferFeeAmount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("withheldAmount");
        try writeBase64Field(jw, 64, &self.withheld_amount);
        try jw.endObject();
    }
};

/// ConfidentialTransferMint (65 bytes) - Confidential transfer mint configuration.
pub const UiConfidentialTransferMint = struct {
    authority: ?Pubkey.Base58String,
    auto_approve_new_accounts: bool,
    auditor_elgamal_pubkey: ?[32]u8,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 65) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        const auditor = readOptionalNonZeroBytes(value[33..65]);
        return .{ .confidential_transfer_mint = .{
            .authority = if (authority) |p| p.base58String() else null,
            .auto_approve_new_accounts = value[32] != 0,
            .auditor_elgamal_pubkey = if (auditor) |bytes| bytes[0..32].* else null,
        } };
    }

    pub fn jsonStringify(self: UiConfidentialTransferMint, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("autoApproveNewAccounts");
        try jw.write(self.auto_approve_new_accounts);
        try jw.objectField("auditorElgamalPubkey");
        if (self.auditor_elgamal_pubkey) |p| try writeBase64Field(jw, 32, &p) else try jw.write(null);
        try jw.endObject();
    }
};

/// TokenGroupMember (72 bytes) - Token group membership.
pub const UiTokenGroupMember = struct {
    mint: Pubkey.Base58String,
    group: Pubkey.Base58String,
    member_number: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 72) return null;
        return .{ .token_group_member = .{
            .mint = (Pubkey{ .data = value[0..32].* }).base58String(),
            .group = (Pubkey{ .data = value[32..64].* }).base58String(),
            .member_number = std.mem.readInt(u64, value[64..72], .little),
        } };
    }

    pub fn jsonStringify(self: UiTokenGroupMember, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("mint");
        try jw.write(self.mint.slice());
        try jw.objectField("group");
        try jw.write(self.group.slice());
        try jw.objectField("memberNumber");
        try jw.write(self.member_number);
        try jw.endObject();
    }
};

/// TokenGroup (80 bytes) - Token group (collection) definition.
pub const UiTokenGroup = struct {
    update_authority: ?Pubkey.Base58String,
    mint: Pubkey.Base58String,
    size: u64,
    max_size: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 80) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .token_group = .{
            .update_authority = if (authority) |p| p.base58String() else null,
            .mint = (Pubkey{ .data = value[32..64].* }).base58String(),
            .size = std.mem.readInt(u64, value[64..72], .little),
            .max_size = std.mem.readInt(u64, value[72..80], .little),
        } };
    }

    pub fn jsonStringify(self: UiTokenGroup, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("updateAuthority");
        if (self.update_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("mint");
        try jw.write(self.mint.slice());
        try jw.objectField("size");
        try jw.write(self.size);
        try jw.objectField("maxSize");
        try jw.write(self.max_size);
        try jw.endObject();
    }
};

/// TransferFee - shared struct for older/newer fees.
pub const UiTransferFee = struct {
    epoch: u64,
    maximum_fee: u64,
    transfer_fee_basis_points: u16,

    pub fn jsonStringify(self: UiTransferFee, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("epoch");
        try jw.write(self.epoch);
        try jw.objectField("maximumFee");
        try jw.write(self.maximum_fee);
        try jw.objectField("transferFeeBasisPoints");
        try jw.write(self.transfer_fee_basis_points);
        try jw.endObject();
    }
};

/// TransferFeeConfig (108 bytes) - Transfer fee configuration.
pub const UiTransferFeeConfig = struct {
    transfer_fee_config_authority: ?Pubkey.Base58String,
    withdraw_withheld_authority: ?Pubkey.Base58String,
    withheld_amount: u64,
    older_transfer_fee: UiTransferFee,
    newer_transfer_fee: UiTransferFee,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 108) return null;
        const config_authority = readOptionalNonZeroPubkey(value[0..32]);
        const withdraw_authority = readOptionalNonZeroPubkey(value[32..64]);
        return .{ .transfer_fee_config = .{
            .transfer_fee_config_authority = if (config_authority) |p| p.base58String() else null,
            .withdraw_withheld_authority = if (withdraw_authority) |p| p.base58String() else null,
            .withheld_amount = std.mem.readInt(u64, value[64..72], .little),
            .older_transfer_fee = .{
                .epoch = std.mem.readInt(u64, value[72..80], .little),
                .maximum_fee = std.mem.readInt(u64, value[80..88], .little),
                .transfer_fee_basis_points = std.mem.readInt(u16, value[88..90], .little),
            },
            .newer_transfer_fee = .{
                .epoch = std.mem.readInt(u64, value[90..98], .little),
                .maximum_fee = std.mem.readInt(u64, value[98..106], .little),
                .transfer_fee_basis_points = std.mem.readInt(u16, value[106..108], .little),
            },
        } };
    }

    pub fn jsonStringify(self: UiTransferFeeConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("transferFeeConfigAuthority");
        if (self.transfer_fee_config_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("withdrawWithheldAuthority");
        if (self.withdraw_withheld_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("withheldAmount");
        try jw.write(self.withheld_amount);
        try jw.objectField("olderTransferFee");
        try self.older_transfer_fee.jsonStringify(jw);
        try jw.objectField("newerTransferFee");
        try self.newer_transfer_fee.jsonStringify(jw);
        try jw.endObject();
    }
};

/// ConfidentialTransferFeeConfig (129 bytes) - Confidential transfer fee configuration.
pub const UiConfidentialTransferFeeConfig = struct {
    authority: ?Pubkey.Base58String,
    withdraw_withheld_authority_elgamal_pubkey: [32]u8,
    harvest_to_mint_enabled: bool,
    withheld_amount: [64]u8,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 129) return null;
        const authority = readOptionalNonZeroPubkey(value[0..32]);
        return .{ .confidential_transfer_fee_config = .{
            .authority = if (authority) |p| p.base58String() else null,
            .withdraw_withheld_authority_elgamal_pubkey = value[32..64].*,
            .harvest_to_mint_enabled = value[64] != 0,
            .withheld_amount = value[65..129].*,
        } };
    }

    pub fn jsonStringify(self: UiConfidentialTransferFeeConfig, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        if (self.authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("withdrawWithheldAuthorityElgamalPubkey");
        try writeBase64Field(jw, 32, &self.withdraw_withheld_authority_elgamal_pubkey);
        try jw.objectField("harvestToMintEnabled");
        try jw.write(self.harvest_to_mint_enabled);
        try jw.objectField("withheldAmount");
        try writeBase64Field(jw, 64, &self.withheld_amount);
        try jw.endObject();
    }
};

/// ConfidentialMintBurn (196 bytes) - Confidential minting and burning.
pub const UiConfidentialMintBurn = struct {
    confidential_supply: [64]u8,
    decryptable_supply: [36]u8,
    supply_elgamal_pubkey: [32]u8,
    pending_burn: [64]u8,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 196) return null;
        return .{ .confidential_mint_burn = .{
            .confidential_supply = value[0..64].*,
            .decryptable_supply = value[64..100].*,
            .supply_elgamal_pubkey = value[100..132].*,
            .pending_burn = value[132..196].*,
        } };
    }

    pub fn jsonStringify(self: UiConfidentialMintBurn, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("confidentialSupply");
        try writeBase64Field(jw, 64, &self.confidential_supply);
        try jw.objectField("decryptableSupply");
        try writeBase64Field(jw, 36, &self.decryptable_supply);
        try jw.objectField("supplyElgamalPubkey");
        try writeBase64Field(jw, 32, &self.supply_elgamal_pubkey);
        try jw.objectField("pendingBurn");
        try writeBase64Field(jw, 64, &self.pending_burn);
        try jw.endObject();
    }
};

/// ConfidentialTransferAccount (295 bytes) - Confidential transfer account state.
pub const UiConfidentialTransferAccount = struct {
    approved: bool,
    elgamal_pubkey: [32]u8,
    pending_balance_lo: [64]u8,
    pending_balance_hi: [64]u8,
    available_balance: [64]u8,
    decryptable_available_balance: [36]u8,
    allow_confidential_credits: bool,
    allow_non_confidential_credits: bool,
    pending_balance_credit_counter: u64,
    maximum_pending_balance_credit_counter: u64,
    expected_pending_balance_credit_counter: u64,
    actual_pending_balance_credit_counter: u64,

    fn parse(value: []const u8) ?UiExtension {
        if (value.len != 295) return null;
        return .{ .confidential_transfer_account = .{
            .approved = value[0] != 0,
            .elgamal_pubkey = value[1..33].*,
            .pending_balance_lo = value[33..97].*,
            .pending_balance_hi = value[97..161].*,
            .available_balance = value[161..225].*,
            .decryptable_available_balance = value[225..261].*,
            .allow_confidential_credits = value[261] != 0,
            .allow_non_confidential_credits = value[262] != 0,
            .pending_balance_credit_counter = std.mem.readInt(u64, value[263..271], .little),
            .maximum_pending_balance_credit_counter = std.mem.readInt(u64, value[271..279], .little),
            .expected_pending_balance_credit_counter = std.mem.readInt(u64, value[279..287], .little),
            .actual_pending_balance_credit_counter = std.mem.readInt(u64, value[287..295], .little),
        } };
    }

    pub fn jsonStringify(self: UiConfidentialTransferAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("approved");
        try jw.write(self.approved);
        try jw.objectField("elgamalPubkey");
        try writeBase64Field(jw, 32, &self.elgamal_pubkey);
        try jw.objectField("pendingBalanceLo");
        try writeBase64Field(jw, 64, &self.pending_balance_lo);
        try jw.objectField("pendingBalanceHi");
        try writeBase64Field(jw, 64, &self.pending_balance_hi);
        try jw.objectField("availableBalance");
        try writeBase64Field(jw, 64, &self.available_balance);
        try jw.objectField("decryptableAvailableBalance");
        try writeBase64Field(jw, 36, &self.decryptable_available_balance);
        try jw.objectField("allowConfidentialCredits");
        try jw.write(self.allow_confidential_credits);
        try jw.objectField("allowNonConfidentialCredits");
        try jw.write(self.allow_non_confidential_credits);
        try jw.objectField("pendingBalanceCreditCounter");
        try jw.write(self.pending_balance_credit_counter);
        try jw.objectField("maximumPendingBalanceCreditCounter");
        try jw.write(self.maximum_pending_balance_credit_counter);
        try jw.objectField("expectedPendingBalanceCreditCounter");
        try jw.write(self.expected_pending_balance_credit_counter);
        try jw.objectField("actualPendingBalanceCreditCounter");
        try jw.write(self.actual_pending_balance_credit_counter);
        try jw.endObject();
    }
};

/// TokenMetadata (variable length, Borsh serialized).
/// NOTE: Strings are stored inline in the struct's bounded arrays.
pub const UiTokenMetadata = struct {
    update_authority: ?Pubkey.Base58String,
    mint: Pubkey.Base58String,
    name: std.BoundedArray(u8, 128),
    symbol: std.BoundedArray(u8, 32),
    uri: std.BoundedArray(u8, 256),
    // Additional metadata as key-value pairs (simplified: store as JSON string)
    additional_metadata_count: u32,

    // TODO: document the Borsh format here.
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

        // additional_metadata: Vec<(String, String)> - just read count for now
        var additional_count: u32 = 0;
        if (offset + 4 <= value.len) {
            additional_count = std.mem.readInt(u32, value[offset..][0..4], .little);
        }

        return .{ .token_metadata = .{
            .update_authority = if (authority) |p| p.base58String() else null,
            .mint = mint.base58String(),
            .name = name,
            .symbol = symbol,
            .uri = uri,
            .additional_metadata_count = additional_count,
        } };
    }

    pub fn jsonStringify(self: UiTokenMetadata, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("updateAuthority");
        if (self.update_authority) |a| try jw.write(a.slice()) else try jw.write(null);
        try jw.objectField("mint");
        try jw.write(self.mint.slice());
        try jw.objectField("name");
        try jw.write(self.name.constSlice());
        try jw.objectField("symbol");
        try jw.write(self.symbol.constSlice());
        try jw.objectField("uri");
        try jw.write(self.uri.constSlice());
        try jw.objectField("additionalMetadata");
        // For now, output empty array. Full implementation would parse Vec<(String, String)>
        try jw.beginArray();
        try jw.endArray();
        try jw.endObject();
    }
};

/// Read a Borsh-encoded string: 4-byte little-endian length + UTF-8 bytes.
fn readBorshString(
    data: []const u8,
    offset: *usize,
    comptime max_len: usize,
) ?std.BoundedArray(u8, max_len) {
    if (offset.* + 4 > data.len) return null;
    const len = std.mem.readInt(u32, data[offset.*..][0..4], .little);
    offset.* += 4;

    if (offset.* + len > data.len) return null;
    if (len > max_len) return null;

    var result: std.BoundedArray(u8, max_len) = .{};
    result.appendSliceAssumeCapacity(data[offset.*..][0..len]);
    offset.* += len;

    return result;
}

/// Write base64-encoded bytes as a JSON string value.
/// TODO: len is known at comptime. Should be able to refactor to use a slice instead?:w
fn writeBase64Field(jw: anytype, comptime len: usize, data: *const [len]u8) @TypeOf(jw.*).Error!void {
    const encoded_len = comptime std.base64.standard.Encoder.calcSize(len);
    var buf: [encoded_len]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&buf, data);
    try jw.write(&buf);
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
