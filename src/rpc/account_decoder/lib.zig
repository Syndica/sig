/// This module provides support for `jsonParsed` decoding of Solana accounts.
const std = @import("std");
const sig = @import("../../sig.zig");
const Pubkey = sig.core.Pubkey;

const parse_vote = @import("parse_vote.zig");
const parse_stake = @import("parse_stake.zig");
const parse_nonce = @import("parse_nonce.zig");
const parse_address_lookup_table = @import("parse_account_lookup_table.zig");
const parse_bpf_upgradeable_loader = @import("parse_bpf_upgradeable_loader.zig");
const parse_sysvar = @import("parse_sysvar.zig");
const parse_config = @import("parse_config.zig");
const parse_token = @import("parse_token.zig");
const parse_token_extension = @import("parse_token_extension.zig");

pub const ParseError = error{
    InvalidAccountData,
    OutOfMemory,
};

/// The result of parsing account data for jsonParsed encoding.
/// [agave] https://github.com/anza-xyz/agave/blob/master/account-decoder-client-types/src/lib.rs#L101-L104
pub const ParsedAccount = struct {
    program: []const u8,
    parsed: ParsedContent,
    space: u64,

    pub fn jsonStringify(self: ParsedAccount, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("program");
        try jw.write(self.program);
        try jw.objectField("parsed");
        try self.parsed.jsonStringify(jw);
        try jw.objectField("space");
        try jw.write(self.space);
        try jw.endObject();
    }
};
/// Tagged union of all parsable account types.
pub const ParsedContent = union(enum) {
    vote: parse_vote.VoteAccountType,
    stake: parse_stake.StakeAccountType,
    nonce: parse_nonce.NonceAccountType,
    address_lookup_table: parse_address_lookup_table.LookupTableAccountType,
    bpf_upgradeable_loader: parse_bpf_upgradeable_loader.BpfUpgradeableLoaderAccountType,
    sysvar: parse_sysvar.SysvarAccountType,
    config: parse_config.ConfigAccountType,
    token: parse_token.TokenAccountType,

    pub fn jsonStringify(self: ParsedContent, jw: anytype) @TypeOf(jw.*).Error!void {
        switch (self) {
            inline else => |content| try content.jsonStringify(jw),
        }
    }
};

/// Enum of programs that support jsonParsed.
const ParsableProgram = enum {
    vote,
    stake,
    nonce,
    address_lookup_table,
    bpf_upgradeable_loader,
    sysvar,
    config,
    token,

    pub fn fromProgramId(program_id: Pubkey) ?ParsableProgram {
        if (program_id.equals(&sig.runtime.program.vote.ID)) return .vote;
        if (program_id.equals(&sig.runtime.program.stake.ID)) return .stake;
        // Nonce accounts are owned by the system program, so we check the program ID against the system program ID.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L36
        if (program_id.equals(&sig.runtime.program.system.ID)) return .nonce;
        if (program_id.equals(&sig.runtime.program.address_lookup_table.ID)) return .address_lookup_table;
        if (program_id.equals(&sig.runtime.program.bpf_loader.v3.ID)) return .bpf_upgradeable_loader;
        // Sysvar accounts are owned by the sysvar program.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L48
        if (program_id.equals(&sig.runtime.sysvar.OWNER_ID)) return .sysvar;
        if (program_id.equals(&sig.runtime.program.config.ID)) return .config;
        if (program_id.equals(&sig.runtime.ids.SPL_TOKEN_PROGRAM_ID) or
            program_id.equals(&sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID)) return .token;
        return null;
    }

    pub fn programName(self: ParsableProgram) []const u8 {
        // NOTE: use camelCase names to match Agave
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L67
        return switch (self) {
            .vote => "vote",
            .stake => "stake",
            .nonce => "nonce",
            // TODO: confirm correct case.
            .address_lookup_table => "addressLookupTable",
            .bpf_upgradeable_loader => "bpfUpgradeableLoader",
            .sysvar => "sysvar",
            .config => "config",
            .token => "spl-token",
        };
    }
};

// TODO: document Agave code.
pub const AdditionalAccountData = struct {
    spl_token: ?parse_token.SplTokenAdditionalData = null,
};

/// SPL Token Account state enum.
pub const AccountState = enum(u8) {
    uninitialized = 0,
    initialized = 1,
    frozen = 2,
};

pub fn parse_account(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    program_id: Pubkey,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
    additional_data: ?AdditionalAccountData,
) ParseError!?ParsedAccount {
    const program = ParsableProgram.fromProgramId(program_id) orelse return null;
    const parsed: ParsedContent = switch (program) {
        .vote => .{ .vote = try parse_vote.parseVote(allocator, reader) },
        .stake => .{ .stake = try parse_stake.parseStake(allocator, reader) },
        .nonce => .{ .nonce = try parse_nonce.parseNonce(allocator, reader) },
        .address_lookup_table => .{
            .address_lookup_table = try parse_address_lookup_table.parseAddressLookupTable(
                allocator,
                reader,
                data_len,
            ),
        },
        .bpf_upgradeable_loader => .{
            .bpf_upgradeable_loader = try parse_bpf_upgradeable_loader.parseBpfUpgradeableLoader(
                allocator,
                reader,
                data_len,
            ),
        },
        .sysvar => {
            // Sysvar parsing dispatches by the account's pubkey, not its owner.
            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_sysvar.rs#L24
            const sysvar_parsed = try parse_sysvar.parseSysvar(
                allocator,
                pubkey,
                reader,
            );
            if (sysvar_parsed) |s| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .sysvar = s },
                    .space = data_len,
                };
            }
            // Unknown sysvar pubkey - return null to fall back to base64 encoding
            return null;
        },
        .config => {
            const config_parsed = try parse_config.parseConfig(
                allocator,
                pubkey,
                reader,
                data_len,
            );
            if (config_parsed) |c| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .config = c },
                    .space = data_len,
                };
            }
            // Unknown config account - return null to fall back to base64 encoding
            return null;
        },
        .token => {
            // Token parsing requires the full data slice.
            const data = try allocator.alloc(u8, data_len);
            defer allocator.free(data);
            const bytes_read = reader.readAll(data) catch return ParseError.InvalidAccountData;
            if (bytes_read != data_len) return ParseError.InvalidAccountData;

            const spl_token_data: ?*const parse_token.SplTokenAdditionalData =
                if (additional_data) |ad| if (ad.spl_token) |*d| d else null else null;
            const token_parsed = try parse_token.parseToken(
                data,
                spl_token_data,
            );
            if (token_parsed) |t| {
                return ParsedAccount{
                    .program = program.programName(),
                    .parsed = .{ .token = t },
                    .space = data_len,
                };
            }
            // Unknown token account - return null to fall back to base64 encoding
            return null;
        },
    };

    return ParsedAccount{
        .program = program.programName(),
        .parsed = parsed,
        .space = data_len,
    };
}

/// Build SplTokenAdditionalData by fetching mint account and Clock syvar.
/// Returns empty additional data if not a token account or fetch fails
pub fn buildTokenAdditionalData(
    allocator: std.mem.Allocator,
    account: sig.core.Account,
    slot_reader: sig.accounts_db.SlotAccountReader,
) AdditionalAccountData {
    // Check if this is a token account
    const is_token_program = account.owner.equals(&sig.runtime.ids.SPL_TOKEN_PROGRAM_ID) or
        account.owner.equals(&sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID);
    if (!is_token_program) return .{};

    // Read account data to extract mint pubkey
    var data_iter = account.data.iterator();
    var data_buf: [parse_token.TokenAccount.LEN]u8 = undefined;
    const bytes_read = data_iter.readBytes(&data_buf) catch return .{};
    if (bytes_read < 32) return .{};

    // Extract mint pubkey from token account (first 32 bytes)
    const mint_pubkey = parse_token.getTokenAccountMint(data_buf[0..bytes_read]) orelse return .{};

    // Fetch the mint account
    const maybe_mint_account = slot_reader.get(allocator, mint_pubkey) catch return .{};
    const mint_account = maybe_mint_account orelse return .{};
    defer mint_account.deinit(allocator);

    // Read mint data
    var mint_iter = mint_account.data.iterator();
    const mint_data = allocator.alloc(u8, mint_account.data.len()) catch return .{};
    defer allocator.free(mint_data);
    _ = mint_iter.readBytes(mint_data) catch return .{};

    // Parse mint to get decimals
    const mint = parse_token.Mint.unpack(mint_data) catch return .{};

    // Fetch Clock sysvar for timestamp
    const maybe_clock_account = slot_reader.get(allocator, sig.runtime.sysvar.Clock.ID) catch return .{};
    const clock_account = maybe_clock_account orelse return .{};
    defer clock_account.deinit(allocator);

    var clock_iter = clock_account.data.iterator();
    const clock = sig.bincode.read(
        allocator,
        sig.runtime.sysvar.Clock,
        clock_iter.reader(),
        .{},
    ) catch return .{};

    // Extract extension configs from mint data
    const interest_config = parse_token_extension.InterestBearingConfigData.extractFromMint(mint_data);
    const scaled_config = parse_token_extension.ScaledUiAmountConfigData.extractFromMint(mint_data);

    return .{
        .spl_token = .{
            .decimals = mint.decimals,
            .unix_timestamp = clock.unix_timestamp,
            .interest_bearing_config = interest_config,
            .scaled_ui_amount_config = scaled_config,
        },
    };
}
