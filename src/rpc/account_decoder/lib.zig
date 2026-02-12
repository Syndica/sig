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
        if (program_id.equals(&sig.runtime.ids.SPL_TOKEN_PROGRAM_ID)) return .token;
        // TODO: Token-2022 support
        // if (program_id.equals(&sig.runtime.ids.SPL_TOKEN_2022_PROGRAM_ID)) return .token;
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
    spl_token: ?*const parse_token.SplTokenAdditionalData = null,
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

            const spl_token_data = if (additional_data) |ad| ad.spl_token else null;
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
