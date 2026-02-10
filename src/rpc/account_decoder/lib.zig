/// This module provides support for `jsonParsed` decoding of Solana accounts.
const std = @import("std");
const sig = @import("../../sig.zig");
const Pubkey = sig.core.Pubkey;

const parse_vote = @import("parse_vote.zig");
const parse_stake = @import("parse_stake.zig");
const parse_nonce = @import("parse_nonce.zig");
const parse_address_lookup_table = @import("parse_account_lookup_table.zig");

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
    // TODO: add more parsers
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
    // TODO: bpf upgradeable loader

    pub fn fromProgramId(program_id: Pubkey) ?ParsableProgram {
        if (program_id.equals(&sig.runtime.program.vote.ID)) return .vote;
        if (program_id.equals(&sig.runtime.program.stake.ID)) return .stake;
        // Nonce accounts are owned by the system program, so we check the program ID against the system program ID.
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_account_data.rs#L36
        if (program_id.equals(&sig.runtime.program.system.ID)) return .nonce;
        if (program_id.equals(&sig.runtime.program.address_lookup_table.ID)) return .address_lookup_table;
        return null;
    }

    pub fn programName(self: ParsableProgram) []const u8 {
        return switch (self) {
            .vote => "vote",
            .stake => "stake",
            .nonce => "nonce",
            .address_lookup_table => "address_lookup_table",
        };
    }
};

pub fn parse_account(
    allocator: std.mem.Allocator,
    program_id: Pubkey,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
) ParseError!?ParsedAccount {
    const program = ParsableProgram.fromProgramId(program_id) orelse return null;
    const parsed: ParsedContent = switch (program) {
        .vote => .{ .vote = try parse_vote.parse_vote(allocator, reader) },
        .stake => .{ .stake = try parse_stake.parse_stake(allocator, reader) },
        .nonce => .{ .nonce = try parse_nonce.parse_nonce(allocator, reader) },
        .address_lookup_table => .{
            .address_lookup_table = try parse_address_lookup_table.parse_address_lookup_table(
                allocator,
                reader,
                data_len,
            ),
        },
    };
    return ParsedAccount{
        .program = program.programName(),
        .parsed = parsed,
        .space = data_len,
    };
}
