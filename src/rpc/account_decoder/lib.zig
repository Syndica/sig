/// This module provides support for `jsonParsed` decoding of Solana accounts.
const std = @import("std");
const sig = @import("../../sig.zig");
const Pubkey = sig.core.Pubkey;

const parse_vote = @import("parse_vote.zig");

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
    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
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
    // TODO: add more parsers
    // stake: parse_stake.StakeAccountType,
    // nonce: parse_nonce.NonceAccountType,
    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        switch (self) {
            inline else => |content| try content.jsonStringify(jw),
        }
    }
};

/// Enum of programs that support jsonParsed.
const ParsableProgram = enum {
    vote,
    // TODO: stake
    // TODO: nonce
    // TODO: address lookup table
    // TODO: bpf upgradeable loader

    pub fn fromProgramId(program_id: Pubkey) ?ParsableProgram {
        if (program_id.equals(&sig.runtime.program.vote.ID)) return .vote;
        // TODO: stake
        // TODO: nonce
        return null;
    }

    pub fn programName(self: @This()) []const u8 {
        return switch (self) {
            .vote => "vote",
            // TODO: stake
            // TODO: nonce
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
        // TODO: stake
        // TODO: nonce
    };
    return ParsedAccount{
        .program = program.programName(),
        .parsed = parsed,
        .space = data_len,
    };
}
