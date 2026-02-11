/// Types for parsing a nonce account for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.hash.Hash;
const nonce = sig.runtime.nonce;
const ParseError = account_decoder.ParseError;

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_nonce.rs#L8
pub fn parseNonce(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
) ParseError!NonceAccountType {
    const versions = sig.bincode.read(
        allocator,
        nonce.Versions,
        reader,
        .{},
    ) catch return ParseError.InvalidAccountData;
    const state = versions.getState();
    return switch (state) {
        .initialized => |data| NonceAccountType{
            .initialized = UiNonceData{
                .authority = data.authority.base58String(),
                .blockhash = data.durable_nonce.base58String(),
                .fee_calculator = UiFeeCalculator{
                    .lamports_per_signature = data.lamports_per_signature,
                },
            },
        },
        // Uninitialized nonces return error per Agave:
        // "This prevents parsing an allocated System-owned account with empty data..."
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L11-L17
        .uninitialized => return ParseError.InvalidAccountData,
    };
}

pub const NonceAccountType = union(enum) {
    initialized: UiNonceData,

    pub fn jsonStringify(self: NonceAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        switch (self) {
            .initialized => |data| {
                try jw.objectField("type");
                try jw.write("initialized");
                try jw.objectField("info");
                try data.jsonStringify(jw);
            },
        }
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L34-L40
pub const UiNonceData = struct {
    authority: Pubkey.Base58String,
    blockhash: Hash.Base58String,
    fee_calculator: UiFeeCalculator,
    pub fn jsonStringify(self: UiNonceData, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authority");
        try jw.write(self.authority.slice());
        try jw.objectField("blockhash");
        try jw.write(self.blockhash.slice());
        try jw.objectField("feeCalculator");
        try self.fee_calculator.jsonStringify(jw);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L104-L108
pub const UiFeeCalculator = struct {
    lamports_per_signature: u64,
    pub fn jsonStringify(self: UiFeeCalculator, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("lamportsPerSignature");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.lamports_per_signature});
        try jw.endObject();
    }
};
