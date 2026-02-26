/// Types for parsing a nonce account for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs
const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const nonce = sig.runtime.nonce;

const Allocator = std.mem.Allocator;
const Hash = sig.core.hash.Hash;
const ParseError = account_codec.ParseError;
const Pubkey = sig.core.Pubkey;
const Stringified = account_codec.Stringified;

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
                .authority = data.authority,
                .blockhash = data.durable_nonce,
                .feeCalculator = UiFeeCalculator{
                    .lamportsPerSignature = Stringified(u64).init(data.lamports_per_signature),
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

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L34-L40
pub const UiNonceData = struct {
    authority: Pubkey,
    blockhash: Hash,
    feeCalculator: UiFeeCalculator,
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/lib.rs#L104-L108
pub const UiFeeCalculator = struct {
    lamportsPerSignature: Stringified(u64),
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L57-L96
test "rpc.account_codec.parse_nonce: parse nonce accounts" {
    const allocator = std.testing.allocator;

    // Parse initialized nonce state (current version)
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L57-L82
    {
        const authority = Pubkey{ .data = [_]u8{1} ** 32 };
        const blockhash = Hash{ .data = [_]u8{2} ** 32 };
        const lamports_per_signature: u64 = 5000;

        const nonce_data = nonce.Data{
            .authority = authority,
            .durable_nonce = blockhash,
            .lamports_per_signature = lamports_per_signature,
        };

        const versions = nonce.Versions{ .current = .{ .initialized = nonce_data } };

        const data = try sig.bincode.writeAlloc(allocator, versions, .{});
        defer allocator.free(data);

        var stream = std.io.fixedBufferStream(data);
        const result = try parseNonce(allocator, stream.reader());

        try std.testing.expectEqual(authority, result.initialized.authority);
        try std.testing.expectEqual(blockhash, result.initialized.blockhash);
        const lps = result.initialized.feeCalculator.lamportsPerSignature.value;
        try std.testing.expectEqual(lamports_per_signature, lps);
    }

    // Parse legacy initialized nonce state
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L57-L82
    {
        const authority = Pubkey{ .data = [_]u8{5} ** 32 };
        const blockhash = Hash{ .data = [_]u8{9} ** 32 };
        const lamports_per_signature: u64 = 10000;

        const nonce_data = nonce.Data{
            .authority = authority,
            .durable_nonce = blockhash,
            .lamports_per_signature = lamports_per_signature,
        };

        const versions = nonce.Versions{ .legacy = .{ .initialized = nonce_data } };

        const data = try sig.bincode.writeAlloc(allocator, versions, .{});
        defer allocator.free(data);

        var stream = std.io.fixedBufferStream(data);
        const result = try parseNonce(allocator, stream.reader());

        try std.testing.expectEqual(authority, result.initialized.authority);
        try std.testing.expectEqual(blockhash, result.initialized.blockhash);
        const lps = result.initialized.feeCalculator.lamportsPerSignature.value;
        try std.testing.expectEqual(lamports_per_signature, lps);
    }

    // Uninitialized nonce returns error
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L84-L89
    {
        const versions = nonce.Versions{ .current = .uninitialized };

        const data = try sig.bincode.writeAlloc(allocator, versions, .{});
        defer allocator.free(data);

        var stream = std.io.fixedBufferStream(data);
        const result = parseNonce(allocator, stream.reader());
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // Bad data returns error
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_nonce.rs#L91-L96
    {
        const bad_data = [_]u8{ 0, 1, 2, 3 };

        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseNonce(allocator, stream.reader());
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }
}
