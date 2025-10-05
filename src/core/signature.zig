const std = @import("std");
const sig = @import("../sig.zig");
const core = @import("lib.zig");
const base58 = @import("base58");
const BASE58_TABLE = base58.Table.BITCOIN;

const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const Pubkey = core.Pubkey;

pub const Signature = struct {
    data: [SIZE]u8,

    pub const SIZE: usize = 64;

    pub const ZEROES: Signature = .{ .data = .{0} ** SIZE };

    pub const VerifyError = e.NonCanonicalError;
    pub fn verify(
        self: Signature,
        pubkey: Pubkey,
        msg: []const u8,
    ) VerifyError!bool {
        const signature = Ed25519.Signature.fromBytes(self.data);
        const byte_pubkey = try Ed25519.PublicKey.fromBytes(pubkey.data);
        signature.verify(msg, byte_pubkey) catch return false;
        return true;
    }

    pub const VerifierError =
        e.NonCanonicalError ||
        e.EncodingError ||
        e.IdentityElementError;
    pub fn verifier(
        self: Signature,
        pubkey: Pubkey,
    ) VerifierError!Verifier {
        const signature = Ed25519.Signature.fromBytes(self.data);
        return signature.verifier(try Ed25519.PublicKey.fromBytes(pubkey.data));
    }

    pub fn eql(self: *const Signature, other: *const Signature) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }

    pub inline fn parse(comptime str: []const u8) Signature {
        comptime {
            return parseRuntime(str) catch @compileError("failed to parse signature");
        }
    }

    const MAX_ENCODED_SIZE = base58.encodedMaxSize(SIZE);

    pub fn parseRuntime(str: []const u8) error{InvalidSignature}!Signature {
        if (str.len > MAX_ENCODED_SIZE) return error.InvalidSignature;
        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);

        var decoded: [MAX_ENCODED_SIZE]u8 = undefined;
        const len = BASE58_TABLE.decode(&decoded, str) catch return error.InvalidSignature;
        if (len != SIZE) return error.InvalidSignature;
        return .{ .data = decoded[0..SIZE].* };
    }

    pub fn format(self: Signature, writer: *std.Io.Writer) !void {
        var encoded: [MAX_ENCODED_SIZE]u8 = undefined;
        const len = BASE58_TABLE.encode(&encoded, &self.data);
        return try writer.writeAll(encoded[0..len]);
    }

    pub fn jsonStringify(self: Signature, writer: *std.io.Writer) !void {
        try writer.print("\"{f}\"", .{self});
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Signature {
        const value = try std.json.Value.jsonParse(allocator, source, options);
        return if (value == .string)
            parseRuntime(value.string) catch return error.InvalidNumber
        else
            error.UnexpectedToken;
    }
};
