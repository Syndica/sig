const std = @import("std");
const core = @import("lib.zig");
const base58 = @import("base58");
const BASE58_ENDEC = base58.Table.BITCOIN;

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

    pub fn parseBase58String(str: []const u8) error{InvalidSignature}!Signature {
        if (str.len > BASE58_MAX_SIZE) return error.InvalidSignature;
        var encoded: std.BoundedArray(u8, BASE58_MAX_SIZE) = .{};
        encoded.appendSliceAssumeCapacity(str);

        if (@inComptime()) @setEvalBranchQuota(str.len * str.len * str.len);
        const decoded = BASE58_ENDEC.decodeBounded(BASE58_MAX_SIZE, encoded) catch {
            return error.InvalidSignature;
        };

        if (decoded.len != SIZE) return error.InvalidSignature;
        return .{ .data = decoded.constSlice()[0..SIZE].* };
    }

    pub const BASE58_MAX_SIZE = base58.encodedMaxSize(SIZE);
    pub const Base58String = std.BoundedArray(u8, BASE58_MAX_SIZE);

    pub fn base58String(self: Signature) Base58String {
        return BASE58_ENDEC.encodeArray(SIZE, self.data);
    }

    pub fn format(
        self: Signature,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const str = self.base58String();
        return writer.writeAll(str.constSlice());
    }

    pub fn jsonStringify(self: Signature, writer: anytype) @TypeOf(writer.*).Error!void {
        try writer.print("\"{s}\"", .{self.base58String().slice()});
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !Signature {
        const value = try std.json.Value.jsonParse(allocator, source, options);
        return if (value == .string)
            parseBase58String(value.string) catch return error.InvalidNumber
        else
            error.UnexpectedToken;
    }
};
