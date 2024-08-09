const std = @import("std");
const Pubkey = @import("pubkey.zig").Pubkey;
const base58 = @import("base58-zig");
const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const BASE58_ENCODER = base58.Encoder.init(.{});
const BASE58_DECODER = base58.Decoder.init(.{});

pub const Signature = struct {
    data: [BYTES_LENGTH]u8,

    pub const BYTES_LENGTH: usize = 64;
    pub const BASE58_MAX_LENGTH: usize = 88;

    const Self = @This();

    pub fn init(bytes: [BYTES_LENGTH]u8) Self {
        return Self{ .data = bytes };
    }

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** BYTES_LENGTH };
    }

    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != BYTES_LENGTH) {
            return Error.InvalidBytesLength;
        }
        return Self{ .data = bytes[0..BYTES_LENGTH].* };
    }

    pub fn fromString(encoded: []const u8) error{DecodingError}!Self {
        var dest: [BYTES_LENGTH]u8 = undefined;
        const written = BASE58_DECODER.decode(encoded, &dest) catch return error.DecodingError;
        if (written != BYTES_LENGTH) {
            return error.DecodingError;
        }
        return Self.init(dest);
    }

    pub fn toString(self: *const Self) error{EncodingError}![BASE58_MAX_LENGTH]u8 {
        var dest: [BASE58_MAX_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > BASE58_MAX_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ BASE58_MAX_LENGTH, written, dest, self.data });
        }
        return dest;
    }

    pub fn toStringAlloc(self: *const Self, allocator: std.mem.Allocator) ![]u8 {
        var dest: [BASE58_MAX_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > BASE58_MAX_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ BASE58_MAX_LENGTH, written, dest, self.data });
        }
        return try allocator.dupe(u8, dest[0..written]);
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []const u8) bool {
        const signature = Ed25519.Signature.fromBytes(self.data);
        signature.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch return false;
        return true;
    }

    pub fn verifier(
        self: Self,
        pubkey: Pubkey,
    ) (e.NonCanonicalError || e.EncodingError || e.IdentityElementError)!Verifier {
        const signature = Ed25519.Signature.fromBytes(self.data);
        return signature.verifier(Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable);
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
