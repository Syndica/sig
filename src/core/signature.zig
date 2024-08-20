const std = @import("std");
const base58 = @import("base58-zig");
const Pubkey = @import("pubkey.zig").Pubkey;
const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

pub const SIGNATURE_LENGTH: usize = 64;

pub const Signature = struct {
    data: [SIGNATURE_LENGTH]u8 = [_]u8{0} ** SIGNATURE_LENGTH,

    const Self = @This();

    pub fn default() Self {
        return Self{
            .data = [_]u8{0} ** SIGNATURE_LENGTH,
        };
    }

    pub fn init(bytes: [SIGNATURE_LENGTH]u8) Self {
        return Self{
            .data = bytes,
        };
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []const u8) bool {
        const sig = Ed25519.Signature.fromBytes(self.data);
        sig.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch return false;
        return true;
    }

    pub fn verifier(
        self: Self,
        pubkey: Pubkey,
    ) (e.NonCanonicalError || e.EncodingError || e.IdentityElementError)!Verifier {
        const sig = Ed25519.Signature.fromBytes(self.data);
        return sig.verifier(Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable);
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }

    pub fn base58String(self: Signature) std.BoundedArray(u8, 88) {
        var result: std.BoundedArray(u8, 88) = .{};
        const b58_encoder = comptime base58.Encoder.init(.{});
        const encoded_len = b58_encoder.encode(&self.data, &result.buffer) catch unreachable; // this is unreachable because '44' is exactly the maximum encoded length for a 32 byte string.
        result.len = @intCast(encoded_len);
        return result;
    }
};
