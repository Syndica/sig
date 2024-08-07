const std = @import("std");
const sig = @import("../sig.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const Pubkey = sig.core.Pubkey;

pub const Signature = struct {
    data: [SIZE]u8 = [_]u8{0} ** SIZE,

    pub const SIZE: usize = 64;
    pub const BASE58_MAX_LENGTH: usize = 88;

    const base58 = sig.crypto.base58.Base58Sized(SIZE);
    const Self = @This();

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** SIZE };
    }

    pub fn init(bytes: [SIZE]u8) Self {
        return .{ .data = bytes };
    }

    pub fn verify(self: Self, pubkey: Pubkey, msg: []const u8) bool {
        const signature = Ed25519.Signature.fromBytes(self.data);
        signature.verify(msg, Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable) catch
            return false;
        return true;
    }

    pub fn verifier(
        self: Self,
        pubkey: Pubkey,
    ) (e.NonCanonicalError || e.EncodingError || e.IdentityElementError)!Verifier {
        const signature = Ed25519.Signature.fromBytes(self.data);
        return signature.verifier(Ed25519.PublicKey.fromBytes(pubkey.data) catch unreachable);
    }

    pub fn fromBase58String(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    pub fn toBase58String(self: Signature) std.BoundedArray(u8, BASE58_MAX_LENGTH) {
        return base58.encode(self.data);
    }

    pub fn format(
        self: Signature,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return base58.format(self.data, writer);
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
