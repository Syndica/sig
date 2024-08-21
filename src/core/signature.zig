const std = @import("std");
const sig = @import("../lib.zig");
const core = @import("lib.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Verifier = std.crypto.sign.Ed25519.Verifier;
const e = std.crypto.errors;

const Pubkey = core.Pubkey;

pub const SIGNATURE_LENGTH: usize = Signature.size;

pub const Signature = struct {
    data: [size]u8 = [_]u8{0} ** size,

    pub const size = 64;

    const base58 = sig.crypto.base58.Base58Sized(size);
    const Self = @This();

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** size };
    }

    pub fn init(bytes: [size]u8) Self {
        return .{ .data = bytes };
    }

    pub fn fromString(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
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

    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.data[0..], other.data[0..]);
    }

    pub fn base58String(self: Signature) std.BoundedArray(u8, 88) {
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
};
