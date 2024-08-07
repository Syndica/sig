const std = @import("std");
const sig = @import("../sig.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const U8ArrayConfig = sig.bincode.int.U8ArrayConfig;

pub const Pubkey = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;
    pub const BASE58_MAX_LENGTH = 44;
    pub const @"!bincode-config:data" = U8ArrayConfig(SIZE);

    const base58 = sig.crypto.base58.Base58Sized(SIZE);
    const Self = @This();

    pub fn init(bytes: [SIZE]u8) Self {
        return .{ .data = bytes };
    }

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** SIZE };
    }

    pub fn random(rng: std.Random) Self {
        var bytes: [SIZE]u8 = undefined;
        rng.bytes(&bytes);
        return .{ .data = bytes };
    }

    pub fn fromKeyPair(keypair: *const Ed25519.KeyPair) Self {
        return Self.init(keypair.public_key.bytes);
    }

    pub fn fromBase58String(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    pub fn toBase58String(self: Self) std.BoundedArray(u8, BASE58_MAX_LENGTH) {
        return base58.encode(self.data);
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return base58.format(self.data, writer);
    }

    pub fn eql(self: *const Self, other: *const Pubkey) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        const r = @reduce(.And, xx == yy);
        return r;
    }

    pub fn isDefault(self: *const Self) bool {
        return std.mem.eql(u8, &self.data, &[_]u8{0} ** SIZE);
    }
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
