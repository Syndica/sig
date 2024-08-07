const std = @import("std");
const sig = @import("../sig.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const U8ArrayConfig = sig.bincode.int.U8ArrayConfig;

pub const Pubkey = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;
    pub const @"!bincode-config:data" = U8ArrayConfig(SIZE);

    const Self = @This();
    const base58 = sig.crypto.base58.Base58Sized(SIZE);

    pub fn fromString(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    /// ***fromBytes*** will automatically base58 decode the value. It will also cache the decoded string
    /// for future calls to string() method.
    ///
    /// Options:
    /// - `skip_encoding`: If (in the unlikely scenario) you will never call the string() method, you can
    /// set this option to true and it will not decode & cache the encoded value. This can be helpful in
    /// scenarios where you plan to only use the bytes and want to save on expensive base58 encoding.
    ///
    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != SIZE) {
            return Error.InvalidBytesLength;
        }
        return .{ .data = bytes[0..SIZE].* };
    }

    pub fn string(self: Self) base58.String {
        return base58.encode(self.data);
    }

    /// ***random*** generates a random pubkey. Optionally set `skip_encoding` to skip expensive base58 encoding.
    pub fn random(rng: std.Random) Self {
        var bytes: [SIZE]u8 = undefined;
        rng.bytes(&bytes);
        return .{ .data = bytes };
    }

    pub fn default() Self {
        return .{ .data = [_]u8{0} ** SIZE };
    }

    pub fn equals(self: *const Self, other: *const Pubkey) bool {
        const xx: @Vector(SIZE, u8) = self.data;
        const yy: @Vector(SIZE, u8) = other.data;
        const r = @reduce(.And, xx == yy);
        return r;
    }

    pub fn fromKeyPair(keypair: *const Ed25519.KeyPair) Self {
        return Self.fromBytes(&keypair.public_key.bytes) catch unreachable;
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
