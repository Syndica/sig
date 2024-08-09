const std = @import("std");
const base58 = @import("base58-zig");
const Ed25519 = std.crypto.sign.Ed25519;
const encoder = base58.Encoder.init(.{});
const decoder = base58.Decoder.init(.{});

pub const Pubkey = extern struct {
    data: [32]u8,

    const Self = @This();

    /// ***fromString*** takea a base58 encoded string and decodes the value. It also caches
    /// the `str` for future calls to string() method.
    /// If `bytes`, it wil automatically encode so that it's able to call string() method.
    ///
    pub fn fromString(str: []const u8) !Self {
        var out: [32]u8 = undefined;
        const written = decoder.decode(str, &out) catch return Error.InvalidEncodedValue;
        if (written != 32) return Error.InvalidBytesLength;

        return Self{ .data = out };
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
        if (bytes.len != 32) {
            return Error.InvalidBytesLength;
        }
        return Self{ .data = bytes[0..32].* };
    }

    pub fn base58_encode(bytes: []const u8) error{EncodingError}![44]u8 {
        var dest: [44]u8 = undefined;
        @memset(&dest, 0);
        const written = encoder.encode(bytes, &dest) catch return error.EncodingError;
        if (written > 44) {
            std.debug.panic("written is > 44, written: {}, dest: {any}, bytes: {any}", .{ written, dest, bytes });
        }
        return dest;
    }

    pub fn string(self: *const Self) [44]u8 {
        return Self.base58_encode(&self.data) catch @panic("could not encode pubkey");
    }

    pub fn stringWithBuf(self: *const Self, dest: []u8) []u8 {
        const written = encoder.encode(&self.data, dest) catch @panic("could not encode pubkey");
        if (written > 44) {
            std.debug.panic("written > 44\n", .{});
        }
        return dest[0..written];
    }

    /// ***random*** generates a random pubkey. Optionally set `skip_encoding` to skip expensive base58 encoding.
    pub fn random(rng: std.Random) Self {
        var bytes: [32]u8 = undefined;
        rng.bytes(&bytes);
        return Self{ .data = bytes };
    }

    pub fn default() Self {
        return Self{ .data = [_]u8{0} ** 32 };
    }

    pub fn equals(self: *const Self, other: *const Pubkey) bool {
        const xx: @Vector(32, u8) = self.data;
        const yy: @Vector(32, u8) = other.data;
        const r = @reduce(.And, xx == yy);
        return r;
    }

    pub fn fromPublicKey(public_key: *const Ed25519.PublicKey) Self {
        return Self.fromBytes(&public_key.bytes) catch unreachable;
    }

    pub fn format(self: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) error{OutOfMemory}!void {
        var dest: [44]u8 = undefined;
        @memset(&dest, 0);
        const written = encoder.encode(&self.data, &dest) catch unreachable;
        return writer.print("{s}", .{dest[0..written]}) catch unreachable;
    }

    pub fn isDefault(self: *const Self) bool {
        return std.mem.eql(u8, &self.data, &[_]u8{0} ** 32);
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
