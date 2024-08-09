const std = @import("std");
const base58 = @import("base58-zig");
const Ed25519 = std.crypto.sign.Ed25519;

const BASE58_ENCODER = base58.Encoder.init(.{});
const BASE58_DECODER = base58.Decoder.init(.{});

pub const Pubkey = extern struct {
    data: [BYTES_LENGTH]u8,

    pub const BYTES_LENGTH: usize = 32;
    pub const BASE58_LENGTH: usize = 44;

    const Self = @This();

    pub fn init(bytes: [BYTES_LENGTH]u8) Self {
        return Self{ .data = bytes };
    }

    pub fn default() Self {
        return Self{ .data = [_]u8{0} ** BYTES_LENGTH };
    }

    pub fn random(rng: std.rand.Random) Self {
        var bytes: [BYTES_LENGTH]u8 = undefined;
        rng.bytes(&bytes);
        return Self{ .data = bytes };
    }

    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != BYTES_LENGTH) {
            return Error.InvalidBytesLength;
        }
        return Self{ .data = bytes[0..BYTES_LENGTH].* };
    }

    pub fn fromKeyPair(keypair: *const Ed25519.KeyPair) Self {
        return Self.fromBytes(&keypair.public_key.bytes) catch unreachable;
    }

    pub fn fromString(encoded: []const u8) !Self {
        var dest: [BYTES_LENGTH]u8 = undefined;
        const written = BASE58_DECODER.decode(encoded, &dest) catch return error.DecodingError;
        if (written != BYTES_LENGTH) {
            return error.DecodingError;
        }
        return Self.fromBytes(&dest);
    }

    pub fn toString(self: *const Self) error{EncodingError}![BASE58_LENGTH]u8 {
        var dest: [BASE58_LENGTH]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > BASE58_LENGTH) {
            std.debug.panic("written is > {}, written: {}, dest: {any}, bytes: {any}", .{ BASE58_LENGTH, written, dest, self.data });
        }
        return dest;
    }

    pub fn format(self: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) error{OutOfMemory}!void {
        var dest: [44]u8 = undefined;
        @memset(&dest, 0);
        const written = BASE58_ENCODER.encode(&self.data, &dest) catch unreachable;
        return writer.print("{s}", .{dest[0..written]}) catch unreachable;
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        const xx: @Vector(BYTES_LENGTH, u8) = self.data;
        const yy: @Vector(BYTES_LENGTH, u8) = other.data;
        const r = @reduce(.And, xx == yy);
        return r;
    }

    pub fn isDefault(self: *const Self) bool {
        return std.mem.eql(u8, &self.data, &[_]u8{0} ** BYTES_LENGTH);
    }
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
