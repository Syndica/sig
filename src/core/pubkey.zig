const std = @import("std");
const base58 = @import("base58-zig");
const bincode = @import("../bincode/bincode.zig");
const Ed25519 = std.crypto.sign.Ed25519;
const encoder = base58.Encoder.init(.{});
const decoder = base58.Decoder.init(.{});

pub const MAX_BASE58_ENCODED_LENGTH: usize = 44;

pub const Pubkey = struct {
    data: [32]u8,

    const Self = @This();

    /// ***fromString*** takea a base58 encoded string and decodes the value.
    pub fn fromString(str: []const u8) !Self {
        if (str.len > MAX_BASE58_ENCODED_LENGTH) {
            return Error.InvalidEncodedLength;
        }
        var out: [32]u8 = .{
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        };
        var written = decoder.decode(str, &out) catch return Error.InvalidEncodedValue;
        std.debug.assert(written == 32);
        return Self{ .data = out };
    }

    /// ***fromBytes*** will automatically base58 decode the value.
    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != 32) {
            return Error.InvalidBytesLength;
        }
        return Self{ .data = bytes[0..32].* };
    }

    pub fn base58_encode(bytes: []const u8) error{EncodingError}![44]u8 {
        var dest: [44]u8 = undefined;
        @memset(&dest, 0);
        var written = encoder.encode(bytes, &dest) catch return error.EncodingError;
        std.debug.assert(written <= MAX_BASE58_ENCODED_LENGTH);
        return dest;
    }

    pub fn toString(self: *const Self, alloc: std.mem.Allocator) error{EncodingError}![]u8 {
        var out = encoder.encodeAlloc(alloc, &self.data) catch return error.EncodingError;
        std.debug.assert(out.len <= MAX_BASE58_ENCODED_LENGTH);
        return out;
    }

    pub fn string(self: *const Self) [44]u8 {
        return base58_encode(&self.data) catch @panic("could not encode pubkey");
    }

    /// ***random*** generates a random pubkey.
    pub fn random(rng: std.rand.Random) Self {
        var bytes: [32]u8 = undefined;
        rng.bytes(&bytes);
        return Self{ .data = bytes[0..32].* };
    }

    pub fn default() Self {
        return Self{ .data = [_]u8{0} ** 32 };
    }

    pub fn equals(self: *const Self, other: *const Pubkey) bool {
        return std.mem.eql(u8, &self.data, &other.data);
    }

    pub fn fromPublicKey(public_key: *const Ed25519.PublicKey) Self {
        return Self.fromBytes(public_key.bytes[0..]) catch unreachable;
    }

    pub fn jsonStringify(
        self: *const Self,
        jw: anytype,
    ) !void {
        var out = base58_encode(&self.data) catch @panic("should not panic");
        try jw.write(out);
    }
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
