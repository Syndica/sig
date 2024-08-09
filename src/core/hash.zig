const std = @import("std");
const base58 = @import("base58-zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

const BASE58_ENCODER = base58.Encoder.init(.{});
const BASE58_DECODER = base58.Decoder.init(.{});

pub const Hash = extern struct {
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

    pub fn parseBase58String(str: []const u8) error{InvalidHash}!Hash {
        var result_data: [BYTES_LENGTH]u8 = undefined;
        const b58_decoder = comptime base58.Decoder.init(.{});
        const encoded_len = b58_decoder.decode(str, &result_data) catch return error.InvalidHash;
        if (encoded_len != BYTES_LENGTH) return error.InvalidHash;
        return .{ .data = result_data };
    }

    pub fn base58String(self: Hash) std.BoundedArray(u8, 44) {
        var result: std.BoundedArray(u8, 44) = .{};
        const b58_encoder = comptime base58.Encoder.init(.{});
        const encoded_len = b58_encoder.encode(&self.data, &result.buffer) catch unreachable; // this is unreachable because '44' is exactly the maximum encoded length for a 32 byte string.
        result.len = @intCast(encoded_len);
        return result;
    }

    pub fn format(self: Hash, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const b58_str_bounded = self.base58String();
        return writer.writeAll(b58_str_bounded.constSlice());
    }

    pub fn generateSha256Hash(bytes: []const u8) Self {
        var data: [BYTES_LENGTH]u8 = undefined;
        Sha256.hash(bytes, &data, .{});
        return .{ .data = data };
    }

    pub fn extendAndHash(self: Self, val: []const u8) Self {
        var hasher = Sha256.init(.{});
        hasher.update(&self.data);
        hasher.update(val);
        return .{ .data = hasher.finalResult() };
    }

    pub fn order(a: *const Self, b: *const Self) std.math.Order {
        for (a.data, b.data) |a_byte, b_byte| {
            if (a_byte > b_byte) return .gt;
            if (a_byte < b_byte) return .lt;
        }
        return .eq;
    }
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
