const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base58 = @import("base58-zig");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

pub const HASH_SIZE: usize = 32;

pub const Hash = extern struct {
    data: [HASH_SIZE]u8,

    pub fn fromSizedSlice(data: *const [HASH_SIZE]u8) Hash {
        var hash: Hash = undefined;
        @memcpy(&hash.data, data);
        return hash;
    }

    pub fn default() Hash {
        return .{ .data = .{0} ** HASH_SIZE };
    }

    pub fn generateSha256Hash(bytes: []const u8) Hash {
        var data: [HASH_SIZE]u8 = undefined;
        Sha256.hash(bytes, &data, .{});
        return .{ .data = data };
    }

    pub fn extendAndHash(id: Hash, val: []const u8) Hash {
        var hasher = Sha256.init(.{});
        hasher.update(&id.data);
        hasher.update(val);
        return .{ .data = hasher.finalResult() };
    }

    pub fn eql(self: Hash, other: Hash) bool {
        return self.order(&other) == .eq;
    }

    pub fn order(a: *const Hash, b: *const Hash) std.math.Order {
        for (a.data, b.data) |a_byte, b_byte| {
            if (a_byte > b_byte) return .gt;
            if (a_byte < b_byte) return .lt;
        }
        return .eq;
    }

    pub fn parseBase58String(str: []const u8) error{InvalidHash}!Hash {
        var result_data: [HASH_SIZE]u8 = undefined;
        const b58_decoder = comptime base58.Decoder.init(.{});
        const encoded_len = b58_decoder.decode(str, &result_data) catch return error.InvalidHash;
        if (encoded_len != HASH_SIZE) return error.InvalidHash;
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

    pub fn base58EncodeAlloc(self: Hash, allocator: Allocator) Allocator.Error![]const u8 {
        const buf = try allocator.alloc(u8, 44);
        const size = self.base58EncodeToSlice(buf[0..44]);
        std.debug.assert(size <= 44);
        return try allocator.realloc(buf, size);
    }

    fn base58EncodeToSlice(self: Hash, buf: *[44]u8) usize {
        const b58_encoder = base58.Encoder.init(.{});
        // unreachable because 44 is the maximum encoded length for 32 bytes.
        const size = b58_encoder.encode(&self.data, buf[0..]) catch unreachable;
        return size;
    }

    /// Intended to be used in tests.
    pub fn random(rand: std.Random) Hash {
        std.debug.assert(builtin.is_test);
        var data: [HASH_SIZE]u8 = undefined;
        rand.bytes(&data);
        return .{ .data = data };
    }
};
