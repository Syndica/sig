const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base58 = @import("base58-zig");
const Allocator = std.mem.Allocator;

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

    pub fn format(self: Hash, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        const b58_encoder = base58.Encoder.init(.{});
        var buf: [44]u8 = undefined;
        const size = b58_encoder.encode(&self.data, &buf) catch unreachable;
        return writer.print("{s}", .{buf[0..size]});
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
    pub fn random(rand: std.rand.Random) Hash {
        var data: [HASH_SIZE]u8 = undefined;
        rand.bytes(&data);
        return .{ .data = data };
    }
};
