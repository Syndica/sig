const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base58 = @import("base58-zig");

pub const HASH_SIZE: usize = 32;

pub const Hash = struct {
    data: [HASH_SIZE]u8,

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

    /// Intended to be used in tests.
    pub fn random(rand: std.rand.Random) Hash {
        var data: [HASH_SIZE]u8 = undefined;
        rand.bytes(&data);
        return .{ .data = data };
    }
};
