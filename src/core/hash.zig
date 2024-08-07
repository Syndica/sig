const std = @import("std");
const sig = @import("../sig.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const Allocator = std.mem.Allocator;

pub const Hash = extern struct {
    data: [SIZE]u8,

    pub const SIZE = 32;
    pub const BASE58_MAX_LENGTH = 44;

    const base58 = sig.crypto.base58.Base58Sized(SIZE);
    const Self = @This();

    pub fn init(bytes: [SIZE]u8) Self {
        return Self{ .data = bytes };
    }

    pub fn default() Self {
        return Self{ .data = [_]u8{0} ** SIZE };
    }

    pub fn random(rng: std.rand.Random) Self {
        var bytes: [SIZE]u8 = undefined;
        rng.bytes(&bytes);
        return Self{ .data = bytes };
    }

    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != SIZE) {
            return Error.InvalidBytesLength;
        }
        return Self{ .data = bytes[0..SIZE].* };
    }

    pub fn fromSizedSlice(data: *const [SIZE]u8) Hash {
        var hash: Hash = undefined;
        @memcpy(&hash.data, data);
        return hash;
    }

    pub fn generateSha256Hash(bytes: []const u8) Hash {
        var data: [SIZE]u8 = undefined;
        Sha256.hash(bytes, &data, .{});
        return .{ .data = data };
    }

    pub fn extendAndHash(id: Hash, val: []const u8) Hash {
        var hasher = Sha256.init(.{});
        hasher.update(&id.data);
        hasher.update(val);
        return .{ .data = hasher.finalResult() };
    }

    pub fn fromBase58String(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    pub fn toBase58String(self: Hash) std.BoundedArray(u8, 44) {
        return base58.encode(self.data);
    }

    pub fn base58EncodeAlloc(self: Hash, allocator: Allocator) Allocator.Error![]const u8 {
        return base58.encodeAlloc(self.data, allocator);
    }

    pub fn format(
        self: Hash,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        return base58.format(self.data, writer);
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
};

/// TODO: InvalidEncodedLength and InvalidEncodedValue are not used
const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
