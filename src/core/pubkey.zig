const std = @import("std");
const sig = @import("../sig.zig");

pub const Pubkey = extern struct {
    data: [size]u8,
    const Self = @This();

    pub const size = 32;

    pub const ZEROES: Pubkey = .{ .data = .{0} ** size };

    const base58 = sig.crypto.base58.Base58Sized(size);

    pub fn fromString(str: []const u8) !Self {
        return .{ .data = try base58.decode(str) };
    }

    pub fn fromBytes(bytes: []const u8) !Self {
        if (bytes.len != size) {
            return Error.InvalidBytesLength;
        }
        return .{ .data = bytes[0..size].* };
    }

    pub fn fromPublicKey(public_key: *const std.crypto.sign.Ed25519.PublicKey) Self {
        return fromBytes(&public_key.bytes) catch unreachable;
    }

    pub fn initRandom(random: std.Random) Self {
        var bytes: [size]u8 = undefined;
        random.bytes(&bytes);
        return .{ .data = bytes };
    }

    pub fn equals(self: *const Self, other: *const Pubkey) bool {
        const xx: @Vector(size, u8) = self.data;
        const yy: @Vector(size, u8) = other.data;
        return @reduce(.And, xx == yy);
    }

    pub fn isZeroed(self: *const Self) bool {
        return self.equals(&ZEROES);
    }

    pub fn string(self: Self) base58.String {
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
};

const Error = error{ InvalidBytesLength, InvalidEncodedLength, InvalidEncodedValue };
