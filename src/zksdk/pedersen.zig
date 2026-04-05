const std = @import("std");
const sig = @import("../sig.zig");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;
const ed25519 = sig.crypto.ed25519;
const Pubkey = sig.zksdk.ElGamalPubkey;

/// Pedersen basepoint.
pub const G = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0xe2, 0xf2, 0xae, 0xa,  0x6a, 0xbc, 0x4e, 0x71,
        0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x0,  0x51, 0x5f,
        0x58, 0xe3, 0xb,  0x6a, 0xa5, 0x82, 0xdd, 0x8d,
        0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    }) catch unreachable;
};

/// Hash-to-ristretto of SHA3-512(G), with G in compressed form.
pub const H = b: {
    // We could compute `H` at comptime, but that would take *way* too long!
    // Maybe we could look into it once comptime execution is sped up a bit.
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x4,  0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
    }) catch unreachable;
};

pub const Opening = struct {
    scalar: Scalar,

    pub fn fromBytes(bytes: [32]u8) !Opening {
        const scalar = Scalar.fromBytes(bytes);
        try Edwards25519.scalar.rejectNonCanonical(bytes);
        return .{ .scalar = scalar };
    }

    pub fn random() Opening {
        return .{ .scalar = .random() };
    }
};

pub const Commitment = struct {
    point: Ristretto255,

    pub fn fromBytes(bytes: [32]u8) !Commitment {
        return .{ .point = try Ristretto255.fromBytes(bytes) };
    }

    pub fn toBytes(self: Commitment) [32]u8 {
        return self.point.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Commitment {
        const base64 = std.base64.standard;
        var buffer: [32]u8 = .{0} ** 32;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn rejectIdentity(self: *const Commitment) error{IdentityElement}!void {
        try self.point.rejectIdentity();
    }
};

pub const DecryptHandle = struct {
    point: Ristretto255,

    pub fn init(pubkey: *const Pubkey, opening: *const Opening) DecryptHandle {
        const point = ed25519.mul(true, pubkey.point, opening.scalar.toBytes());
        return .{ .point = point };
    }

    pub fn fromBytes(bytes: [32]u8) !DecryptHandle {
        return .{ .point = try Ristretto255.fromBytes(bytes) };
    }

    pub fn fromBase64(string: []const u8) !DecryptHandle {
        const base64 = std.base64.standard;
        var buffer: [32]u8 = .{0} ** 32;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

// init with a scalar and an opening
// init with a scalar and generate opening
// init with a value and an opening
// init with a value and generate opening

pub fn init(s: Scalar, opening: *const Opening) Commitment {
    // G and H are not identities and opening.scalar cannot be zero,
    // so this function cannot return an error.
    const point = ed25519.mulMulti(
        2,
        .{ G, H },
        .{ s.toBytes(), opening.scalar.toBytes() },
    );
    return .{ .point = point };
}

pub fn initScalar(s: Scalar) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ init(s, &opening), opening };
}

pub fn initValue(comptime T: type, value: T) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ initOpening(T, value, &opening), opening };
}

pub fn initOpening(comptime T: type, value: T, opening: *const Opening) Commitment {
    const scalar = scalarFromInt(T, value);
    return init(scalar, opening);
}

pub fn scalarFromInt(comptime T: type, value: T) Scalar {
    var buffer: [32]u8 = .{0} ** 32;
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
    return Scalar.fromBytes(buffer);
}
