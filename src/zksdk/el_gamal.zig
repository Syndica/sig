const std = @import("std");
const builtin = @import("builtin");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;
const CompressedScalar = Edwards25519.scalar.CompressedScalar;

pub const G = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0xe2, 0xf2, 0xae, 0xa,  0x6a, 0xbc, 0x4e, 0x71,
        0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x0,  0x51, 0x5f,
        0x58, 0xe3, 0xb,  0x6a, 0xa5, 0x82, 0xdd, 0x8d,
        0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    }) catch unreachable;
};

pub const H = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x4,  0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
    }) catch unreachable;
};

pub const Pubkey = struct {
    p: Ristretto255,

    /// Derives a `Pubkey` that uniquely relates to a `Secret`.
    pub fn fromSecret(secret: Secret) Pubkey {
        const scalar = secret.scalar;
        std.debug.assert(!scalar.isZero());
        // unreachable because `H` is known to not be an identity and `scalar` cannot be zero.
        return .{ .p = Ristretto255.mul(H, scalar.invert().toBytes()) catch unreachable };
    }
};

pub const Secret = struct {
    scalar: Scalar,
};

pub const Keypair = struct {
    secret: Secret,
    public: Pubkey,

    pub fn fromScalar(s: Scalar) Keypair {
        const secret: Secret = .{ .scalar = s };
        const public = Pubkey.fromSecret(secret);
        return .{ .secret = secret, .public = public };
    }

    /// Generates a cryptographically secure random keypair.
    pub fn random() Keypair {
        if (!builtin.is_test) @compileError("only use in tests");

        var scalar = Scalar.random();
        const keypair = Keypair.fromScalar(scalar);
        std.crypto.utils.secureZero(u64, &scalar.limbs);

        return keypair;
    }
};

pub const DecryptHandle = struct {
    point: Ristretto255,

    pub fn init(pubkey: *const Pubkey, opening: *const pedersen.Opening) DecryptHandle {
        // neither pubkey.p nor scalar can be zero, so this function cannot return an error.
        return .{ .point = pubkey.p.mul(opening.scalar.toBytes()) catch unreachable };
    }
};

pub const pedersen = struct {
    pub const Opening = struct {
        scalar: Scalar,

        pub fn random() Opening {
            return .{ .scalar = Scalar.random() };
        }
    };

    pub const Commitment = struct {
        point: Ristretto255,
    };

    pub fn init(comptime T: type, value: T) struct { Commitment, Opening } {
        const opening = Opening.random();
        const commitment = fromValue(T, value, &opening);
        return .{ commitment, opening };
    }

    pub fn fromValue(comptime T: type, value: T, opening: *const Opening) Commitment {
        const x = scalarFromInt(T, value);
        // G and H are not identities and opening.scalar cannot be zero,
        // so this function cannot return an error.
        const result = Edwards25519.mulMulti(
            2,
            .{ G.p, H.p },
            .{ x.toBytes(), opening.scalar.toBytes() },
        ) catch unreachable;
        return .{ .point = .{ .p = result } };
    }
};

pub fn scalarFromInt(comptime T: type, value: T) Scalar {
    var buffer: [32]u8 = .{0} ** 32;
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
    return Scalar.fromBytes(buffer);
}

const Ciphertext = struct {
    commitment: pedersen.Commitment,
    handle: DecryptHandle,
};

pub fn encrypt(comptime T: type, value: T, pubkey: *const Pubkey) Ciphertext {
    const commitment, const opening = pedersen.init(T, value);
    const handle = DecryptHandle.init(pubkey, &opening);
    return .{
        .commitment = commitment,
        .handle = handle,
    };
}

pub fn decrypt(secret: *const Secret, ciphertext: *const Ciphertext) !Ristretto255 {
    const p = ciphertext.commitment.point.p;
    const c = try ciphertext.handle.point.mul(secret.scalar.toBytes());
    const result = p.sub(c.p);
    return .{ .p = result };
}

test "encrypt decrypt" {
    const kp = Keypair.random();
    const amount: u32 = 57;

    const ciphertext = encrypt(u32, amount, &kp.public);

    const expected = try G.mul(scalarFromInt(u32, amount).toBytes());
    const result = try decrypt(&kp.secret, &ciphertext);

    try std.testing.expectEqualSlices(
        u8,
        &expected.toBytes(),
        &result.toBytes(),
    );
}
