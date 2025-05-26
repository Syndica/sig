//! Twisted ElGamal encryption.
//!
//! https://github.com/anza-xyz/agave/blob/b11ca828cfc658b93cb86a6c5c70561875abe237/zk-sdk/src/encryption/elgamal.rs
//! https://spl.solana.com/assets/files/twisted_elgamal-2115c6b1e6c62a2bb4516891b8ae9ee0.pdf
//!
//! Similar to the ElGamal encryption scheme, twisted ElGamal encodes messages directly as
//! a Pedersen commitment. Since the messages (scalars) are encrypted as scalar elements for
//! Curve25519, you'd need to solve the discrete log problem to recover the original encrypted value.
//!
//! (Taken from Agave comment):
//! A twisted ElGamal ciphertext consists of two components:
//! - A Pedersen commitment that encodes a message to be encrypted
//! - A "decryption handle" that binds the Pedersen opening to a specific public ke
//!

const std = @import("std");
const sig = @import("../sig.zig");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;

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
    pub fn fromSecret(secret: Keypair.Secret) Pubkey {
        const scalar = secret.scalar;
        std.debug.assert(!scalar.isZero());
        // unreachable because `H` is known to not be an identity and `scalar` cannot be zero.
        return .{ .p = Ristretto255.mul(H, scalar.invert().toBytes()) catch unreachable };
    }

    pub fn fromBytes(bytes: [32]u8) !Pubkey {
        return .{ .p = try Ristretto255.fromBytes(bytes) };
    }

    pub fn toBytes(self: Pubkey) [32]u8 {
        return self.p.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Pubkey {
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

pub const Keypair = struct {
    secret: Secret,
    public: Pubkey,

    pub const Secret = struct {
        scalar: Scalar,

        pub fn random() Secret {
            return .{ .scalar = Scalar.random() };
        }
    };

    pub fn fromScalar(s: Scalar) Keypair {
        const secret: Secret = .{ .scalar = s };
        const public = Pubkey.fromSecret(secret);
        return .{ .secret = secret, .public = public };
    }

    /// Generates a cryptographically secure random keypair.
    pub fn random() Keypair {
        var scalar = Scalar.random();
        const keypair = Keypair.fromScalar(scalar);
        std.crypto.utils.secureZero(u64, &scalar.limbs);
        return keypair;
    }
};

pub const Ciphertext = struct {
    commitment: pedersen.Commitment,
    handle: pedersen.DecryptHandle,

    pub fn fromBytes(bytes: [64]u8) !Ciphertext {
        return .{
            .commitment = .{ .point = try Ristretto255.fromBytes(bytes[0..32].*) },
            .handle = .{ .point = try Ristretto255.fromBytes(bytes[32..64].*) },
        };
    }

    pub fn toBytes(self: Ciphertext) [64]u8 {
        return self.commitment.point.toBytes() ++ self.handle.point.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Ciphertext {
        const base64 = std.base64.standard;
        var buffer: [64]u8 = .{0} ** 64;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

pub const pedersen = struct {
    pub const Opening = struct {
        scalar: Scalar,

        pub fn fromBytes(bytes: [32]u8) !Opening {
            const scalar = Scalar.fromBytes(bytes);
            try Edwards25519.scalar.rejectNonCanonical(bytes);
            return .{ .scalar = scalar };
        }

        pub fn random() Opening {
            return .{ .scalar = sig.zksdk.bulletproofs.ONE }; // TODO: random
        }
    };

    pub const Commitment = struct {
        point: Ristretto255,

        pub fn fromBytes(bytes: [32]u8) !Commitment {
            return .{ .point = try Ristretto255.fromBytes(bytes) };
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
    };

    pub const DecryptHandle = struct {
        point: Ristretto255,

        pub fn init(pubkey: *const Pubkey, opening: *const pedersen.Opening) DecryptHandle {
            const point = weak_mul.mul(pubkey.p.p, opening.scalar.toBytes());
            return .{ .point = .{ .p = point } };
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
        const point = Edwards25519.mulMulti(
            2,
            .{ G.p, H.p },
            .{ s.toBytes(), opening.scalar.toBytes() },
        ) catch unreachable;
        return .{ .point = .{ .p = point } };
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
};

pub fn encrypt(comptime T: type, value: T, pubkey: *const Pubkey) Ciphertext {
    const commitment, const opening = pedersen.initValue(T, value);
    const handle = pedersen.DecryptHandle.init(pubkey, &opening);
    return .{
        .commitment = commitment,
        .handle = handle,
    };
}

pub fn encryptWithOpening(
    comptime T: type,
    value: T,
    pubkey: *const Pubkey,
    opening: *const pedersen.Opening,
) Ciphertext {
    const commitment = pedersen.initOpening(T, value, opening);
    const handle = pedersen.DecryptHandle.init(pubkey, opening);
    return .{
        .commitment = commitment,
        .handle = handle,
    };
}

/// Represents the Discrete Log Problem needed to decrypt the twisted ElGamal ciphertext
///
/// Recovers x ∈ ℤₚ such that x · G = P.
const DiscreteLog = struct {
    generator: Ristretto255,
    target: Ristretto255,
    step_point: Ristretto255,
    batch_size: u32,

    /// Solves the discrete log problem under the assumption that the solution is a positive number
    /// withing the range `0..max_bound`.
    pub fn findRange(
        dl: DiscreteLog,
        comptime max_bound: u64,
    ) ?std.math.IntFittingRange(0, max_bound) {
        comptime std.debug.assert(max_bound <= std.math.maxInt(u32));
        _ = dl;
        @compileError("TODO");
    }
};

/// Returns a representation of the discrete log problem necassary to solve the original scalar used
/// to create the twisted ElGamal ciphertext.
pub fn decrypt(secret: *const Keypair.Secret, ciphertext: *const Ciphertext) ?DiscreteLog {
    const p = ciphertext.commitment.point.p;
    // The handle point can never be zero, so this function cannot fail.
    const c = ciphertext.handle.point.mul(secret.scalar.toBytes()) catch unreachable;
    const target = p.sub(c.p);
    return .{
        .generator = G,
        .target = .{ .p = target },
        .step_point = G,
        .batch_size = 32,
    };
}

pub fn scalarFromInt(comptime T: type, value: T) Scalar {
    var buffer: [32]u8 = .{0} ** 32;
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
    return Scalar.fromBytes(buffer);
}

// test "encrypt decrypt" {
//     const kp = Keypair.random();
//     const amount: u32 = 57;

//     const ciphertext = encrypt(u32, amount, &kp.public);

//     const expected = try G.mul(scalarFromInt(u32, amount).toBytes());
//     const result = try decrypt(&kp.secret, &ciphertext);

//     try std.testing.expectEqualSlices(
//         u8,
//         &expected.toBytes(),
//         &result.toBytes(),
//     );
// }
