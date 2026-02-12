const std = @import("std");

pub const FnvHasher = @import("fnv.zig").FnvHasher;
pub const bn254 = @import("bn254/lib.zig");
pub const bls12_381 = @import("bls12_381/lib.zig");
pub const ed25519 = @import("ed25519/lib.zig");

/// Extern definition of Ecdsa signature.
pub const EcdsaSignature = extern struct {
    r: [32]u8,
    s: [32]u8,

    const Keccak256 = std.crypto.hash.sha3.Keccak256;
    const Secp256k1 = std.crypto.ecc.Secp256k1;
    const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

    pub fn to(self: EcdsaSignature) Ecdsa.Signature {
        return .{
            .r = self.r,
            .s = self.s,
        };
    }
};
