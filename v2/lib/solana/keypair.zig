const std = @import("std");

const lib = @import("../lib.zig");

const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;

/// Extern struct compatibility for stdlib KeyPair type.
/// TODO: move this to signer service.
pub const KeyPair = extern struct {
    pubkey: Pubkey,
    private: [64]u8,

    pub fn fromKeyPair(kp: std.crypto.sign.Ed25519.KeyPair) KeyPair {
        return .{
            .pubkey = .fromPublicKey(&kp.public_key),
            .private = kp.secret_key.toBytes(),
        };
    }

    pub fn sign(self: *const KeyPair, msg: []const u8) !Signature {
        const kp: std.crypto.sign.Ed25519.KeyPair = .{
            .public_key = try .fromBytes(self.pubkey.data),
            .secret_key = try .fromBytes(self.private),
        };
        return .fromSignature(try kp.sign(msg, null));
    }
};
