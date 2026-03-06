const std = @import("std");

test {
    _ = std.testing.refAllDecls(@This());
}

const common = @import("../common.zig");

const Signature = common.solana.Signature;
const Slot = common.solana.Slot;
const Pubkey = common.solana.Pubkey;

/// Extern struct compatibility for stdlib KeyPair type
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

pub const GossipConfig = extern struct {
    cluster: common.solana.ClusterType,
    keypair: KeyPair,
    turbine_recv_port: u16,
};

pub const scratch_memory_size = 64 * 1024 * 1024;