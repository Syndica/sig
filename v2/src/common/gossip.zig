const std = @import("std");
const Ring = @import("ring.zig").Ring;
const common = @import("../common.zig");

const Pubkey = common.solana.Pubkey;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;

pub const GossipSigner = common.signer.Signer(common.net.Packet.MTU);

pub const GossipConfig = extern struct {
    cluster: common.solana.Cluster,
    turbine_recv_port: u16,
    turbine_repair_port: u16,
};

pub const SnapshotContactQueue = extern struct {
    incoming: Ring(1024, Event), // arbitrary size

    pub const Event = extern struct {
        type: enum(u8) {
            rpc_contact,
            full_snapshot,
            incremental_snapshot,
        },
        data: extern union {
            rpc_contact: extern struct {
                pubkey: Pubkey,
                addr: std.net.Address,
            },
            snapshot: extern struct {
                pubkey: Pubkey,
                slot: Slot,
                hash: Hash,
            },
        },
    };
};

test {
    _ = std.testing.refAllDecls(@This());
}
