const std = @import("std");
const lib = @import("../lib.zig");

const Ring = lib.ipc.Ring;
const SlotAndHash = lib.solana.SlotAndHash;

pub const Queue = extern struct {
    incoming: Incoming,
    outgoing: Outgoing,

    pub const Incoming = Ring(1024, Entry);
    pub const Outgoing = Ring(1, SlotAndHash);

    pub const Entry = extern struct {
        slot_hash: SlotAndHash,
        rpc_address: std.net.Address,
    };
};
