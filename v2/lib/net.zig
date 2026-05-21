const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const Ring = @import("ipc/ring.zig").Ring;

const MAX_PACKETS = 1 << 14;

/// The maximum packet size.
pub const Packet = extern struct {
    data: Buffer,
    len: u16,
    addr: std.net.Address,

    pub const capacity = 1232;
    pub const Buffer = [capacity]u8;
};

pub const Pair = extern struct {
    recv: PacketRing,
    send: PacketRing,
    port: u16,

    pub const PacketRing = Ring(MAX_PACKETS, Packet);

    pub fn init(p: *Pair, port: u16) void {
        p.recv.init();
        p.send.init();
        p.port = port;
    }
};
