const std = @import("std");
const Ring = @import("ring.zig").Ring;

const MAX_PACKETS = 1 << 14;

/// The maximum packet size.
pub const Packet = extern struct {
    data: [1232]u8,
    size: u16,
    addr: std.net.Address,
};

pub const Pair = extern struct {
    recv: Ring(MAX_PACKETS, Packet),
    send: Ring(MAX_PACKETS, Packet),
    port: u16,

    pub fn init(p: *Pair, port: u16) void {
        p.recv.init();
        p.send.init();
        p.port = port;
    }
};
