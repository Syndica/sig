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

    pub const InitParams = struct {
        port: u16,

        pub fn size(_: InitParams) usize {
            return @sizeOf(Pair);
        }

        pub fn init(cfg: InitParams, buf: []align(std.heap.page_size_min) u8) void {
            std.debug.assert(buf.len == @sizeOf(Pair));
            const data: *Pair = @ptrCast(buf);
            data.recv.init();
            data.send.init();
            data.port = cfg.port;
        }
    };
};
