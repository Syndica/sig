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

        pub fn init(cfg: InitParams, data: *Pair) void {
            data.recv.init();
            data.send.init();
            data.port = cfg.port;
        }
    };
};

pub const Address = extern struct {
    is_v6: bool,
    ip: [16]u8,
    port: u16,

    pub fn fromNetAddress(net_addr: std.net.Address) Address {
        return .{
            .is_v6 = net_addr.any.family == std.posix.AF.INET6,
            .ip = switch (net_addr.any.family) {
                std.posix.AF.INET6 => net_addr.in6.sa.addr,
                std.posix.AF.INET => @bitCast([_]u32{ net_addr.in.sa.addr, 0, 0, 0 }),
                else => unreachable,
            },
            .port = net_addr.getPort(),
        };
    }

    pub fn toNetAddress(self: *const Address) std.net.Address {
        if (self.is_v6) return .initIp6(self.ip, self.port, 0, 0);
        return .initIp4(self.ip[0..4].*, self.port);
    }

    pub fn format(self: Address, w: *std.Io.Writer) !void {
        return self.toNetAddress().format(w);
    }

    pub fn withPort(self: Address, new_port: u16) Address {
        return .{ .is_v6 = self.is_v6, .ip = self.ip, .port = new_port };
    }
};

pub const IpAddr = union(enum(u32)) {
    v4: [4]u8,
    v6: [16]u8,
};
