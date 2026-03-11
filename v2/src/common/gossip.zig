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

pub const Config = extern struct {
    keypair: KeyPair,
    cluster_info: ClusterInfo,
    turbine_recv_port: u16,
};

pub const scratch_memory_size = 256 * 1024 * 1024;

pub const ClusterInfo = extern struct {
    public_ip: Address,
    entry_addr: Address,
    shred_version: u16,

    // For std.meta.eql compatibility insice `serviceMap`
    pub const Address = extern struct {
        is_v6: bool,
        ip: [16]u8,
        port: u16,

        pub fn toNetAddress(self: *const Address) std.net.Address {
            if (self.is_v6) return .initIp6(self.ip, self.port, 0, 0);
            return .initIp4(self.ip[0..4].*, self.port);
        }
    };

    pub fn getFromEcho(gossip_port: u16, cluster: common.solana.ClusterType) !ClusterInfo {
        var io_buf: [4096]u8 = undefined;
        var addr_buf: [4096]u8 = undefined;

        for (cluster.getEntrypoints()) |entrypoint| {
            const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
            const port = std.fmt.parseInt(u16, entrypoint[split + 1 ..], 10) catch continue;

            var fba = std.heap.FixedBufferAllocator.init(&addr_buf);
            const addr_list =
                try std.net.getAddressList(fba.allocator(), entrypoint[0..split], port);
            defer addr_list.deinit();

            for (addr_list.addrs) |entry_addr| {
                const socket = try std.posix.socket(
                    entry_addr.any.family,
                    std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
                    std.posix.IPPROTO.TCP,
                );
                defer std.posix.close(socket);

                // set timeout of 1s for connect, read, write.
                const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
                try std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv);
                std.posix.connect(socket, &entry_addr.any, entry_addr.getOsSockLen()) catch {
                    continue;
                };

                var stream_writer = (std.net.Stream{ .handle = socket }).writer(&io_buf);
                const writer = &stream_writer.interface;
                _ = try writer.splatByte(0, 4 + (4 * 2) + (4 * 2)); // hdr + tcp ports + udp ports
                try writer.writeByte('\n'); // trailer
                writer.flush() catch continue;

                var stream_reader = (std.net.Stream{ .handle = socket }).reader(&io_buf);
                const reader: *std.Io.Reader = stream_reader.interface();
                _ = reader.takeInt(u32, .little) catch continue;

                const tag = reader.takeInt(u32, .little) catch continue;
                const is_v6 = (std.math.cast(u1, tag) orelse continue) == 1;
                var ip: [16]u8 = @splat(0);
                if (is_v6) {
                    ip = (reader.takeArray(16) catch continue).*;
                } else {
                    ip[0..4].* = (reader.takeArray(4) catch continue).*;
                }

                const shred_version: u16 = switch (reader.takeByte() catch continue) {
                    0 => 0,
                    1 => reader.takeInt(u16, .little) catch continue,
                    else => continue,
                };

                return .{
                    .public_ip = .{
                        .is_v6 = is_v6,
                        .ip = ip,
                        .port = gossip_port,
                    },
                    .entry_addr = .{
                        .is_v6 = entry_addr.any.family == std.posix.AF.INET6,
                        .ip = switch (entry_addr.any.family) {
                            std.posix.AF.INET6 => entry_addr.in6.sa.addr,
                            std.posix.AF.INET => @bitCast([_]u32{ entry_addr.in.sa.addr, 0, 0, 0 }),
                            else => unreachable,
                        },
                        .port = entry_addr.getPort(),
                    },
                    .shred_version = shred_version,
                };
            }
        }
        return error.NoValidEntrypoint;
    }
};
