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

pub const scratch_memory_size = 64 * 1024 * 1024;

pub const ClusterInfo = extern struct {
    public_ip: std.net.Address,
    entry_addr: std.net.Address,
    shred_version: u16,

    pub fn getFromEcho(gossip_port: u16, cluster: common.solana.ClusterType) !ClusterInfo {
        var io_buf: [4096]u8 = undefined;
        var addr_buf: [4096]u8 = undefined;

        for (cluster.getEntrypoints()) |entrypoint| {
            const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
            const port = std.fmt.parseInt(u16, entrypoint[split + 1..], 10) catch continue;

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
                try writer.splatByte(0, 4 + (4 * 2) + (4 * 2)); // header + tcp ports + udp ports
                try writer.writeByte('\n');
                writer.flush() catch continue;

                var stream_reader = (std.net.Stream{ .handle = socket }).reader(&io_buf);
                const reader: *std.Io.Reader = stream_reader.interface();
                _ = reader.takeInt(u32, .little) catch continue;

                const addr: std.net.Address = switch (reader.takeInt(u32, .little) catch continue) {
                    0 => .initIp4(reader.takeArray(4) catch continue, gossip_port),
                    1 => .initIp6(reader.takeArray(16) catch continue, gossip_port, 0, 0),
                    else => continue,
                };

                const shred_version: u16 = switch (reader.takeByte() catch continue) {
                    0 => 0,
                    1 => reader.takeInt(u16, .little) catch continue,
                    else => continue,
                };

                return .{
                    .public_ip = addr,
                    .entry_addr = entry_addr,
                    .shred_version = shred_version,
                };
            }
        }
        return error.NoValidEntrypoint;
    }
};