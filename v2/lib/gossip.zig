const std = @import("std");
const lib = @import("lib.zig");

pub const GossipNode = @import("gossip/node.zig").GossipNode;

const bincode = lib.solana.bincode;
const Signature = lib.solana.Signature;
const Pubkey = lib.solana.Pubkey;

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

/// Read-only config information needed to run a gossip service instance.
pub const Config = extern struct {
    keypair: KeyPair,
    cluster_info: ClusterInfo,
    turbine_recv_port: u16,
};

/// Bootstrapping network information needed to run a Gossip Node
pub const ClusterInfo = extern struct {
    public_ip: std.net.Address,
    shred_version: u16,
    entry_addrs_len: u8,
    entry_addrs: [MAX_ENTRY_ADDRS]std.net.Address,

    pub const MAX_ENTRY_ADDRS = 16;

    pub fn getEntryAddresses(self: *const ClusterInfo) []const std.net.Address {
        return self.entry_addrs[0..self.entry_addrs_len];
    }

    pub fn getFromEcho(gossip_port: u16, cluster: lib.solana.Cluster) !ClusterInfo {
        var result: ClusterInfo = undefined;
        result.entry_addrs_len = 0;

        for (cluster.getEntrypoints()) |entrypoint| {
            const split = std.mem.indexOfScalar(u8, entrypoint, ':') orelse continue;
            const port = std.fmt.parseInt(u16, entrypoint[split + 1 ..], 10) catch continue;

            var addr_buf: [4096]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&addr_buf);
            const addr_list =
                std.net.getAddressList(fba.allocator(), entrypoint[0..split], port) catch continue;
            defer addr_list.deinit();

            for (addr_list.addrs) |entry_addr| {
                if (result.entry_addrs_len >= MAX_ENTRY_ADDRS) break;

                const socket = std.posix.socket(
                    entry_addr.any.family,
                    std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
                    std.posix.IPPROTO.TCP,
                ) catch continue;
                defer std.posix.close(socket);

                // set timeout of 1s for connect, read, write.
                const tv = comptime std.mem.asBytes(&std.posix.timeval{ .sec = 1, .usec = 0 });
                std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, tv) catch
                    continue;
                std.posix.setsockopt(socket, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, tv) catch
                    continue;
                std.posix.connect(socket, &entry_addr.any, entry_addr.getOsSockLen()) catch {
                    continue;
                };

                // Used for writing, then for reading.
                var io_buf: [4096]u8 = undefined;

                var stream_writer = std.net.Stream.writer(.{ .handle = socket }, &io_buf);
                const writer = &stream_writer.interface;
                bincode.write(writer, lib.solana.gossip.EchoMessage{
                    .tcp_ports = @as([4]u16, @splat(0)),
                    .udp_ports = @as([4]u16, @splat(0)),
                }) catch continue;
                writer.flush() catch continue;

                var stream_reader = std.net.Stream.reader(.{ .handle = socket }, &io_buf);
                const reader: *std.Io.Reader = stream_reader.interface();
                var stub_fba = std.heap.FixedBufferAllocator.init(&.{});
                const resp = bincode.read(&stub_fba, reader, lib.solana.gossip.EchoResponse) catch
                    continue;

                const shred_version = resp.shred_version orelse 0;
                const public_ip: std.net.Address = switch (resp.public_ip) {
                    .v4 => |ip| .initIp4(ip, gossip_port),
                    .v6 => |ip| .initIp6(ip, gossip_port, 0, 0),
                };

                // First successful echo sets public_ip and shred_version.
                // Subsequent echoes must return the same shred_version.
                if (result.entry_addrs_len == 0) {
                    result.public_ip = public_ip;
                    result.shred_version = shred_version;
                } else if (shred_version != result.shred_version) {
                    continue;
                }

                const exists = for (result.getEntryAddresses()) |*e| {
                    if (e.eql(entry_addr)) break true;
                } else false;

                // Only accumulate if entry address isn't a duplicate.
                if (!exists) {
                    result.entry_addrs[result.entry_addrs_len] = entry_addr;
                    result.entry_addrs_len += 1;
                }

                // only one resolved address per entrypoint hostname
                break;
            }
        }

        if (result.entry_addrs_len == 0) return error.NoValidEntrypoint;
        return result;
    }
};
