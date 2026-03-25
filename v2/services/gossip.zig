//! This service participates in the gossip cluster, advertising our service addresses, collecting
//! the service addresses of other nodes, and generally getting status updates in and out of the
//! validator.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");

const Pair = lib.net.Pair;
const Packet = lib.net.Packet;

const Signature = lib.solana.Signature;

const gossip = lib.solana.gossip;

comptime {
    _ = start;
}

pub const name = .gossip;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    pair: *Pair,
};

pub const ReadOnly = struct {
    config: *const lib.solana.gossip.Config,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

const Effects = struct {
    pair: *Pair,
    keypair: *const lib.solana.KeyPair,

    pub fn sendMessage(self: *Effects, addr: std.net.Address, msg: gossip.Message) !void {
        var slice = while (true) break self.pair.send.getWritable() catch continue;
        const packet: *Packet = slice.get(0);
        packet.addr = addr;

        var writer: std.Io.Writer = .fixed(&packet.data);
        try gossip.bincode.write(&writer, msg);
        packet.size = @intCast(writer.buffered().len);

        slice.markUsed(1);
    }

    pub fn sign(self: *Effects, msg: []const u8) Signature {
        return self.keypair.sign(msg) catch |e| {
            std.debug.panic("failed to sign message: {}", .{e});
        };
    }

    pub fn publishContactInfo(self: *Effects, contact_info: gossip.Data) !void {
        try self.sendMessage(
            self.pair.getRemoteAddress(),
            .contactInfo(contact_info),
        );
    }
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const cluster_info = &ro.config.cluster_info;
    std.log.debug(
        "Gossip started on :{} as {f}:\n\tshred_version:{}\n\tentrypoint:{f}",
        .{
            rw.pair.port,
            ro.config.keypair.pubkey,
            cluster_info.shred_version,
            cluster_info.entry_addr.toNetAddress(),
        },
    );

    var socket_entries: [2]gossip.Data.SocketEntry = .{
        .{ .key = .gossip, .ip_idx = 0, .port_offset = .{ .value = rw.pair.port } },
        .{ .key = .tvu, .ip_idx = 0, .port_offset = .{ .value = ro.config.turbine_recv_port } },
    };
    {
        // Sort by ports.
        std.mem.sort(gossip.Data.SocketEntry, &socket_entries, {}, struct {
            fn lessThan(_: void, a: gossip.Data.SocketEntry, b: gossip.Data.SocketEntry) bool {
                return a.port_offset.value < b.port_offset.value;
            }
        }.lessThan);

        // Convert ports into offsets of each other.
        var port: u16 = 0;
        for (&socket_entries) |*e| {
            e.port_offset.value -= port;
            port += e.port_offset.value;
        }
    }

    var now: u64 = @intCast(std.time.milliTimestamp());
    const contact_info: gossip.Data = .{ .contact_info = .{
        .from = ro.config.keypair.pubkey,
        .wallclock = .{ .value = now },
        .created = now,
        .shred_version = cluster_info.shred_version,
        .major = .{ .value = 0 },
        .minor = .{ .value = 0 },
        .patch = .{ .value = 0 },
        .commit = 0,
        .feature_set = 0,
        .client_id = .{ .value = 0 },
        .ips = .{ .items = &.{
            if (cluster_info.public_ip.is_v6)
                .{ .v6 = cluster_info.public_ip.ip }
            else
                .{ .v4 = cluster_info.public_ip.ip[0..4].* },
        } },
        .sockets = .{ .items = &socket_entries },
        .extensions = .{ .items = &.{} },
    } };

    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    var effects: Effects = .{ .pair = rw.pair, .keypair = &ro.config.keypair };
    var gossip_engine = try gossip.Gossip(Effects).init(&fba, &effects, .{
        .identity = ro.config.keypair.pubkey,
        .entry_addr = cluster_info.entry_addr.toNetAddress(),
        .contact_info = contact_info,
    });

    while (true) {
        now = @intCast(std.time.milliTimestamp());

        if (rw.pair.recv.getReadable() catch null) |slice_| {
            var slice = slice_;
            const packet: *const Packet = slice.get(0);
            gossip_engine.handlePacket(now, packet);
            slice.markUsed(1);
        }

        try gossip_engine.poll(now);
    }
}
