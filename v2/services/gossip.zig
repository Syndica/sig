//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");

const Pair = lib.net.Pair;
const Packet = lib.net.Packet;

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;

const GossipNode = lib.gossip.GossipNode;

comptime {
    _ = start;
}

pub const name = .gossip;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    net_pair: *Pair,
};

pub const ReadOnly = struct {
    config: *const lib.gossip.Config,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.info(
        "Gossip started on :{} as {f}:\n\tshred_version:{}\n\tentrypoints:{f}",
        .{
            rw.net_pair.port,
            ro.config.keypair.pubkey,
            ro.config.cluster_info.shred_version,
            lib.util.fmtSlice(ro.config.cluster_info.getEntryAddresses()),
        },
    );

    const Effects = struct {
        packet_writer: *lib.net.Pair.PacketRing.Iterator(.writer),
        keypair: *const lib.gossip.KeyPair,

        const Self = @This();

        pub fn writePacket(self: Self) *Packet {
            while (true) return self.packet_writer.next() orelse {
                self.flushWrittenPackets();
                continue;
            };
        }

        pub fn flushWrittenPackets(self: Self) void {
            self.packet_writer.markUsed();
        }

        pub fn getIdentity(self: Self) Pubkey {
            return self.keypair.pubkey;
        }

        pub fn sign(self: Self, msg: []const u8) Signature {
            return self.keypair.sign(msg) catch |e| std.debug.panic("signing failed: {}", .{e});
        }
    };

    var packet_writer = rw.net_pair.send.get(.writer);
    const effects: Effects = .{
        .packet_writer = &packet_writer,
        .keypair = &ro.config.keypair,
    };

    // TODO: add .rpc for serving snapshots
    var sockets: lib.gossip.SocketMap.Builder = .{};
    sockets.set(.gossip, ro.config.cluster_info.public_ip.withPort(rw.net_pair.port));
    sockets.set(.tvu, ro.config.cluster_info.public_ip.withPort(ro.config.turbine_recv_port));

    var now: u64 = @intCast(std.time.milliTimestamp());
    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    var gossip = try GossipNode(Effects).init(&fba, now, .{
        .effects = effects,
        .shred_version = ro.config.cluster_info.shred_version,
        .socket_map = sockets.asSocketMap(),
        .entrypoints = ro.config.cluster_info.getEntryAddresses(),
    });

    var it = rw.net_pair.recv.get(.reader);
    while (true) {
        now = @intCast(std.time.milliTimestamp());
        try gossip.poll(now);

        const packet = it.next() orelse continue;
        gossip.processPacket(now, packet);
        it.markUsed();
    }
}
