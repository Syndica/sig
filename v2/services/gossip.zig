//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const Pair = lib.net.Pair;
const Packet = lib.net.Packet;

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;

const GossipNode = lib.gossip.GossipNode;
const SnapshotQueue = lib.accounts_db.SnapshotQueue;

comptime {
    _ = start;
}

pub const name = .gossip;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    net_pair: *Pair,
    snapshot_queue: *SnapshotQueue,
    tel: *tel.Region,
};

pub const ReadOnly = struct {
    config: *const lib.gossip.Config,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    logger.info().logf(
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
        snapshot_writer: *SnapshotQueue.Incoming.Iterator(.writer),

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

        pub fn onSnapshot(
            self: Self,
            slot_hash: lib.solana.SlotAndHash,
            rpc_addr: std.net.Address,
        ) void {
            // if SnapshotQueue is full, drop snapshot notifications
            // (receiver likely already busy with existing ones)
            const ptr = self.snapshot_writer.next() orelse return;
            ptr.slot_hash = slot_hash;
            ptr.rpc_address = rpc_addr;
            self.snapshot_writer.markUsed();
        }
    };

    var packet_writer = rw.net_pair.send.get(.writer);
    var snapshot_writer = rw.snapshot_queue.incoming.get(.writer);
    const effects: Effects = .{
        .packet_writer = &packet_writer,
        .keypair = &ro.config.keypair,
        .snapshot_writer = &snapshot_writer,
    };

    // TODO: add .rpc for serving snapshots
    var sockets: lib.solana.gossip.SocketMap.Builder = .{};
    {
        var public_ip = ro.config.cluster_info.public_ip;
        for ([_]struct { lib.solana.gossip.SocketMap.Key, u16 }{
            .{ .gossip, rw.net_pair.port },
            .{ .tvu, ro.config.turbine_recv_port },
        }) |entry| {
            const key, const port = entry;
            public_ip.setPort(port);
            sockets.set(key, public_ip);
        }
    }

    var now: u64 = @intCast(std.time.milliTimestamp());
    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    var gossip = try GossipNode(Effects).init(&fba, now, .{
        .effects = effects,
        .shred_version = ro.config.cluster_info.shred_version,
        .socket_map = sockets.asSocketMap(),
        .entrypoints = ro.config.cluster_info.getEntryAddresses(),
    });

    var snapshot_available = rw.snapshot_queue.outgoing.get(.reader);
    var packet_recv = rw.net_pair.recv.get(.reader);
    while (true) {
        now = @intCast(std.time.milliTimestamp());
        try gossip.poll(.from(logger), now);

        // Send snapshots made available over to gossip
        if (snapshot_available.next()) |slot_hash| {
            try gossip.insert(.from(logger), now, .{ .snapshot_hashes = .{
                .from = effects.getIdentity(),
                .full = slot_hash.*,
                .incremental = .{ .items = &.{} },
                .wallclock = now,
            } });
        }

        const packet = packet_recv.next() orelse continue;
        gossip.processPacket(.from(logger), now, packet);
        packet_recv.markUsed();
    }
}
