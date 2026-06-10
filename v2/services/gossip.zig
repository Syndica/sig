//! Runs a node instance of the gossip protocol, passing around cluster information from the network
//! to other validator services.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tel = lib.telemetry;

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
    gossip_to_snapshot: *lib.snapshot.SnapshotSourceRing,
    tel: *tel.Region,
};

pub const ReadOnly = struct {
    config: *const lib.gossip.Config,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
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
        snapshot_writer: *lib.snapshot.SnapshotSourceRing.Iterator(.writer),

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

        pub fn reportSnapshotSource(
            self: Self,
            from: lib.solana.Pubkey,
            addr: std.net.Address,
            slot: lib.solana.Slot,
            hash: lib.solana.Hash,
        ) void {
            const entry = self.snapshot_writer.next() orelse return;
            entry.* = .{
                .from = from,
                .rpc_addr = .fromNetAddress(addr),
                .slot = slot,
                .hash = hash,
            };
            self.snapshot_writer.markUsed();
        }
    };

    var packet_writer = rw.net_pair.send.get(.writer);
    var snapshot_writer = rw.gossip_to_snapshot.get(.writer);
    const effects: Effects = .{
        .packet_writer = &packet_writer,
        .snapshot_writer = &snapshot_writer,
        .keypair = &ro.config.keypair,
    };

    // TODO: add .rpc for serving snapshots
    var sockets: lib.gossip.SocketMap.Builder = .{};
    sockets.set(.gossip, ro.config.cluster_info.public_ip.withPort(rw.net_pair.port));
    if (ro.config.advertise_tvu_port) {
        sockets.set(.tvu, ro.config.cluster_info.public_ip.withPort(ro.config.turbine_recv_port));
    }

    var now = lib.clock.wallclock(.ms);
    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    var gossip = try GossipNode(Effects).init(&fba, now, .{
        .effects = effects,
        .shred_version = ro.config.cluster_info.shred_version,
        .socket_map = sockets.asSocketMap(),
        .entrypoints = ro.config.cluster_info.getEntryAddresses(),
    });

    var it = rw.net_pair.recv.get(.reader);
    while (true) {
        now = lib.clock.wallclock(.ms);
        try gossip.poll(.from(logger), now);

        const packet = it.next() orelse {
            // TODO(ink): detect whether our output ring buffers (`packet_writer` and co)
            // are all empty, and only signal idle if they are.
            // For now this should work fine, but in theory there's a very slim chance
            // of a race condition (it should be basically impossible to manifest
            // in the one black-box test that currently exists for this).
            try runner.activity.signalIdleSpinning();
            continue;
        };
        try runner.activity.signalActive();
        gossip.processPacket(.from(logger), now, packet);
        it.markUsed();
    }
}
