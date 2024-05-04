const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = network.Socket;

const BasicShredTracker = sig.tvu.BasicShredTracker;
const Channel = sig.sync.Channel;
const GossipTable = sig.gossip.GossipTable;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const RepairPeerProvider = sig.tvu.RepairPeerProvider;
const RepairRequester = sig.tvu.RepairRequester;
const RepairService = sig.tvu.RepairService;
const RwMux = sig.sync.RwMux;
const ServiceManager = sig.utils.ServiceManager;
const ShredReceiver = sig.tvu.ShredReceiver;
const Slot = sig.core.Slot;

const SOCKET_TIMEOUT = sig.net.SOCKET_TIMEOUT;

pub const TvuDependencies = struct {
    allocator: Allocator,
    logger: Logger,
    random: Random,
    /// This validator's keypair
    my_keypair: *const KeyPair,
    /// Shared exit indicator, used to shutdown the TVU.
    exit: *Atomic(bool),
    /// Shared state from gossip
    gossip_table_rw: *RwMux(GossipTable),
    /// Shared state from gossip
    my_shred_version: *const Atomic(u16),
};

/// communication with non-tvu components
pub const TvuCommunication = struct {}; // TODO take from deps

pub const TvuConfig = struct {
    start_slot: ?Slot,
    repair_port: u16,
    tvu_port: u16,
};

pub fn spawnTvu(deps: TvuDependencies, conf: TvuConfig) !ServiceManager {
    var tvu_manager = ServiceManager.init(deps.allocator, deps.logger, deps.exit);

    var repair_socket = try bindUdpReusable(conf.repair_port);
    var tvu_socket = try bindUdpReusable(conf.tvu_port);

    // tracker (shared state)
    const shred_tracker = try tvu_manager.create(sig.tvu.BasicShredTracker, null);
    shred_tracker.* = sig.tvu.BasicShredTracker.init(
        conf.start_slot orelse 0, // TODO
        deps.logger,
    );

    // repair (thread)
    const repair_peer_provider = try RepairPeerProvider.init(
        deps.allocator,
        deps.random,
        deps.gossip_table_rw,
        Pubkey.fromPublicKey(&deps.my_keypair.public_key),
        deps.my_shred_version,
    );
    const repair_requester = try RepairRequester.init(
        deps.allocator,
        deps.logger,
        deps.random,
        deps.my_keypair,
        &repair_socket,
        deps.exit,
    );
    const repair_svc = try tvu_manager.create(RepairService, RepairService.deinit);
    repair_svc.* = RepairService.init(
        deps.allocator,
        deps.logger,
        deps.exit,
        repair_requester,
        repair_peer_provider,
        shred_tracker,
        conf.start_slot,
    );
    try tvu_manager.spawn(
        .{ .name = "Repair Service", .min_loop_duration_ns = 100 * std.time.ns_per_ms },
        RepairService.sendNecessaryRepairs,
        .{repair_svc},
    );

    // receiver (thread)
    const unverified_shreds_channel = sig.sync.Channel(std.ArrayList(sig.net.Packet)).init(
        deps.allocator,
        1000,
    );
    const verified_shreds_channel = sig.sync.Channel(std.ArrayList(sig.net.Packet)).init(
        deps.allocator,
        1000,
    );
    const shred_receiver = try tvu_manager.create(ShredReceiver, null);
    shred_receiver.* = ShredReceiver{
        .allocator = deps.allocator,
        .keypair = deps.my_keypair,
        .exit = deps.exit,
        .logger = deps.logger,
        .repair_socket = &repair_socket,
        .tvu_socket = &tvu_socket,
        .outgoing_shred_channel = unverified_shreds_channel,
        .shred_version = deps.my_shred_version,
    };
    try tvu_manager.spawn(.{ .name = "Shred Receiver" }, ShredReceiver.run, .{shred_receiver});

    // verifier (thread)
    try tvu_manager.spawn(
        .{ .name = "Shred Verifier" },
        sig.tvu.runShredSignatureVerification,
        .{ deps.exit, unverified_shreds_channel, verified_shreds_channel, .{} },
    );

    // processor (thread)
    try tvu_manager.spawn(
        .{ .name = "Shred Processor" },
        sig.tvu.processShreds,
        .{ deps.allocator, verified_shreds_channel, shred_tracker },
    );

    return tvu_manager;
}

fn bindUdpReusable(port: u16) !Socket {
    var socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.udp);
    try sig.net.enablePortReuse(&socket, true);
    try socket.bindToPort(port);
    try socket.setReadTimeout(sig.net.SOCKET_TIMEOUT);
    return socket;
}
