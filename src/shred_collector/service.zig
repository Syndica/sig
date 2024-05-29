const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = network.Socket;

const GossipTable = sig.gossip.GossipTable;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const ServiceManager = sig.utils.ServiceManager;
const Slot = sig.core.Slot;

const this = sig.shred_collector;
const BasicShredTracker = this.BasicShredTracker;
const RepairPeerProvider = this.RepairPeerProvider;
const RepairRequester = this.RepairRequester;
const RepairService = this.RepairService;
const ShredReceiver = this.ShredReceiver;

/// Settings which tell the Shred Collector how to behave.
pub const ShredCollectorConfig = struct {
    start_slot: ?Slot,
    repair_port: u16,
    tvu_port: u16,
};

/// Basic resources that are required for
/// the Shred Collector to operate.
pub const ShredCollectorDependencies = struct {
    allocator: Allocator,
    logger: Logger,
    random: Random,
    /// This validator's keypair
    my_keypair: *const KeyPair,
};

/// Interface between the Shred Collector and other components
/// that are external to the Shred Collector.
pub const ShredCollectorInterface = struct {
    /// Shared exit indicator, used to shutdown the Shred Collector.
    exit: *Atomic(bool),
    /// Shared state that is read from gossip
    gossip_table_rw: *RwMux(GossipTable),
    /// Shared state that is read from gossip
    my_shred_version: *const Atomic(u16),
    leader_schedule: LeaderScheduleCalculator,
};

pub const LeaderScheduleCalculator = struct {
    leader_schedule: []const sig.core.Pubkey,
    start_slot: sig.core.Slot,

    pub fn getLeader(self: *const @This(), slot: sig.core.Slot) ?sig.core.Pubkey {
        const index: usize = @intCast(slot - self.start_slot);
        return if (index >= self.leader_schedule.len) null else self.leader_schedule[index];
    }
};

/// Start the Shred Collector.
///
/// Initializes all state and spawns all threads.
/// Returns as soon as all the threads are running.
///
/// Returns a ServiceManager representing the Shred Collector.
/// This can be used to join and deinit the Shred Collector.
///
/// Analogous to a subset of [Tvu::new](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/tvu.rs#L119)
pub fn start(
    conf: ShredCollectorConfig,
    deps: ShredCollectorDependencies,
    interface: ShredCollectorInterface,
) !ServiceManager {
    var shred_collector = ServiceManager.init(deps.allocator, deps.logger, interface.exit, "shred collector", .{}, .{});
    var arena = shred_collector.arena();

    const repair_socket = try bindUdpReusable(conf.repair_port);
    const tvu_socket = try bindUdpReusable(conf.tvu_port);

    // tracker (shared state, internal to Shred Collector)
    const shred_tracker = try arena.create(BasicShredTracker);
    shred_tracker.* = BasicShredTracker.init(
        conf.start_slot,
        deps.logger,
    );

    // repair (thread)
    const repair_peer_provider = try RepairPeerProvider.init(
        deps.allocator,
        deps.random,
        interface.gossip_table_rw,
        Pubkey.fromPublicKey(&deps.my_keypair.public_key),
        interface.my_shred_version,
    );
    const repair_requester = try RepairRequester.init(
        deps.allocator,
        deps.logger,
        deps.random,
        deps.my_keypair,
        repair_socket,
        interface.exit,
    );
    const repair_svc = try arena.create(RepairService);
    try shred_collector.defers.deferCall(RepairService.deinit, .{repair_svc});
    repair_svc.* = RepairService.init(
        deps.allocator,
        deps.logger,
        interface.exit,
        repair_requester,
        repair_peer_provider,
        shred_tracker,
    );
    try shred_collector.spawnCustom(
        "Repair Service",
        RepairService.run_config,
        .{},
        RepairService.sendNecessaryRepairs,
        .{repair_svc},
    );

    // receiver (threads)
    const unverified_shreds_channel = sig.sync.Channel(std.ArrayList(sig.net.Packet)).init(
        deps.allocator,
        1000,
    );
    const verified_shreds_channel = sig.sync.Channel(std.ArrayList(sig.net.Packet)).init(
        deps.allocator,
        1000,
    );
    const shred_receiver = try arena.create(ShredReceiver);
    shred_receiver.* = ShredReceiver{
        .allocator = deps.allocator,
        .keypair = deps.my_keypair,
        .exit = interface.exit,
        .logger = deps.logger,
        .repair_socket = repair_socket,
        .tvu_socket = tvu_socket,
        .outgoing_shred_channel = unverified_shreds_channel,
        .shred_version = interface.my_shred_version,
    };
    try shred_collector.spawn("Shred Receiver", ShredReceiver.run, .{shred_receiver});

    // verifier (thread)
    try shred_collector.spawn(
        "Shred Verifier",
        sig.shred_collector.runShredSignatureVerification,
        .{
            interface.exit,
            unverified_shreds_channel,
            verified_shreds_channel,
            interface.leader_schedule,
        },
    );

    // processor (thread)
    try shred_collector.spawn(
        "Shred Processor",
        sig.shred_collector.processShreds,
        .{ deps.allocator, verified_shreds_channel, shred_tracker },
    );

    return shred_collector;
}

fn bindUdpReusable(port: u16) !Socket {
    var socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.udp);
    try sig.net.enablePortReuse(&socket, true);
    try socket.bindToPort(port);
    try socket.setReadTimeout(sig.net.SOCKET_TIMEOUT);
    return socket;
}
