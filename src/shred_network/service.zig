const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.Random;
const Socket = network.Socket;

const Channel = sig.sync.Channel;
const EpochContextManager = sig.adapter.EpochContextManager;
const GossipTable = sig.gossip.GossipTable;
const Logger = sig.trace.Logger("shred_network.service");
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Registry = sig.prometheus.Registry;
const ServiceManager = sig.utils.service_manager.ServiceManager;
const Slot = sig.core.Slot;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const RepairPeerProvider = shred_network.repair_service.RepairPeerProvider;
const RepairRequester = shred_network.repair_service.RepairRequester;
const RepairService = shred_network.repair_service.RepairService;
const ShredReceiver = shred_network.shred_receiver.ShredReceiver;
const ShredReceiverMetrics = shred_network.shred_receiver.ShredReceiverMetrics;

/// Settings which instruct the Shred Network how to behave.
pub const ShredNetworkConfig = struct {
    start_slot: Slot,
    repair_port: u16,
    /// tvu port in agave
    turbine_recv_port: u16,
    retransmit: bool,
    dump_shred_tracker: bool,
};

/// Resources that are required for the Shred Network to operate.
pub const ShredNetworkDependencies = struct {
    allocator: Allocator,
    logger: Logger,
    random: Random,
    ledger_db: sig.ledger.LedgerDB,
    registry: *Registry(.{}),
    /// This validator's keypair
    my_keypair: *const KeyPair,
    /// Shared exit indicator, used to shutdown the Shred Network.
    exit: *Atomic(bool),
    /// Shared state that is read from gossip
    gossip_table_rw: *RwMux(GossipTable),
    /// Shared state that is read from gossip
    my_shred_version: *const Atomic(u16),
    my_contact_info: ThreadSafeContactInfo,
    epoch_context_mgr: *EpochContextManager,
    n_retransmit_threads: ?usize,
    overwrite_turbine_stake_for_testing: bool,
};

/// Start the Shred Network.
///
/// Initializes all state and spawns all threads.
/// Returns as soon as all the threads are running.
///
/// Returns a ServiceManager representing the Shred Network.
/// This can be used to join and deinit the Shred Network.
///
/// Analogous to a subset of [Tvu::new](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/turbine.rs#L119)
pub fn start(
    conf: ShredNetworkConfig,
    deps: ShredNetworkDependencies,
) !ServiceManager {
    var service_manager = ServiceManager.init(
        deps.allocator,
        .from(deps.logger),
        deps.exit,
        "shred network",
        .{},
        .{},
    );
    const arena = service_manager.arena.allocator();
    const defers = &service_manager.defers; // use this instead of defer statements

    const repair_socket = try bindUdpReusable(conf.repair_port);
    const turbine_socket = try bindUdpReusable(conf.turbine_recv_port);

    // channels (cant use arena as they need to alloc/free frequently & potentially from multiple sender threads)
    const unverified_shred_channel = try Channel(Packet).create(deps.allocator);
    try defers.deferCall(Channel(Packet).destroy, .{unverified_shred_channel});
    const shreds_to_insert_channel = try Channel(Packet).create(deps.allocator);
    try defers.deferCall(Channel(Packet).destroy, .{shreds_to_insert_channel});
    const retransmit_channel = try Channel(Packet).create(deps.allocator);
    try defers.deferCall(Channel(Packet).destroy, .{retransmit_channel});

    // receiver (threads)
    const shred_receiver = try arena.create(ShredReceiver);
    shred_receiver.* = .{
        .allocator = deps.allocator,
        .keypair = deps.my_keypair,
        .exit = deps.exit,
        .logger = .from(deps.logger),
        .repair_socket = repair_socket,
        .turbine_socket = turbine_socket,
        .unverified_shred_sender = unverified_shred_channel,
        .shred_version = deps.my_shred_version,
        .metrics = try deps.registry.initStruct(ShredReceiverMetrics),
        .root_slot = conf.start_slot -| 1,
    };
    try service_manager.spawn("Shred Receiver", ShredReceiver.run, .{shred_receiver});

    // verifier (thread)
    try service_manager.spawn(
        "Shred Verifier",
        shred_network.shred_verifier.runShredVerifier,
        .{
            deps.exit,
            deps.registry,
            unverified_shred_channel,
            shreds_to_insert_channel,
            if (conf.retransmit) retransmit_channel else null,
            deps.epoch_context_mgr.slotLeaders(),
        },
    );

    // tracker (shared state, internal to Shred Network)
    const shred_tracker = try arena.create(BasicShredTracker);
    shred_tracker.* = try BasicShredTracker.init(
        deps.allocator,
        conf.start_slot,
        .from(deps.logger),
        deps.registry,
    );
    try defers.deferCall(BasicShredTracker.deinit, .{shred_tracker});

    const shred_inserter = try arena.create(sig.ledger.ShredInserter);
    shred_inserter.* = try sig.ledger.ShredInserter.init(
        deps.allocator,
        .from(deps.logger),
        deps.registry,
        deps.ledger_db,
    );
    try defers.deferCall(sig.ledger.ShredInserter.deinit, .{shred_inserter});

    // processor (thread)
    try service_manager.spawn(
        "Shred Processor",
        shred_network.shred_processor.runShredProcessor,
        .{
            deps.allocator,
            deps.exit,
            shred_network.shred_processor.Logger.from(deps.logger),
            deps.registry,
            shreds_to_insert_channel,
            shred_tracker,
            shred_inserter,
            deps.epoch_context_mgr.slotLeaders(),
        },
    );

    // retransmitter (thread)
    if (conf.retransmit) {
        try service_manager.spawn(
            "Shred Retransmitter",
            shred_network.shred_retransmitter.runShredRetransmitter,
            .{shred_network.shred_retransmitter.ShredRetransmitterParams{
                .allocator = deps.allocator,
                .my_contact_info = deps.my_contact_info,
                .epoch_context_mgr = deps.epoch_context_mgr,
                .gossip_table_rw = deps.gossip_table_rw,
                .receiver = retransmit_channel,
                .maybe_num_retransmit_threads = deps.n_retransmit_threads,
                .overwrite_stake_for_testing = deps.overwrite_turbine_stake_for_testing,
                .exit = deps.exit,
                .rand = deps.random,
                .logger = .from(deps.logger),
            }},
        );
    }

    // repair (thread)
    const repair_peer_provider = try RepairPeerProvider.init(
        deps.allocator,
        deps.random,
        deps.registry,
        deps.gossip_table_rw,
        Pubkey.fromPublicKey(&deps.my_keypair.public_key),
        deps.my_shred_version,
    );
    const repair_requester = try RepairRequester.init(
        deps.allocator,
        .from(deps.logger),
        deps.random,
        deps.registry,
        deps.my_keypair,
        repair_socket,
        deps.exit,
    );
    const repair_svc = try arena.create(RepairService);
    try defers.deferCall(RepairService.deinit, .{repair_svc});
    repair_svc.* = try RepairService.init(
        deps.allocator,
        .from(deps.logger),
        deps.exit,
        deps.registry,
        repair_requester,
        repair_peer_provider,
        shred_tracker,
    );
    try service_manager.spawn("Repair Service", RepairService.run, .{repair_svc});

    if (conf.dump_shred_tracker) {
        try service_manager.spawn("dump shred tracker", struct {
            fn run(exit: *const Atomic(bool), trakr: *BasicShredTracker) !void {
                const file = try std.fs.cwd().createFile("shred-tracker.txt", .{});
                while (!exit.load(.monotonic)) {
                    try file.seekTo(0);
                    try file.setEndPos(0);
                    _ = trakr.print(file.writer()) catch unreachable;
                    std.time.sleep(std.time.ns_per_s);
                }
            }
        }.run, .{ deps.exit, shred_tracker });
    }

    return service_manager;
}

fn bindUdpReusable(port: u16) !Socket {
    var socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.udp);
    try sig.net.enablePortReuse(&socket, true);
    try socket.bindToPort(port);
    try socket.setReadTimeout(sig.net.SOCKET_TIMEOUT_US);
    return socket;
}

// This test verifies that the shred_network:
// - does not leak
// - shuts down promptly when requested
test "start and stop gracefully" {
    const allocator = std.testing.allocator;

    const config = ShredNetworkConfig{
        .start_slot = 0,
        .repair_port = 50304,
        .turbine_recv_port = 50305,
        .retransmit = true,
        .dump_shred_tracker = false,
    };

    var exit = Atomic(bool).init(false);

    var rng = Random.DefaultPrng.init(0);

    var registry = Registry(.{}).init(allocator);
    defer registry.deinit();

    const keypair = KeyPair.generate();
    const shred_version = Atomic(u16).init(0);
    const contact_info = try ThreadSafeContactInfo
        .initRandom(rng.random(), Pubkey.initRandom(rng.random()), 0);

    var gossip_table = try GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);

    var epoch_ctx = try EpochContextManager.init(allocator, sig.core.EpochSchedule.DEFAULT);
    defer epoch_ctx.deinit();

    var ledger_db = try sig.ledger.tests.TestDB.init(@src());
    defer ledger_db.deinit();

    const deps: ShredNetworkDependencies = .{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .random = rng.random(),
        .ledger_db = ledger_db,
        .registry = &registry,
        .my_keypair = &keypair,
        .exit = &exit,
        .gossip_table_rw = &gossip_table_rw,
        .my_shred_version = &shred_version,
        .my_contact_info = contact_info,
        .epoch_context_mgr = &epoch_ctx,
        .n_retransmit_threads = 1,
        .overwrite_turbine_stake_for_testing = true,
    };

    var timer = try sig.time.Timer.start();

    var shred_network_service = try start(config, deps);
    defer shred_network_service.deinit();

    exit.store(true, .monotonic);

    shred_network_service.join();

    // always completes in under 200 ms in my testing.
    // set to 2 s to avoid flakiness on extremely slow CI machines.
    try std.testing.expect(timer.read().lt(.fromSecs(2)));
}
