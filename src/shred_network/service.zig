const std = @import("std");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.Random;

const Channel = sig.sync.Channel;
const GossipService = sig.gossip.GossipService;
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
const DuplicateShredHandler = shred_network.duplicate_shred_handler.DuplicateShredHandler;
const RepairPeerProvider = shred_network.repair_service.RepairPeerProvider;
const RepairRequester = shred_network.repair_service.RepairRequester;
const RepairService = shred_network.repair_service.RepairService;
const ShredReceiver = shred_network.shred_receiver.ShredReceiver;

/// Settings which instruct the Shred Network how to behave.
pub const ShredNetworkConfig = struct {
    root_slot: Slot,
    repair_port: u16,
    /// tvu port in agave
    turbine_recv_port: u16,
    retransmit: bool,
    dump_shred_tracker: bool,
    log_finished_slots: bool,
};

/// Resources that are required for the Shred Network to operate.
pub const ShredNetworkDependencies = struct {
    allocator: Allocator,
    logger: Logger,
    random: Random,
    ledger: *sig.ledger.Ledger,
    registry: *Registry(.{}),
    /// Shared exit indicator, used to shutdown the Shred Network.
    exit: *Atomic(bool),

    /// This validator's keypair
    my_keypair: *const KeyPair,
    /// Shared state that is read from gossip
    my_shred_version: *const Atomic(u16),
    /// Shared state that is read from gossip
    gossip_table_rw: *RwMux(GossipTable),
    my_contact_info: ThreadSafeContactInfo,
    epoch_tracker: *sig.core.EpochTracker,
    n_retransmit_threads: ?usize,
    overwrite_turbine_stake_for_testing: bool,

    /// RPC Observability
    rpc_hooks: ?*sig.rpc.Hooks = null,
    duplicate: ?struct {
        /// Data sent by gossip as it's observed.
        shred_receiver: *Channel(sig.gossip.data.DuplicateShred),
        /// Optional channel to send duplicate slot notifications to consensus.
        slots_sender: ?*Channel(Slot),
    },
    /// Optional push message queue mux for broadcasting duplicate shred proofs
    push_msg_queue_mux: ?*GossipService.PushMessageQueue,
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
    );
    const arena = service_manager.arena.allocator();
    const defers = &service_manager.defers; // use this instead of defer statements

    const repair_socket = try bindUdpReusable(conf.repair_port);
    const turbine_socket = try bindUdpReusable(conf.turbine_recv_port);

    // tracker (shared state, internal to Shred Network)
    const shred_tracker = try arena.create(BasicShredTracker);
    try shred_tracker.init(
        deps.allocator,
        conf.root_slot + 1,
        .from(deps.logger),
        deps.registry,
        conf.log_finished_slots,
    );
    try defers.deferCall(BasicShredTracker.deinit, .{shred_tracker});

    // channels (cant use arena as they need to alloc/free frequently &
    // potentially from multiple sender threads)
    const retransmit_channel = try Channel(Packet).create(deps.allocator);
    retransmit_channel.name = "retransmit channel (Packet)";
    try defers.deferCall(Channel(Packet).destroy, .{retransmit_channel});

    // receiver (threads)
    const duplicate_handler = DuplicateShredHandler{
        .ledger_reader = deps.ledger.reader(),
        .result_writer = deps.ledger.resultWriter(),
        .epoch_tracker = deps.epoch_tracker,
        .duplicate_slots_sender = if (deps.duplicate) |dupe| dupe.slots_sender else null,
        .push_msg_queue_mux = deps.push_msg_queue_mux,
        .keypair = deps.my_keypair,
        .logger = .from(deps.logger),
    };
    const shred_receiver = try arena.create(ShredReceiver);
    shred_receiver.* = try .init(deps.allocator, .from(deps.logger), deps.registry, .{
        .keypair = deps.my_keypair,
        .exit = deps.exit,
        .repair_socket = repair_socket,
        .turbine_socket = turbine_socket,
        .shred_version = deps.my_shred_version,
        .maybe_retransmit_shred_sender = if (conf.retransmit) retransmit_channel else null,
        .epoch_tracker = deps.epoch_tracker,
        .tracker = shred_tracker,
        .inserter = deps.ledger.shredInserter(),
        .duplicate_handler = duplicate_handler,
    });
    try defers.deferCall(ShredReceiver.deinit, .{ shred_receiver, deps.allocator });
    try service_manager.spawn(
        "Shred Receiver",
        ShredReceiver.run,
        .{ shred_receiver, deps.allocator },
    );

    // retransmitter (thread)
    if (conf.retransmit) {
        try service_manager.spawn(
            "Shred Retransmitter",
            shred_network.shred_retransmitter.runShredRetransmitter,
            .{shred_network.shred_retransmitter.ShredRetransmitterParams{
                .allocator = deps.allocator,
                .my_contact_info = deps.my_contact_info,
                .epoch_tracker = deps.epoch_tracker,
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

    // duplicate shred listener (thread)
    if (deps.duplicate) |duplicate| if (duplicate.slots_sender) |duplicate_slots_sender| {
        try service_manager.spawn(
            "Duplicate Shred Listener",
            shred_network.duplicate_shred_listener.recvLoop,
            .{
                deps.allocator,
                sig.trace.Logger("duplicate_shred_listener").from(deps.logger),
                shred_network.duplicate_shred_listener.RecvLoopParams{
                    .exit = .{ .unordered = deps.exit },
                    .duplicate_shred_receiver = duplicate.shred_receiver,
                    .handler = .{
                        .result_writer = deps.ledger.resultWriter(),
                        .ledger_reader = deps.ledger.reader(),
                        .duplicate_slots_sender = duplicate_slots_sender,
                        .shred_version = deps.my_shred_version,
                        .epoch_tracker = deps.epoch_tracker,
                    },
                },
            },
        );
    };

    if (conf.dump_shred_tracker) {
        try service_manager.spawn("dump shred tracker", struct {
            fn run(exit: *const Atomic(bool), trakr: *BasicShredTracker) !void {
                const file = try std.fs.cwd().createFile("shred-tracker.txt", .{});
                var write_buffer: [4096]u8 = undefined;
                while (!exit.load(.monotonic)) {
                    try file.seekTo(0);
                    try file.setEndPos(0);
                    var writer = file.writer(&write_buffer);
                    _ = trakr.print(&writer.interface) catch unreachable;
                    try writer.interface.flush();
                    std.Thread.sleep(std.time.ns_per_s);
                }
            }
        }.run, .{ deps.exit, shred_tracker });
    }

    return service_manager;
}

fn bindUdpReusable(port: u16) !sig.net.UdpSocket {
    var socket = try sig.net.UdpSocket.create(.ipv4);
    try socket.enablePortReuse(true);
    try socket.bindToPort(port);
    try socket.setReadTimeout(sig.net.SOCKET_TIMEOUT_US);
    return socket;
}

// This test verifies that the shred_network:
// - does not leak
// - shuts down promptly when requested
test "start and stop gracefully" {
    const allocator = std.testing.allocator;

    var prng_state: Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    var exit = Atomic(bool).init(false);

    var registry = Registry(.{}).init(allocator);
    defer registry.deinit();

    const keypair: KeyPair = .generate();
    const shred_version: Atomic(u16) = .init(0);
    const contact_info: ThreadSafeContactInfo = .initRandom(prng, .initRandom(prng), 0);

    var gossip_table: GossipTable = try .init(allocator, allocator);
    defer gossip_table.deinit();
    var gossip_table_rw: RwMux(GossipTable) = .init(gossip_table);

    var duplicate_shred_receiver: Channel(sig.gossip.data.DuplicateShred) = try .init(allocator);
    defer duplicate_shred_receiver.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var epoch_tracker: sig.core.EpochTracker = .init(.default, 0, .INIT);
    defer epoch_tracker.deinit(allocator);

    const config: ShredNetworkConfig = .{
        .root_slot = 0,
        .repair_port = 50304,
        .turbine_recv_port = 50305,
        .retransmit = true,
        .dump_shred_tracker = false,
        .log_finished_slots = false,
    };

    const deps: ShredNetworkDependencies = .{
        .allocator = allocator,
        .logger = .FOR_TESTS,
        .random = prng,
        .ledger = &state,
        .registry = &registry,
        .my_keypair = &keypair,
        .exit = &exit,
        .gossip_table_rw = &gossip_table_rw,
        .my_shred_version = &shred_version,
        .my_contact_info = contact_info,
        .n_retransmit_threads = 1,
        .overwrite_turbine_stake_for_testing = true,
        .epoch_tracker = &epoch_tracker,
        .duplicate = .{
            .shred_receiver = &duplicate_shred_receiver,
            .slots_sender = null,
        },
        .push_msg_queue_mux = null,
    };

    var timer: sig.time.Timer = .start();

    var shred_network_service = try start(config, deps);
    defer shred_network_service.deinit();

    exit.store(true, .monotonic);

    shred_network_service.join();

    // always completes in under 200ms in my testing.
    // set to 10s to avoid flakiness on extremely slow CI machines.
    try std.testing.expect(timer.read().lt(.fromSecs(10)));
}
