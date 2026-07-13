const std = @import("std");
const sig = @import("../../sig.zig");
const shred_network = @import("../lib.zig");

const socket_utils = sig.net.socket_utils;

const AtomicBool = std.atomic.Value(bool);
const AtomicU64 = std.atomic.Value(u64);
const Random = std.Random;
const UdpSocket = sig.net.UdpSocket;

const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Duration = sig.time.Duration;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const ShredId = sig.ledger.shred.ShredId;
const Slot = sig.core.Slot;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;

const ShredDeduper = shred_network.shred_deduper.ShredDeduper;
const TurbineTree = shred_network.turbine_tree.TurbineTree;
const TurbineTreeCache = shred_network.turbine_tree.TurbineTreeCache;

const Logger = sig.trace.Logger("shred_retransmitter");

const globalRegistry = sig.prometheus.globalRegistry;

/// Shred deduper configuration from agave
const DEDUPER_MAX_DUPLICATE_COUNT: usize = 2;
const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
const DEDUPER_RESET_CYCLE: Duration = Duration.fromSecs(5 * 60);
const DEDUPER_NUM_BITS: u64 = 637_534_199;

pub const ShredRetransmitterParams = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_tracker: *sig.core.EpochTracker,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    receiver: *Channel(Packet),
    maybe_num_retransmit_threads: ?usize,
    overwrite_stake_for_testing: bool,
    exit: *AtomicBool,
    rand: Random,
    logger: Logger,
    forward_shreds_to: ?sig.net.SocketAddr = null,
    max_retransmit_slot: *AtomicU64,
};

/// Retransmit Service
/// The retransmit service receives verified shreds from the shred network and retransmits them to the network.
/// The retransmit service is broken down into two main components:
/// 1. receiveShreds: runs on a single thread and receives shreds from the shred network, deduplicates them, and then packages them
///    into RetransmitShredInfo's which are sent to a channel for further processing.
/// 2. retransmitShreds: runs on N threads and receives RetransmitShredInfo's from the channel, computes the children to retransmit to
///    and then constructs and sends packets to the network.
pub fn runShredRetransmitter(params: ShredRetransmitterParams) !void {
    errdefer {
        params.logger.info().log("retransmit service failed");
        params.exit.store(false, .monotonic);
    }
    const num_retransmit_threads = params.maybe_num_retransmit_threads orelse
        @max(try std.Thread.getCpuCount(), 8);
    params.logger.info().logf("starting retransmit service: num_retransmit_threads={}", .{
        num_retransmit_threads,
    });

    var metrics = try RetransmitServiceMetrics.init();

    var receive_to_retransmit_channel = try Channel(RetransmitShredInfo).init(params.allocator);
    defer receive_to_retransmit_channel.deinit();

    var retransmit_to_socket_channel = try Channel(Packet).init(params.allocator);
    defer retransmit_to_socket_channel.deinit();

    const retransmit_socket: UdpSocket = try .create(.ipv4);
    defer retransmit_socket.close();
    try retransmit_socket.bind(.initIp4(.{ 0, 0, 0, 0 }, 0));

    var thread_handles = std.array_list.Managed(std.Thread).init(params.allocator);
    defer thread_handles.deinit();

    try thread_handles.append(try std.Thread.spawn(
        .{},
        receiveShreds,
        .{
            params.allocator,
            params.my_contact_info,
            params.epoch_tracker,
            params.receiver,
            &receive_to_retransmit_channel,
            params.gossip_table_rw,
            params.rand,
            params.exit,
            params.logger,
            &metrics,
            params.overwrite_stake_for_testing,
            params.forward_shreds_to,
            params.max_retransmit_slot,
        },
    ));

    for (0..num_retransmit_threads) |_| {
        try thread_handles.append(try std.Thread.spawn(
            .{},
            retransmitShreds,
            .{
                params.allocator,
                &receive_to_retransmit_channel,
                &retransmit_to_socket_channel,
                &metrics,
                params.exit,
            },
        ));
    }

    const sender_thread = try socket_utils.SocketThread.spawnSender(
        params.allocator,
        .from(params.logger),
        retransmit_socket,
        &retransmit_to_socket_channel,
        .{ .unordered = params.exit },
        .empty,
    );
    defer sender_thread.join();

    for (thread_handles.items) |thread| thread.join();
}

/// Receive shreds from the network, deduplicate them, and then package
/// them into RetransmitShredInfo's to be sent to the retransmit shred threads.
fn receiveShreds(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    epoch_tracker: *sig.core.EpochTracker,
    receiver: *Channel(Packet),
    sender: *Channel(RetransmitShredInfo),
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    rand: Random,
    exit: *AtomicBool,
    logger: Logger,
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
    forward_shreds_to: ?sig.net.SocketAddr,
    max_retransmit_slot: *AtomicU64,
) !void {
    var turbine_tree_cache = TurbineTreeCache.init(allocator);
    defer turbine_tree_cache.deinit();

    const forward_addr, var forward_socket = if (forward_shreds_to) |a| blk: {
        const sock: UdpSocket = try .create(a.getFamily());
        errdefer sock.close();
        try sock.bindToPort(0);
        break :blk .{ a.toAddress(), sock };
    } else .{ null, null };
    defer if (forward_socket) |s| s.close();

    var deduper = try ShredDeduper(2).init(
        allocator,
        rand,
        DEDUPER_NUM_BITS,
    );
    defer deduper.deinit();

    var shreds = std.array_list.Managed(Packet).init(allocator);
    var receive_shreds_timer = sig.time.Timer.start();

    while (true) {
        receiver.waitToReceive(.{ .unordered = exit }) catch break;
        receive_shreds_timer.reset();

        const receiver_len = receiver.len();
        if (receiver_len == 0) continue;

        shreds.clearRetainingCapacity();
        try shreds.ensureTotalCapacity(receiver_len);

        while (receiver.tryReceive()) |packet| try shreds.append(packet);

        if (shreds.items.len == 0) continue;

        const bytes_filter_saturated, const shred_id_filter_saturated = deduper.maybeReset(
            rand,
            DEDUPER_FALSE_POSITIVE_RATE,
            DEDUPER_RESET_CYCLE,
        );
        metrics.shred_byte_filter_saturated.set(@intFromBool(bytes_filter_saturated));
        metrics.shred_id_filter_saturated.set(@intFromBool(shred_id_filter_saturated));

        var grouped_shreds = try dedupAndGroupShredsBySlot(
            allocator,
            &shreds,
            &deduper,
            metrics,
        );
        defer {
            for (grouped_shreds.values()) |arr| arr.deinit();
            grouped_shreds.deinit();
        }

        if (grouped_shreds.count() > 0) {
            try createAndSendRetransmitInfo(
                allocator,
                grouped_shreds,
                my_contact_info,
                epoch_tracker,
                gossip_table_rw,
                &turbine_tree_cache,
                sender,
                metrics,
                overwrite_stake_for_testing,
                max_retransmit_slot,
            );
        }

        metrics.shreds_received_count.add(shreds.items.len);
        metrics.receive_shreds_nanos.observe(receive_shreds_timer.read().asNanos());

        metrics.maybeLog(logger);

        // Forward raw shreds for v2 testing.
        if (forward_socket) |*sock| {
            for (shreds.items) |p| _ = sock.sendTo(
                forward_addr.?,
                p.buffer[0..p.size],
            ) catch |err| logger.err().logf("failed to forward shred: {}", .{err});
        }
    }
}

/// Group shreds by slot and deduplicate them in the process
/// Returns a map of slot to a list of shred_id and packet pairs
fn dedupAndGroupShredsBySlot(
    allocator: std.mem.Allocator,
    shreds: *std.array_list.Managed(Packet),
    deduper: *ShredDeduper(2),
    metrics: *RetransmitServiceMetrics,
) !std.AutoArrayHashMap(Slot, std.array_list.Managed(ShredIdAndPacket)) {
    var dedup_and_group_shreds_timer = sig.time.Timer.start();
    var result: std.AutoArrayHashMap(Slot, std.array_list.Managed(ShredIdAndPacket)) =
        .init(allocator);
    for (shreds.items) |shred_packet| {
        const shred_id = try sig.ledger.shred.layout.getShredId(&shred_packet);

        switch (deduper.dedup(&shred_id, &shred_packet.buffer, DEDUPER_MAX_DUPLICATE_COUNT)) {
            .byte_duplicate => {
                metrics.shred_byte_filtered_count.inc();
                continue;
            },
            .shred_id_duplicate => {
                metrics.shred_id_filtered_count.inc();
                continue;
            },
            .not_duplicate => {},
        }

        if (result.getEntry(shred_id.slot)) |entry| {
            try entry.value_ptr.append(.{ shred_id, shred_packet });
        } else {
            var new_slot_shreds = std.array_list.Managed(ShredIdAndPacket).init(allocator);
            try new_slot_shreds.append(.{ shred_id, shred_packet });
            try result.put(shred_id.slot, new_slot_shreds);
        }
    }
    metrics.dedup_and_group_shreds_nanos.observe(dedup_and_group_shreds_timer.read().asNanos());
    return result;
}

/// Create and send retransmit info to the retransmit shred threads
/// Retransmit info contains the slot leader, the shred_id, the shred_packet, and the turbine_tree
fn createAndSendRetransmitInfo(
    allocator: std.mem.Allocator,
    shreds: std.AutoArrayHashMap(Slot, std.array_list.Managed(ShredIdAndPacket)),
    my_contact_info: ThreadSafeContactInfo,
    epoch_tracker: *sig.core.EpochTracker,
    gossip_table_rw: *RwMux(sig.gossip.GossipTable),
    turbine_tree_cache: *TurbineTreeCache,
    retransmit_shred_sender: *Channel(RetransmitShredInfo),
    metrics: *RetransmitServiceMetrics,
    overwrite_stake_for_testing: bool,
    max_retransmit_slot: *AtomicU64,
) !void {
    var create_and_send_retransmit_info_timer = sig.time.Timer.start();
    const leader_schedules_with_infos = epoch_tracker.getLeaderSchedules() catch return;
    defer leader_schedules_with_infos.release();
    const leader_schedule = leader_schedules_with_infos.leader_schedules;
    for (shreds.keys(), shreds.values()) |slot, slot_shreds| {
        _ = max_retransmit_slot.fetchMax(slot, .monotonic);
        // NOTE: On transition boundaries we might want ancestors here so that we can get stakes
        // for the new epoch which will be unrooted for a period of time.
        const epoch = epoch_tracker.epoch_schedule.getEpoch(slot);
        const epoch_info = epoch_tracker.getEpochInfo(slot) catch continue;
        defer epoch_info.release();
        const epoch_staked_nodes = &epoch_info.stakes.stakes.vote_accounts.staked_nodes;

        var get_slot_leader_timer = sig.time.Timer.start();
        // We should always have a leader schedule the aggregate leader schedule contains leaders
        // for the current and next epoch.
        const slot_leader = try leader_schedule.getLeader(slot);
        metrics.get_slot_leader_nanos.observe(get_slot_leader_timer.read().asNanos());

        var get_turbine_tree_timer = sig.time.Timer.start();
        const turbine_tree = if (try turbine_tree_cache.get(epoch)) |tree| tree else blk: {
            const turbine_tree = try allocator.create(TurbineTree);
            turbine_tree.* = try TurbineTree.initForRetransmit(
                allocator,
                my_contact_info,
                gossip_table_rw,
                epoch_staked_nodes,
                overwrite_stake_for_testing,
            );
            try turbine_tree_cache.put(epoch, turbine_tree);
            break :blk turbine_tree;
        };
        defer turbine_tree.releaseUnsafe();
        metrics.get_turbine_tree_nanos.observe(get_turbine_tree_timer.read().asNanos());

        for (slot_shreds.items) |shred_id_and_packet| {
            try retransmit_shred_sender.send(.{
                .slot_leader = slot_leader,
                // CAUTION: .acquireUnsafe() is used here as the turbine_tree is guaranteed to be valid since:
                // 1. the turbine_tree_provider has one exactly on reference to the turbine_tree after getTurbineTree
                // 2. each call to .aquireUnsafe() increments the reference count by 1
                // 3. there is exactly one call to .release() per send (see RetransmitShredInfo.deinit and retransmitShreds)
                .turbine_tree = turbine_tree.acquireUnsafe(),
                .shred_id = shred_id_and_packet[0],
                .shred_packet = shred_id_and_packet[1],
            });
        }
    }
    metrics.create_and_send_retransmit_info_nanos.observe(
        create_and_send_retransmit_info_timer.read().asNanos(),
    );
}

/// Retransmit shreds to nodes in the network
/// RetransmitShredInfo contains the shred_id, the shred_packet, the slot_leader, and the turbine_tree
/// The shred_id and slot_leader are used to seed an rng for shuffling the nodes in the turbine_tree before
/// computing the children to retransmit to.
fn retransmitShreds(
    allocator: std.mem.Allocator,
    receiver: *Channel(RetransmitShredInfo),
    sender: *Channel(Packet),
    metrics: *RetransmitServiceMetrics,
    exit: *AtomicBool,
) !void {
    var children = try std.array_list.Managed(TurbineTree.Node).initCapacity(
        allocator,
        TurbineTree.getDataPlaneFanout(),
    );
    defer children.deinit();
    var shuffled_nodes = std.array_list.Managed(TurbineTree.Node).init(allocator);
    defer shuffled_nodes.deinit();

    while (!exit.load(.acquire)) {
        var retransmit_shred_timer = sig.time.Timer.start();

        // NOTE: multiple `retransmitShreds` run concurrently so we can't use
        // `receiver.waitToReceive()` here as it only supports one caller thread.
        const retransmit_info: RetransmitShredInfo = receiver.tryReceive() orelse continue;
        defer retransmit_info.turbine_tree.releaseUnsafe();

        children.clearRetainingCapacity();
        shuffled_nodes.clearRetainingCapacity();
        var get_retransmit_children_timer = sig.time.Timer.start();
        const level = try retransmit_info.turbine_tree.getRetransmitChildren(
            &children,
            &shuffled_nodes,
            retransmit_info.slot_leader,
            retransmit_info.shred_id,
            TurbineTree.getDataPlaneFanout(),
        );

        metrics.turbine_tree_get_children_nanos.observe(
            get_retransmit_children_timer.read().asNanos(),
        );

        var children_with_addresses_count: usize = 0;
        for (children.items) |child| {
            if (child.tvuAddress()) |tvu_address| {
                children_with_addresses_count += 1;
                try sender.send(Packet.init(
                    tvu_address,
                    retransmit_info.shred_packet.buffer,
                    retransmit_info.shred_packet.size,
                ));
            }
        }

        if (children_with_addresses_count > 0) {
            metrics.shreds_sent_count.inc();
        }

        metrics.turbine_tree_level.set(level);
        metrics.turbine_tree_children.set(children.items.len);
        metrics.turbine_tree_children_with_addresses.set(children_with_addresses_count);
        metrics.retransmit_shred_nanos.observe(retransmit_shred_timer.read().asNanos());
    }
}

const ShredIdAndPacket = struct {
    ShredId,
    Packet,
};

const RetransmitShredInfo = struct {
    shred_id: ShredId,
    shred_packet: Packet,
    slot_leader: Pubkey,
    turbine_tree: *TurbineTree,
};

pub const RetransmitServiceMetrics = struct {
    // receiveShreds
    shreds_received_count: *Counter,
    shred_byte_filter_saturated: *Gauge(u64),
    shred_id_filter_saturated: *Gauge(u64),
    receive_shreds_nanos: *Histogram,

    // dedupAndGroupShredsBySlot
    shred_byte_filtered_count: *Counter,
    shred_id_filtered_count: *Counter,
    dedup_and_group_shreds_nanos: *Histogram,

    // createAndSendRetransmitInfo
    get_slot_leader_nanos: *Histogram,
    get_turbine_tree_nanos: *Histogram,
    create_and_send_retransmit_info_nanos: *Histogram,

    // retransmitShreds
    shreds_sent_count: *Counter,
    turbine_tree_level: *Gauge(u64),
    turbine_tree_children: *Gauge(u64),
    turbine_tree_children_with_addresses: *Gauge(u64),
    turbine_tree_get_children_nanos: *Histogram,
    retransmit_shred_nanos: *Histogram,

    // logging info
    logging_fields: struct {
        last_log_instant: sig.time.Instant,
    },

    // metrics prefix
    pub const prefix = "retransmit_service";

    // histogram buckets
    pub const histogram_buckets: [10]f64 = .{
        10,   25,
        50,   100,
        250,  500,
        1000, 2500,
        5000, 10000,
    };

    pub fn init() !RetransmitServiceMetrics {
        var self: RetransmitServiceMetrics = undefined;
        std.debug.assert(try globalRegistry().initFields(&self) == 1);
        self.logging_fields = .{ .last_log_instant = sig.time.Instant.now() };
        return self;
    }

    pub fn maybeLog(self: *RetransmitServiceMetrics, logger: Logger) void {
        if (self.logging_fields.last_log_instant.elapsed().asMillis() > 250) {
            logger.info().logf(
                "turbine-retransmit: received={} retransmitted={} skipped={}:{}:{}",
                .{
                    self.shreds_received_count.get(),
                    self.shreds_sent_count.get(),
                    self.shred_byte_filtered_count.get() + self.shred_id_filtered_count.get(),
                    self.shred_byte_filtered_count.get(),
                    self.shred_id_filtered_count.get(),
                },
            );
            self.logging_fields.last_log_instant = sig.time.Instant.now();
        }
    }
};

test "createAndSendRetransmitInfo" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit();

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw: RwMux(sig.gossip.GossipTable) = .init(gossip_table);
    defer {
        const ptr: *sig.gossip.GossipTable, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        ptr.deinit();
    }

    var turbine_tree_cache = TurbineTreeCache.init(allocator);
    defer {
        // Save heap-allocated TurbineTree pointers before releasing references,
        // so we can free the allocations after the cache clears them.
        var ptrs: [8]*TurbineTree = undefined;
        var count: usize = 0;
        for (turbine_tree_cache.cache.values()) |entry| {
            ptrs[count] = entry.turbine_tree;
            count += 1;
        }
        turbine_tree_cache.deinit();
        for (ptrs[0..count]) |ptr| allocator.destroy(ptr);
    }

    var retransmit_channel = try Channel(RetransmitShredInfo).init(allocator);
    defer {
        while (retransmit_channel.tryReceive()) |info| info.turbine_tree.releaseUnsafe();
        retransmit_channel.deinit();
    }

    var metrics = try RetransmitServiceMetrics.init();

    const my_pubkey = Pubkey.initRandom(random);
    const my_contact_info = ThreadSafeContactInfo.initRandom(random, my_pubkey, 0);

    // Build input: one shred at slot 1
    var slot_shreds = std.array_list.Managed(ShredIdAndPacket).init(allocator);
    defer slot_shreds.deinit();
    try slot_shreds.append(.{
        ShredId{ .slot = 1, .index = 0, .shred_type = .data },
        Packet.init(.initIpv4(.{ 0, 0, 0, 0 }, 0), .{0} ** Packet.DATA_SIZE, 64),
    });

    var shreds_map: std.AutoArrayHashMap(Slot, std.array_list.Managed(ShredIdAndPacket)) = .init(
        allocator,
    );
    defer shreds_map.deinit();
    try shreds_map.put(1, slot_shreds);

    var max_retransmit_slot: AtomicU64 = .init(0);

    try createAndSendRetransmitInfo(
        allocator,
        shreds_map,
        my_contact_info,
        &epoch_tracker,
        &gossip_table_rw,
        &turbine_tree_cache,
        &retransmit_channel,
        &metrics,
        true, // overwrite_stake_for_testing
        &max_retransmit_slot,
    );

    try std.testing.expectEqual(@as(u64, 1), max_retransmit_slot.load(.monotonic));
}

test "forward: socket creation from SocketAddr for both families" {
    // Mirrors the inline socket creation in receiveShreds:
    //   const sock: UdpSocket = try .create(a.getFamily());
    //   try sock.bindToPort(0);
    {
        const v4_addr = sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
        const sock: UdpSocket = try .create(v4_addr.getFamily());
        defer sock.close();
        try sock.bindToPort(0);
    }
    {
        const v6_addr = sig.net.SocketAddr.initIpv6(.{0} ** 16, 0);
        const sock: UdpSocket = try .create(v6_addr.getFamily());
        defer sock.close();
        try sock.bindToPort(0);
    }
}

test "forward: null SocketAddr produces null socket" {
    // Mirrors the inline pattern:
    //   const forward_addr, var forward_socket = if (forward_shreds_to) |a| blk: { ... }
    //   else .{ null, null };
    const forward_shreds_to: ?sig.net.SocketAddr = null;
    const forward_addr, const forward_socket = if (forward_shreds_to) |a| blk: {
        const sock: UdpSocket = try .create(a.getFamily());
        errdefer sock.close();
        try sock.bindToPort(0);
        break :blk .{ a.toAddress(), sock };
    } else .{ @as(?std.net.Address, null), @as(?UdpSocket, null) };
    defer if (forward_socket) |s| s.close();

    try std.testing.expect(forward_addr == null);
    try std.testing.expect(forward_socket == null);
}

test "forward: sends raw packets via sendTo" {
    // Mirrors the inline forwarding in receiveShreds:
    //   for (shreds.items) |p| _ = sock.sendTo(forward_addr.?, p.buffer[0..p.size], ...) catch ...;
    var receiver = try UdpSocket.create(.ipv4);
    defer receiver.close();
    try receiver.bind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
    try receiver.setReadTimeout(250_000); // 250ms
    const receiver_addr = try receiver.getLocalEndPoint();

    var sender = try UdpSocket.create(.ipv4);
    defer sender.close();
    try sender.bindToPort(0);

    var p1: Packet = .ANY_EMPTY;
    p1.size = 3;
    p1.buffer[0] = 1;
    p1.buffer[1] = 2;
    p1.buffer[2] = 3;

    var p2: Packet = .ANY_EMPTY;
    p2.size = 1;
    p2.buffer[0] = 9;

    const shreds = [_]Packet{ p1, p2 };
    for (shreds) |p| _ = try sender.sendTo(receiver_addr, p.buffer[0..p.size]);

    var buf: [Packet.DATA_SIZE]u8 = undefined;
    const len1, _ = try receiver.receiveFrom(buf[0..]);
    const len2, _ = try receiver.receiveFrom(buf[0..]);
    try std.testing.expectEqual(@as(usize, 4), len1 + len2);
}

test "forward: no packets sends nothing" {
    var receiver = try UdpSocket.create(.ipv4);
    defer receiver.close();
    try receiver.bind(std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0));
    try receiver.setReadTimeout(50_000); // 50ms
    const receiver_addr = try receiver.getLocalEndPoint();

    var sender = try UdpSocket.create(.ipv4);
    defer sender.close();
    try sender.bindToPort(0);

    const empty = [_]Packet{};
    for (empty) |p| _ = try sender.sendTo(receiver_addr, p.buffer[0..p.size]);

    var buf: [Packet.DATA_SIZE]u8 = undefined;
    try std.testing.expectError(error.WouldBlock, receiver.receiveFrom(buf[0..]));
}
