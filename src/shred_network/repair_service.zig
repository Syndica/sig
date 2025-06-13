const std = @import("std");
const zig_network = @import("zig-network");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.Random;
const Socket = zig_network.Socket;

const ContactInfo = sig.gossip.ContactInfo;
const Counter = sig.prometheus.Counter;
const Duration = sig.time.Duration;
const Gauge = sig.prometheus.Gauge;
const GossipTable = sig.gossip.GossipTable;
const Histogram = sig.prometheus.Histogram;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;
const LruCacheCustom = sig.utils.lru.LruCacheCustom;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const Registry = sig.prometheus.Registry;
const RwMux = sig.sync.RwMux;
const SignedGossipData = sig.gossip.SignedGossipData;
const SocketAddr = sig.net.SocketAddr;
const SocketThread = sig.net.SocketThread;
const Channel = sig.sync.Channel;
const Slot = sig.core.Slot;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const MultiSlotReport = shred_network.shred_tracker.MultiSlotReport;
const RepairRequest = shred_network.repair_message.RepairRequest;
const RepairMessage = shred_network.repair_message.RepairMessage;

const serializeRepairRequest = shred_network.repair_message.serializeRepairRequest;

const MAX_DATA_SHREDS_PER_SLOT = sig.ledger.shred.DataShred.constants.max_per_slot;

/// Identifies which repairs are needed and sends them
/// - delegates to RepairPeerProvider to identify repair peers.
/// - delegates to RepairRequester to send the requests.
///
/// Analogous to [RepairService](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/core/src/repair/repair_service.rs#L245)
pub const RepairService = struct {
    allocator: Allocator,
    requester: RepairRequester,
    peer_provider: RepairPeerProvider,
    shred_tracker: *BasicShredTracker,
    logger: ScopedLogger(@typeName(Self)),
    exit: *Atomic(bool),
    /// memory to re-use across iterations. initialized to empty
    report: MultiSlotReport,
    thread_pool: RequestBatchThreadPool,
    metrics: Metrics,
    prng: std.Random.DefaultPrng,

    pub const RequestBatchThreadPool = HomogeneousThreadPool(struct {
        requester: *RepairRequester,
        requests: []const AddressedRepairRequest,

        pub fn run(self: *@This()) !void {
            return self.requester.sendRepairRequestBatch(self.requests);
        }
    });

    const Metrics = struct {
        request_count: *Counter,
        oldest_slot_needing_repair: *Gauge(u64),
        newest_slot_needing_repair: *Gauge(u64),

        batch_size: *Histogram,
        batch_process_time: *Histogram,
        last_batch_size: *Gauge(u64),
        last_batch_process_time: *Gauge(f64),

        pub const prefix = "repair_service";

        pub fn histogramBucketsForField(name: []const u8) []const f64 {
            return if (std.mem.eql(u8, name, "batch_size"))
                &.{ 0, 1, 3, 10, 30, 100, 300, 1000, 3_000, 10_000, 30_000, 100_000 }
            else if (std.mem.eql(u8, name, "batch_process_time"))
                &.{ 0, 0.000_1, 0.001, 0.01, 0.1, 1, 10, 100, 1_000 }
            else
                unreachable;
        }
    };

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        exit: *Atomic(bool),
        registry: *Registry(.{}),
        requester: RepairRequester,
        peer_provider: RepairPeerProvider,
        shred_tracker: *BasicShredTracker,
    ) !Self {
        const n_threads = maxRequesterThreads();
        return RepairService{
            .allocator = allocator,
            .requester = requester,
            .peer_provider = peer_provider,
            .shred_tracker = shred_tracker,
            .logger = logger.withScope(@typeName(Self)),
            .exit = exit,
            .report = MultiSlotReport.init(allocator),
            .thread_pool = try RequestBatchThreadPool.init(allocator, n_threads, n_threads),
            .metrics = try registry.initStruct(Metrics),
            .prng = std.Random.DefaultPrng.init(0),
        };
    }

    pub fn deinit(self: *Self) void {
        self.exit.store(true, .release);
        self.peer_provider.deinit();
        self.requester.deinit();
        self.thread_pool.deinit(self.allocator);
        self.report.deinit();
    }

    pub fn run(self: *Self) !void {
        var waiting_for_peers = false;
        var timer = try sig.time.Timer.start();
        while (!self.exit.load(.acquire)) {
            timer.reset();
            var num_repairs_sent: usize = 0;
            if (self.sendNecessaryRepairs()) |count| {
                num_repairs_sent = count;
                if (waiting_for_peers) {
                    waiting_for_peers = false;
                    self.logger.info().logf("Acquired some repair peers.", .{});
                }
            } else |e| switch (e) {
                error.NoRepairPeers => if (!waiting_for_peers) {
                    self.logger.info().logf("Waiting for repair peers...", .{});
                    waiting_for_peers = true;
                },
                else => return e,
            }
            const last_iteration = timer.lap();

            self.metrics.batch_size.observe(num_repairs_sent);
            self.metrics.batch_process_time.observe(last_iteration.asSecsFloat());
            self.metrics.last_batch_size.set(num_repairs_sent);
            self.metrics.last_batch_process_time.set(last_iteration.asSecsFloat());

            sleepRepair(num_repairs_sent, last_iteration);
        }
    }

    /// Identifies which repairs are needed based on the current state,
    /// and sends those repairs, then returns the number of repairs.
    pub fn sendNecessaryRepairs(self: *Self) !usize {
        const repair_requests = try self.getRepairs();
        defer repair_requests.deinit();
        self.metrics.request_count.add(repair_requests.items.len);
        const addressed_requests = try self.assignRequestsToPeers(repair_requests.items);
        defer addressed_requests.deinit();

        if (addressed_requests.items.len < 4) {
            try self.requester.sendRepairRequestBatch(addressed_requests.items);
        } else {
            const num_threads = numRequesterThreads(addressed_requests.items.len);
            for (0..num_threads) |i| {
                const start = (addressed_requests.items.len * i) / num_threads;
                const end = (addressed_requests.items.len * (i + 1)) / num_threads;
                try self.thread_pool.schedule(self.allocator, .{
                    .requester = &self.requester,
                    .requests = addressed_requests.items[start..end],
                });
            }
            try self.thread_pool.joinFallible();
        }

        return addressed_requests.items.len;
    }

    /// The maximum number of `.Shred` repairs to request.
    ///
    /// Supports the maximum number of shreds that could possibly be generated
    /// during a repair loop iteration. This ensures it is always possible to
    /// catch up, assuming the current hardware is powerful enough.
    const MAX_SHRED_REPAIRS = (MAX_DATA_SHREDS_PER_SLOT * MAX_REPAIR_LOOP_DURATION_TARGET.asMillis()) / 400;

    fn getRepairs(self: *Self) !ArrayList(RepairRequest) {
        var oldest_slot_needing_repair: u64 = 0;
        var newest_slot_needing_repair: u64 = 0;
        var repairs = ArrayList(RepairRequest).init(self.allocator);
        if (!try self.shred_tracker.identifyMissing(&self.report, sig.time.clock.sample())) {
            return repairs;
        }
        var individual_count: usize = 0;
        var highest_count: usize = 0;
        var slot: Slot = 0;

        // request every shred that is reported missing, up to MAX_SHRED_REPAIRS
        for (self.report.items()) |*report| {
            slot = report.slot;
            oldest_slot_needing_repair = @min(slot, oldest_slot_needing_repair);
            newest_slot_needing_repair = @max(slot, newest_slot_needing_repair);
            if (individual_count < MAX_SHRED_REPAIRS) {
                for (report.missing_shreds.items) |shred_window| mid_loop: {
                    if (shred_window.end) |end| {
                        for (shred_window.start..end) |i| {
                            if (individual_count > MAX_SHRED_REPAIRS) break :mid_loop;
                            individual_count += 1;
                            try repairs.append(.{ .Shred = .{ slot, i } });
                        }
                    }
                }
            }
            highest_count += 1;
            try repairs.append(.{ .HighestShred = .{ slot, 0 } });
        }

        // eagerly request the next unknown slot in case turbine is laggy
        try repairs.append(.{ .HighestShred = .{ slot + 1, 0 } });

        // request ahead to detect if caught behind. use jitter to avoid skipped slots
        const num_slots_ahead = self.prng.random().intRangeAtMost(u32, 10, 50);
        try repairs.append(.{ .HighestShred = .{ slot + num_slots_ahead, 0 } });

        self.metrics.oldest_slot_needing_repair.set(oldest_slot_needing_repair);
        self.metrics.newest_slot_needing_repair.set(newest_slot_needing_repair);

        return repairs;
    }

    fn assignRequestsToPeers(
        self: *Self,
        requests: []const RepairRequest,
    ) !ArrayList(AddressedRepairRequest) {
        var addressed = ArrayList(AddressedRepairRequest).init(self.allocator);
        for (requests) |request| {
            if (try self.peer_provider.getRandomPeer(request.slot())) |peer| {
                try addressed.append(.{
                    .request = request,
                    .recipient = peer.pubkey,
                    .recipient_addr = peer.serve_repair_socket,
                });
            }
            // TODO do something if a peer is not found?
        }
        return addressed;
    }
};

/// Returns the number of threads that should be used to send this many repair
/// requests.
///
/// Allows the number of repair requester threads to scale up when a lot of
/// repairs are necessary, and scale down during normal operation.
fn numRequesterThreads(num_requests: usize) usize {
    const target_requests_per_thread = 100;
    const target_threads = num_requests / target_requests_per_thread;
    return @max(1, @min(target_threads, maxRequesterThreads()));
}

/// Sets the maximum number of repair threads to either 16 or half the cpu
/// count, whatever is less.
fn maxRequesterThreads() u32 {
    const cpu_count = std.Thread.getCpuCount() catch 1;
    return @min(16, cpu_count / 2);
}

/// Sleeps an appropriate duration after sending some repair requests.
///
/// This avoids sending massive numbers of redundant requests when we're far
/// behind, while allowing low latency to fill small gaps when we're caught up.
/// It also ensures the repair service does not hog resources 100% of the time,
/// so turbine can get a chance to start keeping up on its own.
///
/// The numbers and logic here are somewhat arbitrary, but this was tuned to
/// work well during testing and should not be modified without thorough
/// testing. If the thread allocation strategy for the repair service changes
/// dramatically, it will likely make sense to revise this sleeping approach.
fn sleepRepair(num_requests: u64, last_iteration: Duration) void {
    // time we'd like the entire loop to take for this number of repairs
    const target = Duration.fromMillis(num_requests / 8);
    const bounded = @max(
        @min(target.asNanos(), MAX_REPAIR_LOOP_DURATION_TARGET.asNanos()),
        MIN_REPAIR_LOOP_DURATION.asNanos(),
    );

    // amount of time to sleep after last_iteration to reach the target
    const remaining_sleep_for_target = bounded -| last_iteration.asNanos();

    // if overwhelmed by generating many repair requests, this ensures there is
    // a pause between them to dedicate more CPU to process some incoming
    // shreds. This supplements MIN_REPAIR_DELAY to ensure repairs are actively
    // being processed no more than 80% of the time.
    const take_a_break = last_iteration.asNanos() / 4;

    std.time.sleep(@max(
        remaining_sleep_for_target,
        MIN_REPAIR_DELAY.asNanos(),
        take_a_break,
    ));
}

/// The maximum time that we want the repair loop to take.
///
/// This could be exceeded if it takes longer to actually send the repair
/// requests. But otherwise this is the maximum loop duration that we'll target
/// with the sleeps.
///
/// This is sort of like a timeout for repair responses. After 1 second, we
/// should have gotten all the repairs, and there's no need to delay sending
/// more requests.
const MAX_REPAIR_LOOP_DURATION_TARGET = Duration.fromSecs(1);

/// Ensures the full repair loop doesn't repeat more often than this.
const MIN_REPAIR_LOOP_DURATION = Duration.fromMillis(200);

/// Ensures the repair loop always sleeps for some time to do other work between
/// repairs.
const MIN_REPAIR_DELAY = Duration.fromMillis(100);

/// Signs and serializes repair requests. Sends them over the network.
pub const RepairRequester = struct {
    allocator: Allocator,
    logger: ScopedLogger(@typeName(Self)),
    random: Random,
    keypair: *const KeyPair,
    sender_thread: *SocketThread,
    sender_channel: *Channel(Packet),
    metrics: Metrics,

    const Self = @This();

    const Metrics = struct {
        sent_request_count: *Counter,
        pending_requests: *Gauge(u64),

        const prefix = "repair";
    };

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        random: Random,
        registry: *Registry(.{}),
        keypair: *const KeyPair,
        udp_send_socket: Socket,
        exit: *Atomic(bool),
    ) !Self {
        const channel = try Channel(Packet).create(allocator);
        errdefer channel.destroy();

        const thread = try SocketThread.spawnSender(
            allocator,
            logger,
            udp_send_socket,
            channel,
            .{ .unordered = exit },
        );

        return .{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(Self)),
            .random = random,
            .keypair = keypair,
            .sender_thread = thread,
            .sender_channel = channel,
            .metrics = try registry.initStruct(Metrics),
        };
    }

    pub fn deinit(self: Self) void {
        self.sender_thread.join();
        self.sender_channel.destroy();
    }

    pub fn sendRepairRequestBatch(
        self: *const Self,
        requests: []const AddressedRepairRequest,
    ) !void {
        self.metrics.pending_requests.add(requests.len);
        defer self.metrics.pending_requests.set(0);
        const timestamp = std.time.milliTimestamp();
        for (requests) |request| {
            var packet: Packet = .{
                .addr = request.recipient_addr.toEndpoint(),
                .buffer = undefined,
                .size = undefined,
                .flags = .{},
            };
            const data = try serializeRepairRequest(
                &packet.buffer,
                request.request,
                self.keypair,
                request.recipient,
                @intCast(timestamp),
                self.random.int(Nonce),
            );
            packet.size = data.len;
            try self.sender_channel.send(packet);
            self.metrics.pending_requests.dec();
            self.metrics.sent_request_count.inc();
        }
    }
};

/// A repair request plus its destination.
pub const AddressedRepairRequest = struct {
    request: RepairRequest,
    recipient: Pubkey,
    recipient_addr: SocketAddr,
};

/// How many slots to cache in RepairPeerProvider
const REPAIR_PEERS_CACHE_CAPACITY: usize = 8;
/// Maximum age of a cache item to use for repair peers
const REPAIR_PEERS_CACHE_TTL_SECONDS: u64 = 10;

/// A node that can service a repair request.
pub const RepairPeer = struct {
    pubkey: Pubkey,
    serve_repair_socket: SocketAddr,
};

/// Provides peers that repair requests can be sent to.
///
/// TODO benchmark the performance of some alternate approaches, for example:
/// - directly grab a single random peer from gossip instead
///      of the entire list (good if we don't access a slot many times)
/// - single sorted cache for all slots with a binary search to filter by slot
///     - upside is fewer table locks
///     - good if we're mainly looking at older slots, not the last few slots
///     - downside is it may get stale and not represent the latest slots,
///         unless cache TTL is reduced to less than 1 slot duration, in which
///         case it may defeat the purpose of this approach.
/// The key for these benchmarks is to understand the actual repair requests that
/// are being requested on mainnet. There are trade-offs for different kinds
/// of requests. Naive benchmarks will optimize the wrong behaviors.
pub const RepairPeerProvider = struct {
    allocator: Allocator,
    random: Random,
    gossip_table_rw: *RwMux(GossipTable),
    cache: LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit),
    my_pubkey: Pubkey,
    my_shred_version: *const Atomic(u16),
    metrics: Metrics,

    pub const Metrics = struct {
        latest_count_from_gossip: *Gauge(u64),
        cache_hit_count: *Counter,
        cache_miss_count: *Counter,
        cache_expired_count: *Counter,

        const prefix = "repair_peers";
    };

    const Self = @This();

    const RepairPeers = struct {
        insertion_time_secs: u64,
        peers: []RepairPeer,

        fn deinit(self: *@This(), allocator: Allocator) void {
            allocator.free(self.peers);
        }
    };

    pub fn init(
        allocator: Allocator,
        random: Random,
        registry: *Registry(.{}),
        gossip: *RwMux(GossipTable),
        my_pubkey: Pubkey,
        my_shred_version: *const Atomic(u16),
    ) !RepairPeerProvider {
        return .{
            .allocator = allocator,
            .gossip_table_rw = gossip,
            .cache = try LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit)
                .initWithContext(allocator, REPAIR_PEERS_CACHE_CAPACITY, allocator),
            .my_pubkey = my_pubkey,
            .my_shred_version = my_shred_version,
            .metrics = try registry.initStruct(Metrics),
            .random = random,
        };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
    }

    pub const Error = error{
        /// There are no known peers at all that could handle any repair
        /// request for any slot (not just the current desired slot).
        NoRepairPeers,
    } || Allocator.Error;

    /// Selects a peer at random from gossip or cache that is expected
    /// to be able to handle a repair request for the specified slot.
    pub fn getRandomPeer(self: *Self, slot: Slot) Error!?RepairPeer {
        const peers = try self.getPeers(slot);
        if (peers.len == 0) return null;
        const index = self.random.intRangeLessThan(usize, 0, peers.len);
        return peers[index];
    }

    /// Tries to get peers that could have the slot. Checks cache, falling back to gossip.
    fn getPeers(self: *Self, slot: Slot) Error![]RepairPeer {
        const now: u64 = @intCast(std.time.timestamp());

        if (self.cache.get(slot)) |peers| {
            if (now - peers.insertion_time_secs <= REPAIR_PEERS_CACHE_TTL_SECONDS) {
                self.metrics.cache_hit_count.inc();
                return peers.peers;
            }
            self.metrics.cache_expired_count.inc();
        } else self.metrics.cache_miss_count.inc();

        const peers = try self.getRepairPeersFromGossip(self.allocator, slot);
        self.metrics.latest_count_from_gossip.set(peers.len);
        try self.cache.insert(slot, .{
            .insertion_time_secs = now,
            .peers = peers,
        });
        return peers;
    }

    /// Gets a list of peers from the gossip table that are likely to have the desired slot.
    /// This will always acquire the gossip table lock.
    /// Instead of using this function, access the cache when possible to avoid contention.
    fn getRepairPeersFromGossip(
        self: *Self,
        allocator: Allocator,
        slot: Slot,
    ) Error![]RepairPeer {
        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();
        const buf = try allocator.alloc(RepairPeer, gossip_table.contact_infos.count());
        errdefer allocator.free(buf);
        var potential_peers: usize = 0; // total count of all repair peers, not just the ones for this slot.
        var compatible_peers: usize = 0; // number of peers who can handle this slot.
        var infos = gossip_table.contactInfoIterator(0);
        while (infos.next()) |info| {
            const serve_repair_socket = info.getSocket(.serve_repair);
            if (!info.pubkey.equals(&self.my_pubkey) and // don't request from self
                info.shred_version == self.my_shred_version.load(.monotonic) and // need compatible shreds
                serve_repair_socket != null and // node must be able to receive repair requests
                info.getSocket(.turbine_recv) != null) // node needs access to shreds
            {
                potential_peers += 1;
                // exclude nodes that are known to be missing this slot
                if (gossip_table.getData(.{ .LowestSlot = info.pubkey })) |data| {
                    if (data.LowestSlot[1].lowest > slot) {
                        continue;
                    }
                }
                buf[compatible_peers] = .{
                    .pubkey = info.pubkey,
                    .serve_repair_socket = serve_repair_socket.?,
                };
                compatible_peers += 1;
            }
        }
        if (potential_peers == 0) {
            return error.NoRepairPeers;
        }
        return try allocator.realloc(buf, compatible_peers);
    }
};

test "RepairService sends repair request to gossip peer" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var prng = std.Random.DefaultPrng.init(4328095);
    const random = prng.random();
    const TestLogger = sig.trace.DirectPrintLogger;

    // my details
    const keypair = KeyPair.generate();
    const my_shred_version = Atomic(u16).init(random.int(u16));
    const wallclock = 100;
    var gossip = try GossipTable.init(allocator, allocator);
    defer gossip.deinit();
    var test_logger = TestLogger.init(allocator, Logger.TEST_DEFAULT_LEVEL);

    const logger = test_logger.logger();

    // connectivity
    const repair_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    var repair_socket = try Socket.create(.ipv4, .udp);
    try repair_socket.bind(.{
        .port = repair_port,
        .address = .{ .ipv4 = .{ .value = .{ 0, 0, 0, 0 } } },
    });

    // peer
    const peer_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    const peer_keypair = KeyPair.generate();
    var peer_socket = try Socket.create(.ipv4, .udp);
    const peer_endpoint: zig_network.EndPoint = .{
        .address = .{ .ipv4 = .{ .value = .{ 127, 0, 0, 1 } } },
        .port = peer_port,
    };
    try peer_socket.bind(peer_endpoint);
    try peer_socket.setReadTimeout(100_000);
    var peer_contact_info = ContactInfo.init(
        allocator,
        Pubkey.fromPublicKey(&peer_keypair.public_key),
        wallclock,
        my_shred_version.load(.acquire),
    );
    try peer_contact_info.setSocket(.serve_repair, SocketAddr.fromEndpoint(&peer_endpoint));
    try peer_contact_info.setSocket(.turbine_recv, SocketAddr.fromEndpoint(&peer_endpoint));
    _ = try gossip.insert(SignedGossipData.initSigned(&peer_keypair, .{ .ContactInfo = peer_contact_info }), wallclock);

    // init service
    var exit = Atomic(bool).init(false);
    var gossip_mux = RwMux(GossipTable).init(gossip);
    const peers = try RepairPeerProvider.init(
        allocator,
        random,
        &registry,
        &gossip_mux,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );

    var tracker = try BasicShredTracker.init(13579, .noop, &registry);
    var service = try RepairService.init(
        allocator,
        logger,
        &exit,
        &registry,
        try RepairRequester
            .init(allocator, logger, random, &registry, &keypair, repair_socket, &exit),
        peers,
        &tracker,
    );
    defer service.deinit();

    // run test
    _ = try service.sendNecessaryRepairs();
    var buf: [200]u8 = undefined;
    const size = peer_socket.receive(&buf) catch 0;

    // assertions
    try std.testing.expect(160 == size);
    const msg = try bincode.readFromSlice(allocator, RepairMessage, buf[0..160], .{});
    try msg.verify(buf[0..160], Pubkey.fromPublicKey(&peer_keypair.public_key), @intCast(std.time.milliTimestamp()));
    try std.testing.expect(msg.HighestWindowIndex.slot == 13579);
    try std.testing.expect(msg.HighestWindowIndex.shred_index == 0);
}

test "RepairPeerProvider selects correct peers" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(4328095);
    const random = prng.random();

    // my details
    const keypair = KeyPair.generate();
    const my_shred_version = Atomic(u16).init(random.int(u16));
    var gossip = try GossipTable.init(allocator, allocator);
    defer gossip.deinit();

    // peers
    const peer_generator = TestPeerGenerator{
        .allocator = allocator,
        .gossip = &gossip,
        .random = random,
        .shred_version = my_shred_version.load(.acquire),
        .slot = 13579,
    };
    const good_peers = .{
        try peer_generator.addPeerToGossip(.HasSlot),
        try peer_generator.addPeerToGossip(.SlotPosessionUnclear),
    };
    const bad_peers = .{
        try peer_generator.addPeerToGossip(.MissingServeRepairPort),
        try peer_generator.addPeerToGossip(.MissingTvuPort),
        try peer_generator.addPeerToGossip(.MissingSlot),
        try peer_generator.addPeerToGossip(.WrongShredVersion),
    };

    // init test subject
    var gossip_mux = RwMux(GossipTable).init(gossip);
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    var peers = try RepairPeerProvider.init(
        allocator,
        random,
        &registry,
        &gossip_mux,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );
    defer peers.deinit();

    // run test
    var observed_peers = std.AutoHashMap(RepairPeer, void).init(allocator);
    defer observed_peers.deinit();
    for (0..10) |_| {
        const peer = (try peers.getRandomPeer(13579)).?;
        try observed_peers.put(peer, {});
    }

    // assertions
    var failed = false;
    inline for (good_peers) |good_peer| {
        if (!observed_peers.contains(good_peer[1])) {
            std.debug.print("_\nMISSING: {}\n", .{good_peer[0]});
            failed = true;
        }
    }
    inline for (bad_peers) |bad_peer| {
        if (observed_peers.contains(bad_peer[1])) {
            std.debug.print("_\nUNEXPECTED: {}\n", .{bad_peer[0]});
            failed = true;
        }
    }
    try std.testing.expect(!failed);
}

const TestPeerGenerator = struct {
    allocator: Allocator,
    gossip: *GossipTable,
    random: Random,
    shred_version: u16,
    slot: Slot,

    const PeerType = enum {
        /// There is a LowestSlot for the peer that indicates they have the slot
        HasSlot,
        /// There is not a LowestSlot
        SlotPosessionUnclear,
        /// There is a LowestSlot for the peer that indicates they do not have the slot
        MissingSlot,
        /// There is no serve repair port specified in the peer's contact info
        MissingServeRepairPort,
        /// There is no turbine port specified in the peer's contact info
        MissingTvuPort,
        /// The peer has a different shred version
        WrongShredVersion,
    };

    fn addPeerToGossip(self: *const @This(), peer_type: PeerType) !struct { PeerType, RepairPeer } {
        const wallclock = 1;
        const keypair = KeyPair.generate();
        const serve_repair_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8003);
        const shred_version = if (peer_type == .WrongShredVersion) self.shred_version + 1 else self.shred_version;
        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        var contact_info = ContactInfo.init(self.allocator, pubkey, wallclock, shred_version);
        if (peer_type != .MissingServeRepairPort) {
            try contact_info.setSocket(.serve_repair, serve_repair_addr);
        }
        if (peer_type != .MissingTvuPort) {
            try contact_info.setSocket(.turbine_recv, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8004));
        }
        _ = try self.gossip.insert(SignedGossipData.initSigned(&keypair, .{ .ContactInfo = contact_info }), wallclock);
        switch (peer_type) {
            inline .HasSlot, .MissingSlot => {
                var lowest_slot = sig.gossip.LowestSlot.initRandom(self.random);
                lowest_slot.from = pubkey;
                lowest_slot.lowest = switch (peer_type) {
                    .MissingSlot => self.slot + 1,
                    else => self.slot,
                };
                _ = try self.gossip.insert(SignedGossipData.initSigned(&keypair, .{ .LowestSlot = .{ 0, lowest_slot } }), wallclock);
            },
            else => {},
        }
        return .{ peer_type, .{
            .pubkey = pubkey,
            .serve_repair_socket = serve_repair_addr,
        } };
    }
};
