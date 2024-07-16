const std = @import("std");
const zig_network = @import("zig-network");
const sig = @import("../lib.zig");
const shred_collector = @import("lib.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = zig_network.Socket;

const BasicShredTracker = shred_collector.shred_tracker.BasicShredTracker;
const ContactInfo = sig.gossip.ContactInfo;
const GossipTable = sig.gossip.GossipTable;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const Logger = sig.trace.Logger;
const LruCacheCustom = sig.utils.lru.LruCacheCustom;
const MultiSlotReport = shred_collector.shred_tracker.MultiSlotReport;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const SignedGossipData = sig.gossip.SignedGossipData;
const SocketAddr = sig.net.SocketAddr;
const SocketThread = sig.net.SocketThread;
const Slot = sig.core.Slot;

const RepairRequest = shred_collector.repair_message.RepairRequest;
const RepairMessage = shred_collector.repair_message.RepairMessage;

const serializeRepairRequest = shred_collector.repair_message.serializeRepairRequest;

const NUM_REQUESTER_THREADS = 4;

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
    logger: Logger,
    exit: *Atomic(bool),
    last_big_request_timestamp_ms: i64 = 0,

    /// memory to re-use across iterations. initialized to empty
    report: MultiSlotReport,

    thread_pool: RequestBatchThreadPool,

    pub const RequestBatchThreadPool = HomogeneousThreadPool(struct {
        requester: *RepairRequester,
        requests: []AddressedRepairRequest,

        pub fn run(self: *@This()) !void {
            return self.requester.sendRepairRequestBatch(
                self.requester.allocator,
                self.requests,
            );
        }
    });

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        exit: *Atomic(bool),
        requester: RepairRequester,
        peer_provider: RepairPeerProvider,
        shred_tracker: *BasicShredTracker,
    ) Self {
        return RepairService{
            .allocator = allocator,
            .requester = requester,
            .peer_provider = peer_provider,
            .shred_tracker = shred_tracker,
            .logger = logger,
            .exit = exit,
            .report = MultiSlotReport.init(allocator),
            .thread_pool = RequestBatchThreadPool.init(allocator, NUM_REQUESTER_THREADS),
        };
    }

    pub fn deinit(self: *Self) void {
        self.peer_provider.deinit();
        self.requester.deinit();
        self.thread_pool.deinit();
        self.report.deinit();
    }

    const min_loop_duration_ns = 100 * std.time.ns_per_ms;

    pub fn run(self: *Self) !void {
        var waiting_for_peers = false;
        var timer = try std.time.Timer.start();
        var last_iteration: u64 = 0;
        while (!self.exit.load(.unordered)) {
            if (self.sendNecessaryRepairs()) |_| {
                if (waiting_for_peers) {
                    waiting_for_peers = false;
                    self.logger.infof("Acquired some repair peers.", .{});
                }
            } else |e| switch (e) {
                error.NoRepairPeers => if (!waiting_for_peers) {
                    self.logger.infof("Waiting for repair peers...", .{});
                    waiting_for_peers = true;
                },
                else => return e,
            }
            last_iteration = timer.lap();
            std.time.sleep(min_loop_duration_ns -| last_iteration);
        }
    }

    /// Identifies which repairs are needed based on the current state,
    /// and sends those repairs, then returns.
    pub fn sendNecessaryRepairs(self: *Self) !void {
        const repair_requests = try self.getRepairs();
        defer repair_requests.deinit();
        const addressed_requests = try self.assignRequestsToPeers(repair_requests.items);
        defer addressed_requests.deinit();

        if (addressed_requests.items.len < 4) {
            try self.requester.sendRepairRequestBatch(self.allocator, addressed_requests.items);
        } else {
            for (0..4) |i| {
                const start = (addressed_requests.items.len * i) / 4;
                const end = (addressed_requests.items.len * (i + 1)) / 4;
                try self.thread_pool.schedule(.{
                    .requester = &self.requester,
                    .requests = addressed_requests.items[start..end],
                });
                try self.thread_pool.joinFallible();
            }
        }

        // TODO less often
        if (addressed_requests.items.len > 0) {
            self.logger.debugf(
                "sent {} repair requests",
                .{addressed_requests.items.len},
            );
        }
    }

    const MAX_SHRED_REPAIRS = 1000;
    const MIN_HIGHEST_REPAIRS = 10;
    const MAX_HIGHEST_REPAIRS = 200;

    fn getRepairs(self: *Self) !ArrayList(RepairRequest) {
        var repairs = ArrayList(RepairRequest).init(self.allocator);
        if (!try self.shred_tracker.identifyMissing(&self.report)) {
            return repairs;
        }
        var individual_count: usize = 0;
        var highest_count: usize = 0;
        var slot: Slot = 0;

        var num_highest_repairs: usize = MIN_HIGHEST_REPAIRS;
        if (self.last_big_request_timestamp_ms + 5_000 < std.time.milliTimestamp()) {
            self.last_big_request_timestamp_ms = std.time.milliTimestamp();
            num_highest_repairs = MAX_HIGHEST_REPAIRS;
        }

        for (self.report.items()) |*report| outer: {
            slot = report.slot;
            for (report.missing_shreds.items) |shred_window| {
                if (shred_window.end) |end| {
                    for (shred_window.start..end) |i| {
                        individual_count += 1;
                        try repairs.append(.{ .Shred = .{ slot, i } });
                        if (individual_count > MAX_SHRED_REPAIRS) {
                            break :outer;
                        }
                    }
                }
            }
            if (highest_count < num_highest_repairs) {
                highest_count += 1;
                try repairs.append(.{ .HighestShred = .{ slot, 0 } });
            }
        }

        if (highest_count < num_highest_repairs) {
            for (slot..slot + num_highest_repairs - highest_count) |s| {
                try repairs.append(.{ .HighestShred = .{ s, 0 } });
            }
        }
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

/// Signs and serializes repair requests. Sends them over the network.
pub const RepairRequester = struct {
    allocator: Allocator,
    logger: Logger,
    rng: Random,
    keypair: *const KeyPair,
    sender: SocketThread,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        rng: Random,
        keypair: *const KeyPair,
        udp_send_socket: Socket,
        exit: *Atomic(bool),
    ) !Self {
        const sndr = try SocketThread.initSender(allocator, logger, udp_send_socket, exit);
        return .{
            .allocator = allocator,
            .logger = logger,
            .rng = rng,
            .keypair = keypair,
            .sender = sndr,
        };
    }

    pub fn deinit(self: Self) void {
        self.sender.deinit();
    }

    pub fn sendRepairRequestBatch(
        self: *const Self,
        allocator: Allocator,
        requests: []AddressedRepairRequest,
    ) !void {
        var packet_batch = try std.ArrayList(Packet).initCapacity(allocator, requests.len);
        const timestamp = std.time.milliTimestamp();
        for (requests) |request| {
            const packet = packet_batch.addOneAssumeCapacity();
            packet.* = Packet{
                .addr = request.recipient_addr.toEndpoint(),
                .data = undefined,
                .size = undefined,
            };
            const data = try serializeRepairRequest(
                &packet.data,
                request.request,
                self.keypair,
                request.recipient,
                @intCast(timestamp),
                self.rng.int(Nonce),
            );
            packet.size = data.len;
        }
        try self.sender.channel.send(packet_batch);
    }
};

/// A repair request plus its destination.
pub const AddressedRepairRequest = struct {
    request: RepairRequest,
    recipient: Pubkey,
    recipient_addr: SocketAddr,
};

/// How many slots to cache in RepairPeerProvider
const REPAIR_PEERS_CACHE_CAPACITY: usize = 128;
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
    rng: Random,
    gossip_table_rw: *RwMux(GossipTable),
    cache: LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit),
    my_pubkey: Pubkey,
    my_shred_version: *const Atomic(u16),

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
        rng: Random,
        gossip: *RwMux(GossipTable),
        my_pubkey: Pubkey,
        my_shred_version: *const Atomic(u16),
    ) error{OutOfMemory}!RepairPeerProvider {
        return .{
            .allocator = allocator,
            .gossip_table_rw = gossip,
            .cache = try LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit)
                .initWithContext(allocator, REPAIR_PEERS_CACHE_CAPACITY, allocator),
            .my_pubkey = my_pubkey,
            .my_shred_version = my_shred_version,
            .rng = rng,
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
        const index = self.rng.intRangeLessThan(usize, 0, peers.len);
        return peers[index];
    }

    /// Tries to get peers that could have the slot. Checks cache, falling back to gossip.
    fn getPeers(self: *Self, slot: Slot) Error![]RepairPeer {
        const now: u64 = @intCast(std.time.timestamp());

        if (self.cache.get(slot)) |peers| {
            if (now - peers.insertion_time_secs <= REPAIR_PEERS_CACHE_TTL_SECONDS) {
                return peers.peers;
            }
        }

        const peers = try self.getRepairPeersFromGossip(self.allocator, slot);
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
                if (gossip_table.get(.{ .LowestSlot = info.pubkey })) |lsv| {
                    if (lsv.value.data.LowestSlot[1].lowest > slot) {
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
    var rand = std.rand.DefaultPrng.init(4328095);
    var random = rand.random();

    // my details
    const keypair = KeyPair.create(null) catch unreachable;
    const my_shred_version = Atomic(u16).init(random.int(u16));
    const wallclock = 100;
    var gossip = try GossipTable.init(allocator, undefined);
    defer gossip.deinit();
    var logger = Logger.init(allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();

    // connectivity
    const repair_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    var repair_socket = try Socket.create(.ipv4, .udp);
    try repair_socket.bind(.{
        .port = repair_port,
        .address = .{ .ipv4 = .{ .value = .{ 0, 0, 0, 0 } } },
    });

    // peer
    const peer_port = random.intRangeAtMost(u16, 1000, std.math.maxInt(u16));
    const peer_keypair = KeyPair.create(null) catch unreachable;
    var peer_socket = try Socket.create(.ipv4, .udp);
    const peer_endpoint = .{
        .address = .{ .ipv4 = .{ .value = .{ 127, 0, 0, 1 } } },
        .port = peer_port,
    };
    try peer_socket.bind(peer_endpoint);
    try peer_socket.setReadTimeout(100_000);
    var peer_contact_info = ContactInfo.init(allocator, Pubkey.fromPublicKey(&peer_keypair.public_key), wallclock, my_shred_version.load(.unordered));
    try peer_contact_info.setSocket(.serve_repair, SocketAddr.fromEndpoint(&peer_endpoint));
    try peer_contact_info.setSocket(.turbine_recv, SocketAddr.fromEndpoint(&peer_endpoint));
    _ = try gossip.insert(try SignedGossipData.initSigned(.{ .ContactInfo = peer_contact_info }, &peer_keypair), wallclock);

    // init service
    var exit = Atomic(bool).init(false);
    var gossip_mux = RwMux(GossipTable).init(gossip);
    const peers = try RepairPeerProvider.init(
        allocator,
        random,
        &gossip_mux,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );
    var tracker = BasicShredTracker.init(13579, .noop);
    var service = RepairService.init(
        allocator,
        logger,
        &exit,
        try RepairRequester.init(
            allocator,
            logger,
            random,
            &keypair,
            repair_socket,
            &exit,
        ),
        peers,
        &tracker,
    );
    defer service.deinit();

    // run test
    try service.sendNecessaryRepairs();
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
    var rand = std.rand.DefaultPrng.init(4328095);
    var random = rand.random();

    // my details
    const keypair = KeyPair.create(null) catch unreachable;
    const my_shred_version = Atomic(u16).init(random.int(u16));
    var gossip = try GossipTable.init(allocator, undefined);
    defer gossip.deinit();
    var logger = Logger.init(allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();

    // peers
    const peer_generator = TestPeerGenerator{
        .allocator = allocator,
        .gossip = &gossip,
        .random = random,
        .shred_version = my_shred_version.load(.unordered),
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
    var peers = try RepairPeerProvider.init(
        allocator,
        random,
        &gossip_mux,
        Pubkey.fromPublicKey(&keypair.public_key),
        &my_shred_version,
    );
    defer peers.deinit();

    // run test
    var observed_peers = std.AutoHashMap(RepairPeer, void).init(allocator);
    defer observed_peers.deinit();
    for (0..10) |_| {
        try observed_peers.put(try peers.getRandomPeer(13579) orelse unreachable, {});
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
        const keypair = KeyPair.create(null) catch unreachable;
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
        _ = try self.gossip.insert(try SignedGossipData.initSigned(.{ .ContactInfo = contact_info }, &keypair), wallclock);
        switch (peer_type) {
            inline .HasSlot, .MissingSlot => {
                var lowest_slot = sig.gossip.LowestSlot.random(self.random);
                lowest_slot.from = pubkey;
                lowest_slot.lowest = switch (peer_type) {
                    .MissingSlot => self.slot + 1,
                    else => self.slot,
                };
                _ = try self.gossip.insert(try SignedGossipData.initSigned(.{ .LowestSlot = .{ 0, lowest_slot } }, &keypair), wallclock);
            },
            else => {},
        }
        return .{ peer_type, .{
            .pubkey = pubkey,
            .serve_repair_socket = serve_repair_addr,
        } };
    }
};
