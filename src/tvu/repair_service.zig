const std = @import("std");
const zig_network = @import("zig-network");
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = zig_network.Socket;
const ContactInfo = @import("../gossip/data.zig").ContactInfo;
const GossipTable = @import("../gossip/table.zig").GossipTable;
const Logger = @import("../trace/log.zig").Logger;
const LruCacheCustom = @import("../common/lru.zig").LruCacheCustom;
const Nonce = @import("../core/shred.zig").Nonce;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const RwMux = @import("../sync/mux.zig").RwMux;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const Slot = @import("../core/time.zig").Slot;
const RepairRequest = @import("repair_message.zig").RepairRequest;
const serializeRepairRequest = @import("repair_message.zig").serializeRepairRequest;
const socket_tag = @import("../gossip/data.zig").socket_tag;
const SignedGossipData = @import("../gossip/data.zig").SignedGossipData;
const bincode = @import("../bincode/bincode.zig");
const RepairMessage = @import("repair_message.zig").RepairMessage;
const LowestSlot = @import("../gossip/data.zig").LowestSlot;

/// Identifies which repairs are needed and sends them
/// - delegates to RepairPeerProvider to identify repair peers.
/// - delegates to RepairRequester to send the requests.
pub const RepairService = struct {
    allocator: Allocator,
    requester: RepairRequester,
    peer_provider: RepairPeerProvider,
    logger: Logger,
    exit: *Atomic(bool),
    slot_to_request: ?u64,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.peer_provider.deinit();
    }

    pub fn run(self: *Self) !void {
        self.logger.info("starting repair service");
        defer self.logger.info("exiting repair service");
        while (!self.exit.load(.unordered)) {
            if (try self.initialSnapshotRepair()) |request| {
                try self.requester.sendRepairRequest(request);
            }
            // TODO repair logic
            std.time.sleep(100_000_000);
        }
    }

    fn initialSnapshotRepair(self: *Self) !?AddressedRepairRequest {
        if (self.slot_to_request == null) return null;
        const request: RepairRequest = .{ .HighestShred = .{ self.slot_to_request.?, 0 } };
        const maybe_peer = try self.peer_provider.getRandomPeer(self.slot_to_request.?);

        if (maybe_peer) |peer| return .{
            .request = request,
            .recipient = peer.pubkey,
            .recipient_addr = peer.serve_repair_socket,
        } else {
            return null;
        }
    }
};

/// Signs and serializes repair requests. Sends them over the network.
pub const RepairRequester = struct {
    allocator: Allocator,
    rng: Random,
    keypair: *const KeyPair,
    udp_send_socket: *Socket,
    logger: Logger,

    const Self = @This();

    pub fn sendRepairRequest(
        self: *const Self,
        request: AddressedRepairRequest,
    ) !void {
        const timestamp = std.time.milliTimestamp();
        const data = try serializeRepairRequest(
            self.allocator,
            request.request,
            self.keypair,
            request.recipient,
            @intCast(timestamp),
            self.rng.int(Nonce),
        );
        defer self.allocator.free(data);
        const addr = request.recipient_addr.toString();
        self.logger.infof(
            "sending repair request to {s} - {}",
            .{ addr[0][0..addr[1]], request.request },
        );
        _ = try self.udp_send_socket.sendTo(request.recipient_addr.toEndpoint(), data);
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

    /// Selects a peer at random from gossip or cache that is expected
    /// to be able to handle a repair request for the specified slot.
    pub fn getRandomPeer(self: *Self, slot: Slot) !?RepairPeer {
        const peers = try self.getPeers(slot);
        if (peers.len == 0) return null;
        const index = self.rng.intRangeLessThan(usize, 0, peers.len);
        return peers[index];
    }

    /// Tries to get peers that could have the slot. Checks cache, falling back to gossip.
    fn getPeers(self: *Self, slot: Slot) ![]RepairPeer {
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
    ) error{OutOfMemory}![]RepairPeer {
        var gossip_table_lock = self.gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();
        const buf = try allocator.alloc(RepairPeer, gossip_table.contact_infos.count());
        errdefer allocator.free(buf);
        var i: usize = 0;
        var infos = gossip_table.contactInfoIterator(0);
        while (infos.next()) |info| {
            const serve_repair_socket = info.getSocket(socket_tag.SERVE_REPAIR);
            if (!info.pubkey.equals(&self.my_pubkey) and // don't request from self
                info.shred_version == self.my_shred_version.load(.monotonic) and // need compatible shreds
                serve_repair_socket != null and // node must be able to receive repair requests
                info.getSocket(socket_tag.TVU) != null) // node needs access to shreds
            {
                // exclude nodes that are known to be missing this slot
                if (gossip_table.get(.{ .LowestSlot = info.pubkey })) |lsv| {
                    if (lsv.value.data.LowestSlot[1].lowest > slot) {
                        continue;
                    }
                }
                buf[i] = .{
                    .pubkey = info.pubkey,
                    .serve_repair_socket = serve_repair_socket.?,
                };
                i += 1;
            }
        }
        return try allocator.realloc(buf, i);
    }
};

test "tvu.repair_service: RepairService sends repair request to gossip peer" {
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
    try peer_contact_info.setSocket(socket_tag.SERVE_REPAIR, SocketAddr.fromEndpoint(&peer_endpoint));
    try peer_contact_info.setSocket(socket_tag.TVU, SocketAddr.fromEndpoint(&peer_endpoint));
    try gossip.insert(try SignedGossipData.initSigned(.{ .ContactInfo = peer_contact_info }, &peer_keypair), wallclock);

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
    var service = RepairService{
        .allocator = allocator,
        .requester = RepairRequester{
            .allocator = allocator,
            .rng = random,
            .udp_send_socket = &repair_socket,
            .keypair = &keypair,
            .logger = logger,
        },
        .peer_provider = peers,
        .logger = logger,
        .exit = &exit,
        .slot_to_request = 13579,
    };
    defer service.deinit();

    // run test
    const handle = try std.Thread.spawn(.{}, RepairService.run, .{&service});
    var buf: [200]u8 = undefined;
    const size = peer_socket.receive(&buf) catch 0;

    // assertions
    try std.testing.expect(160 == size);
    const msg = try bincode.readFromSlice(allocator, RepairMessage, buf[0..160], .{});
    try msg.verify(buf[0..160], Pubkey.fromPublicKey(&peer_keypair.public_key), @intCast(std.time.milliTimestamp()));
    try std.testing.expect(msg.HighestWindowIndex.slot == 13579);
    try std.testing.expect(msg.HighestWindowIndex.shred_index == 0);

    // exit
    exit.store(true, .monotonic);
    handle.join();
}

test "tvu.repair_service: RepairPeerProvider selects correct peers" {
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
        /// There is no tvu port specified in the peer's contact info
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
            try contact_info.setSocket(socket_tag.SERVE_REPAIR, serve_repair_addr);
        }
        if (peer_type != .MissingTvuPort) {
            try contact_info.setSocket(socket_tag.TVU, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8004));
        }
        try self.gossip.insert(try SignedGossipData.initSigned(.{ .ContactInfo = contact_info }, &keypair), wallclock);
        switch (peer_type) {
            inline .HasSlot, .MissingSlot => {
                var lowest_slot = LowestSlot.random(self.random);
                lowest_slot.from = pubkey;
                lowest_slot.lowest = switch (peer_type) {
                    .MissingSlot => self.slot + 1,
                    else => self.slot,
                };
                try self.gossip.insert(try SignedGossipData.initSigned(.{ .LowestSlot = .{ 0, lowest_slot } }, &keypair), wallclock);
            },
            else => {},
        }
        return .{ peer_type, .{
            .pubkey = pubkey,
            .serve_repair_socket = serve_repair_addr,
        } };
    }
};
