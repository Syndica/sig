const std = @import("std");
const zig_network = @import("zig-network");
const sig = @import("../../lib.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Atomic;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = zig_network.Socket;

const ContactInfo = sig.gossip.ContactInfo;
const GossipTable = sig.gossip.GossipTable;
const LruCacheCustom = sig.common.LruCacheCustom;
const Nonce = sig.core.Nonce;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const SocketAddr = sig.net.SocketAddr;
const Slot = sig.core.Slot;

const RepairRequest = sig.tvu.repair.RepairRequest;
const serializeRepairRequest = sig.tvu.repair.serializeRepairRequest;

fn getLatestSlotFromSnapshot() u64 {
    return 1;
}

/// Identifies which repairs are needed and sends the requests.
pub const RepairService = struct {
    allocator: Allocator,
    requester: RepairRequester,
    peers: RepairPeerProvider,

    pub fn run(self: *@This(), exit: Atomic(bool)) void {
        const request = self.initialSnapshotRepair();
        try self.requester.sendRepairRequest(request);

        while (true) {
            // TODO repair logic
            if (exit.load(.Monotonic)) return;
            std.time.sleep(1_000_000_000);
        }
    }

    fn initialSnapshotRepair(self: *@This()) Socket.SendError!AddressedRepairRequest {
        const slot = getLatestSlotFromSnapshot();
        const request: RepairRequest = .{ .HighestShred = .{ slot, 0 } };
        const peer = self.peers.getRandomPeer();

        return .{
            .request = request,
            .recipient = peer.pubkey,
            .recipient_addr = peer.serve_repair_socket,
        };
    }
};

/// Signs and serializes messages. Sends data over the network.
pub const RepairRequester = struct {
    allocator: Allocator,
    rng: Random,
    keypair: *const KeyPair,
    udp_send_socket: Socket,

    pub fn sendRepairRequest(
        self: *const @This(),
        request: AddressedRepairRequest,
    ) Socket.SendError!void {
        const timestamp = std.time.milliTimestamp();
        const data = try serializeRepairRequest(
            self.allocator,
            request.request,
            self.keypair,
            request.recipient,
            timestamp,
            self.rng.int(Nonce),
        );
        try self.udp_send_socket.sendTo(request.recipient_addr.toEndpoint(), data);
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
const RepairPeerProvider = struct {
    allocator: Allocator,
    rng: Random,
    gossip: *RwMux(GossipTable),
    cache: LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit),
    my_pubkey: Pubkey,
    my_shred_version: *const Atomic(u16),

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
            .gossip = gossip,
            .cache = try LruCacheCustom(.non_locking, Slot, RepairPeers, Allocator, RepairPeers.deinit)
                .initWithContext(allocator, REPAIR_PEERS_CACHE_CAPACITY, allocator),
            .my_pubkey = my_pubkey,
            .my_shred_version = my_shred_version,
            .rng = rng,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.cache.deinit();
    }

    /// Selects a peer at random from gossip or cache that is expected
    /// to be able to handle a repair request for the specified slot.
    pub fn getRandomPeer(self: *const @This(), slot: Slot) RepairPeer {
        const peers = self.getPeers(slot);
        const index = self.rng.intRangeLessThan(usize, 0, peers.len);
        return peers[index];
    }

    /// Tries to get peers that could have the slot. Checks cache, falling back to gossip.
    fn getPeers(self: *const @This(), slot: Slot) []RepairPeer {
        const now = std.time.timestamp();

        if (self.cache.get(slot)) |peers| {
            if (now - peers.insertion_time_secs <= REPAIR_PEERS_CACHE_TTL_SECONDS) {
                return peers;
            }
        }

        const peers = self.getRepairPeersFromGossip(self.allocator, slot);
        self.cache.insert(slot, .{
            .insertion_time_secs = now,
            .peers = peers,
        });
        return peers;
    }

    /// Gets a list of peers that are likely to have the desired slot.
    /// Acquires the gossip table lock. Use cache when possible to avoid contention.
    fn getRepairPeersFromGossip(
        self: *const @This(),
        allocator: Allocator,
        slot: Slot,
    ) error{OutOfMemory}![]RepairPeer {
        const reader = self.gossip.read();
        defer reader.unlock();
        const gossip: GossipTable = reader.get();
        const buf = try allocator.alloc(RepairPeer, gossip.contact_infos.count());
        errdefer buf.deinit();
        var i = 0;
        var infos = gossip.contactInfoIterator(0);
        while (infos.next()) |info| {
            const socket = info.getSocket(sig.gossip.SOCKET_TAG_SERVE_REPAIR);
            if (info.pubkey != self.my_pubkey and // don't request from self
                info.shred_version == self.my_shred_version and // need compatible shreds
                socket != null and // node must be able to receive repair requests
                info.getSocket(sig.gossip.SOCKET_TAG_TVU) != null) // node needs access to shreds
            {
                // exclude nodes that are known to be missing this slot
                if (gossip.get(.{ .LowestSlot = info.pubkey })) |lsv| {
                    if (lsv.value.data.LowestSlot[1].lowest > slot) {
                        continue;
                    }
                }
                buf[i] = .{
                    .pubkey = info.pubkey,
                    .serve_repair_socket = socket.?,
                };
                i += 1;
            }
        }
        return try allocator.realloc(buf, i);
    }
};

test "tvu.repair.service: RepairService initializes" {
    const allocator = std.testing.allocator;
    var rand = std.rand.DefaultPrng.init(0);

    const keypair = KeyPair.create(null) catch unreachable;
    const my_shred_version = Atomic(u16).init(0);
    var gossip = try GossipTable.init(allocator, undefined);
    var gossip_mux = RwMux(GossipTable).init(gossip);

    var peers = try RepairPeerProvider.init(
        allocator,
        rand.random(),
        &gossip_mux,
        Pubkey.fromPublicKey(&keypair.public_key, true),
        &my_shred_version,
    );
    defer peers.deinit();

    const service = RepairService{
        .allocator = allocator,
        .requester = RepairRequester{
            .allocator = allocator,
            .rng = rand.random(),
            .udp_send_socket = try Socket.create(.ipv4, .udp),
            .keypair = &keypair,
        },
        .peers = peers,
    };
    _ = service;
}
