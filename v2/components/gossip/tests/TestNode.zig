//! Component test harness for a GossipNode with deterministic identity and captured effects.

const std = @import("std");
const lib = @import("lib");
const api = @import("gossip_api");

const Packet = lib.net.Packet;
const Hash = lib.solana.Hash;
const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;
const Slot = lib.solana.Slot;

const Address = api.Address;
const ClusterInfo = api.ClusterInfo;
const GossipMessage = api.GossipMessage;
const GossipNode = @import("../node.zig").GossipNode;
const KeyPair = lib.crypto.KeyPair;
const Metrics = @import("../Metrics.zig");
const SocketMap = api.SocketMap;
const testing = @import("testing.zig");

/// Type just to track fields for a snapshot source reported by the GossipNode effects.
const SnapshotSource = struct {
    from: Pubkey,
    rpc_addr: lib.net.Address,
    slot: Slot,
    hash: Hash,
};
const TestLogStore = lib.telemetry.TestLogStore;
const TestMetricStore = lib.telemetry.TestMetricStore;

allocator: std.mem.Allocator,
/// Backing memory for the node's fixed-buffer allocations, reused by reset.
scratch: []u8,
log_store: TestLogStore,
metric_store: TestMetricStore,
effects: *Effects,
/// GossipNode under test, reinitialized by reset.
node: Node,
/// Wall time in milliseconds tracked to simulate time passing.
now_ms: u64,

const TestNode = @This();
const Node = GossipNode(*Effects);

const scratch_size = 4 * 1024 * 1024;
const packet_capacity = 256;
const snapshot_source_capacity = 16;

/// Implementation of the GossipNode effects interface that captures state for test assertions.
const Effects = struct {
    keypair: KeyPair,
    // These fields back slices retained by the node configuration.
    socket_builder: SocketMap.Builder,
    entrypoints: [ClusterInfo.MAX_ENTRY_ADDRS]Address,
    entrypoints_len: usize,
    // Flushed packets come first, followed by packets pending the next flush.
    packets: [packet_capacity]Packet,
    packets_len: usize,
    pending_packets_len: usize,
    snapshot_sources: [snapshot_source_capacity]SnapshotSource,
    snapshot_sources_len: usize,

    pub fn writePacket(self: *Effects) *Packet {
        const index = self.packets_len + self.pending_packets_len;
        const capacity = self.packets.len;
        std.debug.assert(index < capacity);
        self.pending_packets_len += 1;
        return &self.packets[index];
    }

    pub fn flushWrittenPackets(self: *Effects) void {
        // Publish every packet reserved since the previous flush.
        self.packets_len += self.pending_packets_len;
        self.pending_packets_len = 0;
    }

    pub fn getIdentity(self: *Effects) Pubkey {
        return self.keypair.pubkey;
    }

    pub fn sign(self: *Effects, message: []const u8) Signature {
        return self.keypair.sign(message) catch unreachable;
    }

    pub fn reportSnapshotSource(
        self: *Effects,
        from: Pubkey,
        address: std.net.Address,
        slot: Slot,
        hash: Hash,
    ) void {
        const capacity = self.snapshot_sources.len;
        std.debug.assert(self.snapshot_sources_len < capacity);
        self.snapshot_sources[self.snapshot_sources_len] = .{
            .from = from,
            .rpc_addr = .fromNetAddress(address),
            .slot = slot,
            .hash = hash,
        };
        self.snapshot_sources_len += 1;
    }
};

pub fn init(
    allocator: std.mem.Allocator,
    now_ms: u64,
    identity_seed: [std.crypto.sign.Ed25519.KeyPair.seed_length]u8,
    address: Address,
    entrypoints: []const Address,
) !TestNode {
    std.debug.assert(entrypoints.len <= ClusterInfo.MAX_ENTRY_ADDRS);

    // Keep shared effect state at a stable address if the harness moves.
    const effects = try allocator.create(Effects);
    errdefer allocator.destroy(effects);
    effects.* = .{
        .keypair = try testing.deterministicKeyPair(identity_seed),
        .socket_builder = .{},
        .entrypoints = undefined,
        .entrypoints_len = entrypoints.len,
        .packets = undefined,
        .packets_len = 0,
        .pending_packets_len = 0,
        .snapshot_sources = undefined,
        .snapshot_sources_len = 0,
    };
    @memcpy(effects.entrypoints[0..entrypoints.len], entrypoints);
    effects.socket_builder.set(.gossip, address);

    const scratch = try allocator.alloc(u8, scratch_size);
    errdefer allocator.free(scratch);
    var fixed_buffer: std.heap.FixedBufferAllocator = .init(scratch);

    var log_store = try TestLogStore.init(allocator, .{});
    errdefer log_store.deinit();

    var metric_store = try TestMetricStore.init(allocator, .{});
    errdefer metric_store.deinit();
    const metrics = appendGossipMetrics(&metric_store);

    const node = try Node.init(&fixed_buffer, now_ms, metrics, .{
        .effects = effects,
        .shred_version = 42,
        .socket_map = effects.socket_builder.asSocketMap(),
        .entrypoints = effects.entrypoints[0..effects.entrypoints_len],
        .limits = .{
            .table = 256,
            .expired = 256,
            .peers = 256,
        },
    });

    return .{
        .allocator = allocator,
        .scratch = scratch,
        .log_store = log_store,
        .metric_store = metric_store,
        .effects = effects,
        .node = node,
        .now_ms = now_ms,
    };
}

pub fn deinit(self: *TestNode) void {
    self.log_store.deinit();
    self.metric_store.deinit();
    self.allocator.free(self.scratch);
    self.allocator.destroy(self.effects);
}

fn appendGossipMetrics(metric_store: *TestMetricStore) Metrics {
    return metric_store.appendMetrics(Metrics, .{
        .prefix = "gossip_test",
    });
}

pub fn reset(self: *TestNode, now_ms: u64) !void {
    std.debug.assert(self.effects.pending_packets_len == 0);
    self.effects.packets_len = 0;
    self.effects.snapshot_sources_len = 0;

    self.log_store.reset();
    self.metric_store.reset();
    const metrics = appendGossipMetrics(&self.metric_store);

    // Recreate the node from the start of its fixed backing buffer.
    var fixed_buffer: std.heap.FixedBufferAllocator = .init(self.scratch);
    self.node = try Node.init(&fixed_buffer, now_ms, metrics, self.node.config);
    self.now_ms = now_ms;
    self.node.assertInvariants();
}

pub fn logs(self: *TestNode) *TestLogStore {
    return &self.log_store;
}

pub fn identity(self: *const TestNode) Pubkey {
    return self.effects.keypair.pubkey;
}

pub fn poll(self: *TestNode) !void {
    try self.node.poll(self.log_store.logger("poll"), self.now_ms);
    self.node.assertInvariants();
}

pub fn advanceMs(self: *TestNode, duration_ms: u64) void {
    self.now_ms += duration_ms;
}

pub fn receivePacket(self: *TestNode, packet: *const Packet) void {
    self.node.processPacket(self.log_store.logger("processPacket"), self.now_ms, packet);
    self.node.assertInvariants();
}

pub fn receiveMessage(
    self: *TestNode,
    source: std.net.Address,
    message: GossipMessage,
) !void {
    const packet = try testing.packetFromMessage(source, message);
    self.receivePacket(&packet);
}

pub fn outgoingPackets(self: *const TestNode) []const Packet {
    // Packets remain hidden from tests until the Effects implementation flushes them.
    return self.effects.packets[0..self.effects.packets_len];
}

pub fn clearOutgoingPackets(self: *TestNode) void {
    std.debug.assert(self.effects.pending_packets_len == 0);
    self.effects.packets_len = 0;
}

pub fn snapshotSources(self: *const TestNode) []const SnapshotSource {
    return self.effects.snapshot_sources[0..self.effects.snapshot_sources_len];
}
