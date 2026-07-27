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

const SnapshotSource = struct {
    from: Pubkey,
    rpc_addr: lib.net.Address,
    slot: Slot,
    hash: Hash,
};
const TestMetricStore = lib.telemetry.TestMetricStore;

allocator: std.mem.Allocator,
// Backing memory for the node's fixed-buffer allocations, reused by reset.
scratch: []u8,
metric_store: TestMetricStore,
effects_state: *EffectsState,
node: Node,
// Wall time in milliseconds tracked to simulate time passing
now_ms: u64,

const TestNode = @This();
const Node = GossipNode(Effects);

const scratch_size = 4 * 1024 * 1024;
const packet_capacity = 256;
const snapshot_source_capacity = 16;

const EffectsState = struct {
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
};

// Implementation for GossipNode Effects interface to capture state for test asserts.
const Effects = struct {
    state: *EffectsState,

    pub fn writePacket(self: Effects) *Packet {
        const index = self.state.packets_len + self.state.pending_packets_len;
        const capacity = self.state.packets.len;
        std.debug.assert(index < capacity);
        self.state.pending_packets_len += 1;
        return &self.state.packets[index];
    }

    pub fn flushWrittenPackets(self: Effects) void {
        // Publish every packet reserved since the previous flush.
        self.state.packets_len += self.state.pending_packets_len;
        self.state.pending_packets_len = 0;
    }

    pub fn getIdentity(self: Effects) Pubkey {
        return self.state.keypair.pubkey;
    }

    pub fn sign(self: Effects, message: []const u8) Signature {
        return self.state.keypair.sign(message) catch unreachable;
    }

    pub fn reportSnapshotSource(
        self: Effects,
        from: Pubkey,
        address: std.net.Address,
        slot: Slot,
        hash: Hash,
    ) void {
        const capacity = self.state.snapshot_sources.len;
        std.debug.assert(self.state.snapshot_sources_len < capacity);
        self.state.snapshot_sources[self.state.snapshot_sources_len] = .{
            .from = from,
            .rpc_addr = .fromNetAddress(address),
            .slot = slot,
            .hash = hash,
        };
        self.state.snapshot_sources_len += 1;
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
    const effects_state = try allocator.create(EffectsState);
    errdefer allocator.destroy(effects_state);
    effects_state.* = .{
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
    @memcpy(effects_state.entrypoints[0..entrypoints.len], entrypoints);
    effects_state.socket_builder.set(.gossip, address);

    const scratch = try allocator.alloc(u8, scratch_size);
    errdefer allocator.free(scratch);
    var fixed_buffer: std.heap.FixedBufferAllocator = .init(scratch);

    var metric_store = try TestMetricStore.init(allocator, .{});
    errdefer metric_store.deinit();
    const metrics = appendGossipMetrics(&metric_store);

    const effects: Effects = .{ .state = effects_state };
    const node = try Node.init(&fixed_buffer, now_ms, metrics, .{
        .effects = effects,
        .shred_version = 42,
        .socket_map = effects_state.socket_builder.asSocketMap(),
        .entrypoints = effects_state.entrypoints[0..effects_state.entrypoints_len],
        .limits = .{
            .table = 256,
            .expired = 256,
            .peers = 256,
        },
    });

    return .{
        .allocator = allocator,
        .scratch = scratch,
        .metric_store = metric_store,
        .effects_state = effects_state,
        .node = node,
        .now_ms = now_ms,
    };
}

pub fn deinit(self: *TestNode) void {
    self.metric_store.deinit();
    self.allocator.free(self.scratch);
    self.allocator.destroy(self.effects_state);
}

fn appendGossipMetrics(metric_store: *TestMetricStore) Metrics {
    return metric_store.appendMetrics(Metrics, .{
        .prefix = "gossip_test",
    });
}

pub fn reset(self: *TestNode, now_ms: u64) !void {
    std.debug.assert(self.effects_state.pending_packets_len == 0);
    self.effects_state.packets_len = 0;
    self.effects_state.snapshot_sources_len = 0;

    self.metric_store.reset();
    const metrics = appendGossipMetrics(&self.metric_store);

    // Recreate the node from the start of its fixed backing buffer.
    var fixed_buffer: std.heap.FixedBufferAllocator = .init(self.scratch);
    self.node = try Node.init(&fixed_buffer, now_ms, metrics, self.node.config);
    self.now_ms = now_ms;
    self.node.assertInvariants();
}

pub fn identity(self: *const TestNode) Pubkey {
    return self.effects_state.keypair.pubkey;
}

pub fn poll(self: *TestNode) !void {
    try self.node.poll(.noop, self.now_ms);
    self.node.assertInvariants();
}

pub fn advanceMs(self: *TestNode, duration_ms: u64) void {
    self.now_ms += duration_ms;
}

pub fn receivePacket(self: *TestNode, packet: *const Packet) void {
    self.node.processPacket(.noop, self.now_ms, packet);
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
    return self.effects_state.packets[0..self.effects_state.packets_len];
}

pub fn clearOutgoingPackets(self: *TestNode) void {
    std.debug.assert(self.effects_state.pending_packets_len == 0);
    self.effects_state.packets_len = 0;
}

pub fn snapshotSources(self: *const TestNode) []const SnapshotSource {
    return self.effects_state.snapshot_sources[0..self.effects_state.snapshot_sources_len];
}
