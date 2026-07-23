//! Component test harness for a GossipNode with deterministic identity and captured effects.

const std = @import("std");
const lib = @import("../../lib.zig");
const TestLogStore = lib.telemetry.TestLogStore;
const TestMetricStore = lib.telemetry.TestMetricStore;
const testing = lib.gossip.testing;

allocator: std.mem.Allocator,
// Backing memory for the node's fixed-buffer allocations, reused by reset.
scratch: []u8,
log_store: TestLogStore,
metric_store: TestMetricStore,
effects_state: *EffectsState,
node: Node,
// Wall time in milliseconds tracked to simulate time passing
now_ms: u64,

const TestNode = @This();
const Node = lib.gossip.GossipNode(Effects);

const scratch_size = 4 * 1024 * 1024;
const packet_capacity = 256;
const snapshot_source_capacity = 16;

const EffectsState = struct {
    keypair: lib.gossip.KeyPair,
    // These fields back slices retained by the node configuration.
    socket_builder: lib.gossip.SocketMap.Builder,
    entrypoints: [lib.gossip.ClusterInfo.MAX_ENTRY_ADDRS]lib.gossip.Address,
    entrypoints_len: usize,
    // Flushed packets come first, followed by packets pending the next flush.
    packets: [packet_capacity]lib.net.Packet,
    packets_len: usize,
    pending_packets_len: usize,
    snapshot_sources: [snapshot_source_capacity]lib.snapshot.SnapshotSource,
    snapshot_sources_len: usize,
};

// Implementation for GossipNode Effects interface to capture state for test asserts.
const Effects = struct {
    state: *EffectsState,

    pub fn writePacket(self: Effects) *lib.net.Packet {
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

    pub fn getIdentity(self: Effects) lib.solana.Pubkey {
        return self.state.keypair.pubkey;
    }

    pub fn sign(self: Effects, message: []const u8) lib.solana.Signature {
        return self.state.keypair.sign(message) catch unreachable;
    }

    pub fn reportSnapshotSource(
        self: Effects,
        from: lib.solana.Pubkey,
        address: std.net.Address,
        slot: lib.solana.Slot,
        hash: lib.solana.Hash,
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
    identity_seed: u8,
    address: lib.gossip.Address,
    entrypoints: []const lib.gossip.Address,
) !TestNode {
    std.debug.assert(entrypoints.len <= lib.gossip.ClusterInfo.MAX_ENTRY_ADDRS);

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

    var log_store = try TestLogStore.init(allocator, .{});
    errdefer log_store.deinit();

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
        .log_store = log_store,
        .metric_store = metric_store,
        .effects_state = effects_state,
        .node = node,
        .now_ms = now_ms,
    };
}

pub fn deinit(self: *TestNode) void {
    self.log_store.deinit();
    self.metric_store.deinit();
    self.allocator.free(self.scratch);
    self.allocator.destroy(self.effects_state);
}

fn appendGossipMetrics(metric_store: *TestMetricStore) lib.gossip.Metrics {
    return metric_store.appendMetrics(lib.gossip.Metrics, .{
        .prefix = "gossip_test",
    });
}

pub fn reset(self: *TestNode, now_ms: u64) !void {
    std.debug.assert(self.effects_state.pending_packets_len == 0);
    self.effects_state.packets_len = 0;
    self.effects_state.snapshot_sources_len = 0;

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

pub fn identity(self: *const TestNode) lib.solana.Pubkey {
    return self.effects_state.keypair.pubkey;
}

pub fn poll(self: *TestNode) !void {
    try self.node.poll(self.log_store.logger("poll"), self.now_ms);
    self.node.assertInvariants();
}

pub fn advanceMs(self: *TestNode, duration_ms: u64) void {
    self.now_ms += duration_ms;
}

pub fn receivePacket(self: *TestNode, packet: *const lib.net.Packet) void {
    self.node.processPacket(self.log_store.logger("processPacket"), self.now_ms, packet);
    self.node.assertInvariants();
}

pub fn receiveMessage(
    self: *TestNode,
    source: std.net.Address,
    message: lib.gossip.GossipMessage,
) !void {
    const packet = try testing.packetFromMessage(source, message);
    self.receivePacket(&packet);
}

pub fn outgoingPackets(self: *const TestNode) []const lib.net.Packet {
    // Packets remain hidden from tests until the Effects implementation flushes them.
    return self.effects_state.packets[0..self.effects_state.packets_len];
}

pub fn clearOutgoingPackets(self: *TestNode) void {
    std.debug.assert(self.effects_state.pending_packets_len == 0);
    self.effects_state.packets_len = 0;
}

pub fn snapshotSources(self: *const TestNode) []const lib.snapshot.SnapshotSource {
    return self.effects_state.snapshot_sources[0..self.effects_state.snapshot_sources_len];
}
