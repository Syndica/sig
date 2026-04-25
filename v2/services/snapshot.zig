const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const tel = lib.telemetry;

const Address = lib.gossip.Address;
const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const IoUring = std.os.linux.IoUring;
const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;

const MAX_DRAIN: u8 = 64;
const GOSSIP_DRAIN_INTERVAL: std.os.linux.kernel_timespec = .{ .sec = 0, .nsec = 100_000_000 };

const MAX_CONCURRENT_PROBES: u8 = 20;

const ProbeConn = struct {
    phase: enum { unused, connecting, sending, receiving },
    fd: std.posix.fd_t,
    addr: Address,
    send_buf: [256]u8,
    send_len: u16,
    send_off: u16,
    recv_buf: [4096]u8,
    net_addr: std.net.Address,
    start_time: std.time.Instant,
    slot: Slot,
    hash: Hash,

    pub fn empty() ProbeConn {
        return .{
            .phase = .unused,
            .fd = -1,
            .addr = undefined,
            .send_buf = undefined,
            .send_len = 0,
            .send_off = 0,
            .recv_buf = undefined,
            .net_addr = undefined,
            .start_time = undefined,
            .slot = 0,
            .hash = Hash.ZEROES,
        };
    }
};

const ProbeStatus = enum(u8) {
    pending,
    in_flight,
    succeeded,
    failed,
};

const PeerState = struct {
    slot: Slot,
    hash: Hash,
    probe_status: ProbeStatus,
    latency_ms: u32,

    pub fn eql(self: PeerState, other: PeerState) bool {
        return self.slot == other.slot and std.meta.eql(self.hash, other.hash);
    }
};

const Metrics = struct {
    snapshot_sources_received: tel.Counter,
    snapshot_sources_deduped: tel.Counter,
    snapshot_sources_new: tel.Counter,
    snapshot_sources_updated: tel.Counter,
    snapshot_probes_started: tel.Counter,
    snapshot_probes_succeeded: tel.Counter,
    snapshot_probes_failed: tel.Counter,
};

var dedupe_map_buf: [512 * 1024]u8 = @splat(0);
const DedupeMap = std.array_hash_map.ArrayHashMapUnmanaged(
    Address,
    PeerState,
    std.array_hash_map.AutoContext(Address),
    true,
);

const Op = enum(u8) {
    gossip_drain_timeout,
    probe_connect,
    probe_send,
    probe_recv,

    pub fn encodeUserData(op: Op, index: u8) u64 {
        return @intFromEnum(op) | (@as(u64, index) << 8);
    }

    pub fn decodeUserData(ud: u64) struct { Op, u8 } {
        return .{ @enumFromInt(ud & 0xFF), @intCast((ud >> 8) & 0xFF) };
    }
};

const SnapshotService = struct {
    ring: IoUring,
    gossip_iter: *SnapshotSourceRing.Iterator(.reader),
    dedupe_map: *DedupeMap,
    dedupe_alloc: std.mem.Allocator,
    probe_conns: [MAX_CONCURRENT_PROBES]ProbeConn,
    active_probes: u8,
    timeout_pending: bool,

    metrics: Metrics,
    logger: tel.Logger("snapshot"),

    fn startProbe(self: *SnapshotService, addr: Address, peer: *PeerState) !void {
        if (self.active_probes >= MAX_CONCURRENT_PROBES) return;

        // find a free prob
        const probe_index: u8, const probe = for (&self.probe_conns, 0..) |*p, i| {
            if (p.phase == .unused) break .{ @intCast(i), p };
        } else return;

        // create tcp socket
        probe.net_addr = addr.toNetAddress();
        const fd = try std.posix.socket(
            probe.net_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        errdefer std.posix.close(fd);

        // create req
        var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
        const hash_str = peer.hash.base58String(&hash_buf);
        const send_len = std.fmt.bufPrint(
            &probe.send_buf,
            "HEAD /snapshot-{d}-{s}.tar.zst HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
            .{ peer.slot, hash_str, probe.net_addr },
        ) catch unreachable;
        probe.send_len = @intCast(send_len.len);

        // submit connect sqe
        _ = try self.ring.connect(
            Op.probe_connect.encodeUserData(probe_index),
            fd,
            &probe.net_addr.any,
            probe.net_addr.getOsSockLen(),
        );

        probe.phase = .connecting;
        probe.start_time = std.time.Instant.now() catch unreachable;
        probe.fd = fd;
        probe.addr = addr;
        probe.slot = peer.slot;
        probe.hash = peer.hash;

        peer.probe_status = .in_flight;
        self.active_probes += 1;
        self.metrics.snapshot_probes_started.increment(1);
    }

    fn finishProbe(self: *SnapshotService, probe_index: u8, ok: bool) void {
        const probe = &self.probe_conns[probe_index];
        if (self.dedupe_map.getPtr(probe.addr)) |peer| {
            // NOTE: We gaurd the update here since gossip can update peer in dedupe map while io_uring was completing this probe.
            // If it was updated underneath us, don't update things here since another/newer probe was alread issued to io_uring.
            if (peer.slot == probe.slot and std.meta.eql(peer.hash, probe.hash)) {
                peer.probe_status = if (ok) .succeeded else .failed;
            }
        }

        if (probe.fd >= 0) std.posix.close(probe.fd);
        self.probe_conns[probe_index] = ProbeConn.empty();
        self.active_probes -= 1;

        if (ok) {
            self.metrics.snapshot_probes_succeeded.increment(1);
        } else {
            self.metrics.snapshot_probes_failed.increment(1);
        }
    }

    fn probeNextPending(self: *SnapshotService) !void {
        const keys = self.dedupe_map.keys();
        const values = self.dedupe_map.values();
        for (keys, values) |*addr, *peer| {
            if (peer.probe_status == .pending) {
                try self.startProbe(addr.*, peer);
                return;
            }
        }
    }

    fn handleProbeConnect(self: *SnapshotService, probe_index: u8, cqe_res: i32) !void {
        const probe = &self.probe_conns[probe_index];
        if (probe.phase != .connecting) {
            self.logger.warn().logf("unexpected connect cqe idx={d} phase={s}", .{ probe_index, @tagName(probe.phase) });
            return;
        }
        if (cqe_res < 0) {
            self.logger.info().logf("probe connect failed idx={d} errno={d}", .{ probe_index, -cqe_res });
            self.finishProbe(probe_index, false);
            try self.probeNextPending();
            return;
        }
        _ = try self.ring.send(
            Op.probe_send.encodeUserData(probe_index),
            probe.fd,
            probe.send_buf[0..probe.send_len],
            0,
        );
        probe.phase = .sending;
    }

    fn handleProbeSend(self: *SnapshotService, probe_index: u8, cqe_res: i32) !void {
        const probe = &self.probe_conns[probe_index];
        if (probe.phase != .sending) {
            self.logger.warn().logf("unexpected send cqe idx={d} phase={s}", .{ probe_index, @tagName(probe.phase) });
            return;
        }
        if (cqe_res < 0) {
            self.logger.info().logf("probe send failed idx={d} errno={d}", .{ probe_index, -cqe_res });
            self.finishProbe(probe_index, false);
            try self.probeNextPending();
            return;
        }

        // NOTE: used to track how much we've sent to handle potential partial sends properly.
        // TODO: document that partial sends with io_uring are possible.
        probe.send_off += @intCast(cqe_res);

        // Check for this partial send case
        if (probe.send_off < probe.send_len) {
            _ = try self.ring.send(
                Op.probe_send.encodeUserData(probe_index),
                probe.fd,
                probe.send_buf[probe.send_off..probe.send_len],
                0,
            );
            return;
        }

        // full req sent, so just submit the recv and move to receiving state.
        _ = try self.ring.recv(
            Op.probe_recv.encodeUserData(probe_index),
            probe.fd,
            .{ .buffer = &probe.recv_buf },
            0,
        );
        probe.phase = .receiving;
    }

    fn handleProbeRecv(self: *SnapshotService, probe_index: u8, cqe_res: i32) !void {
        const probe = &self.probe_conns[probe_index];
        if (probe.phase != .receiving) {
            self.logger.warn().logf("unexpected recv cqe idx={d} phase={s}", .{ probe_index, @tagName(probe.phase) });
            return;
        }
        if (cqe_res <= 0) {
            self.logger.info().logf("probe recv failed idx={d} res={d}", .{ probe_index, cqe_res });
            self.finishProbe(probe_index, false);
            try self.probeNextPending();
            return;
        }

        // TODO: Currently assuming no partial receives, and response sizes for probes are tiny, but we should handle them for correctness.
        // accumulate recv bytes across multiple cqes to handle partial receives.
        const len: usize = @intCast(cqe_res);
        const response = probe.recv_buf[0..len];

        // parse status line
        const status_end = std.mem.indexOf(u8, response, "\r\n") orelse {
            self.finishProbe(probe_index, false);
            try self.probeNextPending();
            return;
        };

        const status_line = response[0..status_end];
        const ok = std.mem.indexOf(u8, status_line, "200") != null;
        if (!ok) {
            self.logger.info().logf("probe recv bad status idx={d} status={s}", .{ probe_index, status_line });
            self.finishProbe(probe_index, false);
            try self.probeNextPending();
            return;
        }

        // compute & store latency
        const elapsed_ns = (std.time.Instant.now() catch unreachable).since(probe.start_time);
        const latency_ms: u32 = @intCast(elapsed_ns / std.time.ns_per_ms);
        if (self.dedupe_map.getPtr(probe.addr)) |peer| {
            // NOTE: We gaurd the update here since gossip can update peer in dedupe map while io_uring was completing this probe.
            // If it was updated underneath us, don't update things here since another/newer probe was alread issued to io_uring.
            if (peer.slot == probe.slot and std.meta.eql(peer.hash, probe.hash)) {
                peer.latency_ms = latency_ms;
            }
        }

        self.logger.info().logf("probe succeeded idx={d} latency={d}ms addr={f}", .{ probe_index, latency_ms, probe.addr });
        self.finishProbe(probe_index, true);
        try self.probeNextPending();
    }

    fn handleGossipDrainTimeout(self: *SnapshotService) !void {
        var drained: u8 = 0;
        while (drained < MAX_DRAIN) : (drained += 1) {
            const source = self.gossip_iter.next() orelse break;
            self.metrics.snapshot_sources_received.increment(1);

            const key = source.rpc_addr;
            const value: PeerState = .{
                .slot = source.slot,
                .hash = source.hash,
                .probe_status = .pending,
                .latency_ms = 0,
            };

            const gop = try self.dedupe_map.getOrPut(self.dedupe_alloc, key);
            if (!gop.found_existing) {
                gop.value_ptr.* = value;

                // self.logger.info().logf(
                //     "new snapshot source {f} slot={d} hash={f}",
                //     .{ source.rpc_addr, source.slot, source.hash },
                // );
                self.metrics.snapshot_sources_new.increment(1);

                try self.startProbe(key, gop.value_ptr);
            } else if (!gop.value_ptr.eql(value)) {
                gop.value_ptr.* = value;

                // when a peer's slot/hash changes, start a new probe.
                try self.startProbe(key, gop.value_ptr);

                self.logger.info().logf(
                    "updated snapshot source {f} slot={d} hash={f}",
                    .{ source.rpc_addr, source.slot, source.hash },
                );
                self.metrics.snapshot_sources_updated.increment(1);
            } else {
                // NOTE: if a peer re-announces itself with the same slot and hash in gossip,
                // and a previous probe attempt failed, we give it another try, maybe it's healthy again.
                if (gop.value_ptr.probe_status == .failed) {
                    gop.value_ptr.probe_status = .pending;
                    try self.startProbe(key, gop.value_ptr);
                }
                self.metrics.snapshot_sources_deduped.increment(1);
            }
        }
        if (drained > 0) self.gossip_iter.markUsed();

        if (!self.timeout_pending) {
            _ = try self.ring.timeout(
                Op.gossip_drain_timeout.encodeUserData(0),
                &GOSSIP_DRAIN_INTERVAL,
                0,
                0,
            );
            self.timeout_pending = true;
        }
    }

    fn run(self: *SnapshotService) !noreturn {
        // TODO: what to init to? bunch of undefineds that feel wrong.
        var cqes: [256]std.os.linux.io_uring_cqe = undefined;

        // drain messages from gossip service immidiately. This also submits the first timeout for drain interval.
        try self.handleGossipDrainTimeout();

        while (true) {
            _ = try self.ring.submit_and_wait(1);
            const n = try self.ring.copy_cqes(&cqes, 0);

            for (cqes[0..n]) |cqe| {
                const op, const probe_index = Op.decodeUserData(cqe.user_data);

                switch (op) {
                    .gossip_drain_timeout => {
                        self.timeout_pending = false;
                        try self.handleGossipDrainTimeout();
                    },
                    .probe_connect, .probe_send, .probe_recv => {
                        std.debug.assert(probe_index < MAX_CONCURRENT_PROBES);
                        switch (op) {
                            .probe_connect => try self.handleProbeConnect(probe_index, cqe.res),
                            .probe_send => try self.handleProbeSend(probe_index, cqe.res),
                            .probe_recv => try self.handleProbeRecv(probe_index, cqe.res),
                            else => unreachable,
                        }
                    },
                }
            }
        }
    }
};

comptime {
    _ = start;
}

// Note: matches services.zon name
pub const name = .snapshot;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    config: *const lib.snapshot.SnapshotConfig,
};

pub const ReadWrite = struct {
    tel: *tel.Region,
    gossip_to_snapshot: *SnapshotSourceRing,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "snapshot");
    const metrics = rw.tel.metricAppender().appendFields(Metrics, .{});
    rw.tel.signalReady();

    const folder_path = ro.config.folder_buffer[0..ro.config.folder_len];
    logger.info().logf("snapshot path {s}", .{folder_path});

    // Create a map for deduping candidate node addresses streaming in from gossip service.
    var dedupe_fba = std.heap.FixedBufferAllocator.init(&dedupe_map_buf);
    var dedupe_map = DedupeMap{};
    var gossip_iter = rw.gossip_to_snapshot.get(.reader);

    var service = SnapshotService{
        .ring = try IoUring.init(256, 0),
        .gossip_iter = &gossip_iter,
        .dedupe_map = &dedupe_map,
        .dedupe_alloc = dedupe_fba.allocator(),
        .probe_conns = .{ProbeConn.empty()} ** MAX_CONCURRENT_PROBES,
        .active_probes = 0,
        .timeout_pending = false,
        .metrics = metrics,
        .logger = logger,
    };
    defer service.ring.deinit();

    try service.run();
}
