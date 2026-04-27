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

const MAX_CONCURRENT_PROBES: u8 = 16;
const PROBE_TIMEOUT_SECS: i64 = 3;
const PROBE_TIMEOUT: std.os.linux.kernel_timespec = .{ .sec = PROBE_TIMEOUT_SECS, .nsec = 0 };

const ProbeConn = struct {
    /// Current state in the snapshot probing lifecycle for this particaly peer.
    /// Set to .unused when this slot is available for a new probe.
    phase: enum { unused, connecting, sending, receiving },
    /// tcp socket fd for the peer.
    fd: std.posix.fd_t,
    /// gossip addr for peer
    addr: Address,
    /// stores the http HEAD request pre-formatted to check
    send_buf: [256]u8,
    /// lenfth of the formatted HTTP HEAD request.
    send_len: u16,
    /// buffer for the HTTP response from peer
    /// TODO: prob too big, maybe just close out probes that respond with weird sizes.
    recv_buf: [4096]u8,
    /// os socket addr that addr gets converted into.
    /// stored in the probe ring to ensure it remains stable for io_uring.
    net_addr: std.net.Address,
    /// timestamp captured at probe start. Used to compute
    /// latency on successful completion.
    start_time: std.time.Instant,
    /// Snapshot slot that this probe is testing for.
    slot: Slot,
    /// Snapshot hash that this probe is testing for, used along with
    /// slot as a staleness guard.
    hash: Hash,
    /// monotonically increasing counter for this probe array entry,
    /// incremented each time the entry is reused. Encoded into UserData
    /// so that late cqes from previous occupant can be detected and
    /// discarded.
    gen: u16,
    /// set when a linked timeout fired, but we are still waiting for the
    /// primary op's cqe before freeing/reusing the slot.
    timed_out: bool,
    /// byte offset of the most recently submitted primary op within the current phase.
    /// Used to distinguish stale timeout cqes from previous partial send/recv ops.
    active_offset: u16,

    pub fn empty() ProbeConn {
        return .{
            .phase = .unused,
            .fd = -1,
            .addr = undefined,
            .send_buf = undefined,
            .send_len = 0,
            .recv_buf = undefined,
            .net_addr = undefined,
            .start_time = undefined,
            .slot = 0,
            .hash = Hash.ZEROES,
            .gen = 0,
            .timed_out = false,
            .active_offset = 0,
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

var dedupe_map_buf: [512 * 1024]u8 = @splat(0);
const DedupeMap = std.array_hash_map.ArrayHashMapUnmanaged(
    Address,
    PeerState,
    std.array_hash_map.AutoContext(Address),
    true,
);

// TODO: Can be smaller than u8.
const Op = enum(u8) {
    gossip_drain_timeout,
    probe_connect,
    probe_send,
    probe_recv,
};

/// Packed into io_uring sqe/cqe user_data field for identifying operations on completion
const UserData = packed struct(u64) {
    /// The io_uring operation type that produced this cqe.
    op: Op,
    /// Index into the probe_conns array identifying which probe this (s,c)qe belongs to
    index: u8,
    /// Byte offset tracking send/recv progress across partial completions.
    offset: u16,
    /// monotonic generaton counter to detect stale cqes from reused probe slots.
    gen: u16,
    /// true when this cqe is from a linked timeout sqe (not the primary op).
    is_timeout: bool,
    _reserved: u15,

    pub fn init(op: Op, index: u8, gen: u16) UserData {
        return .{
            .op = op,
            .index = index,
            .offset = 0,
            .gen = gen,
            .is_timeout = false,
            ._reserved = 0,
        };
    }

    pub fn encode(self: UserData) u64 {
        return @bitCast(self);
    }

    pub fn decode(ud: u64) UserData {
        return @bitCast(ud);
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
    snapshot_probes_timed_out: tel.Counter,
    snapshot_sq_fulls: tel.Counter,
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

    fn run(self: *SnapshotService) !noreturn {
        // TODO: what to init to? bunch of undefineds that feel wrong.
        var cqes: [256]std.os.linux.io_uring_cqe = undefined;

        // drain messages from gossip service immidiately. This also submits the first timeout for drain interval.
        try self.handleGossipDrainTimeout();

        while (true) {
            _ = try self.ring.submit_and_wait(1);
            const n = try self.ring.copy_cqes(&cqes, 0);

            for (cqes[0..n]) |cqe| {
                const data = UserData.decode(cqe.user_data);

                if (data.is_timeout) {
                    self.handleProbeTimeout(data, cqe);
                    continue;
                }

                switch (data.op) {
                    .gossip_drain_timeout => {
                        self.timeout_pending = false;
                        try self.handleGossipDrainTimeout();
                    },
                    .probe_connect => self.handleProbeConnect(data, cqe),
                    .probe_send => self.handleProbeSend(data, cqe),
                    .probe_recv => self.handleProbeRecv(data, cqe),
                }
            }
        }
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

                self.startProbe(key, gop.value_ptr) catch |err| {
                    self.logger.warn().logf("failed to start probe err={}", .{err});
                };
            } else if (!gop.value_ptr.eql(value)) {
                gop.value_ptr.* = value;

                // when a peer's slot/hash changes, start a new probe.
                self.startProbe(key, gop.value_ptr) catch |err| {
                    self.logger.warn().logf("failed to start probe err={}", .{err});
                };

                self.logger.info().logf(
                    "updated snapshot source {f} slot={d} hash={f}",
                    .{ source.rpc_addr, source.slot, source.hash },
                );
                self.metrics.snapshot_sources_updated.increment(1);
            } else {
                // Same addr + same slot/hash. Do not retry failed probes here.
                // A failed probe is terminal for this snapshot candidate. It will
                // be retried only if slot/hash changes (the update path above).
                self.metrics.snapshot_sources_deduped.increment(1);
            }
        }
        if (drained > 0) self.gossip_iter.markUsed();

        if (!self.timeout_pending) {
            _ = try self.ring.timeout(
                UserData.init(.gossip_drain_timeout, 0, 0).encode(),
                &GOSSIP_DRAIN_INTERVAL,
                0,
                0,
            );
            self.timeout_pending = true;
        }
    }

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

        probe.gen +%= 1;
        probe.fd = fd;
        probe.addr = addr;
        probe.slot = peer.slot;
        probe.hash = peer.hash;

        // NOTE: try is safe here since errdefer closes fd, and active_probes
        // has not been incremented yet, so the slot remains reusable.
        try self.queueProbeConnectWithTimeout(probe_index, fd);
        probe.start_time = std.time.Instant.now() catch unreachable;

        peer.probe_status = .in_flight;
        self.active_probes += 1;
        self.metrics.snapshot_probes_started.increment(1);
    }

    fn getProbeForCqe(self: *SnapshotService, data: UserData) ?*ProbeConn {
        std.debug.assert(data.index < self.probe_conns.len);
        const probe = &self.probe_conns[data.index];
        if (probe.phase == .unused) {
            self.logger.warn().logf("stale cqe for unused probe slot op={s} idx={d}", .{ @tagName(data.op), data.index });
            return null;
        }
        if (probe.gen != data.gen) {
            self.logger.warn().logf("stale probe cqe op={s} idx={d}", .{ @tagName(data.op), data.index });
            return null;
        }
        return probe;
    }

    /// An atomic batch of sqes. One is the operation of interest, followed by its timeout.
    const LinkedSqes = struct {
        primary: *std.os.linux.io_uring_sqe,
        timeout: *std.os.linux.io_uring_sqe,
    };

    /// Reserves the two sqes needed for a primary op + linked timeout.
    /// NOTE: assumes SnapshotService is the only producer (thread) mutating the ring.
    fn reserveLinkedSqes(self: *SnapshotService) !LinkedSqes {
        // NOTE: it is safe to get capacity this way due to single event producing thread.
        const capacity: u32 = @intCast(self.ring.sq.sqes.len);
        const ready = self.ring.sq_ready();

        std.debug.assert(ready <= capacity);

        if (capacity - ready < 2) {
            return error.SubmissionQueueFull;
        }

        // NOTE: we checked capacity first, and we're producing using a single thread,
        // so get_sqe failing below should not occur.
        return .{
            .primary = self.ring.get_sqe() catch unreachable,
            .timeout = self.ring.get_sqe() catch unreachable,
        };
    }

    /// Enqueues a pair of SQEs to connect and perform the tcp handshake along with a timeout.
    fn queueProbeConnectWithTimeout(
        self: *SnapshotService,
        index: u8,
        fd: std.posix.fd_t,
    ) !void {
        const probe = &self.probe_conns[index];

        const connect_data = UserData.init(.probe_connect, index, probe.gen);
        var timeout_data = connect_data;
        timeout_data.is_timeout = true;

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_connect(fd, &probe.net_addr.any, probe.net_addr.getOsSockLen());
        sqes.primary.user_data = connect_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        probe.phase = .connecting;
        probe.active_offset = 0;
        probe.timed_out = false;
    }

    /// Enqueues a pair of SQEs to send the HTTP HEAD request along with a timeout for the corresponding probe.
    /// After which we update the probe's phase to `sending`.
    fn queueProbeSendWithTimeout(
        self: *SnapshotService,
        data: UserData,
        /// used to track partial completions.
        offset: u16,
    ) !void {
        const probe = &self.probe_conns[data.index];

        var send_data = data;
        send_data.op = .probe_send;
        send_data.offset = offset;

        var timeout_data = send_data;
        timeout_data.is_timeout = true;

        std.debug.assert(offset <= probe.send_len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_send(probe.fd, probe.send_buf[offset..probe.send_len], 0);
        sqes.primary.user_data = send_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        probe.phase = .sending;
        probe.active_offset = offset;
        probe.timed_out = false;
    }

    /// Enqueues a pair of SQEs to recv the HTTP response along with a timeout.
    /// After which we update the probe's phase to `receiving`.
    fn queueProbeRecvWithTimeout(
        self: *SnapshotService,
        data: UserData,
        /// used to track partial completions.
        offset: u16,
    ) !void {
        const probe = &self.probe_conns[data.index];

        var recv_data = data;
        recv_data.op = .probe_recv;
        recv_data.offset = offset;

        var timeout_data = recv_data;
        timeout_data.is_timeout = true;

        std.debug.assert(offset <= probe.recv_buf.len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_recv(probe.fd, probe.recv_buf[offset..], 0);
        sqes.primary.user_data = recv_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;
        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        probe.phase = .receiving;
        probe.active_offset = offset;
        probe.timed_out = false;
    }

    fn handleProbeTimeout(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        std.debug.assert(data.index < self.probe_conns.len);
        const probe = &self.probe_conns[data.index];

        // NOTE: it's possible that slot was already retired by the primary op,
        // or reused by a new probe. Both are expected since the primary cqe completed
        // before the timeout fired. If the probe is marked unused, or the generations don't match,
        // then this timeout is stale. Just ignore it.
        if (probe.phase == .unused or probe.gen != data.gen) return;

        const expected_phase: @TypeOf(probe.phase) = switch (data.op) {
            .probe_connect => .connecting,
            .probe_send => .sending,
            .probe_recv => .receiving,
            else => unreachable,
        };
        if (probe.phase != expected_phase) return;
        if (data.offset != probe.active_offset) return;

        switch (cqe.err()) {
            .CANCELED, .NOENT, .ALREADY => {},
            .TIME => {
                probe.timed_out = true;
                self.logger.info().logf("probe timed out idx={d} phase={s}", .{
                    data.index, @tagName(probe.phase),
                });
                self.metrics.snapshot_probes_timed_out.increment(1);
            },
            else => {
                self.logger.warn().logf("unexpected timeout err idx={d} err={s}", .{
                    data.index, @tagName(cqe.err()),
                });
            },
        }
    }

    fn handleProbeConnect(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        if (probe.phase != .connecting) {
            self.logger.warn().logf("unexpected connect cqe idx={d} phase={s}", .{ data.index, @tagName(probe.phase) });
            return;
        }

        // TODO: coalesce both
        if (probe.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("probe connect failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        // We've succesfully connected, so send the HTTP HEAD request.
        // Enqueuing the entries can only fail if the submission queue is full,
        // if so we finish the probe with result .sq_full so the peer remains .pending for retry later (back pressure).
        self.queueProbeSendWithTimeout(data, 0) catch {
            self.finishProbe(data.index, .sq_full);
            return;
        };
    }

    fn handleProbeSend(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        if (probe.phase != .sending) {
            self.logger.warn().logf("unexpected send cqe idx={d} phase={s}", .{ data.index, @tagName(probe.phase) });
            return;
        }

        // TODO: coalesce both
        if (probe.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("probe send failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        // Track send progress across partial completions via user_data offset.
        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= probe.send_len - data.offset);
        const new_offset = data.offset + @as(u16, @intCast(cqe.res));

        // The previous send was partial, queue up another and return.
        if (new_offset < probe.send_len) {
            self.queueProbeSendWithTimeout(data, new_offset) catch {
                self.finishProbe(data.index, .sq_full);
                return;
            };
            return;
        }

        // We sent all of the payload, so queue up a recieve.
        self.queueProbeRecvWithTimeout(data, 0) catch {
            self.finishProbe(data.index, .sq_full);
            return;
        };
    }

    fn handleProbeRecv(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        if (probe.phase != .receiving) {
            self.logger.warn().logf("unexpected recv cqe idx={d} phase={s}", .{ data.index, @tagName(probe.phase) });
            return;
        }

        // TODO: coalesce these 3 conds
        if (probe.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("probe recv failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.res == 0) {
            self.logger.info().logf("probe recv eof idx={d}", .{data.index});
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        // Track recv progress across partial completions via user_data offset.
        const new_offset = data.offset + @as(u16, @intCast(cqe.res));
        const response = probe.recv_buf[0..new_offset];

        // Check for end of HTTP headers.
        const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse {
            if (new_offset >= probe.recv_buf.len) {
                self.finishProbe(data.index, .failed);
                self.probeNextPending();
                return;
            }
            // Partial headers, submit another recv.
            self.queueProbeRecvWithTimeout(data, new_offset) catch {
                self.finishProbe(data.index, .sq_full);
                return;
            };
            return;
        };

        // Parse status line from complete headers.
        const status_end = std.mem.indexOf(u8, response[0..header_end], "\r\n") orelse header_end;
        const status_line = response[0..status_end];
        const ok = std.mem.indexOf(u8, status_line, "200") != null;
        if (!ok) {
            self.logger.info().logf("probe recv bad status idx={d} status={s}", .{ data.index, status_line });
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        // Parse Content-Length from headers.
        const content_len = parseContentLength(response[0 .. header_end + 4]) orelse {
            self.logger.info().logf("probe missing/zero content-length idx={d}", .{data.index});
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        };

        // Compute and store latency.
        const elapsed_ns = (std.time.Instant.now() catch unreachable).since(probe.start_time);
        const latency_ms: u32 = @intCast(elapsed_ns / std.time.ns_per_ms);
        if (self.dedupe_map.getPtr(probe.addr)) |peer| {
            if (peer.slot == probe.slot and std.meta.eql(peer.hash, probe.hash)) {
                peer.latency_ms = latency_ms;
            }
        }

        self.logger.info().logf("probe succeeded idx={d} latency={d}ms content_len={d} addr={f}", .{ data.index, latency_ms, content_len, probe.addr });
        self.finishProbe(data.index, .succeeded);
        self.probeNextPending();
    }

    const ProbeResult = enum {
        /// probe completed with HTTP 200
        succeeded,
        /// peer/network error, bad status, or timeout (peer is bad/not responsive)
        failed,
        /// local SQE queue is full (back pressure), so retry operation later.
        sq_full,
    };

    fn finishProbe(self: *SnapshotService, probe_index: u8, result: ProbeResult) void {
        const probe = &self.probe_conns[probe_index];
        // If this fn gets called on a probe that's .unused, then return immidiately.
        if (probe.phase == .unused) return;
        if (self.dedupe_map.getPtr(probe.addr)) |peer| {
            // NOTE: We gaurd the update here since gossip can update peer in dedupe map while io_uring was completing this probe.
            // If it was updated underneath us, don't update things here since another/newer probe was alread issued to io_uring.
            if (peer.slot == probe.slot and std.meta.eql(peer.hash, probe.hash)) {
                peer.probe_status = switch (result) {
                    .succeeded => .succeeded,
                    .failed => .failed,
                    .sq_full => .pending,
                };
            }
        }

        if (probe.fd >= 0) std.posix.close(probe.fd);
        const old_gen = probe.gen;
        self.probe_conns[probe_index] = ProbeConn.empty();
        self.probe_conns[probe_index].gen = old_gen;
        self.active_probes -= 1;

        switch (result) {
            .succeeded => self.metrics.snapshot_probes_succeeded.increment(1),
            .failed => self.metrics.snapshot_probes_failed.increment(1),
            .sq_full => self.metrics.snapshot_sq_fulls.increment(1),
        }
    }

    fn probeNextPending(self: *SnapshotService) void {
        const keys = self.dedupe_map.keys();
        const values = self.dedupe_map.values();
        for (keys, values) |*addr, *peer| {
            if (peer.probe_status == .pending) {
                self.startProbe(addr.*, peer) catch |err| {
                    self.logger.warn().logf("failed to start pending probe err={}", .{err});
                };
                return;
            }
        }
    }
};

/// Parses the Content-Length header value from an HTTP response.
/// Returns null if the header is missing, zero, or unparseable.
fn parseContentLength(response: []const u8) ?u64 {
    var iter = std.http.HeaderIterator.init(response);
    while (iter.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-length")) {
            const value = std.fmt.parseInt(u64, header.value, 10) catch return null;
            if (value == 0) return null;
            return value;
        }
    }
    return null;
}

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
