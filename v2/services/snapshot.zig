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

const MAX_DOWNLOAD_RACERS: u8 = 16;
const MAX_DOWNLOAD_CANDIDATES: u8 = 64;
const DOWNLOAD_RACE_THRESHOLD_PCT: u64 = 10;
const SPLICE_CHUNK: u32 = 1024 * 1024;
const NO_OFFSET: u64 = std.math.maxInt(u64);
const DOWNLOAD_TIMEOUT_SECS: i64 = 3;
const DOWNLOAD_TIMEOUT: std.os.linux.kernel_timespec = .{ .sec = DOWNLOAD_TIMEOUT_SECS, .nsec = 0 };

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

/// The current phase of this peer's download during the race.
const DownloadPhase = enum {
    /// This entry in the `DownloadConn` array is free. No active download being tracked.
    unused,
    /// TCP socket exists for this peer, and an async connect has beeen issued to io_uring.
    connecting,
    /// TCP connection succeeded, and an async send of the HTTP GET request issued.
    sending,
    /// GET req was sent, async recv() is reading HTTP response (headers) into peer's `recv_buf`.
    reading_headers,
    /// The received header also captured some body bytes after parsing `\r\n\r\n`, so a write() has been issued
    /// to move those body bytes to the peer's temp file.
    writing_extra,
    /// A splice_in returned EAGAIN (socket not readable yet). A poll for POLLIN has been issued.
    waiting_readable,
    /// Async `splice()` issued to move snapshot body bytes from TCP socket into the pipe.
    /// represents socket -> pipe.
    splicing_in,
    /// Asyne `splice()` moving bytes from pipe to temp file.
    /// represents pipe -> file.
    splicing_out,
    /// All expected bytes written (download complete/this peer won). An async `fsync()` is issued to flush
    /// remaining bytes to temp file, before final rename. Losers don't reach this state.
    fsyncing,
};

const DownloadCandidate = struct {
    addr: Address,
    latency_ms: u32,
    content_len: u64,
    started: bool = false,
};

const DownloadRace = struct {
    phase: enum {
        /// The race hasn't started yet (no candidates have arrived).
        idle,
        /// At least one candidate queued/download in flight.
        racing,
        /// A winner has been declared. Losers are being stopped.
        winner_selected,
        /// The winner's download has completed, final file available.
        completed,
        /// The race has totally failed.
        failed,
    },

    slot: Slot,
    hash: Hash,

    candidates: [MAX_DOWNLOAD_CANDIDATES]DownloadCandidate,
    candidate_count: u8,

    winner_index: ?u8,

    /// NOTE: resets the race phase to .idle
    pub fn empty() DownloadRace {
        return .{
            .phase = .idle,
            .slot = 0,
            .hash = Hash.ZEROES,
            .candidates = undefined,
            .candidate_count = 0,
            .winner_index = null,
        };
    }
};

// TODO: can be unified with ProbeConn in some way, combine all state.
const DownloadConn = struct {
    phase: DownloadPhase,
    /// Similar to ProvbeConn's gen. Used to prevent a late-arriving CQE for this DownloadConn when
    /// the original peer's download was abandoned from overwritting the new peer it's now representing (i.e generations don't match).
    gen: u16,
    /// set when a linked timeout fired, but we are still waiting for the
    /// primary op's cqe before freeing/reusing the slot prematurely.
    timed_out: bool,
    /// byte offset of the most recently submitted primary op within the current phase.
    /// Used to distinguish stale timeout cqes from previous partial send/recv ops when downloading.
    active_offset: u16,
    /// Set once a winner is declared so signal that this download should be stopped and cleaned up.
    cancel_requested: bool,

    /// The tcp socket connected to the snapshot peer. Used for HTTP GET and reading snapshot bytes.
    /// TODO: Would be nice to transfer tcp connection from probing phase to download phase without needing to re-open.
    fd: std.posix.fd_t,
    /// The temp output file being written by this peer.
    file_fd: std.posix.fd_t,
    /// The read end of the pipe used by splice to bridge between socket and file.
    pipe_rd: std.posix.fd_t,
    /// The write end of the pipe used by splice to bridge between socket and file.
    pipe_wr: std.posix.fd_t,

    /// Address used for logging/identity.
    addr: Address,
    /// Address used for the socket connection (must live long enough for io_uring use, hence stored here).
    net_addr: std.net.Address,

    /// Used to store the GET request string for this peer.
    send_buf: [256]u8,
    /// The length of the GET request's payload.
    send_len: u16,

    /// Used to store HTTP responses. Needs to live until the recv CQE completes.
    recv_buf: [4096]u8,
    /// The length of the HTTP payload received and stored in `recv_buf` currently.
    recv_len: u16,

    /// Start of the HTTP body bytes in `recv_buf`.
    extra_body_start: u16,
    /// End of the HTTP body bytes in `recv_buf`.
    extra_body_len: u16,

    /// The number of snapshot body bytes written to this peer's temp file.
    bytes_written: u64,
    /// The expected total size of the snapshot for this racer (from its probe HEAD response).
    content_len: u64,
    /// The number of bytes moved from the socket into the pipe that still need to be flushed to this peer's temp file.
    pipe_pending: u64,

    pub fn empty() DownloadConn {
        return .{
            .phase = .unused,
            .gen = 0,
            .timed_out = false,
            .active_offset = 0,
            .cancel_requested = false,

            .fd = -1,
            .file_fd = -1,
            .pipe_rd = -1,
            .pipe_wr = -1,

            .addr = undefined,
            .net_addr = undefined,

            .send_buf = undefined,
            .send_len = 0,

            .recv_buf = undefined,
            .recv_len = 0,

            .extra_body_start = 0,
            .extra_body_len = 0,

            .bytes_written = 0,
            .content_len = 0,
            .pipe_pending = 0,
        };
    }
};

const DownloadResult = enum {
    succeeded,
    failed,
    cancelled,
};

// TODO: Can be smaller than u8.
const Op = enum(u8) {
    gossip_drain_timeout,

    probe_connect,
    probe_send,
    probe_recv,

    download_connect,
    download_send,
    download_recv_headers,
    download_write_extra,
    download_poll_in,
    download_splice_in,
    download_splice_out,
    download_fsync,
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
    snapshot_download_candidates: tel.Counter,
    snapshot_downloads_started: tel.Counter,
    snapshot_downloads_failed: tel.Counter,
    snapshot_downloads_cancelled: tel.Counter,
    snapshot_downloads_succeeded: tel.Counter,
    snapshot_download_bytes_written: tel.Counter,
};

const SnapshotService = struct {
    ring: IoUring,
    gossip_iter: *SnapshotSourceRing.Iterator(.reader),
    dedupe_map: *DedupeMap,
    dedupe_alloc: std.mem.Allocator,
    probe_conns: [MAX_CONCURRENT_PROBES]ProbeConn,
    active_probes: u8,
    timeout_pending: bool,

    download_conns: [MAX_DOWNLOAD_RACERS]DownloadConn,
    active_downloads: u8,
    download_race: DownloadRace,
    snapshot_dir: []const u8,

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

                // An operation timed out, invoke the corresponding timeout handler.
                if (data.is_timeout) {
                    switch (data.op) {
                        .probe_connect,
                        .probe_send,
                        .probe_recv,
                        => self.handleProbeTimeout(data, cqe),
                        .download_connect,
                        .download_send,
                        .download_recv_headers,
                        .download_poll_in,
                        .download_splice_in,
                        => self.handleDownloadTimeout(data, cqe),
                        // The other op's don't have timeouts.
                        else => {},
                    }
                    continue;
                }

                // Otherwise, an operation has completed, handle state changes.
                switch (data.op) {
                    .gossip_drain_timeout => {
                        self.timeout_pending = false;
                        try self.handleGossipDrainTimeout();
                    },
                    .probe_connect => self.handleProbeConnect(data, cqe),
                    .probe_send => self.handleProbeSend(data, cqe),
                    .probe_recv => self.handleProbeRecv(data, cqe),

                    .download_connect => self.handleDownloadConnect(data, cqe),
                    .download_send => self.handleDownloadSend(data, cqe),
                    .download_recv_headers => self.handleDownloadRecvHeaders(data, cqe),
                    .download_write_extra => self.handleDownloadWriteExtra(data, cqe),
                    .download_poll_in => self.handleDownloadPollIn(data, cqe),
                    .download_splice_in => self.handleDownloadSpliceIn(data, cqe),
                    .download_splice_out => self.handleDownloadSpliceOut(data, cqe),
                    .download_fsync => self.handleDownloadFsync(data, cqe),
                }
            }
        }
    }

    fn handleGossipDrainTimeout(self: *SnapshotService) !void {
        if (self.download_race.phase == .completed) {
            self.timeout_pending = false;
            return;
        }

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
        if (self.download_race.phase == .completed) return;
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

        // Finish out the probe before moving peer info onto download phase.
        const candidate = DownloadCandidate{
            .addr = probe.addr,
            .latency_ms = latency_ms,
            .content_len = content_len,
        };
        const slot = probe.slot;
        const hash = probe.hash;

        self.finishProbe(data.index, .succeeded);

        self.offerDownloadCandidate(candidate, slot, hash);
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
        if (self.download_race.phase == .completed) return;

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

    fn handleDownloadTimeout(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        std.debug.assert(data.index < self.download_conns.len);
        const conn = &self.download_conns[data.index];

        if (conn.phase == .unused or conn.gen != data.gen) return;

        const expected_phase: DownloadPhase = switch (data.op) {
            .download_connect => .connecting,
            .download_send => .sending,
            .download_recv_headers => .reading_headers,
            .download_poll_in => .waiting_readable,
            .download_splice_in => .splicing_in,
            else => unreachable,
        };
        if (conn.phase != expected_phase) return;
        if (data.offset != conn.active_offset) return;

        switch (cqe.err()) {
            .CANCELED, .NOENT, .ALREADY => {},
            .TIME => {
                conn.timed_out = true;
                self.logger.info().logf("download timed out idx={d} phase={s}", .{
                    data.index, @tagName(conn.phase),
                });
            },
            else => {
                self.logger.warn().logf("unexpected download timeout err idx={d} err={s} res={d}", .{
                    data.index, @tagName(cqe.err()), cqe.res,
                });
            },
        }
    }

    fn getDownloadForCqe(self: *SnapshotService, data: UserData) ?*DownloadConn {
        std.debug.assert(data.index < self.download_conns.len);
        const conn = &self.download_conns[data.index];
        if (conn.phase == .unused) {
            // TODO: likely remove these logs due to noise.
            self.logger.debug().logf("stale cqe for unused download slot op={s} idx={d}", .{ @tagName(data.op), data.index });
            return null;
        }
        if (conn.gen != data.gen) {
            // TODO: likely remove these logs due to noise.
            self.logger.debug().logf("stale download cqe op={s} idx={d}", .{ @tagName(data.op), data.index });
            return null;
        }
        return conn;
    }

    fn handleDownloadConnect(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .connecting) {
            self.logger.warn().logf("unexpected download connect cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (conn.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download connect failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.queueDownloadSendWithTimeout(data, 0) catch {
            // TODO: This fails only when the submission queue is full, which is a transient
            // local condition (not a peer failure). Add a retry/backpressure result so the
            // candidate can be marked unstarted/pending instead of being skipped for this race.
            // For now we treat it as a hard racer failure.
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
    }

    fn handleDownloadSend(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .sending) {
            self.logger.warn().logf("unexpected download send cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (conn.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download send failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= conn.send_len - data.offset);
        const new_offset = data.offset + @as(u16, @intCast(cqe.res));

        if (new_offset < conn.send_len) {
            self.queueDownloadSendWithTimeout(data, new_offset) catch {
                // TODO: Same as in handleDownloadCOnnect. Consider retry.
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        self.queueDownloadRecvHeadersWithTimeout(data, 0) catch {
            // TODO: Same as in handleDownloadCOnnect. Consider retry.
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
    }

    fn handleDownloadRecvHeaders(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .reading_headers) {
            self.logger.warn().logf("unexpected download recv_headers cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (conn.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download recv_headers failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res == 0) {
            self.logger.info().logf("download recv_headers eof idx={d}", .{data.index});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= conn.recv_buf.len - data.offset);
        const new_offset = data.offset + @as(u16, @intCast(cqe.res));
        const response = conn.recv_buf[0..new_offset];

        // Check for end of HTTP headers.
        const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse {
            if (new_offset >= conn.recv_buf.len) {
                self.logger.info().logf("download headers too large idx={d}", .{data.index});
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            }
            self.queueDownloadRecvHeadersWithTimeout(data, new_offset) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        };

        // Parse status line.
        const status_end = std.mem.indexOf(u8, response[0..header_end], "\r\n") orelse header_end;
        const status_line = response[0..status_end];
        if (std.mem.indexOf(u8, status_line, "200") == null) {
            self.logger.info().logf("download bad status idx={d} status={s}", .{ data.index, status_line });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        // Parse and verify Content-Length matches the race target.
        const content_len = parseContentLength(response[0 .. header_end + 4]) orelse {
            self.logger.info().logf("download missing/zero content-length idx={d}", .{data.index});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
        if (content_len != conn.content_len) {
            self.logger.info().logf("download content-length mismatch idx={d} got={d} expected={d}", .{
                data.index, content_len, conn.content_len,
            });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        conn.recv_len = new_offset;

        // A winner may have been selected while we were reading headers.
        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        // Detect extra body bytes received after the header terminator.
        const body_start: u16 = @intCast(header_end + 4);
        const extra_len: u16 = new_offset - body_start;

        // If we got body bytes during this header parse phase, start writing em to the file.
        if (extra_len > 0) {
            conn.extra_body_start = body_start;
            conn.extra_body_len = extra_len;
            self.queueDownloadWriteExtra(data, 0) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
        } else {
            // Otherwise move into the full download phase.
            self.queueDownloadSpliceInWithTimeout(data.index) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
        }
    }

    fn handleDownloadWriteExtra(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .writing_extra) {
            self.logger.warn().logf("unexpected download write_extra cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download write_extra failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= conn.extra_body_len - data.offset);
        const new_written = data.offset + @as(u16, @intCast(cqe.res));

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        if (new_written < conn.extra_body_len) {
            self.queueDownloadWriteExtra(data, new_written) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        conn.bytes_written += conn.extra_body_len;
        self.metrics.snapshot_download_bytes_written.increment(conn.extra_body_len);
        self.maybeSelectWinner(data.index);

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        self.queueDownloadSpliceInWithTimeout(data.index) catch {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
    }

    fn handleDownloadPollIn(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .waiting_readable) {
            self.logger.warn().logf("unexpected download poll_in cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (conn.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download poll_in failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        self.queueDownloadSpliceInWithTimeout(data.index) catch {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
        };
    }

    fn handleDownloadSpliceIn(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .splicing_in) {
            self.logger.warn().logf("unexpected download splice_in cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (conn.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() == .AGAIN) {
            self.queueDownloadPollInWithTimeout(data.index) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
            };
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download splice_in failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res == 0) {
            self.logger.info().logf("download splice_in eof idx={d}", .{data.index});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        const n: u64 = @intCast(cqe.res);
        std.debug.assert(n <= conn.content_len - conn.bytes_written - conn.pipe_pending);
        conn.pipe_pending += n;

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        self.queueDownloadSpliceOut(data.index) catch {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
    }

    fn handleDownloadSpliceOut(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .splicing_out) {
            self.logger.warn().logf("unexpected download splice_out cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        if (cqe.err() != .SUCCESS) {
            self.logger.info().logf("download splice_out failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res <= 0) {
            self.logger.info().logf("download splice_out zero idx={d}", .{data.index});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        const n: u64 = @intCast(cqe.res);
        std.debug.assert(n <= conn.pipe_pending);
        conn.pipe_pending -= n;
        conn.bytes_written += n;
        self.metrics.snapshot_download_bytes_written.increment(n);

        self.maybeSelectWinner(data.index);

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        if (conn.pipe_pending > 0) {
            self.queueDownloadSpliceOut(data.index) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        // Download's complete.
        if (conn.bytes_written >= conn.content_len) {
            self.queueDownloadFsync(data.index) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        self.queueDownloadSpliceInWithTimeout(data.index) catch {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
    }

    fn handleDownloadFsync(self: *SnapshotService, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        if (conn.phase != .fsyncing) {
            self.logger.warn().logf("unexpected download fsync cqe idx={d} phase={s}", .{ data.index, @tagName(conn.phase) });
            return;
        }

        std.debug.assert(self.download_race.winner_index == data.index);

        const race = &self.download_race;

        // Since this is the final stage for fsyncing the downloaded file, a failure here is likely not to resolve
        // with retry/re-download (local storage issue). So cancel all other running downloads as well as with winner's.
        // TODO: should we consider EINTR for retry?
        if (cqe.err() != .SUCCESS) {
            self.logger.err().logf("download fsync failed idx={d} err={s}", .{ data.index, @tagName(cqe.err()) });
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            return;
        }

        // Close file before publishing final path.
        if (conn.file_fd >= 0) {
            std.posix.close(conn.file_fd);
            conn.file_fd = -1;
        }

        // Rename temp file to final path.
        var tmp_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        var final_buf: [std.fs.max_path_bytes:0]u8 = undefined;

        const tmp_path = formatTempSnapshotPath(&tmp_buf, self.snapshot_dir, race.slot, race.hash, data.index, conn.gen);
        tmp_buf[tmp_path.len] = 0;

        const final_path = formatFinalSnapshotPath(&final_buf, self.snapshot_dir, race.slot, race.hash);
        final_buf[final_path.len] = 0;

        std.posix.rename(tmp_buf[0..tmp_path.len :0], final_buf[0..final_path.len :0]) catch |err| {
            self.logger.err().logf("download rename failed after fsync+close idx={d} err={s}", .{ data.index, @errorName(err) });
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            return;
        };

        race.phase = .completed;
        self.finishOtherDownloads(data.index);

        self.logger.info().logf("download complete slot={d} path={s}", .{ race.slot, final_path });
        self.finishDownload(data.index, .succeeded);
    }

    fn offerDownloadCandidate(
        self: *SnapshotService,
        candidate: DownloadCandidate,
        slot: Slot,
        hash: Hash,
    ) void {
        if (self.download_race.phase == .completed or
            self.download_race.phase == .winner_selected)
        {
            return;
        }

        // Handles the case where the race for the previous target snapshot (slot + hash)
        // failed, and we must restart the race with a new slot + hash.
        if (self.download_race.phase == .failed) {
            // Only accept a candidate that difers from the failed race target.
            // Accepting the same target would restart the same doomed race.
            const same_target = self.download_race.slot == slot and
                std.meta.eql(self.download_race.hash, hash);

            if (same_target) return;

            // Different target, reset for a new race (.empty() sets phase to .idle).
            self.download_race = DownloadRace.empty();
        }

        // The case where we haven't started the race.
        if (self.download_race.phase == .idle) {
            self.download_race = DownloadRace.empty();
            self.download_race.phase = .racing;
            self.download_race.slot = slot;
            self.download_race.hash = hash;
        }

        // Only accept candidates matching the current race target.
        if (self.download_race.slot != slot) return;
        if (!std.meta.eql(self.download_race.hash, hash)) return;

        self.insertDownloadCandidateSorted(candidate);
        self.startPendingRacers();
    }

    fn insertDownloadCandidateSorted(self: *SnapshotService, candidate: DownloadCandidate) void {
        const race = &self.download_race;

        // Reject duplicate address.
        for (race.candidates[0..race.candidate_count]) |*existing| {
            if (std.meta.eql(existing.addr, candidate.addr)) return;
        }

        // Full, so we reject the new candidate
        if (race.candidate_count >= MAX_DOWNLOAD_CANDIDATES) return;

        // Insertion sort by latency_ms (ascending).
        // TODO: Do we even need this?
        var pos: u8 = race.candidate_count;
        while (pos > 0 and race.candidates[pos - 1].latency_ms > candidate.latency_ms) {
            race.candidates[pos] = race.candidates[pos - 1];
            pos -= 1;
        }
        race.candidates[pos] = candidate;
        race.candidate_count += 1;

        self.metrics.snapshot_download_candidates.increment(1);
    }

    fn startPendingRacers(self: *SnapshotService) void {
        if (self.download_race.phase != .racing) return;

        while (self.active_downloads < MAX_DOWNLOAD_RACERS) {
            const candidate_index = self.nextUnstartedCandidate() orelse return;

            self.startDownloadRacer(candidate_index) catch |err| {
                self.logger.warn().logf("failed to start download racer err={}", .{err});
                self.download_race.candidates[candidate_index].started = true;
                continue;
            };
        }
    }

    // TODO: Remove this. store a pending cancidate list that we pull from instead of linear scan.
    fn nextUnstartedCandidate(self: *SnapshotService) ?u8 {
        for (self.download_race.candidates[0..self.download_race.candidate_count], 0..) |*c, i| {
            if (!c.started) return @intCast(i);
        }
        return null;
    }

    // TODO: We can clean these by generalizing over Op and sharing them with probe's fns (redundant).
    fn queueDownloadConnectWithTimeout(
        self: *SnapshotService,
        index: u8,
        fd: std.posix.fd_t,
    ) !void {
        const conn = &self.download_conns[index];

        const connect_data = UserData.init(.download_connect, index, conn.gen);
        // TODO: add a lil .timeout() to UserData to get the timeout variant.
        var timeout_data = connect_data;
        timeout_data.is_timeout = true;

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_connect(fd, &conn.net_addr.any, conn.net_addr.getOsSockLen());
        sqes.primary.user_data = connect_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        conn.phase = .connecting;
        conn.active_offset = 0;
        conn.timed_out = false;
    }

    fn queueDownloadSendWithTimeout(
        self: *SnapshotService,
        data: UserData,
        offset: u16,
    ) !void {
        const conn = &self.download_conns[data.index];

        var send_data = data;
        send_data.op = .download_send;
        send_data.offset = offset;

        var timeout_data = send_data;
        timeout_data.is_timeout = true;

        const sqes = try self.reserveLinkedSqes();

        std.debug.assert(offset < conn.send_len);

        sqes.primary.prep_send(conn.fd, conn.send_buf[offset..conn.send_len], 0);
        sqes.primary.user_data = send_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        conn.phase = .sending;
        conn.active_offset = offset;
        conn.timed_out = false;
    }

    fn queueDownloadRecvHeadersWithTimeout(
        self: *SnapshotService,
        data: UserData,
        offset: u16,
    ) !void {
        const conn = &self.download_conns[data.index];

        var recv_data = data;
        recv_data.op = .download_recv_headers;
        recv_data.offset = offset;

        var timeout_data = recv_data;
        timeout_data.is_timeout = true;

        std.debug.assert(offset < conn.recv_buf.len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_recv(conn.fd, conn.recv_buf[offset..], 0);
        sqes.primary.user_data = recv_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        conn.phase = .reading_headers;
        conn.active_offset = offset;
        conn.timed_out = false;
    }

    fn queueDownloadWriteExtra(self: *SnapshotService, data: UserData, written: u16) !void {
        const conn = &self.download_conns[data.index];

        var write_data = data;
        write_data.op = .download_write_extra;
        write_data.offset = written;

        const capacity: u32 = @intCast(self.ring.sq.sqes.len);
        if (capacity - self.ring.sq_ready() < 1) return error.SubmissionQueueFull;
        const sqe = self.ring.get_sqe() catch unreachable;

        const buf_start = conn.extra_body_start + written;
        std.debug.assert(buf_start + (conn.extra_body_len - written) <= conn.recv_len);

        sqe.prep_write(
            conn.file_fd,
            conn.recv_buf[buf_start .. conn.extra_body_start + conn.extra_body_len],
            conn.bytes_written + written,
        );
        sqe.user_data = write_data.encode();

        conn.phase = .writing_extra;
        conn.active_offset = written;
    }

    fn queueDownloadSpliceInWithTimeout(self: *SnapshotService, index: u8) !void {
        const conn = &self.download_conns[index];

        const remaining = conn.content_len - conn.bytes_written - conn.pipe_pending;
        std.debug.assert(remaining > 0);

        const sqes = try self.reserveLinkedSqes();

        conn.active_offset +%= 1;

        var splice_data = UserData.init(.download_splice_in, index, conn.gen);
        splice_data.offset = conn.active_offset;

        var timeout_data = splice_data;
        timeout_data.is_timeout = true;

        const len: usize = @intCast(@min(SPLICE_CHUNK, remaining));
        sqes.primary.prep_splice(conn.fd, NO_OFFSET, conn.pipe_wr, NO_OFFSET, len);
        sqes.primary.user_data = splice_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        conn.phase = .splicing_in;
        conn.timed_out = false;
    }

    fn queueDownloadPollInWithTimeout(self: *SnapshotService, index: u8) !void {
        const conn = &self.download_conns[index];

        const sqes = try self.reserveLinkedSqes();

        conn.active_offset +%= 1;

        var poll_data = UserData.init(.download_poll_in, index, conn.gen);
        poll_data.offset = conn.active_offset;

        var timeout_data = poll_data;
        timeout_data.is_timeout = true;

        sqes.primary.prep_poll_add(conn.fd, std.os.linux.POLL.IN);
        sqes.primary.user_data = poll_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        conn.phase = .waiting_readable;
        conn.timed_out = false;
    }

    fn queueDownloadSpliceOut(self: *SnapshotService, index: u8) !void {
        const conn = &self.download_conns[index];

        std.debug.assert(conn.pipe_pending > 0);

        const capacity: u32 = @intCast(self.ring.sq.sqes.len);
        if (capacity - self.ring.sq_ready() < 1) return error.SubmissionQueueFull;
        const sqe = self.ring.get_sqe() catch unreachable;

        var splice_ud = UserData.init(.download_splice_out, index, conn.gen);
        splice_ud.offset = conn.active_offset;

        const len: usize = @intCast(conn.pipe_pending);
        sqe.prep_splice(conn.pipe_rd, NO_OFFSET, conn.file_fd, conn.bytes_written, len);
        sqe.user_data = splice_ud.encode();

        conn.phase = .splicing_out;
    }

    fn queueDownloadFsync(self: *SnapshotService, index: u8) !void {
        const conn = &self.download_conns[index];

        // TODO: this is repeated in bunch of places, can coalesce.
        const capacity: u32 = @intCast(self.ring.sq.sqes.len);
        if (capacity - self.ring.sq_ready() < 1) return error.SubmissionQueueFull;
        const sqe = self.ring.get_sqe() catch unreachable;

        var fsync_data = UserData.init(.download_fsync, index, conn.gen);
        fsync_data.offset = conn.active_offset;

        sqe.prep_fsync(conn.file_fd, 0);
        sqe.user_data = fsync_data.encode();

        conn.phase = .fsyncing;
    }

    fn startDownloadRacer(self: *SnapshotService, candidate_index: u8) !void {
        const candidate = &self.download_race.candidates[candidate_index];
        const race = &self.download_race;

        // Find a free download conn.
        const dl_index: u8, const conn = for (&self.download_conns, 0..) |*c, i| {
            if (c.phase == .unused) break .{ @intCast(i), c };
        } else return;

        // Create nonblocking TCP socket.
        conn.net_addr = candidate.addr.toNetAddress();
        const fd = try std.posix.socket(
            conn.net_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        );
        errdefer std.posix.close(fd);

        // Create pipe for splice.
        // TODO: Do we want to size the pipe?
        const pipe_fds = try std.posix.pipe2(.{ .NONBLOCK = true });
        errdefer {
            std.posix.close(pipe_fds[0]);
            std.posix.close(pipe_fds[1]);
        }

        // Create temp file
        // TODO: can prob be moved into io_uring.
        // TODO: We create the temp path here, but don't store it anywhere. So need to recreate it again when the winner is declared. kinda cringe.
        conn.gen +%= 1;
        var path_buf: [std.fs.max_path_bytes:0]u8 = undefined;
        const tmp_path = formatTempSnapshotPath(&path_buf, self.snapshot_dir, race.slot, race.hash, dl_index, conn.gen);
        path_buf[tmp_path.len] = 0;
        const file_fd = try std.posix.openat(
            std.posix.AT.FDCWD,
            path_buf[0..tmp_path.len :0],
            .{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
            },
            0o644,
        );
        errdefer std.posix.close(file_fd);

        // Format GET request.
        var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
        const hash_str = race.hash.base58String(&hash_buf);
        const send_len = std.fmt.bufPrint(
            &conn.send_buf,
            "GET /snapshot-{d}-{s}.tar.zst HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
            .{ race.slot, hash_str, conn.net_addr },
        ) catch unreachable;
        conn.send_len = @intCast(send_len.len);

        conn.fd = fd;
        conn.file_fd = file_fd;
        conn.pipe_rd = pipe_fds[0];
        conn.pipe_wr = pipe_fds[1];
        conn.addr = candidate.addr;
        conn.content_len = candidate.content_len;

        try self.queueDownloadConnectWithTimeout(dl_index, fd);
        // TODO: catch error here and totally reset DownloadConn state.

        candidate.started = true;
        self.active_downloads += 1;
        self.metrics.snapshot_downloads_started.increment(1);
    }

    fn shouldCancelDownload(self: *SnapshotService, index: u8) bool {
        return self.download_conns[index].cancel_requested and
            self.download_race.winner_index != index;
    }

    fn maybeSelectWinner(self: *SnapshotService, index: u8) void {
        if (self.download_race.phase != .racing) return;

        const conn = &self.download_conns[index];

        const threshold = @max(
            @as(u64, 1),
            conn.content_len * DOWNLOAD_RACE_THRESHOLD_PCT / 100,
        );

        if (conn.bytes_written < threshold) return;

        self.download_race.phase = .winner_selected;
        self.download_race.winner_index = index;

        for (&self.download_conns, 0..) |*other, i| {
            if (i == index) continue;
            if (other.phase != .unused) {
                other.cancel_requested = true;
            }
        }

        self.logger.info().logf("download winner idx={d} addr={f}", .{ index, conn.addr });
    }

    /// Retires all active download connections except the one at `keep_index`.
    /// Used after the race reaches a terminal state (completed or failed) to
    /// clean up losers. Late CQEs from retired slots are ignored via gen mismatch.
    fn finishOtherDownloads(self: *SnapshotService, keep_index: u8) void {
        for (&self.download_conns, 0..) |*conn, i| {
            if (i == @as(usize, keep_index)) continue;
            if (conn.phase == .unused) continue;

            self.finishDownload(@intCast(i), .cancelled);
        }
    }

    fn finishDownload(self: *SnapshotService, index: u8, result: DownloadResult) void {
        const conn = &self.download_conns[index];
        if (conn.phase == .unused) return;

        self.logger.info().logf("finishDownload idx={d} result={s} addr={f} bytes_written={d}", .{
            index, @tagName(result), conn.addr, conn.bytes_written,
        });

        switch (result) {
            .failed => self.metrics.snapshot_downloads_failed.increment(1),
            .cancelled => self.metrics.snapshot_downloads_cancelled.increment(1),
            .succeeded => self.metrics.snapshot_downloads_succeeded.increment(1),
        }

        if (conn.fd >= 0) std.posix.close(conn.fd);
        if (conn.file_fd >= 0) std.posix.close(conn.file_fd);
        if (conn.pipe_rd >= 0) std.posix.close(conn.pipe_rd);
        if (conn.pipe_wr >= 0) std.posix.close(conn.pipe_wr);

        // If this download was cancelled/failed delete its temp file.
        if (result != .succeeded) {
            var tmp_buf: [std.fs.max_path_bytes:0]u8 = undefined;
            // TODO: we gotta store this bruh.
            const tmp_path = formatTempSnapshotPath(
                &tmp_buf,
                self.snapshot_dir,
                self.download_race.slot,
                self.download_race.hash,
                index,
                conn.gen,
            );
            tmp_buf[tmp_path.len] = 0;
            std.posix.unlink(tmp_buf[0..tmp_path.len :0]) catch {};
        }

        const old_gen = conn.gen;
        // TODO: add an emptyWithGen() or reset()
        self.download_conns[index] = DownloadConn.empty();
        self.download_conns[index].gen = old_gen;

        std.debug.assert(self.active_downloads > 0);
        self.active_downloads -= 1;
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

/// Formats a temp download path:
///   {snapshot_dir}/snapshot-{slot}-{hash}.tar.zst.tmp.{index}.{gen}
fn formatTempSnapshotPath(buf: []u8, snapshot_dir: []const u8, slot: Slot, hash: Hash, index: u8, gen: u16) []const u8 {
    var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
    const hash_str = hash.base58String(&hash_buf);
    return std.fmt.bufPrint(buf, "{s}/snapshot-{d}-{s}.tar.zst.tmp.{d}.{d}", .{
        snapshot_dir, slot, hash_str, index, gen,
    }) catch unreachable;
}

/// Formats the final snapshot path:
///   {snapshot_dir}/snapshot-{slot}-{hash}.tar.zst
fn formatFinalSnapshotPath(buf: []u8, snapshot_dir: []const u8, slot: Slot, hash: Hash) []const u8 {
    var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
    const hash_str = hash.base58String(&hash_buf);
    return std.fmt.bufPrint(buf, "{s}/snapshot-{d}-{s}.tar.zst", .{
        snapshot_dir, slot, hash_str,
    }) catch unreachable;
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
        .download_conns = .{DownloadConn.empty()} ** MAX_DOWNLOAD_RACERS,
        .active_downloads = 0,
        .download_race = DownloadRace.empty(),
        .snapshot_dir = folder_path,
        .metrics = metrics,
        .logger = logger,
    };
    defer service.ring.deinit();

    try service.run();
}
