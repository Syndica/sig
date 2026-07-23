const std = @import("std");
const lib = @import("../lib.zig");
const tel = lib.telemetry;

const Address = lib.gossip.Address;
const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const IoUring = std.os.linux.IoUring;

const FinalSnapshot = lib.snapshot.ReadySnapshot;
const SnapshotSourceRing = lib.snapshot.SnapshotSourceRing;
const KnownValidators = lib.snapshot.SnapshotConfig.KnownValidators;

const AddressContext = std.hash_map.AutoContext(Address);

const IO_URING_ENTRIES = 256;
const MAX_DEDUPE_PEERS = 4096;

const MAX_CONCURRENT_PROBES: u8 = 16;
const PROBE_TIMEOUT_SECS: i64 = 3;
const PROBE_TIMEOUT: std.os.linux.kernel_timespec = .{ .sec = PROBE_TIMEOUT_SECS, .nsec = 0 };

const MAX_DOWNLOAD_RACERS: u8 = 16;
const MAX_DOWNLOAD_CANDIDATES: u8 = 64;
const DOWNLOAD_RACE_THRESHOLD_PCT: u64 = 10;
const SPLICE_CHUNK: u32 = 1 * 1024 * 1024;
const NO_OFFSET: u64 = std.math.maxInt(u64);
const DOWNLOAD_TIMEOUT_SECS: i64 = 3;
const DOWNLOAD_TIMEOUT: std.os.linux.kernel_timespec = .{ .sec = DOWNLOAD_TIMEOUT_SECS, .nsec = 0 };

const QueueSqeError = error{SubmissionQueueFull};
const StartProbeError = QueueSqeError || error{SocketOpenFailed};
const StartDownloadRacerError = QueueSqeError || error{
    SocketOpenFailed,
    PipeOpenFailed,
    PathFormatFailed,
    FileOpenFailed,
};

const LinkedTimeoutOp = struct {
    /// set when a linked timeout fired, but we are still waiting for the
    /// primary op's cqe before freeing/reusing the slot.
    timed_out: bool,
    /// byte offset of the most recently submitted primary op within the current phase.
    /// Used to distinguish stale timeout cqes from previous partial send/recv ops.
    active_offset: u16,
    /// Timestamp captured when the current io_uring op was submitted.
    /// Used to measure SQE to CQE received latency.
    op_start_time: u64,

    fn empty() LinkedTimeoutOp {
        return .{
            .active_offset = 0,
            .timed_out = false,
            .op_start_time = 0,
        };
    }

    fn initOffset(active_offset: u16) LinkedTimeoutOp {
        return .{
            .active_offset = active_offset,
            .timed_out = false,
            .op_start_time = lib.clock.monotonic(.ns),
        };
    }
};

pub const ProbeConn = struct {
    /// monotonically increasing counter for this probe array entry,
    /// incremented each time the entry is reused. Encoded into UserData
    /// so that late cqes from previous occupant can be detected and
    /// discarded.
    gen: u16,
    /// Current lifecycle in the snapshot probing for this particular peer.
    /// Set to .unused when this slot is available for a new probe.
    lifecycle: ProbeLifecycle,

    const ProbeLifecycle = union(enum) {
        unused,
        active: ActiveProbe,
    };

    const ActiveProbe = struct {
        state: ProbeRuntimeState,
        phase: ProbePhase,
    };

    const ProbePhase = union(enum) {
        connecting: ProbeConnecting,
        sending: ProbeSending,
        receiving: ProbeReceiving,
    };

    const ProbeConnecting = struct {
        op: LinkedTimeoutOp,
    };

    const ProbeSending = struct {
        op: LinkedTimeoutOp,
        /// stores the http HEAD request pre-formatted to check
        send_buf: [256]u8,
        /// length of the formatted HTTP HEAD request.
        send_len: std.math.IntFittingRange(0, 256),
    };

    const ProbeReceiving = struct {
        op: LinkedTimeoutOp,
        /// buffer for the HTTP response from peer
        /// TODO: prob too big, maybe just close out probes that respond with weird sizes.
        recv_buf: [4096]u8,
    };

    const ProbeRuntimeState = struct {
        /// tcp socket fd for the peer.
        fd: std.posix.fd_t,
        /// gossip addr for peer
        addr: Address,
        /// pubkey of the peer that announced this snapshot, used for identity in logs.
        from: Pubkey,
        /// os socket addr that addr gets converted into.
        /// stored in the probe ring to ensure it remains stable for io_uring.
        net_addr: std.net.Address,
        /// timestamp captured at probe start. Used to compute
        /// latency on successful completion.
        start_time: u64,
        /// Snapshot slot that this probe is testing for.
        slot: Slot,
        /// Snapshot hash that this probe is testing for, used along with
        /// slot as a staleness guard.
        hash: Hash,
    };

    pub fn empty() ProbeConn {
        return .{
            .gen = 0,
            .lifecycle = .unused,
        };
    }

    fn isUnused(self: *const ProbeConn) bool {
        return self.lifecycle == .unused;
    }

    fn phaseName(self: *const ProbeConn) []const u8 {
        return switch (self.lifecycle) {
            .unused => "unused",
            .active => |active| @tagName(active.phase),
        };
    }

    fn activePtr(self: *ProbeConn) ?*ActiveProbe {
        return switch (self.lifecycle) {
            .unused => null,
            .active => |*active| active,
        };
    }

    fn timedOpPtr(self: *ProbeConn) ?*LinkedTimeoutOp {
        return switch (self.lifecycle) {
            .active => |*active| switch (active.phase) {
                inline else => |*phase| &phase.op,
            },
            else => null,
        };
    }

    fn enterSending(self: *ProbeConn) *ProbeSending {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .connecting => {
                active.phase = .{ .sending = .{
                    .op = .empty(),
                    .send_buf = undefined,
                    .send_len = 0,
                } };
            },
            .sending => {},
            else => unreachable,
        }

        return &active.phase.sending;
    }

    fn enterReceiving(self: *ProbeConn) *ProbeReceiving {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .sending => {
                active.phase = .{ .receiving = .{
                    .op = .empty(),
                    .recv_buf = undefined,
                } };
            },
            .receiving => {},
            else => unreachable,
        }

        return &active.phase.receiving;
    }
};

const ProbeStatus = enum(u2) {
    pending,
    in_flight,
    succeeded,
    failed,
};

pub const PeerState = struct {
    from: Pubkey,
    slot: Slot,
    hash: Hash,
    probe_status: ProbeStatus,
    latency_ms: u32,

    pub fn eql(self: PeerState, other: PeerState) bool {
        return self.slot == other.slot and self.hash.eql(&other.hash);
    }
};

const DownloadCandidate = struct {
    addr: Address,
    from: Pubkey,
    slot: Slot,
    hash: Hash,
    latency_ms: u32,
    content_len: u64,
    started: bool = false,
};

const DownloadProgressSample = struct {
    time: u64,
    bytes_written: u64,
};

pub const DownloadRace = struct {
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

    candidates: [MAX_DOWNLOAD_CANDIDATES]DownloadCandidate,
    candidate_count: u8,

    winner_index: ?u8,
    progress_sample: ?DownloadProgressSample,

    /// NOTE: resets the race phase to .idle
    pub fn empty() DownloadRace {
        return .{
            .phase = .idle,
            .candidates = undefined,
            .candidate_count = 0,
            .winner_index = null,
            .progress_sample = null,
        };
    }
};

// TODO: can be unified with ProbeConn in some way, combine all state.
pub const DownloadConn = struct {
    /// Similar to `ProbeConn`'s gen. Used to prevent a late-arriving CQE for
    /// this DownloadConn when the original peer's download was abandoned from
    /// overwritting the new peer it's now representing (i.e generations don't
    /// match).
    gen: u16,
    /// Current lifecycle in the snapshot download for this particular peer.
    /// Set to .unused when this slot is available for a new download.
    lifecycle: DownloadLifecycle,

    const DownloadLifecycle = union(enum) {
        unused,
        active: ActiveDownload,
    };

    const ActiveDownload = struct {
        state: DownloadRuntimeState,
        phase: DownloadPhase,
    };

    const DownloadPhase = union(enum) {
        connecting: DownloadConnecting,
        sending: DownloadSending,
        reading_headers: DownloadReadingHeaders,
        writing_extra: DownloadWritingExtra,
        waiting_readable: DownloadWaitingReadable,
        splicing_in: DownloadSplicingIn,
        splicing_out: DownloadSplicingOut,
        fsyncing: DownloadFsyncing,
    };

    const DownloadConnecting = struct {
        op: LinkedTimeoutOp,
    };

    const DownloadSending = struct {
        op: LinkedTimeoutOp,
        /// Used to store the GET request string for this peer.
        send_buf: [256]u8,
        /// The length of the GET request's payload.
        send_len: std.math.IntFittingRange(0, 256),
    };

    const DownloadReadingHeaders = struct {
        op: LinkedTimeoutOp,
        /// Used to store HTTP responses. Needs to live until the recv CQE completes.
        recv_buf: [4096]u8,
    };

    const DownloadWritingExtra = struct {
        /// Timestamp captured when the current io_uring op was submitted.
        /// Used to measure SQE to CQE received latency.
        op_start_time: u64,
        /// Used to store HTTP responses. Needs to live until the extra body bytes are written.
        recv_buf: [4096]u8,
        /// The length of the HTTP payload received and stored in `recv_buf` currently.
        recv_len: u16,
        /// Start of the HTTP body bytes in `recv_buf`.
        extra_body_start: u16,
        /// Number of extra HTTP body bytes already buffered in `recv_buf`.
        extra_body_len: u16,
    };

    const DownloadWaitingReadable = struct {
        op: LinkedTimeoutOp,
    };

    const DownloadSplicingIn = struct {
        op: LinkedTimeoutOp,
    };

    const DownloadSplicingOut = struct {
        /// Timestamp captured when the current io_uring op was submitted.
        /// Used to measure SQE to CQE received latency.
        op_start_time: u64,
    };

    const DownloadFsyncing = struct {
        /// Timestamp captured when the current io_uring op was submitted.
        /// Used to measure SQE to CQE received latency.
        op_start_time: u64,
    };

    const DownloadRuntimeState = struct {
        /// The tcp socket connected to the snapshot peer. Used for HTTP GET
        /// and reading snapshot bytes.
        /// TODO: Would be nice to transfer tcp connection from probing phase
        /// to download phase without needing to re-open.
        fd: std.posix.fd_t,
        /// The temp output file being written by this peer.
        file_fd: std.posix.fd_t,
        /// The read end of the pipe used by splice to bridge between socket and file.
        pipe_rd: std.posix.fd_t,
        /// The write end of the pipe used by splice to bridge between socket and file.
        pipe_wr: std.posix.fd_t,
        /// Address used for logging/identity.
        addr: Address,
        /// Pubkey of the peer being downloaded from, used for identity in logs.
        from: Pubkey,
        /// Address used for the socket connection (must live long enough for
        /// io_uring use, hence stored here).
        net_addr: std.net.Address,
        /// The expected total size of the snapshot for this racer (from its probe HEAD response).
        content_len: u64,
        /// Snapshot slot this racer is downloading.
        slot: Slot,
        /// Snapshot hash this racer is downloading.
        hash: Hash,
        /// The number of snapshot body bytes written to this peer's temp file.
        bytes_written: u64,
        /// The number of bytes moved from the socket into the pipe that still
        /// need to be flushed to this peer's temp file.
        pipe_pending: u64,
        /// Monotonic per-download sequence for linked ops without a natural byte offset.
        op_seq: u16,
        /// Set once a winner is declared so signal that this download should
        /// be stopped and cleaned up.
        cancel_requested: bool,
    };

    pub fn empty() DownloadConn {
        return .{
            .gen = 0,
            .lifecycle = .unused,
        };
    }

    fn isUnused(self: *const DownloadConn) bool {
        return self.lifecycle == .unused;
    }

    fn phaseName(self: *const DownloadConn) []const u8 {
        return switch (self.lifecycle) {
            .unused => "unused",
            .active => |active| @tagName(active.phase),
        };
    }

    fn activePtr(self: *DownloadConn) ?*ActiveDownload {
        return switch (self.lifecycle) {
            .unused => null,
            .active => |*active| active,
        };
    }

    fn linkedTimeoutOpPtr(self: *DownloadConn) ?*LinkedTimeoutOp {
        return switch (self.lifecycle) {
            .active => |*active| switch (active.phase) {
                .connecting => |*phase| &phase.op,
                .sending => |*phase| &phase.op,
                .reading_headers => |*phase| &phase.op,
                .waiting_readable => |*phase| &phase.op,
                .splicing_in => |*phase| &phase.op,
                else => null,
            },
            else => null,
        };
    }

    fn enterSending(self: *DownloadConn) *DownloadSending {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .connecting => {
                active.phase = .{ .sending = .{
                    .op = .empty(),
                    .send_buf = undefined,
                    .send_len = 0,
                } };
            },
            .sending => {},
            else => unreachable,
        }

        return &active.phase.sending;
    }

    fn enterReadingHeaders(self: *DownloadConn) *DownloadReadingHeaders {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .sending => {
                active.phase = .{ .reading_headers = .{
                    .op = .empty(),
                    .recv_buf = undefined,
                } };
            },
            .reading_headers => {},
            else => unreachable,
        }

        return &active.phase.reading_headers;
    }

    fn enterWritingExtra(
        self: *DownloadConn,
        body_start: u16,
        extra_len: u16,
    ) *DownloadWritingExtra {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .reading_headers => |state| {
                active.phase = .{ .writing_extra = .{
                    .op_start_time = lib.clock.monotonic(.ns),
                    .recv_buf = state.recv_buf,
                    .recv_len = body_start + extra_len,
                    .extra_body_start = body_start,
                    .extra_body_len = extra_len,
                } };
            },
            .writing_extra => {},
            else => unreachable,
        }

        return &active.phase.writing_extra;
    }

    fn enterWaitingReadable(self: *DownloadConn) *DownloadWaitingReadable {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .splicing_in => {
                active.phase = .{ .waiting_readable = .{
                    .op = .empty(),
                } };
            },
            .waiting_readable => {},
            else => unreachable,
        }

        return &active.phase.waiting_readable;
    }

    fn enterSplicingIn(self: *DownloadConn) *DownloadSplicingIn {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .reading_headers,
            .writing_extra,
            .waiting_readable,
            .splicing_out,
            => active.phase = .{
                .splicing_in = .{
                    .op = .empty(),
                },
            },
            .splicing_in => {},
            else => unreachable,
        }

        return &active.phase.splicing_in;
    }

    fn enterSplicingOut(self: *DownloadConn) *DownloadSplicingOut {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .splicing_in => {
                active.phase = .{ .splicing_out = .{
                    .op_start_time = lib.clock.monotonic(.ns),
                } };
            },
            .splicing_out => {},
            else => unreachable,
        }

        return &active.phase.splicing_out;
    }

    fn enterFsyncing(self: *DownloadConn) *DownloadFsyncing {
        const active = &self.lifecycle.active;
        switch (active.phase) {
            .splicing_out => {
                active.phase = .{ .fsyncing = .{
                    .op_start_time = lib.clock.monotonic(.ns),
                } };
            },
            .fsyncing => {},
            else => unreachable,
        }

        return &active.phase.fsyncing;
    }
};

/// The result set of an individual download being raced.
const RacerResult = enum {
    succeeded,
    failed,
    cancelled,
};

const TempSnapshot = struct {
    snapshot: FinalSnapshot,
    index: u8,
    gen: u16,

    pub fn format(self: TempSnapshot, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        return writer.print("{f}.tmp.{d}.{d}", .{ self.snapshot, self.index, self.gen });
    }

    fn name(self: TempSnapshot, buf: []u8) std.fmt.BufPrintError![]const u8 {
        return std.fmt.bufPrint(buf, "{f}", .{self});
    }
};

const DownloadFailureReason = enum {
    path_format_failed,
    fsync_failed,
    rename_failed,
};

pub const DownloadResult = union(enum) {
    already_exists: FinalSnapshot,
    downloaded: FinalSnapshot,
    failed: DownloadFailureReason,
};

const Op = enum(u4) {
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

    fn matchesProbePhase(self: Op, phase: ProbeConn.ProbePhase) bool {
        return switch (self) {
            .probe_connect => phase == .connecting,
            .probe_send => phase == .sending,
            .probe_recv => phase == .receiving,
            else => false,
        };
    }

    fn matchesDownloadPhase(self: Op, phase: DownloadConn.DownloadPhase) bool {
        return switch (self) {
            .download_connect => phase == .connecting,
            .download_send => phase == .sending,
            .download_recv_headers => phase == .reading_headers,
            .download_poll_in => phase == .waiting_readable,
            .download_splice_in => phase == .splicing_in,
            else => false,
        };
    }
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
    _reserved: u19,

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

    fn timeout(self: UserData) UserData {
        var data = self;
        data.is_timeout = true;
        return data;
    }
};

// TODO: add support for labels to metrics (should just auto-create a
// histogram per label, or whatever's in line with prom. spec).
pub const Metrics = struct {
    sources_received: tel.Counter,
    sources_deduped: tel.Counter,
    sources_new: tel.Counter,
    sources_updated: tel.Counter,
    probes_started: tel.Counter,
    probes_succeeded: tel.Counter,
    probes_failed: tel.Counter,
    probes_timed_out: tel.Counter,
    sq_fulls: tel.Counter,
    download_candidates: tel.Counter,
    downloads_started: tel.Counter,
    downloads_failed: tel.Counter,
    downloads_cancelled: tel.Counter,
    downloads_succeeded: tel.Counter,
    download_bytes_written: tel.Counter,

    io_uring_timeouts_total: tel.Counter,
    io_uring_cqe_batch_fulls_total: tel.Counter,

    // TODO: likely remove these, mostly used for debugging.
    io_latency_probe_connect: tel.Histogram,
    io_latency_probe_send: tel.Histogram,
    io_latency_probe_recv: tel.Histogram,
    io_latency_download_connect: tel.Histogram,
    io_latency_download_send: tel.Histogram,
    io_latency_download_recv_headers: tel.Histogram,
    io_latency_download_write_extra: tel.Histogram,
    io_latency_download_poll_in: tel.Histogram,
    io_latency_download_splice_in: tel.Histogram,
    io_latency_download_splice_out: tel.Histogram,
    io_latency_download_fsync: tel.Histogram,

    fn getHistogram(self: *const Metrics, op: Op) *const tel.Histogram {
        return switch (op) {
            .probe_connect => &self.io_latency_probe_connect,
            .probe_send => &self.io_latency_probe_send,
            .probe_recv => &self.io_latency_probe_recv,
            .download_connect => &self.io_latency_download_connect,
            .download_send => &self.io_latency_download_send,
            .download_recv_headers => &self.io_latency_download_recv_headers,
            .download_write_extra => &self.io_latency_download_write_extra,
            .download_poll_in => &self.io_latency_download_poll_in,
            .download_splice_in => &self.io_latency_download_splice_in,
            .download_splice_out => &self.io_latency_download_splice_out,
            .download_fsync => &self.io_latency_download_fsync,
        };
    }

    const IO_LATENCY_BOUNDS = &[_]f64{
        10 * std.time.ns_per_us, // 10us
        100 * std.time.ns_per_us, // 0.1ms
        500 * std.time.ns_per_us, // 0.5ms
        1 * std.time.ns_per_ms, // 1ms
        5 * std.time.ns_per_ms, // 5ms
        10 * std.time.ns_per_ms, // 10ms
        50 * std.time.ns_per_ms, // 50ms
        100 * std.time.ns_per_ms, // 100ms
        500 * std.time.ns_per_ms, // 500ms
        1 * std.time.ns_per_s, // 1s
        3 * std.time.ns_per_s, // 3s
    };

    // TODO: This was to not have a big fat anon. struct with the same fields
    // repeated. But perhaps there's a better way?
    pub const fields_config = blk: {
        var config: tel.metric.FieldsConfig(Metrics) = .{
            .prefix = "snapshot",
        };
        for (@typeInfo(Metrics).@"struct".fields) |field| {
            if (field.type == tel.Histogram) {
                @field(config.fields, field.name) = .{
                    .id_override = null,
                    .upper_bounds = IO_LATENCY_BOUNDS,
                };
            }
        }
        break :blk config;
    };
};

pub const DedupeMap = DedupeMapType(MAX_DEDUPE_PEERS);

fn DedupeMapType(comptime capacity: usize) type {
    comptime {
        std.debug.assert(capacity > 0);
        std.debug.assert(std.math.isPowerOfTwo(capacity));
        std.debug.assert(capacity <= std.math.maxInt(u16));
    }

    return struct {
        entries: [BUCKET_COUNT]Entry = @splat(.empty()),
        len: u16 = 0,

        const Map = @This();
        const BUCKET_COUNT = capacity * 2;
        // Gossip contact info rejects unspecified RPC addresses, so zero IP marks an empty bucket.
        const EMPTY_IP: [16]u8 = @splat(0);
        const ADDRESS_CONTEXT = std.hash_map.AutoContext(Address){};

        const Meta = packed struct(u32) {
            is_v6: bool,
            probe_status: ProbeStatus,
            latency_ms: u29,
        };

        const Entry = extern struct {
            slot: Slot,
            from: Pubkey,
            hash: Hash,
            ip: [16]u8,
            meta: Meta,
            port: u16,

            fn empty() Entry {
                return .{
                    .slot = 0,
                    .from = Pubkey.ZEROES,
                    .hash = Hash.ZEROES,
                    .ip = EMPTY_IP,
                    .meta = .{
                        .is_v6 = false,
                        .probe_status = .pending,
                        .latency_ms = 0,
                    },
                    .port = 0,
                };
            }

            fn init(addr: Address, peer: PeerState) Entry {
                return .{
                    .slot = peer.slot,
                    .from = peer.from,
                    .hash = peer.hash,
                    .ip = addr.ip,
                    .meta = .{
                        .is_v6 = addr.is_v6,
                        .probe_status = peer.probe_status,
                        .latency_ms = std.math.lossyCast(u29, peer.latency_ms),
                    },
                    .port = addr.port,
                };
            }

            fn isEmpty(self: *const Entry) bool {
                return std.mem.eql(u8, &self.ip, &EMPTY_IP);
            }

            fn address(self: *const Entry) Address {
                return .{
                    .is_v6 = self.meta.is_v6,
                    .ip = self.ip,
                    .port = self.port,
                };
            }

            fn eqlPeer(self: *const Entry, peer: PeerState) bool {
                return self.slot == peer.slot and self.hash.eql(&peer.hash);
            }
        };

        const FindBucketResult = packed struct(u32) {
            state: enum(u1) { found, empty },
            bucket: u31,
        };

        const GetOrPutResult = struct {
            found_existing: bool,
            // Only use within the current event-loop turn. `clear()`
            // invalidates map entry pointers.
            entry: *Entry,
        };

        const Pending = struct {
            addr: Address,
            // Only use within the current event-loop turn. SQEs must copy
            // needed state, not store this pointer.
            entry: *Entry,
        };

        pub fn empty() Map {
            return .{
                .entries = @splat(.empty()),
                .len = 0,
            };
        }

        fn firstBucket(key: Address) usize {
            const hash = ADDRESS_CONTEXT.hash(key);
            return @intCast(hash & @as(u64, BUCKET_COUNT - 1));
        }

        fn findBucket(self: *Map, key: Address) FindBucketResult {
            var bucket = firstBucket(key);
            while (true) {
                const entry = &self.entries[bucket];
                if (entry.isEmpty()) return .{ .state = .empty, .bucket = @intCast(bucket) };
                if (ADDRESS_CONTEXT.eql(entry.address(), key)) {
                    return .{ .state = .found, .bucket = @intCast(bucket) };
                }
                bucket = (bucket + 1) & (BUCKET_COUNT - 1);
            }
        }

        pub fn getPtr(self: *Map, key: Address) ?*Entry {
            const result = self.findBucket(key);
            return switch (result.state) {
                .found => &self.entries[result.bucket],
                .empty => null,
            };
        }

        pub fn getOrPut(self: *Map, key: Address, peer: PeerState) GetOrPutResult {
            if (self.len == capacity) self.clear();

            const result = self.findBucket(key);
            return switch (result.state) {
                .found => .{
                    .found_existing = true,
                    .entry = &self.entries[result.bucket],
                },
                .empty => self.insertAt(result.bucket, key, peer),
            };
        }

        pub fn nextPending(self: *Map) ?Pending {
            for (&self.entries) |*entry| {
                if (entry.isEmpty()) continue;
                if (entry.meta.probe_status != .pending) continue;
                return .{
                    .addr = entry.address(),
                    .entry = entry,
                };
            }
            return null;
        }

        pub fn clear(self: *Map) void {
            self.entries = @splat(.empty());
            self.len = 0;
        }

        fn insertAt(self: *Map, bucket: usize, key: Address, peer: PeerState) GetOrPutResult {
            const entry = &self.entries[bucket];
            std.debug.assert(entry.isEmpty());
            entry.* = .init(key, peer);
            self.len += 1;
            return .{
                .found_existing = false,
                .entry = entry,
            };
        }
    };
}

pub const Downloader = struct {
    ring: IoUring,
    gossip_iter: SnapshotSourceRing.Iterator(.reader),
    dedupe_map: DedupeMap,
    known_validators: KnownValidators,

    probe_conns: [MAX_CONCURRENT_PROBES]ProbeConn,
    active_probes: u8,

    download_conns: [MAX_DOWNLOAD_RACERS]DownloadConn,
    active_downloads: u8,
    download_race: DownloadRace,
    snapshot_dir: std.fs.Dir,
    run_result: ?DownloadResult,

    metrics: Metrics,
    logger: tel.Logger("snapshot"),

    pub fn init(
        gossip_to_snapshot: *SnapshotSourceRing,
        known_validators: KnownValidators,
        snapshot_dir: std.fs.Dir,
        metrics: Metrics,
        logger: tel.Logger("snapshot"),
    ) !Downloader {
        return .{
            .ring = try IoUring.init(IO_URING_ENTRIES, 0),
            .gossip_iter = gossip_to_snapshot.get(.reader),
            .dedupe_map = .empty(),
            .known_validators = known_validators,
            .probe_conns = @splat(.empty()),
            .active_probes = 0,
            .download_conns = @splat(.empty()),
            .active_downloads = 0,
            .download_race = .empty(),
            .snapshot_dir = snapshot_dir,
            .run_result = null,
            .metrics = metrics,
            .logger = logger,
        };
    }

    pub fn deinit(self: *Downloader) void {
        for (&self.probe_conns, 0..) |*probe_conn, i| {
            if (!probe_conn.isUnused()) {
                self.finishProbe(@intCast(i), .failed);
            }
        }

        for (&self.download_conns, 0..) |*download_conn, i| {
            if (!download_conn.isUnused()) {
                self.finishDownload(@intCast(i), .cancelled);
            }
        }

        self.ring.deinit();
    }

    pub fn run(self: *Downloader) !DownloadResult {
        var cqes: [256]std.os.linux.io_uring_cqe = undefined;

        while (true) {
            try self.drainGossip();

            _ = try self.ring.submit_and_wait(0);
            const n = try self.ring.copy_cqes(&cqes, 0);
            if (n == cqes.len) {
                self.metrics.io_uring_cqe_batch_fulls_total.increment(1);
            }

            for (cqes[0..n]) |cqe| {
                // A previous cqe in this copied batch may have set the final result. Stop before
                // handling any more completions.
                if (self.run_result) |result| return result;

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

            // It's possible that the last cqe in the copied batch set the
            // final result. The top-of-loop check will not run again (since
            // the downloader is done, and no more submissions are made).
            // We check again here to return.
            if (self.run_result) |result| return result;
        }
    }

    fn drainGossip(self: *Downloader) !void {
        if (self.download_race.phase == .completed) return;

        self.maybeLogWinnerProgress();

        var drained = false;
        while (true) {
            const source = self.gossip_iter.next() orelse break;
            drained = true;
            self.metrics.sources_received.increment(1);

            // Check and skip non-whitelisted known validators.
            if (!self.known_validators.trusts(source.from)) {
                continue;
            }

            const key = source.rpc_addr;
            const value: PeerState = .{
                .from = source.from,
                .slot = source.slot,
                .hash = source.hash,
                .probe_status = .pending,
                .latency_ms = 0,
            };

            const gop = self.dedupe_map.getOrPut(key, value);
            if (!gop.found_existing) {
                self.metrics.sources_new.increment(1);

                self.startProbe(key, gop.entry) catch |err| {
                    self.logger.warn().logf(
                        "failed to start probe from={f} err={}",
                        .{ source.from, err },
                    );
                };
            } else if (!gop.entry.eqlPeer(value)) {
                gop.entry.* = .init(key, value);

                // when a peer's slot/hash changes, start a new probe.
                self.startProbe(key, gop.entry) catch |err| {
                    self.logger.warn().logf(
                        "failed to start probe from={f} err={}",
                        .{ source.from, err },
                    );
                };

                self.logger.debug().logf(
                    "updated snapshot source from={f} addr={f} slot={d} hash={f}",
                    .{ source.from, source.rpc_addr, source.slot, source.hash },
                );
                self.metrics.sources_updated.increment(1);
            } else {
                // Same addr + same slot/hash. Do not retry failed probes here.
                // A failed probe is terminal for this snapshot candidate. It will
                // be retried only if slot/hash changes (the update path above).
                self.metrics.sources_deduped.increment(1);
            }
        }
        if (drained) self.gossip_iter.markUsed();
    }

    fn startProbe(self: *Downloader, addr: Address, peer: *DedupeMap.Entry) StartProbeError!void {
        if (self.download_race.phase == .completed) return;
        if (self.active_probes >= MAX_CONCURRENT_PROBES) return;

        // find a free prob
        const probe_index: u8, const probe = for (&self.probe_conns, 0..) |*p, i| {
            if (p.isUnused()) break .{ @intCast(i), p };
        } else return;

        // create tcp socket
        const net_addr = addr.toNetAddress();
        const fd = std.posix.socket(
            net_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch return error.SocketOpenFailed;
        errdefer std.posix.close(fd);

        probe.gen +%= 1;
        probe.lifecycle = .{ .active = .{
            .state = .{
                .fd = fd,
                .addr = addr,
                .from = peer.from,
                .net_addr = net_addr,
                .start_time = lib.clock.monotonic(.ns),
                .slot = peer.slot,
                .hash = peer.hash,
            },
            .phase = .{ .connecting = .{
                .op = .empty(),
            } },
        } };

        // NOTE: try is safe here since errdefer closes fd, and active_probes
        // has not been incremented yet, so the slot remains reusable.
        self.queueProbeConnectWithTimeout(probe_index, fd) catch |err| {
            probe.lifecycle = .unused;
            return err;
        };

        peer.meta.probe_status = .in_flight;
        self.active_probes += 1;
        self.metrics.probes_started.increment(1);
    }

    fn getProbeForCqe(self: *Downloader, data: UserData) ?*ProbeConn {
        std.debug.assert(data.index < self.probe_conns.len);
        const probe = &self.probe_conns[data.index];
        if (probe.isUnused()) {
            self.logger.warn().logf(
                "stale cqe for unused probe slot op={s} idx={d}",
                .{ @tagName(data.op), data.index },
            );
            return null;
        }
        if (probe.gen != data.gen) {
            self.logger.warn().logf(
                "stale probe cqe op={s} idx={d}",
                .{ @tagName(data.op), data.index },
            );
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
    fn reserveLinkedSqes(self: *Downloader) QueueSqeError!LinkedSqes {
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
            .primary = self.ring.get_sqe() catch @panic("submission queue unexpectedly full"),
            .timeout = self.ring.get_sqe() catch @panic("submission queue unexpectedly full"),
        };
    }

    /// Enqueues a pair of SQEs to connect and perform the tcp handshake along with a timeout.
    fn queueProbeConnectWithTimeout(
        self: *Downloader,
        index: u8,
        fd: std.posix.fd_t,
    ) QueueSqeError!void {
        const probe = &self.probe_conns[index];
        // NOTE: startProbe sets this slot active before queueing connect;
        // CQE handlers cannot retire it until we return to the event loop.
        const active = probe.activePtr() orelse unreachable;
        const state = active.state;
        const connecting = &active.phase.connecting;

        const connect_data = UserData.init(.probe_connect, index, probe.gen);
        const timeout_data = connect_data.timeout();

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_connect(fd, &state.net_addr.any, state.net_addr.getOsSockLen());
        sqes.primary.user_data = connect_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        connecting.op = LinkedTimeoutOp.initOffset(0);
    }

    /// Enqueues a pair of SQEs to send the HTTP HEAD request along with a
    /// timeout for the corresponding probe.
    /// After which we update the probe's phase to `sending`.
    fn queueProbeSendWithTimeout(
        self: *Downloader,
        data: UserData,
        /// used to track partial completions.
        offset: u16,
    ) QueueSqeError!void {
        const probe = &self.probe_conns[data.index];

        var send_data = data;
        send_data.op = .probe_send;
        send_data.offset = offset;

        const timeout_data = send_data.timeout();

        // NOTE: callers either just connected or are handling a
        // current-generation send CQE; queueing cannot retire the slot.
        const active = probe.activePtr() orelse unreachable;
        const state = &active.state;
        const needs_request = active.phase == .connecting;
        const sending = probe.enterSending();
        if (needs_request) {
            std.debug.assert(offset == 0);

            var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
            const hash_str = state.hash.base58String(&hash_buf);
            const send_len = std.fmt.bufPrint(
                &sending.send_buf,
                "HEAD /snapshot-{d}-{s}.tar.zst HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
                .{ state.slot, hash_str, state.net_addr },
            ) catch unreachable;
            sending.send_len = @intCast(send_len.len);
        }
        std.debug.assert(offset <= sending.send_len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_send(state.fd, sending.send_buf[offset..sending.send_len], 0);
        sqes.primary.user_data = send_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        sending.op = LinkedTimeoutOp.initOffset(offset);
    }

    /// Enqueues a pair of SQEs to recv the HTTP response along with a timeout.
    /// After which we update the probe's phase to `receiving`.
    fn queueProbeRecvWithTimeout(
        self: *Downloader,
        data: UserData,
        /// used to track partial completions.
        offset: u16,
    ) QueueSqeError!void {
        const probe = &self.probe_conns[data.index];

        var recv_data = data;
        recv_data.op = .probe_recv;
        recv_data.offset = offset;

        const timeout_data = recv_data.timeout();

        // NOTE: callers either just finished sending or are handling a
        // current-generation recv CQE; queueing cannot retire the slot.
        const active = probe.activePtr() orelse unreachable;
        const receiving = probe.enterReceiving();
        std.debug.assert(offset <= receiving.recv_buf.len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_recv(active.state.fd, receiving.recv_buf[offset..], 0);
        sqes.primary.user_data = recv_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;
        sqes.timeout.prep_link_timeout(&PROBE_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        receiving.op = LinkedTimeoutOp.initOffset(offset);
    }

    fn handleProbeTimeout(self: *Downloader, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        std.debug.assert(data.index < self.probe_conns.len);
        const probe = &self.probe_conns[data.index];

        // NOTE: it's possible that slot was already retired by the primary op,
        // or reused by a new probe. Both are expected since the primary cqe completed
        // before the timeout fired. If the probe is marked unused, or the generations don't match,
        // then this timeout is stale. Just ignore it.
        if (probe.isUnused() or probe.gen != data.gen) return;

        const active = probe.activePtr() orelse return;
        if (!data.op.matchesProbePhase(active.phase)) return;

        const timed_op = probe.timedOpPtr() orelse return;
        if (data.offset != timed_op.active_offset) return;

        switch (cqe.err()) {
            .CANCELED, .NOENT, .ALREADY => {},
            .TIME => {
                timed_op.timed_out = true;
                self.onOpTimeout(data.op);
                self.logger.debug().logf("probe timed out from={f} phase={s}", .{
                    active.state.from, probe.phaseName(),
                });
                self.metrics.probes_timed_out.increment(1);
            },
            else => {
                self.logger.warn().logf("unexpected timeout err from={f} err={s}", .{
                    active.state.from, @tagName(cqe.err()),
                });
            },
        }
    }

    fn handleProbeConnect(self: *Downloader, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        const active = probe.activePtr() orelse return;
        if (active.phase != .connecting) {
            self.logger.warn().logf(
                "unexpected connect cqe from={f} phase={s}",
                .{ active.state.from, probe.phaseName() },
            );
            return;
        }
        const connecting = &active.phase.connecting;

        // TODO: coalesce both
        if (connecting.op.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.debug().logf(
                "probe connect failed from={f} err={s}",
                .{ active.state.from, @tagName(cqe.err()) },
            );
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        self.onOpComplete(.probe_connect, connecting.op.op_start_time);

        // We've succesfully connected, so send the HTTP HEAD request.
        // Enqueuing the entries can only fail if the submission queue is full,
        // if so we finish the probe with result .sq_full so the peer remains
        // .pending for retry later (back pressure).
        self.queueProbeSendWithTimeout(data, 0) catch {
            self.finishProbe(data.index, .sq_full);
            return;
        };
    }

    fn handleProbeSend(self: *Downloader, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        const active = probe.activePtr() orelse return;
        if (active.phase != .sending) {
            self.logger.warn().logf(
                "unexpected send cqe from={f} phase={s}",
                .{ active.state.from, probe.phaseName() },
            );
            return;
        }
        const sending = &active.phase.sending;

        // TODO: coalesce both
        if (sending.op.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.debug().logf(
                "probe send failed from={f} err={s}",
                .{ active.state.from, @tagName(cqe.err()) },
            );
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        self.onOpComplete(.probe_send, sending.op.op_start_time);

        // Track send progress across partial completions via user_data offset.
        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= sending.send_len - data.offset);
        const new_offset: u16 = @intCast(data.offset + cqe.res);

        // The previous send was partial, queue up another and return.
        if (new_offset < sending.send_len) {
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

    fn handleProbeRecv(self: *Downloader, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const probe = self.getProbeForCqe(data) orelse return;
        const active = probe.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .receiving) {
            self.logger.warn().logf(
                "unexpected recv cqe from={f} phase={s}",
                .{ state.from, probe.phaseName() },
            );
            return;
        }
        const receiving = &active.phase.receiving;

        // TODO: coalesce these 3 conds
        if (receiving.op.timed_out) {
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "probe recv failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }
        if (cqe.res == 0) {
            self.logger.warn().logf("probe recv eof from={f}", .{state.from});
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        self.onOpComplete(.probe_recv, receiving.op.op_start_time);

        // Track recv progress across partial completions via user_data offset.
        const new_offset: u16 = @intCast(data.offset + cqe.res);
        const response = receiving.recv_buf[0..new_offset];

        // Check for end of HTTP headers.
        const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse {
            if (new_offset >= receiving.recv_buf.len) {
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
            self.logger.warn().logf(
                "probe recv bad status from={f} status={s}",
                .{ state.from, status_line },
            );
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        }

        // Parse Content-Length from headers.
        const content_len = parseContentLength(response[0 .. header_end + 4]) orelse {
            self.logger.warn().logf("probe missing/zero content-length from={f}", .{state.from});
            self.finishProbe(data.index, .failed);
            self.probeNextPending();
            return;
        };

        // Compute and store latency.
        const elapsed_ns = lib.clock.monotonic(.ns) -| state.start_time;
        const latency_ms: u32 = @intCast(elapsed_ns / std.time.ns_per_ms);
        if (self.dedupe_map.getPtr(state.addr)) |peer| {
            if (peer.slot == state.slot and peer.hash.eql(&state.hash)) {
                peer.meta.latency_ms = std.math.lossyCast(u29, latency_ms);
            }
        }

        self.logger.debug().logf(
            "probe succeeded from={f} addr={f} latency={d}ms content_len={d}",
            .{
                state.from,
                state.addr,
                latency_ms,
                content_len,
            },
        );

        // Finish out the probe before moving peer info onto download phase.
        const candidate = DownloadCandidate{
            .addr = state.addr,
            .from = state.from,
            .slot = state.slot,
            .hash = state.hash,
            .latency_ms = latency_ms,
            .content_len = content_len,
        };

        self.finishProbe(data.index, .succeeded);

        self.offerDownloadCandidate(candidate);
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

    fn finishProbe(self: *Downloader, probe_index: u8, result: ProbeResult) void {
        const probe = &self.probe_conns[probe_index];
        // If this fn gets called on a probe that's .unused, then return immediately.
        const active = probe.activePtr() orelse return;
        const state = &active.state;
        if (self.dedupe_map.getPtr(state.addr)) |peer| {
            // NOTE: We guard the update here since gossip can update peer in
            // dedupe map while io_uring was completing this probe.
            // If it was updated underneath us, don't update things here since
            // another/newer probe was already issued to io_uring.
            if (peer.slot == state.slot and peer.hash.eql(&state.hash)) {
                peer.meta.probe_status = switch (result) {
                    .succeeded => .succeeded,
                    .failed => .failed,
                    .sq_full => .pending,
                };
            }
        }

        std.posix.close(state.fd);
        const old_gen = probe.gen;
        probe.* = .empty();
        probe.gen = old_gen;
        self.active_probes -= 1;

        switch (result) {
            .succeeded => self.metrics.probes_succeeded.increment(1),
            .failed => self.metrics.probes_failed.increment(1),
            .sq_full => self.metrics.sq_fulls.increment(1),
        }
    }

    fn probeNextPending(self: *Downloader) void {
        if (self.download_race.phase == .completed) return;

        const pending = self.dedupe_map.nextPending() orelse return;
        self.startProbe(pending.addr, pending.entry) catch |err| {
            self.logger.warn().logf(
                "failed to start pending probe from={f} err={}",
                .{ pending.entry.from, err },
            );
        };
    }

    fn handleDownloadTimeout(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        std.debug.assert(data.index < self.download_conns.len);
        const conn = &self.download_conns[data.index];

        if (conn.isUnused() or conn.gen != data.gen) return;

        const active = conn.activePtr() orelse return;
        if (!data.op.matchesDownloadPhase(active.phase)) return;

        const op = conn.linkedTimeoutOpPtr() orelse return;
        if (data.offset != op.active_offset) return;

        switch (cqe.err()) {
            .CANCELED, .NOENT, .ALREADY => {},
            .TIME => {
                op.timed_out = true;
                self.onOpTimeout(data.op);
                self.logger.warn().logf("download timed out from={f} phase={s}", .{
                    active.state.from, conn.phaseName(),
                });
            },
            else => {
                self.logger.warn().logf(
                    "unexpected download timeout err from={f} err={s} res={d}",
                    .{
                        active.state.from,
                        @tagName(cqe.err()),
                        cqe.res,
                    },
                );
            },
        }
    }

    fn getDownloadForCqe(self: *Downloader, data: UserData) ?*DownloadConn {
        std.debug.assert(data.index < self.download_conns.len);
        const conn = &self.download_conns[data.index];
        if (conn.isUnused()) {
            // TODO: likely remove these logs due to noise.
            self.logger.debug().logf(
                "stale cqe for unused download slot op={s} idx={d}",
                .{ @tagName(data.op), data.index },
            );
            return null;
        }
        if (conn.gen != data.gen) {
            // TODO: likely remove these logs due to noise.
            self.logger.debug().logf(
                "stale download cqe op={s} idx={d}",
                .{ @tagName(data.op), data.index },
            );
            return null;
        }
        return conn;
    }

    fn handleDownloadConnect(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        if (active.phase != .connecting) {
            self.logger.warn().logf(
                "unexpected download connect cqe from={f} phase={s}",
                .{ active.state.from, conn.phaseName() },
            );
            return;
        }
        const connecting = &active.phase.connecting;

        if (connecting.op.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download connect failed from={f} err={s}",
                .{ active.state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_connect, connecting.op.op_start_time);

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

    fn handleDownloadSend(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        if (active.phase != .sending) {
            self.logger.warn().logf(
                "unexpected download send cqe from={f} phase={s}",
                .{ active.state.from, conn.phaseName() },
            );
            return;
        }
        const sending = &active.phase.sending;

        if (sending.op.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download send failed from={f} err={s}",
                .{ active.state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_send, sending.op.op_start_time);

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= sending.send_len - data.offset);
        const new_offset: u16 = @intCast(data.offset + cqe.res);

        if (new_offset < sending.send_len) {
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

    fn handleDownloadRecvHeaders(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .reading_headers) {
            self.logger.warn().logf(
                "unexpected download recv_headers cqe from={f} phase={s}",
                .{ state.from, conn.phaseName() },
            );
            return;
        }
        const reading_headers = &active.phase.reading_headers;

        if (reading_headers.op.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download recv_headers failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res == 0) {
            self.logger.warn().logf("download recv_headers eof from={f}", .{state.from});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_recv_headers, reading_headers.op.op_start_time);

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= reading_headers.recv_buf.len - data.offset);
        const new_offset: u16 = @intCast(data.offset + cqe.res);
        const response = reading_headers.recv_buf[0..new_offset];

        // Check for end of HTTP headers.
        const header_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse {
            if (new_offset >= reading_headers.recv_buf.len) {
                self.logger.warn().logf("download headers too large from={f}", .{state.from});
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
            self.logger.warn().logf(
                "download bad status from={f} status={s}",
                .{ state.from, status_line },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        // Parse and verify Content-Length matches the race target.
        const content_len = parseContentLength(response[0 .. header_end + 4]) orelse {
            self.logger.warn().logf(
                "download missing/zero content-length from={f}",
                .{state.from},
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        };
        if (content_len != state.content_len) {
            self.logger.warn().logf(
                "download content-length mismatch from={f} got={d} expected={d}",
                .{ state.from, content_len, state.content_len },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

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
            _ = conn.enterWritingExtra(body_start, extra_len);
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

    fn handleDownloadWriteExtra(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .writing_extra) {
            self.logger.warn().logf(
                "unexpected download write_extra cqe from={f} phase={s}",
                .{ state.from, conn.phaseName() },
            );
            return;
        }
        const writing_extra = &active.phase.writing_extra;

        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download write_extra failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_write_extra, writing_extra.op_start_time);

        std.debug.assert(cqe.res > 0);
        std.debug.assert(cqe.res <= writing_extra.extra_body_len - data.offset);
        const new_written: u16 = @intCast(data.offset + cqe.res);

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        if (new_written < writing_extra.extra_body_len) {
            self.queueDownloadWriteExtra(data, new_written) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        state.bytes_written += writing_extra.extra_body_len;
        self.metrics.download_bytes_written.increment(writing_extra.extra_body_len);
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

    fn handleDownloadPollIn(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        if (active.phase != .waiting_readable) {
            self.logger.warn().logf(
                "unexpected download poll_in cqe from={f} phase={s}",
                .{ active.state.from, conn.phaseName() },
            );
            return;
        }
        const waiting_readable = &active.phase.waiting_readable;

        if (waiting_readable.op.timed_out) {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download poll_in failed from={f} err={s}",
                .{ active.state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_poll_in, waiting_readable.op.op_start_time);

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        self.queueDownloadSpliceInWithTimeout(data.index) catch {
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
        };
    }

    fn handleDownloadSpliceIn(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .splicing_in) {
            self.logger.warn().logf(
                "unexpected download splice_in cqe from={f} phase={s}",
                .{ state.from, conn.phaseName() },
            );
            return;
        }
        const splicing_in = &active.phase.splicing_in;

        if (splicing_in.op.timed_out) {
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
            self.logger.warn().logf(
                "download splice_in failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res == 0) {
            self.logger.warn().logf("download splice_in eof from={f}", .{state.from});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_splice_in, splicing_in.op.op_start_time);

        const n: u64 = @intCast(cqe.res);
        std.debug.assert(n <= state.content_len - state.bytes_written - state.pipe_pending);
        state.pipe_pending += n;

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

    fn handleDownloadSpliceOut(
        self: *Downloader,
        data: UserData,
        cqe: std.os.linux.io_uring_cqe,
    ) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .splicing_out) {
            self.logger.warn().logf(
                "unexpected download splice_out cqe from={f} phase={s}",
                .{ state.from, conn.phaseName() },
            );
            return;
        }
        const splicing_out = &active.phase.splicing_out;

        if (cqe.err() != .SUCCESS) {
            self.logger.warn().logf(
                "download splice_out failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }
        if (cqe.res <= 0) {
            self.logger.warn().logf("download splice_out zero from={f}", .{state.from});
            self.finishDownload(data.index, .failed);
            self.startPendingRacers();
            return;
        }

        self.onOpComplete(.download_splice_out, splicing_out.op_start_time);

        const n: u64 = @intCast(cqe.res);
        std.debug.assert(n <= state.pipe_pending);
        state.pipe_pending -= n;
        state.bytes_written += n;
        self.metrics.download_bytes_written.increment(n);

        self.maybeSelectWinner(data.index);

        if (self.shouldCancelDownload(data.index)) {
            self.finishDownload(data.index, .cancelled);
            return;
        }

        if (state.pipe_pending > 0) {
            self.queueDownloadSpliceOut(data.index) catch {
                self.finishDownload(data.index, .failed);
                self.startPendingRacers();
                return;
            };
            return;
        }

        // Download's complete.
        if (state.bytes_written >= state.content_len) {
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

    fn handleDownloadFsync(self: *Downloader, data: UserData, cqe: std.os.linux.io_uring_cqe) void {
        const conn = self.getDownloadForCqe(data) orelse return;
        const active = conn.activePtr() orelse return;
        const state = &active.state;
        if (active.phase != .fsyncing) {
            self.logger.warn().logf(
                "unexpected download fsync cqe from={f} phase={s}",
                .{ state.from, conn.phaseName() },
            );
            return;
        }
        const fsyncing = &active.phase.fsyncing;

        std.debug.assert(self.download_race.winner_index == data.index);

        const race = &self.download_race;

        // Since this is the final stage for fsyncing the downloaded file, a
        // failure here is likely not to resolve with retry/re-download (local
        // storage issue). So cancel all other running downloads as well as
        // with winner's.
        // TODO: should we consider EINTR for retry?
        if (cqe.err() != .SUCCESS) {
            self.logger.err().logf(
                "download fsync failed from={f} err={s}",
                .{ state.from, @tagName(cqe.err()) },
            );
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            self.run_result = .{ .failed = .fsync_failed };
            return;
        }

        self.onOpComplete(.download_fsync, fsyncing.op_start_time);

        // Close file before publishing final path.
        std.posix.close(state.file_fd);
        state.file_fd = -1;

        // Rename temp file to final path.
        var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
        var final_buf: [std.fs.max_path_bytes]u8 = undefined;

        const final_snapshot: FinalSnapshot = .{ .slot = state.slot, .hash = state.hash };
        const tmp_name = (TempSnapshot{
            .snapshot = final_snapshot,
            .index = data.index,
            .gen = conn.gen,
        }).name(&tmp_buf) catch |err| {
            self.logger.err().logf(
                "download temp path format failed from={f} err={s}",
                .{ state.from, @errorName(err) },
            );
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            self.run_result = .{ .failed = .path_format_failed };
            return;
        };

        const final_name = final_snapshot.name(&final_buf) catch |err| {
            self.logger.err().logf(
                "download final path format failed from={f} err={s}",
                .{ state.from, @errorName(err) },
            );
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            self.run_result = .{ .failed = .path_format_failed };
            return;
        };

        self.snapshot_dir.rename(tmp_name, final_name) catch |err| {
            self.logger.err().logf(
                "download rename failed after fsync+close from={f} err={s}",
                .{ state.from, @errorName(err) },
            );
            race.phase = .failed;
            self.finishOtherDownloads(data.index);
            self.finishDownload(data.index, .failed);
            self.run_result = .{ .failed = .rename_failed };
            return;
        };

        race.phase = .completed;
        self.finishOtherDownloads(data.index);

        self.logger.info()
            .field("slot", &final_snapshot.slot)
            .field("name", &final_name)
            .log("download complete");

        self.finishDownload(data.index, .succeeded);

        self.run_result = .{
            .downloaded = final_snapshot,
        };
    }

    fn offerDownloadCandidate(self: *Downloader, candidate: DownloadCandidate) void {
        if (self.download_race.phase == .completed or
            self.download_race.phase == .winner_selected)
        {
            return;
        }

        // The case where we haven't started the race.
        if (self.download_race.phase == .idle) {
            self.download_race = .empty();
            self.download_race.phase = .racing;
        }

        self.insertDownloadCandidateSorted(candidate);
        self.startPendingRacers();
    }

    fn insertDownloadCandidateSorted(self: *Downloader, candidate: DownloadCandidate) void {
        const race = &self.download_race;

        // Keep one queued/active candidate per RPC address.
        for (race.candidates[0..race.candidate_count]) |*existing| {
            if (AddressContext.eql(.{}, existing.addr, candidate.addr)) return;
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

        self.metrics.download_candidates.increment(1);
    }

    fn startPendingRacers(self: *Downloader) void {
        if (self.download_race.phase != .racing) return;

        while (self.active_downloads < MAX_DOWNLOAD_RACERS) {
            const candidate_index = self.nextUnstartedCandidate() orelse return;

            self.startDownloadRacer(candidate_index) catch |err| {
                const candidate = &self.download_race.candidates[candidate_index];
                self.logger.warn().logf("failed to start download racer from={f} err={}", .{
                    candidate.from, err,
                });
                candidate.started = true;
                continue;
            };
        }
    }

    // TODO: Remove this. store a pending cancidate list that we pull from instead of linear scan.
    fn nextUnstartedCandidate(self: *Downloader) ?u8 {
        for (self.download_race.candidates[0..self.download_race.candidate_count], 0..) |*c, i| {
            if (!c.started) return @intCast(i);
        }
        return null;
    }

    // TODO: We can clean these by generalizing over Op and sharing them
    // with probe's fns (redundant).
    fn queueDownloadConnectWithTimeout(
        self: *Downloader,
        index: u8,
        fd: std.posix.fd_t,
    ) QueueSqeError!void {
        const conn = &self.download_conns[index];
        // NOTE: startDownloadRacer sets this slot active before queueing
        // connect; CQE handlers cannot retire it until we return to the
        // event loop.
        const active = conn.activePtr() orelse unreachable;
        const state = active.state;
        const connecting = &active.phase.connecting;

        const connect_data = UserData.init(.download_connect, index, conn.gen);
        const timeout_data = connect_data.timeout();

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_connect(fd, &state.net_addr.any, state.net_addr.getOsSockLen());
        sqes.primary.user_data = connect_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        connecting.op = LinkedTimeoutOp.initOffset(0);
    }

    fn queueDownloadSendWithTimeout(
        self: *Downloader,
        data: UserData,
        offset: u16,
    ) QueueSqeError!void {
        const conn = &self.download_conns[data.index];
        // NOTE: callers either just connected or are handling a
        // current-generation send CQE; queueing cannot retire the slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        const needs_request = active.phase == .connecting;
        const sending = conn.enterSending();

        var send_data = data;
        send_data.op = .download_send;
        send_data.offset = offset;

        const timeout_data = send_data.timeout();

        const sqes = try self.reserveLinkedSqes();

        if (needs_request) {
            std.debug.assert(offset == 0);

            var hash_buf: [Hash.BASE58_MAX_SIZE]u8 = undefined;
            const hash_str = state.hash.base58String(&hash_buf);
            const send_len = std.fmt.bufPrint(
                &sending.send_buf,
                "GET /snapshot-{d}-{s}.tar.zst HTTP/1.1\r\nHost: {f}\r\nConnection: close\r\n\r\n",
                .{ state.slot, hash_str, state.net_addr },
            ) catch unreachable;
            sending.send_len = @intCast(send_len.len);
        }

        std.debug.assert(offset < sending.send_len);

        sqes.primary.prep_send(state.fd, sending.send_buf[offset..sending.send_len], 0);
        sqes.primary.user_data = send_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        sending.op = LinkedTimeoutOp.initOffset(offset);
    }

    fn queueDownloadRecvHeadersWithTimeout(
        self: *Downloader,
        data: UserData,
        offset: u16,
    ) QueueSqeError!void {
        const conn = &self.download_conns[data.index];
        // NOTE: callers either just finished sending or are handling a
        // current-generation header recv CQE; queueing cannot retire the
        // slot.
        const active = conn.activePtr() orelse unreachable;
        const reading_headers = conn.enterReadingHeaders();

        var recv_data = data;
        recv_data.op = .download_recv_headers;
        recv_data.offset = offset;

        const timeout_data = recv_data.timeout();

        std.debug.assert(offset < reading_headers.recv_buf.len);

        const sqes = try self.reserveLinkedSqes();

        sqes.primary.prep_recv(active.state.fd, reading_headers.recv_buf[offset..], 0);
        sqes.primary.user_data = recv_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        reading_headers.op = LinkedTimeoutOp.initOffset(offset);
    }

    /// handles HTTP edge case where the header recv can read past
    /// `\r\n\r\n` and already consume some snapshot body bytes into recv_buf.
    fn queueDownloadWriteExtra(self: *Downloader, data: UserData, written: u16) QueueSqeError!void {
        const conn = &self.download_conns[data.index];
        // NOTE: callers either just transitioned to writing_extra or are
        // handling its current-generation CQE; queueing cannot retire the
        // slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        const writing_extra = &active.phase.writing_extra;

        var write_data = data;
        write_data.op = .download_write_extra;
        write_data.offset = written;

        const sqe = try self.ring.get_sqe();

        std.debug.assert(written <= writing_extra.extra_body_len);

        const buf_start = writing_extra.extra_body_start + written;
        const buf_end = writing_extra.extra_body_start + writing_extra.extra_body_len;

        std.debug.assert(buf_start <= buf_end);
        std.debug.assert(buf_end <= writing_extra.recv_len);

        sqe.prep_write(
            state.file_fd,
            writing_extra.recv_buf[buf_start..buf_end],
            state.bytes_written + written,
        );
        sqe.user_data = write_data.encode();
    }

    fn queueDownloadSpliceInWithTimeout(self: *Downloader, index: u8) QueueSqeError!void {
        const conn = &self.download_conns[index];
        // NOTE: callers either just transitioned to splicing_in or are
        // handling an adjacent current-generation CQE; queueing cannot
        // retire the slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        const splicing_in = conn.enterSplicingIn();

        const remaining = state.content_len - state.bytes_written - state.pipe_pending;
        std.debug.assert(remaining > 0);

        const sqes = try self.reserveLinkedSqes();

        state.op_seq +%= 1;

        var splice_data = UserData.init(.download_splice_in, index, conn.gen);
        splice_data.offset = state.op_seq;

        const timeout_data = splice_data.timeout();

        const len = std.math.lossyCast(usize, @min(SPLICE_CHUNK, remaining));
        sqes.primary.prep_splice(state.fd, NO_OFFSET, state.pipe_wr, NO_OFFSET, len);
        sqes.primary.user_data = splice_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        splicing_in.op = LinkedTimeoutOp.initOffset(splice_data.offset);
    }

    fn queueDownloadPollInWithTimeout(self: *Downloader, index: u8) QueueSqeError!void {
        const conn = &self.download_conns[index];
        // NOTE: callers reach this from a current-generation splice_in CQE;
        // queueing cannot retire the slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        const waiting_readable = conn.enterWaitingReadable();

        const sqes = try self.reserveLinkedSqes();

        state.op_seq +%= 1;

        var poll_data = UserData.init(.download_poll_in, index, conn.gen);
        poll_data.offset = state.op_seq;

        const timeout_data = poll_data.timeout();

        sqes.primary.prep_poll_add(state.fd, std.os.linux.POLL.IN);
        sqes.primary.user_data = poll_data.encode();
        sqes.primary.flags |= std.os.linux.IOSQE_IO_LINK;

        sqes.timeout.prep_link_timeout(&DOWNLOAD_TIMEOUT, 0);
        sqes.timeout.user_data = timeout_data.encode();

        waiting_readable.op = LinkedTimeoutOp.initOffset(poll_data.offset);
    }

    fn queueDownloadSpliceOut(self: *Downloader, index: u8) QueueSqeError!void {
        const conn = &self.download_conns[index];
        // NOTE: callers reach this while the current-generation download has
        // pipe bytes pending; queueing cannot retire the slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        _ = conn.enterSplicingOut();

        std.debug.assert(state.pipe_pending > 0);

        const sqe = try self.ring.get_sqe();

        var splice_ud = UserData.init(.download_splice_out, index, conn.gen);
        splice_ud.offset = state.op_seq;

        const len: usize = @intCast(state.pipe_pending);
        sqe.prep_splice(state.pipe_rd, NO_OFFSET, state.file_fd, state.bytes_written, len);
        sqe.user_data = splice_ud.encode();
    }

    fn queueDownloadFsync(self: *Downloader, index: u8) QueueSqeError!void {
        const conn = &self.download_conns[index];
        // NOTE: callers reach this after a current-generation splice_out CQE
        // completes the download; queueing cannot retire the slot.
        const active = conn.activePtr() orelse unreachable;
        const state = &active.state;
        _ = conn.enterFsyncing();

        const sqe = try self.ring.get_sqe();

        var fsync_data = UserData.init(.download_fsync, index, conn.gen);
        fsync_data.offset = state.op_seq;

        sqe.prep_fsync(state.file_fd, 0);
        sqe.user_data = fsync_data.encode();
    }

    fn startDownloadRacer(self: *Downloader, candidate_index: u8) StartDownloadRacerError!void {
        const candidate = &self.download_race.candidates[candidate_index];

        // Find a free download conn.
        const dl_index: u8, const conn = for (&self.download_conns, 0..) |*c, i| {
            if (c.isUnused()) break .{ @intCast(i), c };
        } else return;

        // Create nonblocking TCP socket.
        const net_addr = candidate.addr.toNetAddress();
        const fd = std.posix.socket(
            net_addr.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            0,
        ) catch return error.SocketOpenFailed;
        errdefer std.posix.close(fd);

        // Create pipe for splice.
        // TODO: Do we want to size the pipe?
        const pipe_fds = std.posix.pipe2(.{ .NONBLOCK = true }) catch return error.PipeOpenFailed;
        errdefer {
            std.posix.close(pipe_fds[0]);
            std.posix.close(pipe_fds[1]);
        }

        // Create temp file
        // TODO: can prob be moved into io_uring.
        conn.gen +%= 1;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const tmp_name = (TempSnapshot{
            .snapshot = .{ .slot = candidate.slot, .hash = candidate.hash },
            .index = dl_index,
            .gen = conn.gen,
        }).name(&path_buf) catch return error.PathFormatFailed;

        const file = self.snapshot_dir.createFile(
            tmp_name,
            .{ .mode = 0o644 },
        ) catch return error.FileOpenFailed;
        errdefer file.close();

        conn.lifecycle = .{ .active = .{
            .state = .{
                .fd = fd,
                .file_fd = file.handle,
                .pipe_rd = pipe_fds[0],
                .pipe_wr = pipe_fds[1],
                .addr = candidate.addr,
                .from = candidate.from,
                .net_addr = net_addr,
                .content_len = candidate.content_len,
                .slot = candidate.slot,
                .hash = candidate.hash,
                .bytes_written = 0,
                .pipe_pending = 0,
                .op_seq = 0,
                .cancel_requested = false,
            },
            .phase = .{ .connecting = .{
                .op = .empty(),
            } },
        } };

        self.queueDownloadConnectWithTimeout(dl_index, fd) catch |err| {
            conn.lifecycle = .unused;
            return err;
        };

        candidate.started = true;
        self.active_downloads += 1;
        self.metrics.downloads_started.increment(1);
    }

    fn shouldCancelDownload(self: *Downloader, index: u8) bool {
        const active = self.download_conns[index].activePtr() orelse return false;
        return active.state.cancel_requested and
            self.download_race.winner_index != index;
    }

    fn maybeSelectWinner(self: *Downloader, index: u8) void {
        if (self.download_race.phase != .racing) return;

        const conn = &self.download_conns[index];
        const active = conn.activePtr() orelse return;
        const state = &active.state;

        const threshold = @max(
            @as(u64, 1),
            state.content_len * DOWNLOAD_RACE_THRESHOLD_PCT / 100,
        );

        if (state.bytes_written < threshold) return;

        self.download_race.phase = .winner_selected;
        self.download_race.winner_index = index;
        self.download_race.progress_sample = .{
            .time = lib.clock.monotonic(.ns),
            .bytes_written = state.bytes_written,
        };

        for (&self.download_conns, 0..) |*other, i| {
            if (i == index) continue;
            if (other.activePtr()) |other_active| {
                other_active.state.cancel_requested = true;
            }
        }

        self.logger.info().logf("download winner from={f} addr={f}", .{ state.from, state.addr });
    }

    fn maybeLogWinnerProgress(self: *Downloader) void {
        if (self.download_race.phase != .winner_selected) return;

        const winner_index = self.download_race.winner_index orelse return;
        const active = self.download_conns[winner_index].activePtr() orelse return;
        const state = &active.state;
        if (state.content_len == 0) return;

        const now = lib.clock.monotonic(.ns);
        const sample = self.download_race.progress_sample orelse {
            self.download_race.progress_sample = .{
                .time = now,
                .bytes_written = state.bytes_written,
            };
            return;
        };

        const elapsed_ns = now -| sample.time;
        if (elapsed_ns < std.time.ns_per_s) return;

        const delta_bytes = state.bytes_written - sample.bytes_written;
        const mib_per_s = @as(f64, @floatFromInt(delta_bytes)) *
            @as(f64, @floatFromInt(std.time.ns_per_s)) /
            @as(f64, @floatFromInt(elapsed_ns)) /
            (1024.0 * 1024.0);
        const percent = @as(f64, @floatFromInt(state.bytes_written)) * 100.0 /
            @as(f64, @floatFromInt(state.content_len));

        self.logger.info().logf(
            "download progress from={f} completed={d:.1}% speed={d:.2}MiB/s",
            .{ state.from, percent, mib_per_s },
        );

        self.download_race.progress_sample = .{
            .time = now,
            .bytes_written = state.bytes_written,
        };
    }

    /// Retires all active download connections except the one at `keep_index`.
    /// Used after the race reaches a terminal state (completed or failed) to
    /// clean up losers. Late CQEs from retired slots are ignored via gen mismatch.
    fn finishOtherDownloads(self: *Downloader, keep_index: u8) void {
        for (&self.download_conns, 0..) |*conn, i| {
            if (i == @as(usize, keep_index)) continue;
            if (conn.isUnused()) continue;

            self.finishDownload(@intCast(i), .cancelled);
        }
    }

    fn finishDownload(self: *Downloader, index: u8, result: RacerResult) void {
        const conn = &self.download_conns[index];
        const active = conn.activePtr() orelse return;
        const state = &active.state;

        switch (result) {
            .failed => self.metrics.downloads_failed.increment(1),
            .cancelled => self.metrics.downloads_cancelled.increment(1),
            .succeeded => self.metrics.downloads_succeeded.increment(1),
        }

        if (state.fd >= 0) std.posix.close(state.fd);
        if (state.file_fd >= 0) std.posix.close(state.file_fd);
        if (state.pipe_rd >= 0) std.posix.close(state.pipe_rd);
        if (state.pipe_wr >= 0) std.posix.close(state.pipe_wr);

        // If this download was cancelled/failed delete its temp file.
        if (result != .succeeded) {
            var tmp_buf: [std.fs.max_path_bytes]u8 = undefined;
            const tmp_name = (TempSnapshot{
                .snapshot = .{ .slot = state.slot, .hash = state.hash },
                .index = index,
                .gen = conn.gen,
            }).name(&tmp_buf) catch return;
            self.snapshot_dir.deleteFile(tmp_name) catch {};
        }

        const old_gen = conn.gen;
        // TODO: add an emptyWithGen() or reset()
        self.download_conns[index] = .empty();
        self.download_conns[index].gen = old_gen;

        std.debug.assert(self.active_downloads > 0);
        self.active_downloads -= 1;
    }

    // TODO: Maybe move these into some kinda effects interface struct for tests?
    fn onOpTimeout(self: *Downloader, _: Op) void {
        self.metrics.io_uring_timeouts_total.increment(1);
    }

    fn onOpComplete(self: *Downloader, op: Op, op_start: u64) void {
        const elapsed_ns: f64 = @floatFromInt(lib.clock.monotonic(.ns) -| op_start);
        self.metrics.getHistogram(op).observe(elapsed_ns);
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

fn isFinalSnapshotFilename(file_name: []const u8) bool {
    return std.mem.startsWith(u8, file_name, "snapshot-") and
        std.mem.endsWith(u8, file_name, ".tar.zst") and
        std.mem.indexOf(u8, file_name, ".tmp.") == null;
}

fn parseFinalSnapshotFilename(file_name: []const u8) ?FinalSnapshot {
    if (!isFinalSnapshotFilename(file_name)) return null;

    const prefix = "snapshot-";
    const suffix = ".tar.zst";
    const body = file_name[prefix.len .. file_name.len - suffix.len];
    const split = std.mem.indexOfScalar(u8, body, '-') orelse return null;
    const slot = std.fmt.parseInt(Slot, body[0..split], 10) catch return null;
    const hash = Hash.parseRuntime(body[split + 1 ..]) catch return null;
    return .{ .slot = slot, .hash = hash };
}

/// Scans the snapshot directory for an existing finalized snapshot file.
/// TODO: check how old the snapshot is on disk before skipping.
pub fn findExistingSnapshot(snapshot_dir: std.fs.Dir) !?FinalSnapshot {
    var iter = snapshot_dir.iterate();
    while (try iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (parseFinalSnapshotFilename(entry.name)) |snapshot| return snapshot;
    }

    return null;
}

test "snapshot.download: DedupeMap" {
    const testing = std.testing;
    const TestDedupeMap = DedupeMapType(8);

    const testAddress = struct {
        fn run(port: u16) Address {
            return .{
                .is_v6 = false,
                .ip = .{127} ++ @as([15]u8, @splat(0)),
                .port = port,
            };
        }
    }.run;

    const testPeer = struct {
        fn run(slot: Slot, status: ProbeStatus) PeerState {
            return .{
                .from = Pubkey.ZEROES,
                .slot = slot,
                .hash = Hash.ZEROES,
                .probe_status = status,
                .latency_ms = 0,
            };
        }
    }.run;

    try testing.expectEqual(@as(usize, 96), @sizeOf(TestDedupeMap.Entry));
    try testing.expectEqual(@as(usize, 16), TestDedupeMap.BUCKET_COUNT);

    {
        var map = TestDedupeMap.empty();
        const addr = testAddress(8001);
        const gop = map.getOrPut(addr, testPeer(1, .pending));
        try testing.expect(!gop.found_existing);

        const entry = map.getPtr(addr) orelse return error.TestExpectedEqual;
        try testing.expectEqual(addr, entry.address());
        try testing.expectEqual(@as(Slot, 1), entry.slot);
        try testing.expectEqual(ProbeStatus.pending, entry.meta.probe_status);
    }

    {
        var map = TestDedupeMap.empty();
        const addr = testAddress(8002);
        const first = map.getOrPut(addr, testPeer(2, .failed));

        const second = map.getOrPut(addr, testPeer(9, .pending));
        try testing.expect(second.found_existing);
        try testing.expectEqual(first.entry, second.entry);
        try testing.expectEqual(ProbeStatus.failed, second.entry.meta.probe_status);
    }

    {
        var map = TestDedupeMap.empty();
        const a = testAddress(8003);
        const b = testAddress(8004);
        const c = testAddress(8005);
        _ = map.getOrPut(a, testPeer(3, .succeeded));
        _ = map.getOrPut(b, testPeer(4, .failed));
        _ = map.getOrPut(c, testPeer(5, .pending));

        try testing.expectEqual(
            @as(Slot, 3),
            (map.getPtr(a) orelse return error.TestExpectedEqual).slot,
        );
        try testing.expectEqual(
            @as(Slot, 4),
            (map.getPtr(b) orelse return error.TestExpectedEqual).slot,
        );
        try testing.expectEqual(
            @as(Slot, 5),
            (map.getPtr(c) orelse return error.TestExpectedEqual).slot,
        );
    }

    {
        var map = TestDedupeMap.empty();
        _ = map.getOrPut(testAddress(8006), testPeer(6, .failed));
        _ = map.getOrPut(testAddress(8007), testPeer(7, .succeeded));
        _ = map.getOrPut(testAddress(8008), testPeer(8, .pending));

        const pending = map.nextPending() orelse return error.TestExpectedEqual;
        try testing.expectEqual(testAddress(8008), pending.addr);
        try testing.expectEqual(@as(Slot, 8), pending.entry.slot);
    }

    {
        var map = TestDedupeMap.empty();
        for (0..8) |i| {
            const addr = testAddress(@intCast(8100 + i));
            _ = map.getOrPut(addr, testPeer(@intCast(i), .failed));
        }
        try testing.expectEqual(@as(u16, 8), map.len);

        const replacement_addr = testAddress(9000);
        const replacement = map.getOrPut(replacement_addr, testPeer(9000, .pending));
        try testing.expect(!replacement.found_existing);

        try testing.expectEqual(@as(u16, 1), map.len);
        try testing.expect(map.getPtr(testAddress(8100)) == null);
        try testing.expectEqual(
            @as(Slot, 9000),
            (map.getPtr(replacement_addr) orelse return error.TestExpectedEqual).slot,
        );
    }

    {
        var map = TestDedupeMap.empty();
        const addr = testAddress(8200);
        _ = map.getOrPut(addr, testPeer(10, .pending));
        map.clear();

        try testing.expectEqual(@as(u16, 0), map.len);
        try testing.expect(map.getPtr(addr) == null);
        try testing.expect(map.nextPending() == null);
    }

    {
        var map = TestDedupeMap.empty();
        const addr = testAddress(8300);
        const peer = PeerState{
            .from = Pubkey.ZEROES,
            .slot = 11,
            .hash = Hash.ZEROES,
            .probe_status = .in_flight,
            .latency_ms = std.math.maxInt(u29),
        };
        const entry = map.getOrPut(addr, peer).entry;

        try testing.expectEqual(@as(Slot, 11), entry.slot);
        try testing.expectEqual(ProbeStatus.in_flight, entry.meta.probe_status);
        try testing.expectEqual(@as(u32, std.math.maxInt(u29)), entry.meta.latency_ms);
        try testing.expect(entry.eqlPeer(peer));
    }
}
