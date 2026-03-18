//! QUIC client for sending Solana transactions to validator TPU endpoints.
//!
//! Architecture: a single-threaded xev event loop runs on a dedicated thread,
//! driven by two event sources — a periodic tick timer and a UDP socket read.
//! External code submits `Packet`s via the `receiver` channel. Each tick, the
//! loop drains the channel, routes packets to a fixed-size connection pool,
//! creates lsquic unidirectional streams, and calls `lsquic_engine_process_conns`
//! to drive the QUIC state machine. Each stream writes exactly one packet and
//! then closes.
//!
//! Ownership: `create()` returns a heap-allocated client that owns all resources
//! (socket, SSL context, lsquic engine, connection pool, receiver channel).
//! `destroy()` tears them down in dependency order.

const lsquic = @import("lsquic");
const std = @import("std");
const xev = @import("xev");
const ssl = @import("ssl");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Address = std.net.Address;
const Packet = sig.net.Packet;
const UdpSocket = sig.net.UdpSocket;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const ExitCondition = sig.sync.ExitCondition;
const Gauge = sig.prometheus.Gauge;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;

pub const Logger = sig.trace.Logger("quic_client");

const QuicClient = @This();

gpa: Allocator,
exit: ExitCondition,
logger: Logger,
config: Config,
metrics: Metrics,
metrics_last_logged: Instant,

receiver: *Channel(Packet),
connections: []Connection,

socket: UdpSocket,
local_address: Address,
ssl_ctx: *ssl.SSL_CTX,

lsquic_engine: *lsquic.lsquic_engine,
lsquic_engine_api: lsquic.lsquic_engine_api,
lsquic_engine_settings: lsquic.lsquic_engine_settings,
lsquic_stream_interface: lsquic.lsquic_stream_if,

pub const Config = struct {
    /// Size of the fixed connection pool.
    max_connections: usize = 20,
    /// Per-connection packet buffer capacity; limits in-flight packets per peer.
    max_streams_per_connection: usize = 20,
    /// Event loop tick period. Controls how often the channel is drained
    /// and lsquic connections are serviced.
    tick_interval_ms: u64 = 10,
    /// Interval for logging metrics; set to null to disable logging.
    log_metrics_interval: ?Duration = null,
};

pub const Metrics = struct {
    active_connections: *Gauge(u64),
    packets_received_count: *Counter,
    packets_sent_count: *Counter,
    packets_dropped_count: *Counter,
    datagrams_sent_count: *Counter,
    stream_write_errors_count: *Counter,

    pub const prefix = "QuicClient";

    pub fn log(
        self: *Metrics,
        logger: Logger,
    ) void {
        // zig fmt: off
        logger.info().logf(
            "active_connections={d}, packets_received={d}, packets_sent={d}, packets_dropped={d}, datagrams_sent={d}, stream_write_errors={d}",
            .{
                self.active_connections.get(),
                self.packets_received_count.get(),
                self.packets_sent_count.get(),
                self.packets_dropped_count.get(),
                self.datagrams_sent_count.get(),
                self.stream_write_errors_count.get(),
            },
        );
        // zig fmt: on
    }
};

/// Creates a heap-allocated QuicClient. Must be heap-allocated because
/// `lsquic_engine_api` contains pointers into `self` (settings, stream
/// interface, socket) that must remain stable for the engine's lifetime.
pub fn create(
    gpa: Allocator,
    logger: Logger,
    exit: ExitCondition,
    config: Config,
) !*QuicClient {
    if (lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT) != 0)
        @panic("lsquic_global_init failed");

    const receiver = try Channel(Packet).create(gpa);
    errdefer receiver.destroy();

    const socket = try UdpSocket.create(.ipv4);
    errdefer socket.close();
    try socket.bind(.initIp4(.{ 0, 0, 0, 0 }, 0));
    const local_address = try socket.getLocalEndPoint();

    const ssl_ctx = initSslContext();

    const self = try gpa.create(QuicClient);
    errdefer gpa.destroy(self);

    const metrics = try sig.prometheus.globalRegistry().initStruct(Metrics);

    self.* = .{
        .gpa = gpa,
        .config = config,
        .receiver = receiver,
        .exit = exit,
        .logger = logger,
        .metrics = metrics,
        .metrics_last_logged = Instant.EPOCH_ZERO,
        .connections = undefined, // set below
        .socket = socket,
        .local_address = local_address,
        .ssl_ctx = ssl_ctx,
        .lsquic_engine = undefined, // set below
        .lsquic_engine_api = undefined, // set below
        .lsquic_engine_settings = .{},
        .lsquic_stream_interface = .{
            .on_new_conn = Connection.onNewConn,
            .on_conn_closed = Connection.onConnClosed,
            .on_new_stream = Stream.onNewStream,
            .on_write = Stream.onWrite,
            .on_close = Stream.onClose,
        },
    };

    self.connections = try gpa.alloc(Connection, config.max_connections);
    var connections_initialised: u64 = 0;
    errdefer {
        for (self.connections[0..connections_initialised]) |*conn| conn.packets.deinit(gpa);
        gpa.free(self.connections);
    }
    for (self.connections) |*conn| {
        conn.* = .{
            .lsquic_connection = null,
            .client = self,
            .endpoint = null,
            .packets = try PacketBuffer.init(gpa, config.max_streams_per_connection),
        };
        connections_initialised += 1;
    }

    self.lsquic_engine_api = .{
        .ea_alpn = "solana-tpu",
        .ea_settings = &self.lsquic_engine_settings,
        .ea_stream_if = &self.lsquic_stream_interface,
        .ea_stream_if_ctx = self,
        .ea_packets_out = &packetsOut,
        .ea_packets_out_ctx = self,
        .ea_get_ssl_ctx = &getSslContext,
    };

    lsquic.lsquic_engine_init_settings(&self.lsquic_engine_settings, 0);
    var err_buf: [100]u8 = @splat(0);
    if (lsquic.lsquic_engine_check_settings(
        self.lsquic_engine_api.ea_settings,
        0,
        &err_buf,
        err_buf.len,
    ) != 0) @panic("lsquic_check_engine_settings failed: err=" ++ err_buf);

    self.lsquic_engine = lsquic.lsquic_engine_new(
        0,
        &self.lsquic_engine_api,
    ) orelse @panic("lsquic_engine_new failed");

    return self;
}

/// Destroys the client and all owned resources including the receiver channel.
/// Order matters: the engine must be destroyed first (it fires `onConnClosed`
/// callbacks that reference the connection pool), then connections, socket,
/// SSL context, lsquic global state, receiver channel, and finally self.
pub fn destroy(self: *QuicClient) void {
    lsquic.lsquic_engine_destroy(self.lsquic_engine);

    for (self.connections) |*conn| conn.packets.deinit(self.gpa);
    self.gpa.free(self.connections);

    self.socket.close();
    ssl.SSL_CTX_free(self.ssl_ctx);
    lsquic.lsquic_global_cleanup();
    self.receiver.destroy();

    const allocator = self.gpa;
    allocator.destroy(self);
}

/// Event loop entry point, run on a dedicated thread via `spawn()`.
/// Registers a tick timer and a UDP read event, then runs until
/// `exit` is signalled or an error occurs.
pub fn run(self: *QuicClient) !void {
    errdefer |err| {
        self.logger.err().logf("QuicClient Error: {s}", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
        self.exit.setExit();
    }

    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var tick_completion: xev.Completion = undefined;
    var tick_timer = try xev.Timer.init();
    tick_timer.run(
        &loop,
        &tick_completion,
        @intCast(self.config.tick_interval_ms),
        QuicClient,
        self,
        onTick,
    );

    var packets_in_completion: xev.Completion = undefined;
    const read_buffer = try self.gpa.alloc(u8, 1500);
    defer self.gpa.free(read_buffer);
    var udp_state: xev.UDP.State = undefined;
    const packets_in_event = xev.UDP.initFd(self.socket.handle);
    packets_in_event.read(
        &loop,
        &packets_in_completion,
        &udp_state,
        .{ .slice = read_buffer },
        QuicClient,
        self,
        onPacketsIn,
    );

    try loop.run(.until_done);
}

/// Find an existing connection for `endpoint`, or acquire a free slot.
/// If no free slots, return error. Connections close naturally via
/// idle timeout or peer close.
fn acquireConnection(self: *QuicClient, endpoint: Address) !*Connection {
    var maybe_conn: ?*Connection = null;
    for (self.connections) |*conn| {
        if (conn.endpointEql(endpoint)) return conn;
        if (conn.lsquic_connection == null and maybe_conn == null) maybe_conn = conn;
    }

    const conn = maybe_conn orelse return error.NoFreeConnections;
    const lsquic_connection = lsquic.lsquic_engine_connect(
        self.lsquic_engine,
        lsquic.N_LSQVER,
        @ptrCast(&self.local_address.any),
        @ptrCast(&endpoint.any),
        self.ssl_ctx,
        @ptrCast(conn),
        null,
        0,
        null,
        0,
        @ptrCast(&[_]u8{}),
        0,
    ) orelse return error.ConnectFailed;
    conn.endpoint = endpoint;
    conn.lsquic_connection = lsquic_connection;
    self.metrics.active_connections.inc();
    self.logger.debug().logf("connected: endpoint={f}", .{endpoint});

    return conn;
}

/// Periodic tick callback (xev timer). Three phases:
/// 1. Drain the receiver channel and route packets to connections.
/// 2. For each connected connection with pending packets, request
///    unidirectional streams from lsquic (which fires `onNewStream`
///    during `process_conns`).
/// 3. Drive the lsquic engine to process all pending I/O.
///
/// Re-arms itself after each invocation; stops the loop on exit signal.
fn onTick(
    maybe_self: ?*QuicClient,
    xev_loop: *xev.Loop,
    xev_completion: *xev.Completion,
    xev_timer_error: xev.Timer.RunError!void,
) xev.CallbackAction {
    const self = maybe_self orelse @panic("onTick called with null context");

    xev_timer_error catch |err| std.debug.panic("xev timer error: {s}", .{@errorName(err)});

    while (self.receiver.tryReceive()) |packet| {
        self.metrics.packets_received_count.inc();
        const conn = self.acquireConnection(packet.addr.toAddress()) catch |err| {
            self.logger.warn().logf(
                "acquire connection failed, dropping packet: err={s}",
                .{@errorName(err)},
            );
            self.metrics.packets_dropped_count.inc();
            continue;
        };
        conn.packets.push(packet) catch {
            self.logger.warn().log("connection packet buffer full, dropping packet");
            self.metrics.packets_dropped_count.inc();
        };
    }

    for (self.connections) |*connection| {
        if (connection.lsquic_connection == null) continue;
        // Streams can only be opened after the QUIC handshake completes.
        if (connection.getStatus() != .CONNECTED) continue;
        while (connection.packets.reserve()) {
            lsquic.lsquic_conn_make_uni_stream(
                connection.lsquic_connection.?,
                -1,
                self.lsquic_engine_api.ea_stream_if,
                self.lsquic_engine_api.ea_stream_if_ctx,
            );
        }
    }

    lsquic.lsquic_engine_process_conns(self.lsquic_engine);

    var tick_timer = xev.Timer.init() catch std.debug.panic("xev timer re-init failed");
    tick_timer.run(
        xev_loop,
        xev_completion,
        @intCast(self.config.tick_interval_ms),
        QuicClient,
        self,
        onTick,
    );

    if (self.exit.shouldExit()) xev_loop.stop();

    if (self.config.log_metrics_interval) |interval| {
        if (self.metrics_last_logged.elapsed().gt(interval)) {
            self.metrics_last_logged = Instant.now();
            self.metrics.log(self.logger);
        }
    }

    return .disarm;
}

/// UDP read callback (xev). Feeds incoming datagrams into the lsquic engine
/// for processing (handshake responses, ACKs, etc.). Always re-arms.
fn onPacketsIn(
    maybe_self: ?*QuicClient,
    _: *xev.Loop,
    _: *xev.Completion,
    _: *xev.UDP.State,
    peer_address: Address,
    _: xev.UDP,
    xev_read_buffer: xev.ReadBuffer,
    xev_read_error: xev.ReadError!usize,
) xev.CallbackAction {
    const self = maybe_self orelse @panic("onPacketsIn called with null context");

    const bytes = xev_read_error catch |err| {
        self.logger.warn().logf("UDP read error: {s}", .{@errorName(err)});
        return .rearm;
    };

    const packet_in_result = lsquic.lsquic_engine_packet_in(
        self.lsquic_engine,
        xev_read_buffer.slice.ptr,
        bytes,
        @ptrCast(&self.local_address.any),
        @ptrCast(&peer_address.any),
        self.ssl_ctx,
        0,
    );
    if (packet_in_result < 0) self.logger.warn().logf(
        "lsquic_engine_packet_in failed: err={d}",
        .{packet_in_result},
    );

    lsquic.lsquic_engine_process_conns(self.lsquic_engine);

    return .rearm;
}

/// A slot in the fixed-size connection pool. Each slot maps to at most one
/// QUIC connection to a remote endpoint. A slot is "free" when `endpoint`
/// is null. Slots are acquired by `acquireConnection` and released by
/// lsquic's `on_conn_closed` callback (fired on idle timeout, peer close,
/// or engine destruction).
///
/// Invariant: `endpoint` and `lsquic_connection` are always both null or
/// both non-null.
pub const Connection = struct {
    client: *QuicClient,
    packets: PacketBuffer,
    endpoint: ?Address,
    lsquic_connection: ?*lsquic.lsquic_conn_t,

    /// `lsquic_conn_status` values.
    const Status = enum(u32) {
        INPROGRESS,
        CONNECTED,
        FAILURE,
        GOING_AWAY,
        TIMED_OUT,
        RESET,
        USER_ABORTED,
        ERROR,
        CLOSED,
        PEER_GOING_AWAY,
        VERNEG_FAILURE,
    };

    fn endpointEql(self: *const Connection, other: Address) bool {
        if (self.endpoint == null) return false;
        const self_bytes = std.mem.asBytes(&self.endpoint.?.any);
        const other_bytes = std.mem.asBytes(&other.any);
        return std.mem.eql(u8, self_bytes, other_bytes);
    }

    fn getStatus(self: *Connection) Status {
        var errbuf: [100]u8 = undefined;
        return @enumFromInt(lsquic.lsquic_conn_status(
            self.lsquic_connection.?,
            &errbuf,
            100,
        ));
    }

    /// lsquic callback. Called when a new connection is established.
    /// Returns the connection context (the `Connection` pointer originally
    /// passed as `conn_ctx` to `lsquic_engine_connect`).
    fn onNewConn(
        _: ?*anyopaque,
        maybe_lsquic_connection: ?*lsquic.lsquic_conn_t,
    ) callconv(.c) *lsquic.lsquic_conn_ctx_t {
        return lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection).?;
    }

    /// lsquic callback. Resets the pool slot to free by clearing the
    /// endpoint, lsquic handle, and packet buffer. Called on idle timeout,
    /// peer-initiated close, or engine destruction.
    fn onConnClosed(maybe_lsquic_connection: ?*lsquic.lsquic_conn_t) callconv(.c) void {
        const conn_ctx = lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection) orelse return;
        const conn: *Connection = @ptrCast(@alignCast(conn_ctx));

        conn.client.logger.debug().logf("disconnected: endpoint={f}", .{conn.endpoint.?});
        lsquic.lsquic_conn_set_ctx(maybe_lsquic_connection, null);

        conn.client.metrics.packets_dropped_count.add(conn.packets.len());
        conn.packets.reset();
        conn.endpoint = null;
        conn.lsquic_connection = null;
        conn.client.metrics.active_connections.dec();
    }
};

/// Represents a single unidirectional QUIC stream that writes exactly one
/// packet. Heap-allocated in `onNewStream`, freed in `onClose`. Lifetime
/// is managed entirely by lsquic callbacks.
const Stream = struct {
    lsquic_stream: *lsquic.lsquic_stream_t,
    connection: *Connection,
    packet: Packet,
    bytes_written: usize,

    /// lsquic callback. Allocates a Stream, pops the next reserved packet
    /// from the connection's buffer, and signals write-readiness to lsquic.
    fn onNewStream(
        _: ?*anyopaque,
        maybe_lsquic_stream: ?*lsquic.lsquic_stream_t,
    ) callconv(.c) *lsquic.lsquic_stream_ctx_t {
        const lsquic_stream = maybe_lsquic_stream orelse
            @panic("onNewStream called with null stream");

        const lsquic_connection = lsquic.lsquic_stream_conn(lsquic_stream);
        const conn_ctx = lsquic.lsquic_conn_get_ctx(lsquic_connection).?;
        const conn: *Connection = @ptrCast(@alignCast(conn_ctx));

        const stream = conn.client.gpa.create(Stream) catch @panic("OutOfMemory");
        stream.* = .{
            .lsquic_stream = lsquic_stream,
            .connection = conn,
            .packet = conn.packets.pop() catch @panic("new stream without packet"),
            .bytes_written = 0,
        };

        _ = lsquic.lsquic_stream_wantwrite(lsquic_stream, 1);

        return @ptrCast(stream);
    }

    /// lsquic callback. Writes remaining packet bytes to the stream. Handles
    /// partial writes by tracking `bytes_written`; flushes and closes the
    /// stream once all bytes are sent. On write error, closes immediately.
    fn onWrite(
        maybe_lsquic_stream: ?*lsquic.lsquic_stream_t,
        maybe_stream: ?*lsquic.lsquic_stream_ctx_t,
    ) callconv(.c) void {
        const stream: *Stream = @ptrCast(@alignCast(maybe_stream.?));

        const remaining = stream.packet.buffer[stream.bytes_written..stream.packet.size];
        const n = lsquic.lsquic_stream_write(maybe_lsquic_stream, remaining.ptr, remaining.len);

        if (n < 0) {
            stream.connection.client.logger.warn().log("stream write failed; closing stream");
            _ = lsquic.lsquic_stream_wantwrite(maybe_lsquic_stream, 0);
            _ = lsquic.lsquic_stream_close(maybe_lsquic_stream);
            stream.connection.client.metrics.stream_write_errors_count.inc();
        } else if (n > 0) {
            stream.bytes_written += @intCast(n);

            if (stream.bytes_written > stream.packet.size)
                @panic("lsquic_stream_write wrote more bytes than requested");

            if (stream.bytes_written == stream.packet.size) {
                _ = lsquic.lsquic_stream_flush(maybe_lsquic_stream);
                _ = lsquic.lsquic_stream_wantwrite(maybe_lsquic_stream, 0);
                _ = lsquic.lsquic_stream_close(maybe_lsquic_stream);
                stream.connection.client.metrics.packets_sent_count.inc();
            }
        }
    }

    /// lsquic callback. Frees the heap-allocated Stream.
    fn onClose(
        _: ?*lsquic.lsquic_stream_t,
        maybe_stream: ?*lsquic.lsquic_stream_ctx_t,
    ) callconv(.c) void {
        const stream: *Stream = @ptrCast(@alignCast(maybe_stream.?));
        stream.connection.client.gpa.destroy(stream);
    }
};

/// A fixed-capacity ring buffer for packets, using a three-pointer design:
/// - `tail`: next write position (producer pushes here)
/// - `resv`: next reservation position (consumer reserves ahead of pop)
/// - `head`: next read position (consumer pops from here)
///
/// Flow: push increments tail, reserve increments resv, pop increments head.
/// Invariant: head <= resv <= tail (modular).
pub const PacketBuffer = struct {
    pkts: []Packet,
    head: usize = 0,
    resv: usize = 0,
    tail: usize = 0,

    pub fn init(allocator: Allocator, capacity: usize) !PacketBuffer {
        const pkts = try allocator.alloc(Packet, capacity + 1); // + 1 for sentinel
        return .{
            .pkts = pkts,
            .head = 0,
            .resv = 0,
            .tail = 0,
        };
    }

    pub fn deinit(self: *PacketBuffer, allocator: Allocator) void {
        allocator.free(self.pkts);
    }

    pub fn reset(self: *PacketBuffer) void {
        self.head = 0;
        self.resv = 0;
        self.tail = 0;
    }

    /// Reserve a slot for consumption. Returns true if a slot was reserved
    /// (i.e. there are unreserved pushed packets). Must be followed by a
    /// corresponding `pop` after the stream is created.
    pub fn reserve(self: *PacketBuffer) bool {
        if (self.resv == self.tail) return false;
        self.resv = (self.resv + 1) % self.pkts.len;
        return true;
    }

    /// Pop the next reserved packet for writing to a stream.
    pub fn pop(self: *PacketBuffer) error{NoMoreReservations}!Packet {
        if (self.head == self.resv) return error.NoMoreReservations;
        const pkt = self.pkts[self.head];
        self.head = (self.head + 1) % self.pkts.len;
        return pkt;
    }

    /// Push a packet into the buffer. Returns error if the buffer is full.
    pub fn push(self: *PacketBuffer, pkt: Packet) error{PacketBufferFull}!void {
        if ((self.tail + 1) % self.pkts.len == self.head) return error.PacketBufferFull;
        self.pkts[self.tail] = pkt;
        self.tail = (self.tail + 1) % self.pkts.len;
    }

    /// Number of packets currently in the buffer (pushed but not yet popped).
    pub fn len(self: *const PacketBuffer) usize {
        if (self.tail >= self.head) {
            return self.tail - self.head;
        } else {
            return self.pkts.len - self.head + self.tail;
        }
    }
};

/// lsquic `ea_packets_out` callback. Sends QUIC packets over UDP via
/// `sendmsg`. Returns the number of packets successfully sent, or -1 if
/// none could be sent. On partial failure, lsquic will retry the remainder
/// via `lsquic_engine_send_unsent_packets`.
fn packetsOut(
    ctx: ?*anyopaque,
    specs: ?[*]const lsquic.lsquic_out_spec,
    n_specs: c_uint,
) callconv(.c) c_int {
    var msg: std.posix.msghdr_const = undefined;
    const self: *QuicClient = @ptrCast(@alignCast(ctx.?));

    for (specs.?[0..n_specs], 0..) |spec, i| {
        const sa: *const std.posix.sockaddr = @ptrCast(@alignCast(spec.dest_sa));
        msg.name = sa;
        msg.namelen = if (sa.family == std.posix.AF.INET)
            @sizeOf(std.posix.sockaddr.in)
        else
            @sizeOf(std.posix.sockaddr.in6);
        msg.iov = @ptrCast(spec.iov.?);
        msg.iovlen = @intCast(spec.iovlen);
        msg.flags = 0;
        msg.control = null;
        msg.controllen = 0;
        _ = std.posix.sendmsg(self.socket.handle, &msg, 0) catch |err| {
            // Return number of packets sent so far, or -1 if none.
            // lsquic will check errno and retry via lsquic_engine_send_unsent_packets().
            self.logger.warn().logf("sendmsg failed: err={s}", .{@errorName(err)});
            if (i == 0) return -1;
            return @intCast(i);
        };
        self.metrics.datagrams_sent_count.inc();
    }

    return @intCast(n_specs);
}

/// lsquic `ea_get_ssl_ctx` callback. The `peer_ctx` passed to
/// `lsquic_engine_connect` is the `SSL_CTX` pointer itself.
fn getSslContext(
    peer_ctx: ?*anyopaque,
    _: ?*const lsquic.struct_sockaddr,
) callconv(.c) *lsquic.struct_ssl_ctx_st {
    return @ptrCast(peer_ctx.?);
}

/// Creates a TLS 1.3 context with a self-signed Ed25519 certificate,
/// as required by Solana's QUIC TPU protocol.
fn initSslContext() *ssl.SSL_CTX {
    const ssl_ctx = ssl.SSL_CTX_new(ssl.TLS_method()) orelse
        @panic("SSL_CTX_new failed");

    if (ssl.SSL_CTX_set_min_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0)
        @panic("SSL_CTX_set_min_proto_version failed");

    if (ssl.SSL_CTX_set_max_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0)
        @panic("SSL_CTX_set_max_proto_version failed");

    const signature_algs: []const u16 = &.{ssl.SSL_SIGN_ED25519};
    if (ssl.SSL_CTX_set_verify_algorithm_prefs(ssl_ctx, signature_algs.ptr, 1) == 0)
        @panic("SSL_CTX_set_verify_algorithm_prefs failed");

    const pubkey, const cert = initX509Certificate();
    if (ssl.SSL_CTX_use_PrivateKey(ssl_ctx, pubkey) == 0)
        @panic("SSL_CTX_use_PrivateKey failed");

    if (ssl.SSL_CTX_use_certificate(ssl_ctx, cert) == 0)
        @panic("SSL_CTX_use_certificate failed");

    return ssl_ctx;
}

/// Generates an ephemeral Ed25519 keypair and a self-signed X.509 certificate.
fn initX509Certificate() struct { *ssl.EVP_PKEY, *ssl.X509 } {
    const pctx = ssl.EVP_PKEY_CTX_new_id(ssl.EVP_PKEY_ED25519, null) orelse
        @panic("EVP_PKEY_CTX_new_id failed");
    defer ssl.EVP_PKEY_CTX_free(pctx);

    if (ssl.EVP_PKEY_keygen_init(pctx) == 0)
        @panic("EVP_PKEY_keygen_init failed");

    var maybe_pkey: ?*ssl.EVP_PKEY = null;
    if (ssl.EVP_PKEY_keygen(pctx, &maybe_pkey) == 0)
        @panic("EVP_PKEY_keygen failed");
    const pkey = maybe_pkey orelse @panic("EVP_PKEY_keygen failed");

    const cert = ssl.X509_new() orelse @panic("X509_new failed");

    if (ssl.X509_set_version(cert, ssl.X509_VERSION_3) == 0)
        @panic("X509_set_version failed");

    const serial = ssl.ASN1_INTEGER_new() orelse @panic("ASN1_INTEGER_new failed");
    defer ssl.ASN1_INTEGER_free(serial);
    if (ssl.ASN1_INTEGER_set(serial, 1) == 0)
        @panic("ASN1_INTEGER_set failed");
    if (ssl.X509_set_serialNumber(cert, serial) == 0)
        @panic("X509_set_serialNumber failed");

    const issuer = ssl.X509_get_issuer_name(cert) orelse
        @panic("X509_get_issuer_name failed");
    if (ssl.X509_NAME_add_entry_by_txt(
        issuer,
        "CN",
        ssl.MBSTRING_ASC,
        "Solana",
        -1,
        -1,
        0,
    ) == 0) @panic("X509_NAME_add_entry_by_txt failed");

    if (ssl.X509_gmtime_adj(ssl.X509_get_notBefore(cert), 0) == null)
        @panic("X509_gmtime_adj failed");
    if (ssl.X509_gmtime_adj(ssl.X509_get_notAfter(cert), 60 * 60 * 24 * 365 * 1000) == null)
        @panic("X509_gmtime_adj failed");

    if (ssl.X509_set_subject_name(cert, issuer) == 0)
        @panic("X509_set_subject_name failed");

    if (ssl.X509_set_pubkey(cert, pkey) == 0)
        @panic("X509_set_pubkey failed");

    if (ssl.X509_sign(cert, pkey, null) == 0)
        @panic("X509_sign failed");

    return .{ pkey, cert };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "PacketBuffer: push, reserve, pop cycle" {
    const allocator = std.testing.allocator;
    var buf = try PacketBuffer.init(allocator, 4);
    defer buf.deinit(allocator);

    // Buffer is empty.
    try std.testing.expectEqual(@as(usize, 0), buf.len());
    try std.testing.expect(!buf.reserve());

    // Push two packets.
    var p1 = Packet.ANY_EMPTY;
    p1.size = 1;
    var p2 = Packet.ANY_EMPTY;
    p2.size = 2;

    try buf.push(p1);
    try buf.push(p2);
    try std.testing.expectEqual(@as(usize, 2), buf.len());

    // Reserve and pop first.
    try std.testing.expect(buf.reserve());
    const popped1 = try buf.pop();
    try std.testing.expectEqual(@as(usize, 1), popped1.size);

    // Reserve and pop second.
    try std.testing.expect(buf.reserve());
    const popped2 = try buf.pop();
    try std.testing.expectEqual(@as(usize, 2), popped2.size);

    // No more to reserve.
    try std.testing.expect(!buf.reserve());

    // Pop without reservation fails.
    try std.testing.expectError(error.NoMoreReservations, buf.pop());
}

test "PacketBuffer: full buffer returns error" {
    const allocator = std.testing.allocator;
    // Capacity 4 means 3 usable slots (ring buffer wastes one).
    var buf = try PacketBuffer.init(allocator, 3);
    defer buf.deinit(allocator);

    const p = Packet.ANY_EMPTY;
    try buf.push(p);
    try buf.push(p);
    try buf.push(p);

    try std.testing.expectError(error.PacketBufferFull, buf.push(p));
    try std.testing.expectEqual(@as(usize, 3), buf.len());
}

test "PacketBuffer: reset clears state" {
    const allocator = std.testing.allocator;
    var buf = try PacketBuffer.init(allocator, 4);
    defer buf.deinit(allocator);

    const p = Packet.ANY_EMPTY;
    try buf.push(p);
    try buf.push(p);
    try std.testing.expectEqual(@as(usize, 2), buf.len());

    buf.reset();
    try std.testing.expectEqual(@as(usize, 0), buf.len());
    try std.testing.expect(!buf.reserve());
}

test "PacketBuffer: wrap-around" {
    const allocator = std.testing.allocator;
    // Capacity 4, 3 usable slots.
    var buf = try PacketBuffer.init(allocator, 4);
    defer buf.deinit(allocator);

    var p = Packet.ANY_EMPTY;

    // Fill and drain twice to force wrap-around.
    for (0..2) |_| {
        p.size = 10;
        try buf.push(p);
        p.size = 20;
        try buf.push(p);
        p.size = 30;
        try buf.push(p);

        try std.testing.expect(buf.reserve());
        try std.testing.expect(buf.reserve());
        try std.testing.expect(buf.reserve());

        try std.testing.expectEqual(@as(usize, 10), (try buf.pop()).size);
        try std.testing.expectEqual(@as(usize, 20), (try buf.pop()).size);
        try std.testing.expectEqual(@as(usize, 30), (try buf.pop()).size);
    }
}
