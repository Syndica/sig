const std = @import("std");
const builtin = @import("builtin");
const lsquic = @import("lsquic");
const xev = @import("xev");
const ssl = @import("ssl");
const network = @import("zig-network");
const sig = @import("../../sig.zig");

const Packet = sig.net.Packet;
const Channel = sig.sync.Channel;
const Atomic = std.atomic.Value;

const MAX_NUM_TRANSACTIONS = 100;
const MAX_NUM_CONNECTIONS = 10;

pub fn runTestClient() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa = gpa_state.allocator();
    defer _ = gpa_state.deinit();

    var send_channel = try sig.sync.Channel(sig.net.Packet).init(gpa);
    defer send_channel.deinit();

    const test_address = try network.EndPoint.parse("127.0.0.1:1033");
    var test_packet: Packet = .{
        .addr = test_address,
        .data = .{0xaa} ** sig.net.PACKET_DATA_SIZE,
        .size = 30,
    };

    var exit = Atomic(bool).init(false);
    var client_handle = try std.Thread.spawn(
        .{},
        runClient,
        .{
            gpa,
            &send_channel,
            &exit,
        },
    );

    for (0..10) |i| {
        test_packet.data[0] = @intCast(i);
        try send_channel.send(test_packet);
        std.time.sleep(1_000_000_000);
    }

    for (0..10) |i| {
        test_packet.data[0] = @intCast(10 + i);
        try send_channel.send(test_packet);
        std.time.sleep(5_000_000_000);
    }

    exit.store(true, .release);
    client_handle.join();
}

/// Spawn this function on a new thread
pub fn runClient(
    allocator: std.mem.Allocator,
    send_channel: *Channel(Packet),
    exit: *Atomic(bool),
) !void {
    // setup the global state
    if (lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT) == 1) {
        @panic("lsquic_global_init failed");
    }

    var tick_event = try xev.Timer.init();
    var channel_event = try xev.Timer.init();

    var socket = try network.Socket.create(.ipv4, .udp);
    var packets_event = xev.UDP.initFd(socket.internal);
    socket.bind(.{ .address = network.Address{ .ipv4 = network.Address.IPv4.any }, .port = 4444 }) catch {
        @panic("failed to bind to port");
    };

    // setup our sol context
    var ctx: Context = undefined;
    try ctx.init(
        allocator,
        &packets_event,
        &channel_event,
        &tick_event,
        send_channel,
        &socket,
        exit,
    );

    // Setup the event loop.
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var tick_complete: xev.Completion = undefined;
    var channel_complete: xev.Completion = undefined;
    var packets_complete: xev.Completion = undefined;
    tick_event.run(&loop, &tick_complete, 500, Context, &ctx, tickCallback);
    channel_event.run(&loop, &channel_complete, 500, Context, &ctx, channelCallback);

    // TODO: figure out a better solution for this
    const read_buffer = try allocator.alloc(u8, 1500);
    defer allocator.free(read_buffer);
    var state: xev.UDP.State = undefined;
    packets_event.read(
        &loop,
        &packets_complete,
        &state,
        .{ .slice = read_buffer },
        Context,
        &ctx,
        packetsCallback,
    );

    // Run the loop!
    try loop.run(.until_done);
}

pub const Context = struct {
    engine: *lsquic.lsquic_engine,
    settings: lsquic.lsquic_engine_settings,
    api: lsquic.lsquic_engine_api,

    socket: *network.Socket,

    ssl_ctx: *ssl.SSL_CTX,

    // events for managing the event loop
    packets_event: *xev.UDP,
    channel_event: *xev.Timer,
    tick_event: *xev.Timer,

    allocator: std.mem.Allocator,
    send_channel: *Channel(Packet),
    conns: std.BoundedArray(*Connection, MAX_NUM_CONNECTIONS),

    exit: *Atomic(bool),

    pub fn TransactionBuffer(comptime N: usize) type {
        return struct {
            txns: [N]Packet = undefined,
            head: usize = 0, // Points to the first index of the next transaction to pop
            resv: usize = 0, // Points to the first index of the next transaction to reserve
            tail: usize = 0, // Points to the first index of the next transaction to push

            const TransactionBufferN = @This();

            pub fn reserve(self: *TransactionBufferN) bool {
                if (self.resv == self.tail) {
                    return false;
                } else {
                    self.resv = (self.resv + 1) % MAX_NUM_TRANSACTIONS;
                    return true;
                }
            }

            pub fn pop(self: *TransactionBufferN) !Packet {
                if (self.head == self.resv) {
                    return error.NoMoreReservations;
                }

                const txn = self.txns[self.head];
                self.head = (self.head + 1) % MAX_NUM_TRANSACTIONS;

                return txn;
            }

            pub fn push(self: *TransactionBufferN, txn: Packet) !void {
                if ((self.tail + 1) % MAX_NUM_TRANSACTIONS == self.head) {
                    return error.TxnBufferFull;
                }

                self.txns[self.tail] = txn;
                self.tail = (self.tail + 1) % MAX_NUM_TRANSACTIONS;
            }

            pub fn len(self: *TransactionBufferN) usize {
                if (self.tail >= self.head) {
                    return self.tail - self.head;
                } else {
                    return MAX_NUM_TRANSACTIONS - self.head + self.tail;
                }
            }

            pub fn reserved(self: *TransactionBufferN) usize {
                if (self.resv >= self.head) {
                    return self.resv - self.head;
                } else {
                    return MAX_NUM_TRANSACTIONS - self.head + self.resv;
                }
            }

            pub fn constSlice(self: *TransactionBufferN) []Packet {
                return self.txns[self.head..self.tail];
            }
        };
    }

    const Connection = struct {
        ctx: *Context,
        /// lsquic's connection type
        conn: ?*lsquic.lsquic_conn_t,
        /// the peer we're connected to
        address: network.EndPoint,
        /// NOTE: even though Packet stores an endpoint, it's easier to just use the Packet type
        /// for now; can be slimed to just the transaction bytes later.
        transactions: TransactionBuffer(MAX_NUM_TRANSACTIONS),

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
    };

    const Stream = struct {
        stream: ?*lsquic.lsquic_stream_t,
        conn_ctx: *Context.Connection,
        txn: Packet,
    };

    fn init(
        ctx: *Context,
        allocator: std.mem.Allocator,
        packets_event: *xev.UDP,
        channel_event: *xev.Timer,
        tick_event: *xev.Timer,
        send_channel: *Channel(Packet),
        socket: *network.Socket,
        exit: *Atomic(bool),
    ) !void {
        ctx.* = .{
            .allocator = allocator,
            .packets_event = packets_event,
            .channel_event = channel_event,
            .tick_event = tick_event,
            .send_channel = send_channel,
            .conns = .{},
            .settings = .{},
            .api = .{
                .ea_alpn = "solana-tpu",
                .ea_settings = &ctx.settings,
                .ea_stream_if = &Callbacks.callbacks,
                .ea_stream_if_ctx = ctx,
                .ea_packets_out = packetsOut,
                .ea_packets_out_ctx = socket,
                .ea_get_ssl_ctx = getSslCtx,
            },
            .engine = undefined,
            .ssl_ctx = initSSL(),
            .socket = socket,
            .exit = exit,
        };

        // setup the default configs for client
        lsquic.lsquic_engine_init_settings(&ctx.settings, 0);

        ctx.engine = lsquic.lsquic_engine_new(0, &ctx.api) orelse {
            @panic("lsquic_engine_new failed");
        };

        // check the engine settings
        var err_buf: [100]u8 = undefined;
        if (lsquic.lsquic_engine_check_settings(ctx.api.ea_settings, 0, &err_buf, 100) == 1) {
            @panic("lsquic_engine_check_settings failed " ++ err_buf);
        }
    }

    fn initSSL() *ssl.SSL_CTX {
        const ssl_ctx = ssl.SSL_CTX_new(ssl.TLS_method()) orelse
            @panic("SSL_CTX_new failed");
        if (ssl.SSL_CTX_set_min_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0) {
            @panic("SSL_CTX_set_min_proto_version failed");
        }
        if (ssl.SSL_CTX_set_max_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0) {
            @panic("SSL_CTX_set_max_proto_version failed\n");
        }

        const sigalg: u16 = ssl.SSL_SIGN_ED25519;
        if (ssl.SSL_CTX_set_verify_algorithm_prefs(ssl_ctx, &sigalg, 1) == 0) {
            @panic("SSL_CTX_set_verify_algorithm_prefs failed\n");
        }

        var pkey: *ssl.EVP_PKEY = undefined;
        var cert: *ssl.X509 = undefined;

        var public_key: [32]u8 = undefined;
        var private_key: [64]u8 = undefined;

        ssl.ED25519_keypair(&public_key, &private_key);

        const pkcs8_prefix: [16]u8 = .{
            0x30, 0x2e, 0x02, 0x01, 0x00,
            0x30, 0x05, 0x06, 0x03, 0x2b,
            0x65, 0x70, 0x04, 0x22, 0x04,
            0x20,
        };

        var key_pkcs8_der: [48]u8 = undefined;
        @memcpy(key_pkcs8_der[0..16], &pkcs8_prefix);
        @memcpy(key_pkcs8_der[16..], private_key[0..32]);

        const cert_prefix: [100]u8 = .{
            0x30, 0x81, 0xf6, 0x30, 0x81, 0xa9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x16,
            0x31, 0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0b, 0x53, 0x6f, 0x6c, 0x61,
            0x6e, 0x61, 0x20, 0x6e, 0x6f, 0x64, 0x65, 0x30, 0x20, 0x17, 0x0d, 0x37, 0x30, 0x30, 0x31,
            0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x18, 0x0f, 0x34, 0x30, 0x39, 0x36,
            0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x00, 0x30, 0x2a,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        };
        const cert_suffix: [117]u8 = .{
            0xa3, 0x29, 0x30, 0x27, 0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x01, 0x01, 0xff, 0x04,
            0x0d, 0x30, 0x0b, 0x82, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73, 0x74, 0x30,
            0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };

        var cert_der: [249]u8 = undefined;
        @memcpy(cert_der[0..100], &cert_prefix);
        @memcpy(cert_der[100..][0..32], &public_key);
        @memcpy(cert_der[132..], &cert_suffix);

        pkey = ssl.EVP_PKEY_new_raw_private_key(ssl.EVP_PKEY_ED25519, null, &private_key, 32) orelse {
            @panic("EVP_PKEY_new_raw_private_key failed");
        };

        const bio: *ssl.BIO = ssl.BIO_new_mem_buf(&cert_der, 249);
        cert = ssl.d2i_X509_bio(bio, null) orelse @panic("d2i_X509_bio failed");
        _ = ssl.BIO_free(bio);

        if (ssl.SSL_CTX_use_PrivateKey(ssl_ctx, pkey) == 0) {
            @panic("SSL_CTX_use_PrivateKey failed");
        }
        if (ssl.SSL_CTX_use_certificate(ssl_ctx, cert) == 0) {
            @panic("SSL_CTX_use_certificate failed");
        }

        return ssl_ctx;
    }

    fn getConnectionContext(
        ctx: *Context,
        address: network.EndPoint,
    ) !*Connection {
        for (ctx.conns.constSlice()) |connection| {
            if (connection.address.address.eql(address.address) and
                connection.address.port == address.port)
            {
                return connection;
            }
        }

        // create a new connection context
        const conn_ctx = try ctx.allocator.create(Connection);
        conn_ctx.* = .{
            .ctx = ctx,
            .conn = null,
            .address = address,
            .transactions = .{},
        };

        const local_endpoint = try ctx.socket.getLocalEndPoint();
        const local_socketaddr = switch (toSocketAddress(local_endpoint)) {
            .ipv4 => |addr| addr,
            .ipv6 => @panic("add ipv6 support"),
        };

        const peer_socketaddr = switch (toSocketAddress(address)) {
            .ipv4 => |addr| addr,
            .ipv6 => @panic("add ipv6 support"),
        };

        std.debug.print("connecting to: {}\n", .{address});

        if (lsquic.lsquic_engine_connect(
            ctx.engine,
            lsquic.N_LSQVER,
            @ptrCast(&local_socketaddr),
            @ptrCast(&peer_socketaddr),
            ctx.ssl_ctx,
            @ptrCast(conn_ctx),
            null,
            0,
            null,
            0,
            null,
            0,
        ) == null) {
            @panic("error connecting to server");
        }

        return conn_ctx;
    }

    fn deinit(ctx: *Context) void {
        ctx.socket.close();
    }
};

const Callbacks = struct {
    const callbacks: lsquic.lsquic_stream_if = .{
        .on_new_conn = onNewConn,
        .on_goaway_received = onGoawayReceived,
        .on_conn_closed = onConnClosed,
        .on_new_stream = onNewStream,
        .on_read = onRead,
        .on_write = onWrite,
        .on_close = onClose,
        .on_dg_write = onDbWrite,
        .on_datagram = onDatagram,
        .on_hsk_done = onHskDone,
        .on_new_token = onNewToken,
        .on_sess_resume_info = onSessResumeInfo,
        .on_reset = onReset,
        .on_conncloseframe_received = onConnCloseFrameReceived,
    };

    fn onNewConn(
        _: ?*anyopaque,
        conn: ?*lsquic.lsquic_conn_t,
    ) callconv(.C) *lsquic.lsquic_conn_ctx_t {
        const connection: *Context.Connection = @alignCast(@ptrCast(lsquic.lsquic_conn_get_ctx(conn).?));
        std.debug.print("on new connection, open connections: {}\n", .{connection.ctx.conns.len});

        connection.conn = conn;
        connection.ctx.conns.append(connection) catch {
            @panic("reached max connections");
        };

        return @ptrCast(connection);
    }

    fn onGoawayReceived(conn: ?*lsquic.lsquic_conn_t) callconv(.C) void {
        _ = conn;

        @panic("TODO: onGoawayReceived");
    }

    fn onConnClosed(conn: ?*lsquic.lsquic_conn_t) callconv(.C) void {
        const conn_ctx: *Context.Connection =
            @alignCast(@ptrCast(lsquic.lsquic_conn_get_ctx(conn).?));

        for (conn_ctx.ctx.conns.constSlice(), 0..) |connection, i| {
            if (@intFromPtr(connection) == @intFromPtr(conn_ctx)) {
                _ = conn_ctx.ctx.conns.swapRemove(i);
            }
        }

        lsquic.lsquic_conn_set_ctx(conn, null);
        conn_ctx.ctx.allocator.destroy(conn_ctx);
    }

    fn onNewStream(
        _: ?*anyopaque,
        stream: ?*lsquic.lsquic_stream_t,
    ) callconv(.C) *lsquic.lsquic_stream_ctx_t {
        const conn = lsquic.lsquic_stream_conn(stream);
        const conn_ctx: *Context.Connection = @alignCast(@ptrCast(lsquic.lsquic_conn_get_ctx(conn).?));

        const stream_ctx = conn_ctx.ctx.allocator.create(Context.Stream) catch {
            @panic("OutOfMemory");
        };
        stream_ctx.* = .{
            .stream = stream,
            .conn_ctx = conn_ctx,
            .txn = conn_ctx.transactions.pop() catch @panic("Failed to pop transaction"),
        };

        _ = lsquic.lsquic_stream_wantwrite(stream, 1);

        return @ptrCast(stream_ctx);
    }

    fn onRead(
        stream: ?*lsquic.lsquic_stream_t,
        stream_ctx: ?*lsquic.lsquic_stream_ctx_t,
    ) callconv(.C) void {
        _ = stream;
        _ = stream_ctx;

        @panic("TODO: onRead");
    }

    fn onWrite(
        stream: ?*lsquic.lsquic_stream_t,
        stream_ctx: ?*lsquic.lsquic_stream_ctx_t,
    ) callconv(.C) void {
        const ctx: *Context.Stream = @alignCast(@ptrCast(stream_ctx.?));

        const bytes_written = lsquic.lsquic_stream_write(stream, &ctx.txn.data, ctx.txn.size);
        if (bytes_written != ctx.txn.size) {
            @panic("only wrote part of the transaction");
        }
        std.debug.print("wrote {d} of {d} bytes to stream\n", .{ bytes_written, ctx.txn.size });

        // flush and close the stream
        _ = lsquic.lsquic_stream_flush(stream);
        _ = lsquic.lsquic_stream_wantwrite(stream, 0);
        _ = lsquic.lsquic_stream_close(stream);
    }

    fn onClose(
        stream: ?*lsquic.lsquic_stream_t,
        stream_ctx: ?*lsquic.lsquic_stream_ctx_t,
    ) callconv(.C) void {
        _ = stream;

        const ctx: *Context.Stream = @alignCast(@ptrCast(stream_ctx.?));
        ctx.conn_ctx.ctx.allocator.destroy(ctx);
    }

    fn onDbWrite(
        conn: ?*lsquic.lsquic_conn_t,
        ctx: ?*anyopaque,
        n_to_write: usize,
    ) callconv(.C) isize {
        _ = conn;
        _ = ctx;
        _ = n_to_write;

        @panic("onDbWrite");
    }

    fn onDatagram(
        conn: ?*lsquic.lsquic_conn_t,
        ctx: ?*const anyopaque,
        n_to_write: usize,
    ) callconv(.C) void {
        _ = conn;
        _ = ctx;
        _ = n_to_write;

        @panic("onDatagram");
    }

    const HskStatus = enum(c_uint) {
        FAIL,
        OK,
        RESUMED_OK,
        RESUMED_FAIL,
    };

    fn onHskDone(
        conn: ?*lsquic.lsquic_conn_t,
        status_code: u32,
    ) callconv(.C) void {
        _ = conn;
        const status: HskStatus = @enumFromInt(status_code);
        std.debug.print("onHskDone {s}\n", .{@tagName(status)});

        // nothing else needs to be done
    }

    fn onNewToken(
        conn: ?*lsquic.lsquic_conn_t,
        token: ?[*]const u8,
        token_size: usize,
    ) callconv(.C) void {
        _ = conn;
        _ = token;
        _ = token_size;
        @panic("TODO: onNewToken");
    }

    fn onSessResumeInfo(
        conn: ?*lsquic.lsquic_conn_t,
        info: ?[*]const u8,
        info_size: usize,
    ) callconv(.C) void {
        _ = conn;
        _ = info;
        _ = info_size;
        @panic("TODO: onSessResumeInfo");
    }

    fn onReset(
        stream: ?*lsquic.lsquic_stream_t,
        ctx: ?*lsquic.lsquic_stream_ctx_t,
        how: i32,
    ) callconv(.C) void {
        _ = stream;
        _ = ctx;
        _ = how;

        @panic("TODO: onReset");
    }

    fn onConnCloseFrameReceived(
        conn: ?*lsquic.lsquic_conn_t,
        app_error: i32,
        error_code: u64,
        reason: ?[*]const u8,
        reason_len: i32,
    ) callconv(.C) void {
        _ = conn;
        _ = app_error;
        _ = error_code;
        _ = reason;
        _ = reason_len;

        @panic("TODO: onConnCloseFrameReceived");
    }
};

// zig stdlib does not define the msghdr{_const} for macos.
const msghdr_const = extern struct {
    name: ?*const std.posix.sockaddr,
    namelen: std.posix.socklen_t,
    iov: [*]const std.posix.iovec_const,
    iovlen: usize,
    control: ?*const anyopaque,
    controllen: usize,
    flags: i32,
};
pub extern "c" fn sendmsg(sockfd: std.posix.fd_t, msg: *const msghdr_const, flags: u32) isize;

pub fn sendmsgPosix(
    /// The file descriptor of the sending socket.
    sockfd: std.posix.fd_t,
    /// Message header and iovecs
    msg: *const msghdr_const,
    flags: u32,
) std.posix.SendMsgError!usize {
    while (true) {
        const rc = sendmsg(sockfd, msg, flags);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),

            .ACCES => return error.AccessDenied,
            .AGAIN => return error.WouldBlock,
            .ALREADY => return error.FastOpenAlreadyInProgress,
            .BADF => unreachable, // always a race condition
            .CONNRESET => return error.ConnectionResetByPeer,
            .DESTADDRREQ => unreachable, // The socket is not connection-mode, and no peer address is set.
            .FAULT => unreachable, // An invalid user space address was specified for an argument.
            .INTR => continue,
            .INVAL => unreachable, // Invalid argument passed.
            .ISCONN => unreachable, // connection-mode socket was connected already but a recipient was specified
            .MSGSIZE => return error.MessageTooBig,
            .NOBUFS => return error.SystemResources,
            .NOMEM => return error.SystemResources,
            .NOTSOCK => unreachable, // The file descriptor sockfd does not refer to a socket.
            .OPNOTSUPP => unreachable, // Some bit in the flags argument is inappropriate for the socket type.
            .PIPE => return error.BrokenPipe,
            .AFNOSUPPORT => return error.AddressFamilyNotSupported,
            .LOOP => return error.SymLinkLoop,
            .NAMETOOLONG => return error.NameTooLong,
            .NOENT => return error.FileNotFound,
            .NOTDIR => return error.NotDir,
            .HOSTUNREACH => return error.NetworkUnreachable,
            .NETUNREACH => return error.NetworkUnreachable,
            .NOTCONN => return error.SocketNotConnected,
            .NETDOWN => return error.NetworkSubsystemFailed,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

fn packetsOut(
    ctx: ?*anyopaque,
    specs: ?[*]const lsquic.lsquic_out_spec,
    n_specs: u32,
) callconv(.C) i32 {
    var msg: msghdr_const = undefined;
    const socket: *network.Socket = @alignCast(@ptrCast(ctx.?));

    for (specs.?[0..n_specs]) |spec| {
        msg.name = @alignCast(@ptrCast(spec.dest_sa));
        msg.namelen = @sizeOf(std.posix.sockaddr.in);
        msg.iov = @ptrCast(spec.iov.?);
        msg.iovlen = @intCast(spec.iovlen);
        msg.flags = 0;
        msg.control = null;
        msg.controllen = 0;

        const bytes_sent = sendmsgPosix(socket.internal, &msg, 0) catch |err| {
            std.debug.print("sendmsg error: {s}", .{@errorName(err)});
            return -1;
        };

        std.debug.print("sent {d} bytes\n", .{bytes_sent});
    }

    return @intCast(n_specs);
}

fn getSslCtx(
    peer_ctx: ?*anyopaque,
    _: ?*const lsquic.struct_sockaddr,
) callconv(.C) *lsquic.struct_ssl_ctx_st {
    return @ptrCast(peer_ctx.?);
}

fn tickCallback(
    maybe_ctx: ?*Context,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    errdefer |err| std.debug.panic("tickCallback failed with: {s}", .{@errorName(err)});
    try r;
    const ctx = maybe_ctx.?;

    for (ctx.conns.constSlice(), 0..) |connection, i| {
        var errbuf: [100]u8 = undefined;
        const status: Context.Connection.Status = @enumFromInt(lsquic.lsquic_conn_status(
            @ptrCast(connection.conn),
            &errbuf,
            100,
        ));

        std.debug.print("connection ({d}) status: {s}\n", .{ i, @tagName(status) });

        while (status == .CONNECTED and connection.transactions.reserve()) {
            std.debug.print(
                "creating new stream for conn: n_txns={d} n_stms={d}\n",
                .{ connection.transactions.len(), connection.transactions.reserved() },
            );
            lsquic.lsquic_conn_make_uni_stream(connection.conn, -1, &Callbacks.callbacks, ctx);
        }
    }

    lsquic.lsquic_engine_process_conns(ctx.engine);

    ctx.tick_event.run(l, c, 100, Context, ctx, tickCallback);
    return .disarm;
}

fn channelCallback(
    maybe_ctx: ?*Context,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    errdefer |err| std.debug.panic("channelCallback failed with: {s}", .{@errorName(err)});
    try r;
    const ctx = maybe_ctx.?;

    while (ctx.send_channel.receive()) |packet| {
        const conn_ctx = try ctx.getConnectionContext(packet.addr);

        // only add the transaction to the connection context if we do not already
        // have a transaction going to that address.
        for (conn_ctx.transactions.constSlice()) |txn| {
            _ = txn;
            // TODO: check for existing transactions here
        }

        std.debug.print("added transaction to connection context: address={}, bytes_size={}\n", .{
            packet.addr,
            packet.size,
        });
        try conn_ctx.transactions.push(packet);
    }

    if (ctx.exit.load(.acquire)) {
        l.stop();
    } else {
        ctx.channel_event.run(l, c, 100, Context, ctx, channelCallback);
    }

    return .disarm;
}

fn packetsCallback(
    maybe_ctx: ?*Context,
    _: *xev.Loop,
    _: *xev.Completion,
    _: *xev.UDP.State,
    peer_address: std.net.Address,
    _: xev.UDP,
    b: xev.ReadBuffer,
    r: xev.UDP.ReadError!usize,
) xev.CallbackAction {
    errdefer |err| std.debug.panic("channelCallback failed with: {s}", .{@errorName(err)});
    const bytes = try r;

    const ctx = maybe_ctx.?;

    const local_endpoint = try ctx.socket.getLocalEndPoint();
    const local_socketaddr = switch (toSocketAddress(local_endpoint)) {
        .ipv4 => |addr| addr,
        .ipv6 => @panic("add ipv6 support"),
    };

    const peer_sockaddr = peer_address.in.sa;

    if (0 > lsquic.lsquic_engine_packet_in(
        ctx.engine,
        b.slice.ptr,
        bytes,
        @ptrCast(&local_socketaddr),
        @ptrCast(&peer_sockaddr),
        ctx,
        0,
    )) {
        @panic("lsquic_engine_packet_in failed");
    }

    return .rearm;
}
// helper functions

// function is private inside of zig-network
fn toSocketAddress(self: network.EndPoint) network.EndPoint.SockAddr {
    return switch (self.address) {
        .ipv4 => |addr| .{
            .ipv4 = .{
                .family = std.posix.AF.INET,
                .port = std.mem.nativeToBig(u16, self.port),
                .addr = @bitCast(addr.value),
                .zero = [_]u8{0} ** 8,
            },
        },
        .ipv6 => |addr| .{
            .ipv6 = .{
                .family = std.posix.AF.INET6,
                .port = std.mem.nativeToBig(u16, self.port),
                .flowinfo = 0,
                .addr = addr.value,
                .scope_id = addr.scope_id,
            },
        },
    };
}
