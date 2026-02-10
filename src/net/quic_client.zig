const lsquic = @import("lsquic");
const std = @import("std");
const std14 = @import("std14");
const xev = @import("xev");
const ssl = @import("ssl");
const sig = @import("../sig.zig");

const Packet = sig.net.Packet;
const Channel = sig.sync.Channel;
const AtomicBool = std.atomic.Value(bool);
const ExitCondition = sig.sync.ExitCondition;

pub const Logger = sig.trace.Logger("quic_client");

pub fn runClient(
    allocator: std.mem.Allocator,
    receiver: *Channel(Packet),
    logger: Logger,
    exit: ExitCondition,
) !void {
    var client = try Client(20, 20).create(allocator, receiver, logger, exit);
    defer {
        client.deinit();
        allocator.destroy(client);
    }
    try client.run();
}

pub fn Client(
    comptime max_connections: usize,
    comptime max_streams_per_connection: usize,
) type {
    return struct {
        allocator: std.mem.Allocator,
        receiver: *Channel(Packet),
        socket: sig.net.UdpSocket,
        connections: std14.BoundedArray(*Connection, max_connections),
        exit: ExitCondition,
        logger: Logger,

        ssl_ctx: *ssl.SSL_CTX,

        packets_in_event: xev.UDP,
        tick_event: xev.Timer,

        lsquic_engine: *lsquic.lsquic_engine,
        lsquic_engine_api: lsquic.lsquic_engine_api,
        lsquic_engine_settings: lsquic.lsquic_engine_settings,
        lsquic_stream_iterface: lsquic.lsquic_stream_if = .{
            // Mandatory callbacks
            .on_new_conn = Connection.onNewConn,
            .on_conn_closed = Connection.onConnClosed,
            .on_new_stream = Stream.onNewStream,
            .on_read = Stream.onRead,
            .on_write = Stream.onWrite,
            .on_close = Stream.onClose,
            // Optional callbacks
            // .on_goaway_received = Connection.onGoawayReceived,
            // .on_dg_write = onDbWrite,
            // .on_datagram = onDatagram,
            // .on_hsk_done = Connection.onHskDone,
            // .on_new_token = onNewToken,
            // .on_sess_resume_info = onSessResumeInfo,
            // .on_reset = onReset,
            // .on_conncloseframe_received = Connection.onConnCloseFrameReceived,
        },

        const Self = @This();

        pub fn create(
            allocator: std.mem.Allocator,
            receiver: *Channel(Packet),
            logger: Logger,
            exit: ExitCondition,
        ) !*Self {
            const self = try allocator.create(Self);
            try self.init(allocator, receiver, logger, exit);
            return self;
        }

        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            receiver: *Channel(Packet),
            logger: Logger,
            exit: ExitCondition,
        ) !void {
            if (lsquic.lsquic_global_init(
                lsquic.LSQUIC_GLOBAL_CLIENT,
            ) == 1) @panic("lsquic_global_init failed");

            self.* = .{
                .allocator = allocator,
                .receiver = receiver,
                .socket = try .create(.ipv4),
                .connections = .{},
                .exit = exit,
                .logger = logger,
                .ssl_ctx = initSslContext(),
                .lsquic_engine = undefined,
                .lsquic_engine_api = .{
                    .ea_alpn = "solana-tpu",
                    .ea_settings = &self.lsquic_engine_settings,
                    .ea_stream_if = &self.lsquic_stream_iterface,
                    .ea_stream_if_ctx = self,
                    .ea_packets_out = &packetsOut,
                    .ea_packets_out_ctx = &self.socket,
                    .ea_get_ssl_ctx = &getSslContext,
                },
                .lsquic_engine_settings = .{},
                .packets_in_event = xev.UDP.initFd(self.socket.handle),
                .tick_event = try xev.Timer.init(),
            };

            try self.socket.bind(.initIp4(.{ 0, 0, 0, 0 }, 4444));

            lsquic.lsquic_engine_init_settings(&self.lsquic_engine_settings, 0);

            self.lsquic_engine = lsquic.lsquic_engine_new(0, &self.lsquic_engine_api) orelse {
                @panic("lsquic_engine_new failed");
            };

            var err_buf: [100]u8 = undefined;
            if (lsquic.lsquic_engine_check_settings(
                self.lsquic_engine_api.ea_settings,
                0,
                &err_buf,
                100,
            ) == 1) {
                @panic("lsquic_engine_check_settings failed " ++ err_buf);
            }
        }

        pub fn run(self: *Self) !void {
            var loop = try xev.Loop.init(.{});
            defer loop.deinit();

            var tick_complete: xev.Completion = undefined;
            self.tick_event.run(&loop, &tick_complete, 500, Self, self, onTick);

            var packets_in_complete: xev.Completion = undefined;
            // 1500 is the interface's MTU, so we'll never receive more bytes than that
            // from UDP.
            const read_buffer = try self.allocator.alloc(u8, 1500);
            defer self.allocator.free(read_buffer);
            var state: xev.UDP.State = undefined;
            self.packets_in_event.read(
                &loop,
                &packets_in_complete,
                &state,
                .{ .slice = read_buffer },
                Self,
                self,
                onPacketsIn,
            );

            try loop.run(.until_done);
        }

        fn deinit(self: *Self) void {
            _ = self;
            lsquic.lsquic_global_cleanup();
        }

        fn onTick(
            maybe_self: ?*Self,
            xev_loop: *xev.Loop,
            xev_completion: *xev.Completion,
            xev_timer_error: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            errdefer |err| std.debug.panic("onTick failed with: {s}", .{@errorName(err)});
            try xev_timer_error;

            const self = maybe_self.?;

            while (self.receiver.tryReceive()) |packet| {
                const connection = try self.getConnection(packet.addr.toAddress());
                try connection.packets.push(packet);
            }

            for (self.connections.constSlice()) |connection| {
                if (connection.getStatus() != .CONNECTED) continue;
                while (connection.packets.reserve()) {
                    lsquic.lsquic_conn_make_uni_stream(
                        connection.lsquic_connection,
                        -1,
                        self.lsquic_engine_api.ea_stream_if,
                        self.lsquic_engine_api.ea_stream_if_ctx,
                    );
                }
            }

            lsquic.lsquic_engine_process_conns(self.lsquic_engine);
            self.tick_event.run(xev_loop, xev_completion, 100, Self, self, onTick);

            if (self.exit.shouldExit()) {
                xev_loop.stop();
            }

            return .disarm;
        }

        fn onPacketsIn(
            maybe_self: ?*Self,
            _: *xev.Loop,
            _: *xev.Completion,
            _: *xev.UDP.State,
            peer_address: std.net.Address,
            _: xev.UDP,
            xev_read_buffer: xev.ReadBuffer,
            xev_read_error: xev.ReadError!usize,
        ) xev.CallbackAction {
            errdefer |err| std.debug.panic("onPacketsIn failed with: {s}", .{@errorName(err)});
            const bytes = try xev_read_error;

            const self = maybe_self.?;

            const local_endpoint = try self.socket.getLocalEndPoint();
            const local_socketaddr = switch (toSocketAddress(local_endpoint)) {
                .V4 => |addr| addr,
                .V6 => @panic("add ipv6 support"),
            };

            const peer_sockaddr = peer_address.in.sa;

            if (0 > lsquic.lsquic_engine_packet_in(
                self.lsquic_engine,
                xev_read_buffer.slice.ptr,
                bytes,
                @ptrCast(&local_socketaddr),
                @ptrCast(&peer_sockaddr),
                self,
                0,
            )) {
                @panic("lsquic_engine_packet_in failed");
            }

            return .rearm;
        }

        // TODO: add connection eviction
        fn getConnection(
            self: *Self,
            peer_endpoint: std.net.Address,
        ) !*Connection {
            for (self.connections.constSlice()) |connection| {
                if (connection.endpoint.eql(peer_endpoint)) return connection;
            }

            const connection = try self.allocator.create(Connection);
            connection.* = .{
                .lsquic_connection = undefined,
                .client = self,
                .endpoint = peer_endpoint,
                .packets = .{},
            };

            const local_endpoint = try self.socket.getLocalEndPoint();

            if (lsquic.lsquic_engine_connect(
                self.lsquic_engine,
                lsquic.N_LSQVER,
                @ptrCast(&local_endpoint.any),
                @ptrCast(&peer_endpoint.any),
                self.ssl_ctx,
                @ptrCast(connection),
                null,
                0,
                null,
                0,
                null,
                0,
            ) == null) {
                @panic("lsquic_engine_connect failed");
            }

            return connection;
        }

        const Connection = struct {
            lsquic_connection: *lsquic.lsquic_conn_t,
            client: *Self,
            endpoint: std.net.Address,
            packets: PacketBuffer,

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

            const HandshakeStatus = enum(c_uint) {
                FAIL,
                OK,
                RESUMED_OK,
                RESUMED_FAIL,
            };

            const PacketBuffer = struct {
                pkts: [max_streams_per_connection]Packet = undefined,
                head: usize = 0, // Points to the first index of the next transaction to pop
                resv: usize = 0, // Points to the first index of the next transaction to reserve
                tail: usize = 0, // Points to the first index of the next transaction to push

                pub fn reserve(self: *PacketBuffer) bool {
                    if (self.resv == self.tail) {
                        return false;
                    } else {
                        self.resv = (self.resv + 1) % self.pkts.len;
                        return true;
                    }
                }

                pub fn pop(self: *PacketBuffer) !Packet {
                    if (self.head == self.resv) {
                        return error.NoMoreReservations;
                    }

                    const txn = self.pkts[self.head];
                    self.head = (self.head + 1) % self.pkts.len;

                    return txn;
                }

                pub fn push(self: *PacketBuffer, txn: Packet) !void {
                    if ((self.tail + 1) % self.pkts.len == self.head) {
                        return error.TxnBufferFull;
                    }

                    self.pkts[self.tail] = txn;
                    self.tail = (self.tail + 1) % self.pkts.len;
                }

                pub fn len(self: *PacketBuffer) usize {
                    if (self.tail >= self.head) {
                        return self.tail - self.head;
                    } else {
                        return self.pkts.len - self.head + self.tail;
                    }
                }

                pub fn reserved(self: *PacketBuffer) usize {
                    if (self.resv >= self.head) {
                        return self.resv - self.head;
                    } else {
                        return self.pkts.len - self.head + self.resv;
                    }
                }

                pub fn slice(self: *PacketBuffer) []Packet {
                    return self.pkts[self.head..self.tail];
                }
            };

            fn getStatus(self: *Connection) Status {
                var errbuf: [100]u8 = undefined;
                return @enumFromInt(lsquic.lsquic_conn_status(
                    @ptrCast(self.lsquic_connection),
                    &errbuf,
                    100,
                ));
            }

            fn onNewConn(
                _: ?*anyopaque,
                maybe_lsquic_connection: ?*lsquic.lsquic_conn_t,
            ) callconv(.c) *lsquic.lsquic_conn_ctx_t {
                const conn_ctx = lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection).?;
                const self: *Connection = @ptrCast(@alignCast(conn_ctx));

                self.client.logger.debug().logf("onNewConn: {}", .{self.endpoint});
                self.lsquic_connection = maybe_lsquic_connection.?;
                self.client.connections.append(self) catch @panic("reached max connections");

                return @ptrCast(self);
            }

            fn onConnClosed(maybe_lsquic_connection: ?*lsquic.lsquic_conn_t) callconv(.c) void {
                const conn_ctx = lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection).?;
                const conn: *Connection = @ptrCast(@alignCast(conn_ctx));

                for (conn.client.connections.constSlice(), 0..) |connection, i| {
                    if (@intFromPtr(connection) == @intFromPtr(conn)) {
                        _ = conn.client.connections.swapRemove(i);
                    }
                }

                lsquic.lsquic_conn_set_ctx(maybe_lsquic_connection, null);
                conn.client.allocator.destroy(conn);
            }
        };

        const Stream = struct {
            lsquic_stream: *lsquic.lsquic_stream_t,
            connection: *Connection,
            packet: Packet,

            fn onNewStream(
                _: ?*anyopaque,
                maybe_lsquic_stream: ?*lsquic.lsquic_stream_t,
            ) callconv(.c) *lsquic.lsquic_stream_ctx_t {
                const lsquic_connection = lsquic.lsquic_stream_conn(maybe_lsquic_stream);
                const conn_ctx = lsquic.lsquic_conn_get_ctx(lsquic_connection).?;
                const connection: *Connection = @ptrCast(@alignCast(conn_ctx));

                const stream = connection.client.allocator.create(Stream) catch
                    @panic("OutOfMemory");
                stream.* = .{
                    .lsquic_stream = maybe_lsquic_stream.?,
                    .connection = connection,
                    .packet = connection.packets.pop() catch @panic("new stream without packet"),
                };

                _ = lsquic.lsquic_stream_wantwrite(maybe_lsquic_stream, 1);
                return @ptrCast(stream);
            }

            fn onRead(
                _: ?*lsquic.lsquic_stream_t,
                _: ?*lsquic.lsquic_stream_ctx_t,
            ) callconv(.c) void {
                @panic("uni-directional streams should never receive data");
            }

            fn onWrite(
                maybe_lsquic_stream: ?*lsquic.lsquic_stream_t,
                maybe_stream: ?*lsquic.lsquic_stream_ctx_t,
            ) callconv(.c) void {
                const stream: *Stream = @ptrCast(@alignCast(maybe_stream.?));

                if (stream.packet.size != lsquic.lsquic_stream_write(
                    maybe_lsquic_stream,
                    &stream.packet.buffer,
                    stream.packet.size,
                )) {
                    @panic("failed to write complete packet to stream");
                }

                _ = lsquic.lsquic_stream_flush(maybe_lsquic_stream);
                _ = lsquic.lsquic_stream_wantwrite(maybe_lsquic_stream, 0);
                _ = lsquic.lsquic_stream_close(maybe_lsquic_stream);
            }

            fn onClose(
                _: ?*lsquic.lsquic_stream_t,
                maybe_stream: ?*lsquic.lsquic_stream_ctx_t,
            ) callconv(.c) void {
                const stream: *Stream = @ptrCast(@alignCast(maybe_stream.?));
                stream.connection.client.allocator.destroy(stream);
            }
        };
    };
}

fn getSslContext(
    peer_ctx: ?*anyopaque,
    _: ?*const lsquic.struct_sockaddr,
) callconv(.c) *lsquic.struct_ssl_ctx_st {
    return @ptrCast(peer_ctx.?);
}

fn initSslContext() *ssl.SSL_CTX {
    const ssl_ctx = ssl.SSL_CTX_new(ssl.TLS_method()) orelse
        @panic("SSL_CTX_new failed");

    if (ssl.SSL_CTX_set_min_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0)
        @panic("SSL_CTX_set_min_proto_version failed");

    if (ssl.SSL_CTX_set_max_proto_version(ssl_ctx, ssl.TLS1_3_VERSION) == 0)
        @panic("SSL_CTX_set_max_proto_version failed\n");

    const signature_algs: []const u16 = &.{ssl.SSL_SIGN_ED25519};
    if (ssl.SSL_CTX_set_verify_algorithm_prefs(ssl_ctx, signature_algs.ptr, 1) == 0)
        @panic("SSL_CTX_set_verify_algorithm_prefs failed\n");

    const pubkey, const cert = initX509Certificate();
    if (ssl.SSL_CTX_use_PrivateKey(ssl_ctx, pubkey) == 0) {
        @panic("SSL_CTX_use_PrivateKey failed");
    }

    if (ssl.SSL_CTX_use_certificate(ssl_ctx, cert) == 0) {
        @panic("SSL_CTX_use_certificate failed");
    }

    return ssl_ctx;
}

fn initX509Certificate() struct { *ssl.EVP_PKEY, *ssl.X509 } {
    const pctx = ssl.EVP_PKEY_CTX_new_id(ssl.EVP_PKEY_ED25519, null) orelse {
        @panic("EVP_PKEY_CTX_new_id failed");
    };
    if (ssl.EVP_PKEY_keygen_init(pctx) == 0) {
        @panic("EVP_PKEY_keygen_init failed");
    }
    var maybe_pkey: ?*ssl.EVP_PKEY = null;
    if (ssl.EVP_PKEY_keygen(pctx, &maybe_pkey) == 0) {
        @panic("EVP_PKEY_keygen failed");
    }
    const pkey = maybe_pkey orelse @panic("EVP_PKEY_keygen failed");

    const cert = ssl.X509_new() orelse {
        @panic("X509_new failed");
    };

    if (ssl.X509_set_version(cert, ssl.X509_VERSION_3) == 0) {
        @panic("EVP_PKEY_keygen failed");
    }

    const serial = ssl.ASN1_INTEGER_new() orelse {
        @panic("ASN1_INTEGER_new failed");
    };
    defer ssl.ASN1_INTEGER_free(serial);
    if (ssl.ASN1_INTEGER_set(serial, 1) == 0) {
        @panic("ASN1_INTEGER_set failed");
    }
    if (ssl.X509_set_serialNumber(cert, serial) == 0) {
        @panic("X509_set_serialNumber failed");
    }

    const issuer = ssl.X509_get_issuer_name(cert) orelse {
        @panic("X509_get_issuer_name failed");
    };
    if (ssl.X509_NAME_add_entry_by_txt(
        issuer,
        "CN",
        ssl.MBSTRING_ASC,
        "Solana",
        -1,
        -1,
        0,
    ) == 0) {
        @panic("X509_NAME_add_entry_by_txt failed");
    }

    if (ssl.X509_gmtime_adj(ssl.X509_get_notBefore(cert), 0) == null) {
        @panic("X509_gmtime_adj failed");
    }
    // I sure hope 1000 years is enough :P
    if (ssl.X509_gmtime_adj(ssl.X509_get_notAfter(cert), 60 * 60 * 24 * 365 * 1000) == null) {
        @panic("X509_gmtime_adj failed");
    }

    if (ssl.X509_set_subject_name(cert, issuer) == 0) {
        @panic("X509_set_subject_name failed");
    }

    if (ssl.X509_set_pubkey(cert, pkey) == 0) {
        @panic("X509_set_pubkey failed");
    }

    if (ssl.X509_sign(cert, pkey, null) == 0) {
        @panic("X509_sign failed");
    }

    return .{ pkey, cert };
}

fn packetsOut(
    ctx: ?*anyopaque,
    specs: ?[*]const lsquic.lsquic_out_spec,
    n_specs: u32,
) callconv(.c) i32 {
    var msg: std.posix.msghdr_const = undefined;
    const socket: *sig.net.UdpSocket = @ptrCast(@alignCast(ctx.?));

    for (specs.?[0..n_specs]) |spec| {
        msg.name = @ptrCast(@alignCast(spec.dest_sa));
        msg.namelen = @sizeOf(std.posix.sockaddr.in);
        msg.iov = @ptrCast(spec.iov.?);
        msg.iovlen = @intCast(spec.iovlen);
        msg.flags = 0;
        msg.control = null;
        msg.controllen = 0;
        _ = std.posix.sendmsg(socket.handle, &msg, 0) catch |err| {
            std.debug.panic("sendmsgPosix failed with: {s}", .{@errorName(err)});
        };
    }

    return @intCast(n_specs);
}

fn toSocketAddress(address: std.net.Address) sig.net.SocketAddr {
    return .initAddress(address);
}
