const lsquic = @import("lsquic");
const std = @import("std");
const network = @import("zig-network");
const xev = @import("xev");
const ssl = @import("ssl");
const sig = @import("../../sig.zig");
const send_posix = @import("send_posix.zig");

const Packet = sig.net.Packet;
const Channel = sig.sync.Channel;
const AtomicBool = std.atomic.Value(bool);
const Logger = sig.trace.log.Logger;
const ChannelPrintLogger = sig.trace.log.ChannelPrintLogger;

pub fn runClient(
    allocator: std.mem.Allocator,
    receiver: *Channel(Packet),
    exit: *AtomicBool,
    logger: Logger,
) !void {
    if (lsquic.lsquic_global_init(
        lsquic.LSQUIC_GLOBAL_CLIENT,
    ) == 1) @panic("lsquic_global_init failed");
    var client: Client(20, 20) = undefined;
    try client.init(allocator, receiver, exit, logger);
    try client.run();
}

pub fn runTestClient() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    const gpa_allocator = gpa_state.allocator();
    // defer _ = gpa_state.deinit();

    var send_channel = try sig.sync.Channel(sig.net.Packet).init(gpa_allocator);
    defer send_channel.deinit();

    const test_address = try network.EndPoint.parse("127.0.0.1:1033");
    var test_packet: Packet = .{
        .addr = test_address,
        .data = .{0xaa} ** sig.net.PACKET_DATA_SIZE,
        .size = 30,
    };

    const logger = (try ChannelPrintLogger.init(.{
        .allocator = gpa_allocator,
        .max_level = .debug,
        .max_buffer = 1 << 20,
    })).logger();

    var exit = AtomicBool.init(false);
    var client_handle = try std.Thread.spawn(
        .{},
        runClient,
        .{
            gpa_allocator,
            &send_channel,
            &exit,
            logger,
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

pub fn Client(comptime max_connections: usize, comptime max_streams_per_connection: usize) type {
    return struct {
        allocator: std.mem.Allocator,
        receiver: *Channel(Packet),
        socket: network.Socket,
        connections: std.BoundedArray(*Connection, max_connections),
        exit: *AtomicBool,
        logger: Logger,

        // SSL
        ssl_ctx: *ssl.SSL_CTX,

        // XEV
        packets_in_event: xev.UDP,
        tick_event: xev.Timer,

        // LSQUIC
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

        pub fn init(
            self: *Self,
            allocator: std.mem.Allocator,
            receiver: *Channel(Packet),
            exit: *AtomicBool,
            logger: Logger,
        ) !void {
            self.* = .{
                .allocator = allocator,
                .receiver = receiver,
                .socket = try network.Socket.create(.ipv4, .udp),
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
                .packets_in_event = xev.UDP.initFd(self.socket.internal),
                .tick_event = try xev.Timer.init(),
            };

            try self.socket.bind(.{
                .address = .{ .ipv4 = network.Address.IPv4.any },
                .port = 4444,
            });

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

        fn onTick(
            maybe_self: ?*Self,
            xev_loop: *xev.Loop,
            xev_completion: *xev.Completion,
            xev_timer_error: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            errdefer |err| std.debug.panic("onTick failed with: {s}", .{@errorName(err)});
            try xev_timer_error;

            const self = maybe_self.?;

            while (self.receiver.receive()) |packet| {
                const connection = try self.getConnection(packet.addr);
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

            if (self.exit.load(.acquire)) {
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
            xev_read_error: xev.UDP.ReadError!usize,
        ) xev.CallbackAction {
            errdefer |err| std.debug.panic("onPacketsIn failed with: {s}", .{@errorName(err)});
            const bytes = try xev_read_error;

            const self = maybe_self.?;

            const local_endpoint = try self.socket.getLocalEndPoint();
            const local_socketaddr = switch (toSocketAddress(local_endpoint)) {
                .ipv4 => |addr| addr,
                .ipv6 => @panic("add ipv6 support"),
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
            peer_endpoint: network.EndPoint,
        ) !*Connection {
            for (self.connections.constSlice()) |connection| {
                if (connection.endpoint.address.eql(peer_endpoint.address) and
                    connection.endpoint.port == peer_endpoint.port)
                    return connection;
            }

            const connection = try self.allocator.create(Connection);
            connection.* = .{
                .lsquic_connection = undefined,
                .client = self,
                .endpoint = peer_endpoint,
                .packets = .{},
            };

            const local_endpoint = try self.socket.getLocalEndPoint();
            const local_socketaddr = switch (toSocketAddress(local_endpoint)) {
                .ipv4 => |addr| addr,
                .ipv6 => @panic("add ipv6 support"),
            };

            const peer_socketaddr = switch (toSocketAddress(peer_endpoint)) {
                .ipv4 => |addr| addr,
                .ipv6 => @panic("add ipv6 support"),
            };

            if (lsquic.lsquic_engine_connect(
                self.lsquic_engine,
                lsquic.N_LSQVER,
                @ptrCast(&local_socketaddr),
                @ptrCast(&peer_socketaddr),
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
            endpoint: network.EndPoint,
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
            ) callconv(.C) *lsquic.lsquic_conn_ctx_t {
                const conn_ctx = lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection).?;
                const self: *Connection = @alignCast(@ptrCast(conn_ctx));

                self.client.logger.debug().logf("onNewConn: {s}", .{self.endpoint});
                self.lsquic_connection = maybe_lsquic_connection.?;
                self.client.connections.append(self) catch @panic("reached max connections");

                return @ptrCast(self);
            }

            fn onConnClosed(maybe_lsquic_connection: ?*lsquic.lsquic_conn_t) callconv(.C) void {
                const conn_ctx = lsquic.lsquic_conn_get_ctx(maybe_lsquic_connection).?;
                const conn: *Connection = @alignCast(@ptrCast(conn_ctx));

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
            ) callconv(.C) *lsquic.lsquic_stream_ctx_t {
                const lsquic_connection = lsquic.lsquic_stream_conn(maybe_lsquic_stream);
                const conn_ctx = lsquic.lsquic_conn_get_ctx(lsquic_connection).?;
                const connection: *Connection = @alignCast(@ptrCast(conn_ctx));

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
            ) callconv(.C) void {
                @panic("uni-directional streams should never receive data");
            }

            fn onWrite(
                maybe_lsquic_stream: ?*lsquic.lsquic_stream_t,
                maybe_stream: ?*lsquic.lsquic_stream_ctx_t,
            ) callconv(.C) void {
                const stream: *Stream = @alignCast(@ptrCast(maybe_stream.?));

                if (stream.packet.size != lsquic.lsquic_stream_write(
                    maybe_lsquic_stream,
                    &stream.packet.data,
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
            ) callconv(.C) void {
                const stream: *Stream = @alignCast(@ptrCast(maybe_stream.?));
                stream.connection.client.allocator.destroy(stream);
            }
        };
    };
}

fn getSslContext(
    peer_ctx: ?*anyopaque,
    _: ?*const lsquic.struct_sockaddr,
) callconv(.C) *lsquic.struct_ssl_ctx_st {
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

    const pkey = ssl.EVP_PKEY_new_raw_private_key(
        ssl.EVP_PKEY_ED25519,
        null,
        &private_key,
        32,
    ) orelse {
        @panic("EVP_PKEY_new_raw_private_key failed");
    };

    const bio: *ssl.BIO = ssl.BIO_new_mem_buf(&cert_der, 249);
    const cert = ssl.d2i_X509_bio(bio, null) orelse @panic("d2i_X509_bio failed");
    _ = ssl.BIO_free(bio);

    return .{ pkey, cert };
}

fn packetsOut(
    ctx: ?*anyopaque,
    specs: ?[*]const lsquic.lsquic_out_spec,
    n_specs: u32,
) callconv(.C) i32 {
    var msg: send_posix.msghdr_const = undefined;
    const socket: *network.Socket = @alignCast(@ptrCast(ctx.?));

    for (specs.?[0..n_specs]) |spec| {
        msg.name = @alignCast(@ptrCast(spec.dest_sa));
        msg.namelen = @sizeOf(std.posix.sockaddr.in);
        msg.iov = @ptrCast(spec.iov.?);
        msg.iovlen = @intCast(spec.iovlen);
        msg.flags = 0;
        msg.control = null;
        msg.controllen = 0;
        _ = send_posix.sendmsgPosix(socket.internal, &msg, 0) catch |err| {
            std.debug.panic("sendmsgPosix failed with: {s}", .{@errorName(err)});
        };
    }

    return @intCast(n_specs);
}

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
