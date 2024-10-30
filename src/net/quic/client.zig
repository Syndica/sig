const std = @import("std");
const lsquic = @import("lsquic");
const xev = @import("xev");
const ssl = @import("ssl");
const network = @import("zig-network");
const sig = @import("../../sig.zig");

pub const Context = struct {
    engine: *lsquic.lsquic_engine,
    settings: lsquic.lsquic_engine_settings,
    api: lsquic.lsquic_engine_api,

    socket: network.Socket,

    ssl_ctx: *ssl.SSL_CTX,

    // events for managing the event loop
    packets_event: *xev.Async,
    channel_event: *xev.Timer,
    tick_event: *xev.Timer,

    fn init(
        ctx: *Context,
        packets_event: *xev.Async,
        channel_event: *xev.Timer,
        tick_event: *xev.Timer,
    ) !void {
        ctx.* = .{
            .packets_event = packets_event,
            .channel_event = channel_event,
            .tick_event = tick_event,
            .settings = .{},
            .api = .{
                .ea_alpn = "solana-tpu",
                .ea_settings = &ctx.settings,
                .ea_stream_if = &callbacks,
                .ea_stream_if_ctx = ctx,
                .ea_packets_out = packets_out,
                .ea_packets_out_ctx = null,
                .ea_get_ssl_ctx = get_ssl_ctx,
            },
            .engine = undefined,
            .ssl_ctx = initSSL(),
            .socket = undefined,
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

        var socket = try network.Socket.create(.ipv4, .udp);
        try socket.bind(.{ .address = try network.Address.parse("127.0.0.1"), .port = 4444 });
        ctx.socket = socket;
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

    fn deinit(ctx: *Context) void {
        ctx.socket.close();
    }
};

const callbacks: lsquic.lsquic_stream_if = .{
    .on_new_conn = null,
    .on_goaway_received = null,
    .on_conn_closed = null,
    .on_new_stream = null,
    .on_read = null,
    .on_write = null,
    .on_close = null,
    .on_dg_write = null,
    .on_datagram = null,
    .on_hsk_done = null,
    .on_new_token = null,
    .on_sess_resume_info = null,
    .on_reset = null,
    .on_conncloseframe_received = null,
};

fn packets_out(
    ctx: ?*anyopaque,
    specs: ?[*]const lsquic.lsquic_out_spec,
    n_specs: u32,
) callconv(.C) c_int {
    _ = ctx;
    _ = specs;
    _ = n_specs;

    return -1;
}

fn get_ssl_ctx(
    peer_ctx: ?*anyopaque,
    _: ?*const lsquic.struct_sockaddr,
) callconv(.C) *lsquic.struct_ssl_ctx_st {
    return @ptrCast(peer_ctx.?);
}

pub fn runClient() !void {
    // setup the global state
    if (lsquic.lsquic_global_init(lsquic.LSQUIC_GLOBAL_CLIENT) == 1) {
        @panic("lsquic_global_init failed");
    }

    var tick_event = try xev.Timer.init();
    var channel_event = try xev.Timer.init();
    var packets_event = try xev.Async.init();

    // setup our sol context
    var ctx: Context = undefined;
    try ctx.init(&packets_event, &channel_event, &tick_event);

    // Setup the event loop.
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var tick_complete: xev.Completion = undefined;
    var channel_complete: xev.Completion = undefined;

    tick_event.run(&loop, &tick_complete, 500, xev.Timer, &tick_event, tickCallback);
    channel_event.run(&loop, &channel_complete, 500, xev.Timer, &channel_event, channelCallback);

    // Run the loop!
    try loop.run(.until_done);
}

fn tickCallback(
    event: ?*xev.Timer,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    r catch @panic("failed");

    std.debug.print("tick event\n", .{});

    // TODO: uhhh, use event.reset instead. this is not correct.
    event.?.run(l, c, 500, xev.Timer, event, tickCallback);
    return .disarm;
}

fn channelCallback(
    event: ?*xev.Timer,
    l: *xev.Loop,
    c: *xev.Completion,
    r: xev.Timer.RunError!void,
) xev.CallbackAction {
    r catch @panic("failed");

    event.?.run(l, c, 500, xev.Timer, event, channelCallback);
    return .disarm;
}
