const std = @import("std");
const xquic = @import("xquic");
const xev = @import("xev");

const XQC_INTEROP_TLS_GROUPS = "X25519:P-256:P-384:P-521";

pub const Config = extern struct {
    log_level: u32,
};

pub const Context = extern struct {
    engine: *xquic.xqc_engine_t,
    engine_event: *xev.Async,
    task_event: *xev.Async,

    // /* libevent context */
    // struct event    *ev_engine;
    // struct event    *ev_task;
    // struct event    *ev_kill;
    // struct event_base *eb;  /* handle of libevent */

    // /* log context */
    // int             log_fd;
    // char            log_path[256];

    // /* key log context */
    // int             keylog_fd;

    // /* client context */
    // xqc_demo_cli_client_args_t  *args;

    // /* task schedule context */
    // xqc_demo_cli_task_ctx_t     task_ctx;

    fn deinit(ctx: *Context) void {
        xquic.xqc_engine_destroy(ctx.engine);
    }
};

pub fn initEngine() !*xquic.xqc_engine_t {
    // specifically using the c_allocator due to engine_deinit calling free()
    const allocator = std.heap.c_allocator;
    const engine_type = xquic.XQC_ENGINE_CLIENT;

    var engine_ssl_config: xquic.xqc_engine_ssl_config_t = .{
        .ciphers = try allocator.dupeZ(u8, xquic.XQC_TLS_CIPHERS),
        .groups = try allocator.dupeZ(u8, XQC_INTEROP_TLS_GROUPS),
    };

    const engine_cbs: xquic.xqc_engine_callback_t = .{
        .set_event_timer = EngineLayerCallbacks.setEventTimer,
    };

    const transport_cbs: xquic.xqc_transport_callbacks_t = .{
        .write_socket = TransportCallbacks.writeSocket,
        .write_socket_ex = TransportCallbacks.writeSocketEx,
        .save_token = TransportCallbacks.saveToken,
        .save_session_cb = TransportCallbacks.saveSessionCb,
        .save_tp_cb = TransportCallbacks.saveTpCb,
        .conn_update_cid_notify = TransportCallbacks.connUpdateCidNotify,
        .ready_to_create_path_notify = TransportCallbacks.readyToCreatePathNotify,
        .path_removed_notify = TransportCallbacks.pathRemoved,
    };

    var config: xquic.xqc_config_t = undefined;
    if (xquic.xqc_engine_get_default_config(&config, engine_type) < 0) {
        std.debug.print("failed to get default config\n", .{});
    }
    config.cfg_log_level = xquic.XQC_LOG_DEBUG;

    return xquic.xqc_engine_create(
        engine_type,
        &config,
        &engine_ssl_config,
        &engine_cbs,
        &transport_cbs,
        null,
    ) orelse @panic("failed to init engine");
}

pub fn runClient() !void {
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var engine_event = try xev.Async.init();
    var task_event = try xev.Async.init();

    var context: Context = .{
        .engine = try initEngine(),
        .engine_event = &engine_event,
        .task_event = &task_event,
    };
    defer context.deinit();

    var engine_c: xev.Completion = undefined;
    var task_c: xev.Completion = undefined;

    std.debug.print("before\n", .{});

    engine_event.wait(&loop, &engine_c, Context, &context, engineCallback);
    task_event.wait(&loop, &task_c, Context, &context, taskScheduleCallback);

    std.debug.print("after\n", .{});
    std.debug.print("loop len: {}\n", .{loop.active});

    try loop.run(.until_done);
}

fn engineCallback(
    _: ?*Context,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = result catch unreachable;

    // std.debug.print("after!\n", .{});
    std.debug.print("engineCallback\n", .{});

    return .disarm;
}

fn taskScheduleCallback(
    _: ?*Context,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    _ = result catch unreachable;

    // std.debug.print("after!\n", .{});
    std.debug.print("taskScheduleCallback\n", .{});

    // start the next task scheduling round
    return .rearm;
}

const EngineLayerCallbacks = struct {
    fn writeLogFile(
        level: xquic.xqc_log_level_t,
        buf: ?*const anyopaque,
        size: usize,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = level;
        _ = buf;
        _ = size;
        _ = engine_user_data;
        std.debug.print("writeLogFile\n", .{});
    }

    fn writeQLogFile(
        imp: xquic.qlog_event_importance_t,
        buf: ?*const anyopaque,
        size: usize,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = imp;
        _ = buf;
        _ = size;
        _ = engine_user_data;
        std.debug.print("writeQLogFile\n", .{});
    }

    fn keyLogCb(
        scid: ?*const xquic.xqc_cid_t,
        line: ?[*]const u8,
        engine_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = scid;
        _ = line;
        _ = engine_user_data;
        std.debug.print("keyLogCb\n", .{});
    }

    fn setEventTimer(wake_after: xquic.xqc_usec_t, engine_user_data: ?*anyopaque) callconv(.C) void {
        _ = wake_after;
        _ = engine_user_data;
        std.debug.print("setEventTimer\n", .{});
    }
};

const AlpnCallbacks = struct {};

const TransportCallbacks = struct {
    fn writeSocket(
        buf: ?[*]const u8,
        size: usize,
        peer_address: ?*const xquic.struct_sockaddr,
        addr_len: std.c.socklen_t,
        user_data: ?*anyopaque,
    ) callconv(.C) isize {
        std.debug.print("writeSocket\n", .{});
        return writeSocketEx(
            0,
            buf,
            size,
            peer_address,
            addr_len,
            user_data,
        );
    }
    fn writeSocketEx(
        path_id: u64,
        buf: ?[*]const u8,
        size: usize,
        peer_address: ?*const xquic.struct_sockaddr,
        addr_len: std.c.socklen_t,
        user_data: ?*anyopaque,
    ) callconv(.C) isize {
        std.debug.print("writeSocketEx\n", .{});
        _ = path_id;
        _ = buf;
        _ = size;
        _ = peer_address;
        _ = addr_len;
        _ = user_data;
        return -1;
    }
    fn saveToken(
        token: ?[*]const u8,
        token_len: u32,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = token;
        _ = token_len;
        _ = user_data;
        std.debug.print("saveToken\n", .{});
    }
    fn saveSessionCb(
        data: ?[*]const u8,
        data_len: usize,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = data;
        _ = data_len;
        _ = user_data;
        std.debug.print("saveSessionCb\n", .{});
    }
    fn saveTpCb(
        data: ?[*]const u8,
        data_len: usize,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = data;
        _ = data_len;
        _ = user_data;
        std.debug.print("saveSessionCb\n", .{});
    }
    fn connUpdateCidNotify(
        conn: ?*xquic.xqc_connection_t,
        retire_cid: ?*const xquic.xqc_cid_t,
        new_cid: ?*const xquic.xqc_cid_t,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = conn;
        _ = retire_cid;
        _ = new_cid;
        _ = user_data;
        std.debug.print("connUpdateCidNotify\n", .{});
    }
    fn readyToCreatePathNotify(
        cid: ?*const xquic.xqc_cid_t,
        conn_user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = cid;
        _ = conn_user_data;
        std.debug.print("connCreatePath\n", .{});
    }
    fn pathRemoved(
        scid: ?*const xquic.xqc_cid_t,
        path_id: u64,
        user_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = scid;
        _ = path_id;
        _ = user_data;
        std.debug.print("pathRemoved\n", .{});
    }
};
