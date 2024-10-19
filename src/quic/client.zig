const std = @import("std");
const xquic = @import("xquic");
const xev = @import("xev");
const sig = @import("../sig.zig");

const ConnectionCallbacks = sig.quic.ConnectionCallbacks;
const SolCallbacks = sig.quic.SolCallbacks;
const EngineCallbacks = sig.quic.EngineCallbacks;
const TransportCallbacks = sig.quic.TransportCallbacks;

const XQC_INTEROP_TLS_GROUPS = "X25519:P-256:P-384:P-521";

pub const Args = struct {
    log_level: u32 = xquic.XQC_LOG_DEBUG,
};

pub const Context = struct {
    // underlying xquic engine
    engine: *xquic.xqc_engine_t,

    // events for managing the event loop
    engine_event: *xev.Async,
    task_event: *xev.Async,

    // task scheduling
    mode: TaskMode,
    tasks: TaskContext,

    const TaskMode = enum {
        // send multi requests in single connection with multi streams
        scmr,
        // serially send multi requests in multi connections, with one request each connection
        scsr_serial,
        // concurrently send multi requests in multi connections, with one request each connection
        scsr_concurrent,
    };

    const TaskContext = struct {
        /// Numbers of "connections". Tasks can be thought of as connections.
        count: usize,
        tasks: []const Task,
    };

    const Task = struct {
        connection: Connection,
        requests: []const Request,

        const Request = struct {};
    };

    const Connection = struct {};

    fn initTasks(ctx: *Context, allocator: std.mem.Allocator) !void {
        _ = ctx;
        _ = allocator;
    }

    fn deinit(ctx: *const Context) void {
        xquic.xqc_engine_destroy(ctx.engine);
    }
};

const SolContext = struct {
    sol_cbs: SolCallbacks,
};

pub fn registerCallbacks(engine: *xquic.xqc_engine_t) !void {
    // https://github.com/alibaba/xquic/blob/main/include/xquic/xquic.h#L816
    var app_proto_cbs: xquic.xqc_app_proto_callbacks_t = .{
        // https://github.com/alibaba/xquic/blob/main/include/xquic/xquic.h#L698
        .conn_cbs = .{
            .conn_create_notify = ConnectionCallbacks.connCreateNotify,
            .conn_close_notify = ConnectionCallbacks.connCloseNotify,
            .conn_handshake_finished = ConnectionCallbacks.connHandshakeFinished,
            .conn_ping_acked = ConnectionCallbacks.connPingAcked,
        },
    };

    // Create our custom callbacks context
    // This is a ... api
    const sol_ctx = try std.heap.c_allocator.create(SolContext);
    sol_ctx.* = SolContext{
        .sol_cbs = .{
            //     .hqc_cbs = {
            //         .conn_create_notify = xqc_demo_cli_hq_conn_create_notify,
            //         .conn_close_notify = xqc_demo_cli_hq_conn_close_notify,
            //     },
            //     .hqr_cbs = {
            //         .req_close_notify = xqc_demo_cli_hq_req_close_notify,
            //         .req_read_notify = xqc_demo_cli_hq_req_read_notify,
            //         .req_write_notify = xqc_demo_cli_hq_req_write_notify,
            //     }
        },
    };

    if (xquic.xqc_engine_register_alpn(
        engine,
        "sol-interop".ptr,
        "sol-interop".len,
        &app_proto_cbs,
        sol_ctx,
    ) != xquic.XQC_OK) return error.EngineRegisterAlpnFailed;
}

pub fn initEngine(args: *const Args) !*xquic.xqc_engine_t {
    // specifically using the c_allocator due to engine_deinit calling free()
    const allocator = std.heap.c_allocator;

    // Engine type: either client or server
    const engine_type = xquic.XQC_ENGINE_CLIENT;

    // SSL configuration: copies from xquic/demo/demo_client.c
    var engine_ssl_config: xquic.xqc_engine_ssl_config_t = .{
        .ciphers = try allocator.dupeZ(u8, xquic.XQC_TLS_CIPHERS),
        .groups = try allocator.dupeZ(u8, XQC_INTEROP_TLS_GROUPS),
    };

    // Engine callbacks: see docs
    const engine_cbs: xquic.xqc_engine_callback_t = .{
        .set_event_timer = EngineCallbacks.setEventTimer,
    };

    // Transport callbacks: see docs
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

    // Engine configuration: load defaults and set log level
    var config: xquic.xqc_config_t = undefined;
    if (xquic.xqc_engine_get_default_config(&config, engine_type) < 0) {
        std.debug.print("failed to get default config\n", .{});
    }
    config.cfg_log_level = args.log_level;

    // Create xquic engine
    const engine = xquic.xqc_engine_create(
        engine_type,
        &config,
        &engine_ssl_config,
        &engine_cbs,
        &transport_cbs,
        null,
    ) orelse @panic("failed to init engine");

    // Register callbacks
    try registerCallbacks(engine);

    return engine;
}

pub fn runClient() !void {
    // Initialize our Args
    const args = Args{};

    // Setup the event loop.
    var loop = try xev.Loop.init(.{});
    defer loop.deinit();

    var engine_event = try xev.Async.init();
    var task_event = try xev.Async.init();

    var engine_complete: xev.Completion = undefined;
    var task_complete: xev.Completion = undefined;

    // Initialize our context
    var ctx = Context{
        .engine = try initEngine(&args),
        .engine_event = &engine_event,
        .task_event = &task_event,
        .mode = .scmr,
        .tasks = .{
            .count = 0,
            .tasks = &.{},
        },
    };
    defer ctx.deinit();

    // Setup the main callbacks
    engine_event.wait(&loop, &engine_complete, Context, &ctx, engineCallback);
    task_event.wait(&loop, &task_complete, Context, &ctx, taskScheduleCallback);

    // Notify the task_even so that it triggers immediately and can start our setup.
    try task_event.notify();

    // Run the loop!
    try loop.run(.until_done);
}

fn engineCallback(
    maybe_ctx: ?*Context,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    const ctx: *Context = maybe_ctx orelse @panic("ctx null");
    _ = result catch @panic("callback paniced");

    const engine = ctx.engine;
    xquic.xqc_engine_main_logic(engine);
    return .disarm;
}

fn taskScheduleCallback(
    maybe_ctx: ?*Context,
    _: *xev.Loop,
    _: *xev.Completion,
    result: xev.Async.WaitError!void,
) xev.CallbackAction {
    const ctx: *Context = maybe_ctx orelse @panic("ctx null");
    _ = result catch @panic("callback paniced");

    // TODO: check task status, get first task we see as waiting.

    // Re-notify and re-arm so the task scheduler can run again.
    // TODO: do we need a forced delay here maybe? or is the logic enough of a slow down?
    ctx.task_event.notify() catch
        @panic("failed to re-notify");
    return .rearm;
}
