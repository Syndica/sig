const std = @import("std");
const xquic = @import("xquic");

const XQC_INTEROP_TLS_GROUPS = "X25519:P-256:P-384:P-521";

pub const Config = struct {
    log_level: u32,
};

pub const Client = struct {
    xqc_engine: *xquic.xqc_engine_t,

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

};

pub fn initEngine() !?*xquic.xqc_engine_t {
    const engine_type = xquic.XQC_ENGINE_CLIENT;

    var engine_ssl_config: xquic.xqc_engine_ssl_config_t = undefined;

    engine_ssl_config.ciphers = xquic.XQC_TLS_CIPHERS;
    engine_ssl_config.groups = XQC_INTEROP_TLS_GROUPS;

    var transport_cbs: xquic.xqc_transport_callbacks_t = undefined;
    var callback: xquic.xqc_engine_callback_t = undefined;

    // static xqc_engine_callback_t callback = {
    //     .log_callbacks = {
    //         .xqc_log_write_err = xqc_demo_cli_write_log_file,
    //         .xqc_log_write_stat = xqc_demo_cli_write_log_file,
    //         .xqc_qlog_event_write = xqc_demo_cli_write_qlog_file,
    //     },
    //     .keylog_cb = xqc_demo_cli_keylog_cb,
    //     .set_event_timer = xqc_demo_cli_set_event_timer,
    // };

    // static xqc_transport_callbacks_t tcb = {
    //     .write_socket = xqc_demo_cli_write_socket,
    //     .write_socket_ex = xqc_demo_cli_write_socket_ex,
    //     .save_token = xqc_demo_cli_save_token, /* save token */
    //     .save_session_cb = xqc_demo_cli_save_session_cb,
    //     .save_tp_cb = xqc_demo_cli_save_tp_cb,
    //     .conn_update_cid_notify = xqc_demo_cli_conn_update_cid_notify,
    //     .ready_to_create_path_notify = xqc_demo_cli_conn_create_path,
    //     .path_removed_notify = xqc_demo_cli_path_removed,
    // };

    // *cb = callback;
    // *transport_cbs = tcb;

    var config: xquic.xqc_config_t = undefined;
    if (xquic.xqc_engine_get_default_config(&config, engine_type) < 0) {
        std.debug.print("failed to get default config\n", .{});
    }
    config.cfg_log_level = xquic.XQC_LOG_DEBUG;

    return xquic.xqc_engine_create(
        engine_type,
        &config,
        &engine_ssl_config,
        &callback,
        &transport_cbs,
        null,
    );
}

pub fn runClient() !void {
    // const client: Client = .{};

    // client.eb = event_base_new();
    // client.ev_engine = event_new(ctx->eb, -1, 0, xqc_demo_cli_engine_callback, ctx);

    const engine = try initEngine() orelse @panic("failed to init engine");
    std.debug.print("engine: {any}\n", .{engine});
}
