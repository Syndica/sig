const std = @import("std");
const xquic = @import("xquic");

pub const ConnectionCallbacks = struct {
    // connection create notify callback. REQUIRED for server, OPTIONAL for client.
    //
    // this function will be invoked after connection is created, user can create application layer
    // context in this callback function
    //
    // return 0 for success, -1 for failure, e.g. malloc error, on which xquic will close connection
    // typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data);
    pub fn connCreateNotify(
        conn: ?*xquic.xqc_connection_t,
        cid: ?*const xquic.xqc_cid_t,
        conn_user_data: ?*anyopaque,
        conn_proto_data: ?*anyopaque,
    ) callconv(.C) i32 {
        _ = conn;
        _ = cid;
        _ = conn_user_data;
        _ = conn_proto_data;
        std.debug.print("connCreateNotify\n", .{});
        return 0;
    }

    // connection close notify. REQUIRED for both client and server
    //
    // this function will be invoked after QUIC connection is closed. user can free application
    // level context created in conn_create_notify callback function
    // typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid, void *conn_user_data, void *conn_proto_data);
    pub fn connCloseNotify(
        conn: ?*xquic.xqc_connection_t,
        cid: ?*const xquic.xqc_cid_t,
        conn_user_data: ?*anyopaque,
        conn_proto_data: ?*anyopaque,
    ) callconv(.C) i32 {
        _ = conn;
        _ = cid;
        _ = conn_user_data;
        _ = conn_proto_data;
        std.debug.print("connCloseNotify\n", .{});
        return 0;
    }

    // handshake complete callback. OPTIONAL for client and server
    // typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data, void *conn_proto_data);
    pub fn connHandshakeFinished(
        conn: ?*xquic.xqc_connection_t,
        conn_user_data: ?*anyopaque,
        conn_proto_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = conn;
        _ = conn_user_data;
        _ = conn_proto_data;
        std.debug.print("handshakeComplete\n", .{});
    }

    // active PING acked callback. OPTIONAL for both client and server
    // typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid, void *ping_user_data, void *conn_user_data, void *conn_proto_data);
    pub fn connPingAcked(
        conn: ?*xquic.xqc_connection_t,
        cid: ?*const xquic.xqc_cid_t,
        ping_user_data: ?*anyopaque,
        conn_user_data: ?*anyopaque,
        conn_proto_data: ?*anyopaque,
    ) callconv(.C) void {
        _ = conn;
        _ = cid;
        _ = ping_user_data;
        _ = conn_user_data;
        _ = conn_proto_data;
        std.debug.print("activePingAcked\n", .{});
    }
};
