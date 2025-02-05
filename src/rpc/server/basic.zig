const std = @import("std");
const sig = @import("../../sig.zig");

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;

pub const AcceptAndServeConnectionError =
    connection.AcceptHandledError ||
    connection.SetSocketSyncError ||
    std.mem.Allocator.Error ||
    std.http.Server.ReceiveHeadError ||
    requests.HandleRequestError;

pub fn acceptAndServeConnection(server_ctx: *server.Context) !void {
    const conn = connection.acceptHandled(
        server_ctx.tcp,
        .blocking,
    ) catch |err| switch (err) {
        error.WouldBlock => return,
        else => |e| return e,
    };
    defer conn.stream.close();

    if (!connection.HAVE_ACCEPT4) {
        // make sure the accepted socket is in blocking mode
        try connection.setSocketSync(conn.stream.handle, .blocking);
    }

    server_ctx.wait_group.start();
    defer server_ctx.wait_group.finish();

    const buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
    defer server_ctx.allocator.free(buffer);

    var http_server = std.http.Server.init(conn, buffer);
    var request = try http_server.receiveHead();

    try requests.handleRequest(
        server_ctx.logger,
        &request,
        server_ctx.snapshot_dir,
        server_ctx.latest_snapshot_gen_info,
    );
}
