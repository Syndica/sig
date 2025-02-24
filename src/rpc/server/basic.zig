const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;

const LOGGER_SCOPE = "rpc.server.basic";

pub const AcceptAndServeConnectionError =
    AcceptHandledError ||
    SetSocketSyncError ||
    std.http.Server.ReceiveHeadError ||
    std.http.Server.Response.WriteError ||
    std.mem.Allocator.Error ||
    std.fs.File.GetSeekPosError ||
    std.fs.File.OpenError ||
    std.fs.File.ReadError;

pub fn acceptAndServeConnection(server_ctx: *server.Context) !void {
    const logger = server_ctx.logger.withScope(LOGGER_SCOPE);

    const conn = acceptHandled(
        server_ctx.tcp,
        .blocking,
    ) catch |err| switch (err) {
        error.WouldBlock => return,
        else => |e| return e,
    };
    defer conn.stream.close();

    server_ctx.wait_group.start();
    defer server_ctx.wait_group.finish();

    const buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
    defer server_ctx.allocator.free(buffer);

    var http_server = std.http.Server.init(conn, buffer);
    var request = try http_server.receiveHead();

    const conn_address = request.server.connection.address;
    logger.info().logf("Responding to request from {}: {} {s}", .{
        conn_address, requests.methodFmt(request.head.method), request.head.target,
    });

    switch (request.head.method) {
        .HEAD, .GET => switch (requests.getRequestTargetResolve(
            logger.unscoped(),
            request.head.target,
            server_ctx.latest_snapshot_gen_info,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
                const snap_info, var full_info_lg = pair;
                defer full_info_lg.unlock();

                const archive_name_bounded = snap_info.snapshotArchiveName();
                const archive_name = archive_name_bounded.constSlice();

                const archive_file = try server_ctx.snapshot_dir.openFile(archive_name, .{});
                defer archive_file.close();

                const archive_len = try archive_file.getEndPos();

                var send_buffer: [4096]u8 = undefined;
                var response = request.respondStreaming(.{
                    .send_buffer = &send_buffer,
                    .content_length = archive_len,
                    .respond_options = .{},
                });
                // flush the headers, so that if this is a head request, we can mock the response without doing unnecessary work
                try response.flush();

                if (!response.elide_body) {
                    // use a length which is still a multiple of 2, greater than the send_buffer length,
                    // in order to almost always force the http server method to flush, instead of
                    // pointlessly copying data into the send buffer.
                    const read_buffer_len = comptime std.mem.alignForward(
                        usize,
                        send_buffer.len + 1,
                        2,
                    );
                    var read_buffer: [read_buffer_len]u8 = undefined;

                    while (true) {
                        const file_data_len = try archive_file.read(&read_buffer);
                        if (file_data_len == 0) break;
                        const file_data = read_buffer[0..file_data_len];
                        try response.writeAll(file_data);
                    }
                } else {
                    std.debug.assert(response.transfer_encoding.content_length == archive_len);
                    // NOTE: in order to avoid needing to actually spend time writing the response body,
                    // just trick the API into thinking we already wrote the entire thing by setting this
                    // to 0.
                    response.transfer_encoding.content_length = 0;
                }

                try response.end();
                return;
            },
            .health => {
                try request.respond("unknown", .{
                    .status = .ok,
                    .keep_alive = false,
                });
                return;
            },

            .genesis_file => {},

            .not_found => {},
        },
        .POST => {
            logger.err().logf("{} tried to invoke our RPC", .{conn_address});
            try request.respond("RPCs are not yet implemented", .{
                .status = .service_unavailable,
                .keep_alive = false,
            });
            return;
        },
        else => {},
    }

    // fallthrough to 404 Not Found

    logger.err().logf(
        "{} made an unrecognized request '{} {s}'",
        .{ conn_address, requests.methodFmt(request.head.method), request.head.target },
    );
    try request.respond("", .{
        .status = .not_found,
        .keep_alive = false,
    });
}

const SyncKind = enum { blocking, nonblocking };

const AcceptHandledError =
    error{
    ConnectionAborted,
    ProtocolFailure,
    WouldBlock,
} || connection.HandleAcceptError ||
    SetSocketSyncError;

fn acceptHandled(
    tcp_server: std.net.Server,
    sync: SyncKind,
) AcceptHandledError!std.net.Server.Connection {
    var accept_flags: u32 = std.posix.SOCK.CLOEXEC;
    accept_flags |= switch (sync) {
        .blocking => 0,
        .nonblocking => std.posix.SOCK.NONBLOCK,
    };

    // When this is false, it means we can't apply flags to
    // the accepted socket, and we'll have to ensure that the
    // relevant flags are enabled/disabled after acceptance.
    const have_accept4 = comptime !builtin.target.isDarwin();

    const conn: std.net.Server.Connection = while (true) {
        var addr: std.net.Address = .{ .any = undefined };
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr.any));
        const rc = if (have_accept4)
            std.posix.system.accept4(tcp_server.stream.handle, &addr.any, &addr_len, accept_flags)
        else
            std.posix.system.accept(tcp_server.stream.handle, &addr.any, &addr_len);

        break switch (try connection.handleAcceptResult(std.posix.errno(rc))) {
            .intr => continue,
            .conn_aborted => return error.ConnectionAborted,
            .proto_fail => return error.ProtocolFailure,
            .again => return error.WouldBlock,
            .success => .{
                .stream = .{ .handle = rc },
                .address = addr,
            },
        };
    };

    if (!have_accept4) {
        try setSocketSync(conn.stream.handle, sync);
    }

    return conn;
}

const SetSocketSyncError = std.posix.FcntlError;

/// Ensure the socket is set to be blocking or nonblocking.
/// Useful in tandem with the situation described by `HAVE_ACCEPT4`.
fn setSocketSync(
    socket: std.posix.socket_t,
    sync: SyncKind,
) SetSocketSyncError!void {
    const FlagsInt = @typeInfo(std.posix.O).Struct.backing_integer.?;
    var flags_int: FlagsInt = @intCast(try std.posix.fcntl(socket, std.posix.F.GETFL, 0));
    const flags = std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));

    const nonblock_wanted = switch (sync) {
        .blocking => false,
        .nonblocking => true,
    };
    if (flags.NONBLOCK != nonblock_wanted) {
        flags.NONBLOCK = nonblock_wanted;
        _ = try std.posix.fcntl(socket, std.posix.F.SETFL, flags_int);
    }
}
