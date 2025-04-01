const builtin = @import("builtin");
const std = @import("std");

const sig = @import("../../sig.zig");
const rpc = sig.rpc;

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
    std.fs.File.ReadError ||

    // TODO: eventually remove this once not directly called?
    sig.accounts_db.AccountsDB.GetAccountError;

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
    var request = http_server.receiveHead() catch |err| {
        logger.err()
            .field("conn", conn.address)
            .logf("Receive head error: {s}", .{@errorName(err)});
        return;
    };
    const head_info = requests.HeadInfo.parseFromStdHead(request.head) catch |err| switch (err) {
        error.RequestTargetTooLong => {
            logger.err().field("conn", conn.address).logf(
                "Request target was too long: '{}'",
                .{std.zig.fmtEscapes(request.head.target)},
            );
            return;
        },
        error.UnexpectedTransferEncoding => if (request.head.content_length == null) {
            logger.err().field("conn", conn.address).log("Request missing content-length");
            try request.respond("", .{
                .status = .length_required,
                .keep_alive = false,
            });
            return;
        } else {
            logger.err().field("conn", conn.address).log(
                "Request missing content-length",
            );
            try request.respond("", .{
                .status = .bad_request,
                .keep_alive = false,
            });
            return;
        },
        error.RequestContentTypeUnrecognized => {
            logger.err().field("conn", conn.address).log(
                "Request contained both content-length and transfer-encoding",
            );
            try request.respond("", .{
                .status = .not_acceptable,
                .keep_alive = false,
            });
            return;
        },
    };

    logger.debug().field("conn", conn.address).logf(
        "Responding to request: {} {s}",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
    );

    switch (head_info.method) {
        .HEAD, .GET => switch (requests.getRequestTargetResolve(
            logger.unscoped(),
            request.head.target,
            &server_ctx.accountsdb.latest_snapshot_gen_info,
        )) {
            inline .full_snapshot, .inc_snapshot => |pair| {
                const snap_info, var full_info_lg = pair;
                defer full_info_lg.unlock();

                const archive_name_bounded = snap_info.snapshotArchiveName();
                const archive_name = archive_name_bounded.constSlice();

                const archive_file = try server_ctx.accountsdb.snapshot_dir.openFile(archive_name, .{});
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

            .genesis_file => {
                logger.err()
                    .field("conn", conn.address)
                    .logf("Attempt to get our genesis file", .{});
                try request.respond("Genesis file get is not yet implemented", .{
                    .status = .service_unavailable,
                    .keep_alive = false,
                });
                return;
            },

            .not_found => {},
        },
        .POST => {
            if (head_info.content_type != .@"application/json") {
                try request.respond("", .{
                    .status = .not_acceptable,
                    .keep_alive = false,
                });
                return;
            }

            const req_reader = sig.utils.io.narrowAnyReader(
                // make the server handle the 100-continue in case there is one
                request.reader() catch |err| switch (err) {
                    error.HttpExpectationFailed => return,
                    else => |e| return e,
                },
                std.http.Server.Request.ReadError,
            );

            const content_len = head_info.content_len orelse {
                try request.respond("", .{
                    .status = .length_required,
                    .keep_alive = false,
                });
                return;
            };
            if (content_len > requests.MAX_REQUEST_BODY_SIZE) {
                try request.respond("", .{
                    .status = .payload_too_large,
                    .keep_alive = false,
                });
                return;
            }

            var send_buffer: [4096]u8 = undefined;
            var response = request.respondStreaming(.{
                .send_buffer = &send_buffer,
                .content_length = null,
                .respond_options = .{ .keep_alive = false },
            });
            const resp_writer = sig.utils.io.narrowAnyWriter(
                response.writer(),
                std.http.Server.Response.WriteError,
            );
            var json_writer = std.json.writeStream(resp_writer, .{});

            const parsed_result = json: {
                var limited_reader = std.io.limitedReader(req_reader, content_len);
                var json_reader = std.json.reader(server_ctx.allocator, limited_reader.reader());
                defer json_reader.deinit();

                break :json std.json.parseFromTokenSource(
                    rpc.request.Request.JsonParseResult,
                    server_ctx.allocator,
                    &json_reader,
                    .{},
                ) catch |err| switch (err) {
                    error.HttpChunkInvalid,
                    error.HttpHeadersOversize,
                    => {
                        try request.respond("", .{
                            .status = .bad_request,
                            .keep_alive = false,
                        });
                        return;
                    },

                    error.InvalidEnumTag,
                    error.UnexpectedToken,
                    error.InvalidNumber,
                    error.DuplicateField,
                    error.UnknownField,
                    error.MissingField,
                    error.LengthMismatch,
                    error.SyntaxError,
                    error.UnexpectedEndOfInput,
                    error.ValueTooLong,
                    error.Overflow,
                    error.InvalidCharacter,
                    => {
                        try json_writer.write(.{
                            .jsonrpc = "2.0",
                            .id = .null,
                            .@"error" = rpc.response.Error{
                                .code = .parse_error,
                                .message = "Invalid json",
                            },
                        });
                        try response.end();
                        return;
                    },

                    else => |e| return e,
                };
            };
            defer parsed_result.deinit();
            const rpc_request = switch (parsed_result.value) {
                .ok => |req| req,

                inline //
                .invalid_request,
                .method_not_found,
                .invalid_params,
                => |maybe_id, tag| {
                    try json_writer.write(.{
                        .jsonrpc = "2.0",
                        .id = maybe_id orelse .null,
                        .@"error" = rpc.response.Error{
                            .code = switch (tag) {
                                .invalid_request => .invalid_request,
                                .method_not_found => .method_not_found,
                                .invalid_params => .invalid_params,
                                else => comptime unreachable,
                            },
                            .message = switch (tag) {
                                .invalid_request => "Invalid request",
                                .method_not_found => "Method not found",
                                .invalid_params => "Invalid parameters",
                                else => comptime unreachable,
                            },
                        },
                    });
                    try response.end();
                    return;
                },
            };

            switch (rpc_request.method) {
                .getAccountInfo => |params| {
                    const config: rpc.methods.GetAccountInfo.Config = params.config orelse .{};
                    if (config.commitment) |commitment| {
                        std.debug.panic("TODO: handle commitment={s}", .{@tagName(commitment)});
                    }

                    const account: sig.accounts_db.AccountsDB.AccountInCacheOrFile, //
                    var account_lg: sig.accounts_db.AccountsDB.AccountInCacheOrFileLock //
                    = try server_ctx.accountsdb.getAccountInSlotRangeWithReadLock(
                        &params.pubkey,
                        // if it's null, it's null, there's no floor to the query.
                        config.minContextSlot orelse null,
                        null,
                    ) orelse {
                        try request.respond("", .{
                            .status = .range_not_satisfiable,
                            .keep_alive = false,
                        });
                        return;
                    };
                    _ = account; // autofix
                    defer account_lg.unlock();

                    return;
                },
                else => {
                    try request.respond("", .{
                        .status = .not_implemented,
                        .keep_alive = false,
                    });
                    return;
                },
            }

            try response.end();
            return;
        },
        else => {},
    }

    // fallthrough to 404 Not Found

    logger.err().field("conn", conn.address).logf(
        "Unrecognized request '{} {s}'",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
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
