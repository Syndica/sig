const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");
const rpc = sig.rpc;

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;

const Logger = sig.trace.Logger("rpc.server.basic");

pub const AcceptAndServeConnectionError =
    error{AcceptError} ||
    error{SetSocketSyncError} ||
    error{SystemIoError} ||
    error{NoSpaceLeft} ||
    std.mem.Allocator.Error ||
    // TODO: eventually remove this once we move accountsdb operations to a separate thread, and/or handle them in a way that doesn't kill the server.
    error{AccountsDbError};

pub fn acceptAndServeConnection(server_ctx: *server.Context) AcceptAndServeConnectionError!void {
    const logger = Logger.from(server_ctx.logger);

    const conn = acceptHandled(
        server_ctx.tcp,
        .blocking,
    ) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return error.AcceptError,
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
    const head_info = try parseAndHandleHead(&request, logger) orelse return;

    logger.debug().field("conn", conn.address).logf(
        "Responding to request: {} {s}",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
    );

    switch (head_info.method) {
        .HEAD => try handleGetOrHead(.HEAD, server_ctx, &request, logger),
        .GET => try handleGetOrHead(.GET, server_ctx, &request, logger),
        .POST => try handlePost(server_ctx, &request, logger, head_info),
        else => try respondSimpleErrorStatusBody(&request, logger, .not_found, ""),
    }
}

fn respondSimpleErrorStatusBody(
    request: *std.http.Server.Request,
    logger: Logger,
    status: std.http.Status,
    body: []const u8,
) !void {
    switch (status.class()) {
        .client_error, .server_error => {},
        else => unreachable,
    }

    const conn = request.server.connection;
    logger.err().field("conn", conn.address).logf(
        "Unrecognized request '{} {s}'",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
    );
    request.respond(body, .{
        .status = status,
        .keep_alive = false,
    }) catch |e| switch (e) {
        error.ConnectionResetByPeer => return,
        else => return error.SystemIoError,
    };
}

fn parseAndHandleHead(
    request: *std.http.Server.Request,
    logger: Logger,
) !?requests.HeadInfo {
    const conn = request.server.connection;
    return requests.HeadInfo.parseFromStdHead(request.head) catch |err| switch (err) {
        error.RequestTargetTooLong => {
            logger.err().field("conn", conn.address).logf(
                "Request target was too long: '{}'",
                .{std.zig.fmtEscapes(request.head.target)},
            );
            return null;
        },
        error.UnexpectedTransferEncoding => {
            if (request.head.content_length == null) {
                logger.err().field("conn", conn.address).log("Request missing Content-Length");
                try respondSimpleErrorStatusBody(request, logger, .length_required, "");
            } else {
                logger.err().field("conn", conn.address).log("Transfer-Encoding & Content-Length");
                try respondSimpleErrorStatusBody(request, logger, .bad_request, "");
            }
            return null;
        },
        error.RequestContentTypeUnrecognized => {
            logger.err().field("conn", conn.address).log(
                "Request content type unrecognized",
            );
            try respondSimpleErrorStatusBody(request, logger, .not_acceptable, "");
            return null;
        },
    };
}

fn handleGetOrHead(
    method: enum { HEAD, GET },
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
) !void {
    const target = request.head.target;
    if (std.mem.startsWith(u8, target, "/")) {
        const path = target[1..];

        if (std.mem.eql(u8, path, "health")) {
            // TODO: https://github.com/Syndica/sig/issues/558
            request.respond("unknown", .{
                .status = .ok,
                .keep_alive = false,
            }) catch |err| switch (err) {
                error.ConnectionResetByPeer => return,
                else => return error.SystemIoError,
            };
            return;
        }

        if (server_ctx.rpc_hooks.call(
            server_ctx.allocator,
            .getSnapshot,
            .{
                .path = path,
                .get = switch (method) {
                    .HEAD => .size,
                    .GET => .file,
                },
            },
        )) |snapshot_result| {
            switch (snapshot_result) {
                .ok => |result| {
                    const maybe_archive_file, const archive_len = switch (result) {
                        .file => |file| blk: {
                            errdefer file.close();
                            const len = file.getEndPos() catch return error.SystemIoError;
                            break :blk .{ file, len };
                        },
                        .size => |len| .{ null, len },
                    };
                    defer if (maybe_archive_file) |file| file.close();

                    var send_buffer: [4096]u8 = undefined;
                    var response = request.respondStreaming(.{
                        .send_buffer = &send_buffer,
                        .content_length = archive_len,
                        .respond_options = .{},
                    });
                    // flush the headers, so that if this is a head request, we can mock the response without doing unnecessary work
                    response.flush() catch |err| switch (err) {
                        error.ConnectionResetByPeer => return,
                        else => return error.SystemIoError,
                    };

                    if (!response.elide_body) {
                        // use a length which is still a multiple of 2, greater than the send_buffer length,
                        // in order to almost always force the http server method to flush, instead of
                        // pointlessly copying data into the send buffer.
                        const read_buffer_len = comptime std.mem.alignForward(
                            usize,
                            send_buffer.len + 1,
                            2,
                        );

                        while (maybe_archive_file) |archive_file| {
                            var read_buffer: [read_buffer_len]u8 = undefined;
                            const file_data_len =
                                archive_file.read(&read_buffer) catch |err| switch (err) {
                                    error.ConnectionResetByPeer,
                                    error.ConnectionTimedOut,
                                    => return,
                                    else => return error.SystemIoError,
                                };
                            if (file_data_len == 0) break;
                            const file_data = read_buffer[0..file_data_len];
                            response.writeAll(file_data) catch |err| switch (err) {
                                error.ConnectionResetByPeer => return,
                                else => return error.SystemIoError,
                            };
                        }
                    } else {
                        std.debug.assert(
                            response.transfer_encoding.content_length == archive_len,
                        );
                        // NOTE: in order to avoid needing to actually spend time writing the response body,
                        // just trick the API into thinking we already wrote the entire thing by setting this
                        // to 0.
                        response.transfer_encoding.content_length = 0;
                    }

                    response.end() catch |err| switch (err) {
                        error.ConnectionResetByPeer => return,
                        else => return error.SystemIoError,
                    };
                    return;
                },
                .err => |err| {
                    try respondSimpleErrorStatusBody(
                        request,
                        logger,
                        .service_unavailable,
                        err.message,
                    );
                    return;
                },
            }
        } else |e| switch (e) {
            error.MethodNotImplemented => {}, // not found
        }
    }

    try respondSimpleErrorStatusBody(request, logger, .not_found, "");
}

fn handlePost(
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
    head_info: requests.HeadInfo,
) !void {
    const conn = request.server.connection;
    if (head_info.content_type != .@"application/json") {
        try respondSimpleErrorStatusBody(request, logger, .not_acceptable, "");
        return;
    }

    const req_reader = sig.utils.io.narrowAnyReader(
        // make the server handle the 100-continue in case there is one
        request.reader() catch |err| switch (err) {
            error.HttpExpectationFailed => return,
            error.ConnectionResetByPeer => return,
            else => return error.SystemIoError,
        },
        std.http.Server.Request.ReadError,
    );

    const content_len = head_info.content_len orelse {
        try respondSimpleErrorStatusBody(request, logger, .length_required, "");
        return;
    };

    if (content_len > requests.MAX_REQUEST_BODY_SIZE) {
        try respondSimpleErrorStatusBody(request, logger, .payload_too_large, "");
        return;
    }

    const content_body = try server_ctx.allocator.alloc(u8, content_len);
    defer server_ctx.allocator.free(content_body);
    req_reader.readNoEof(content_body) catch |err| switch (err) {
        error.EndOfStream,
        error.HttpChunkInvalid,
        error.HttpHeadersOversize,
        => {
            try respondSimpleErrorStatusBody(request, logger, .bad_request, "");
            return;
        },

        error.OperationAborted,
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        => |e| {
            logger.err()
                .field("conn", conn.address)
                .logf("{s}", .{@errorName(e)});
            return;
        },

        else => return error.SystemIoError,
    };

    try handleRpcRequest(server_ctx, request, logger, content_body);
}

fn handleRpcRequest(
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
    content_body: []const u8,
) !void {
    var json_arena_state = std.heap.ArenaAllocator.init(server_ctx.allocator);
    defer json_arena_state.deinit();
    const json_arena = json_arena_state.allocator();

    const rpc_request_dyn = std.json.parseFromSliceLeaky(
        rpc.request.Request.Dynamic,
        json_arena,
        content_body,
        .{},
    ) catch |err| switch (err) {
        error.BufferUnderrun,
        => unreachable,

        error.OutOfMemory,
        error.ValueTooLong,
        => return error.OutOfMemory,

        error.SyntaxError,
        error.UnexpectedEndOfInput,
        error.InvalidCharacter,
        => {
            try writeFinalJsonResponse(request, .{}, .{
                .jsonrpc = "2.0",
                .id = null,
                .@"error" = rpc.response.Error{
                    .code = .parse_error,
                    .message = "Parse error",
                },
            });
            return;
        },

        error.UnexpectedToken,
        error.InvalidNumber,
        error.Overflow,
        error.InvalidEnumTag,
        error.DuplicateField,
        error.UnknownField,
        error.MissingField,
        error.LengthMismatch,
        => {
            try writeFinalJsonResponse(request, .{}, .{
                .jsonrpc = "2.0",
                .id = null,
                .@"error" = rpc.response.Error{
                    .code = .invalid_request,
                    .message = "Invalid Request",
                },
            });
            return;
        },
    };

    const rpc_request = json: {
        var diag = rpc.Request.Dynamic.ParseDiagnostic.INIT;
        const result = rpc_request_dyn.parse(json_arena, .{}, &diag) catch |err| {
            const code: rpc.response.ErrorCode, //
            const message: []const u8 //
            = switch (err) {
                error.OutOfMemory,
                => |e| return e,

                error.MissingJsonRpcVersion,
                error.MissingMethod,
                error.MissingParams,
                error.InvalidJsonRpcVersion,
                => .{ .invalid_request, "Invalid Request" },

                error.InvalidMethod,
                => .{ .method_not_found, "Method not found" },

                error.InvalidParams,
                error.ParamsLengthMismatch,
                => .{ .invalid_params, "Invalid method parameters" },
            };
            const err_obj: rpc.response.Error = .{
                .code = code,
                .message = message,
            };
            try writeFinalJsonResponse(request, .{}, .{
                .jsonrpc = "2.0",
                .id = diag.err.id orelse .null,
                .@"error" = err_obj,
            });
            return;
        };
        break :json result;
    };

    switch (@as(rpc.methods.MethodAndParams.Tag, rpc_request.method)) {
        // GetSnapshot is not a real RPC method & should not be reachable from a POST request.
        .getSnapshot => {
            try sendFinalMethodNotFound(request, logger, .getSnapshot, rpc_request.id);
            return;
        },
        inline else => |method| {
            // For unimplemented methods, hard-code sending a not-found error.
            const FieldType = @FieldType(sig.rpc.methods.MethodAndParams, @tagName(method));
            if (comptime FieldType == noreturn) {
                try sendFinalMethodNotFound(request, logger, method, rpc_request.id);
                return;
            }

            const allocator = json_arena;
            const result = server_ctx.rpc_hooks.call(
                allocator,
                method,
                @field(rpc_request.method, @tagName(method)),
            ) catch |e| switch (e) {
                error.MethodNotImplemented => {
                    try sendFinalMethodNotFound(request, logger, method, rpc_request.id);
                    return;
                },
            };

            return switch (result) {
                .ok => |response_result| try writeFinalJsonResponse(request, .{}, .{
                    .jsonrpc = "2.0",
                    .id = rpc_request.id,
                    .result = response_result,
                }),
                .err => |err| try writeFinalJsonResponse(request, .{}, .{
                    .jsonrpc = "2.0",
                    .id = rpc_request.id,
                    .@"error" = err,
                }),
            };
        },
    }
}

fn sendFinalMethodNotFound(
    request: *std.http.Server.Request,
    logger: Logger,
    comptime method: sig.rpc.methods.MethodAndParams.Tag,
    request_id: anytype,
) !void {
    logger.err().logf("RPC server hooks did not implement {s}", .{@tagName(method)});

    var buffer: [256]u8 = undefined;
    const message = try std.fmt.bufPrint(
        &buffer,
        "RPC server does not currently implement {s}",
        .{@tagName(method)},
    );

    return try writeFinalJsonResponse(request, .{}, .{
        .jsonrpc = "2.0",
        .id = request_id,
        .@"error" = rpc.response.Error{
            .code = .method_not_found,
            .message = message,
        },
    });
}

fn writeFinalJsonResponse(
    request: *std.http.Server.Request,
    http_respond_opts: std.http.Server.Request.RespondOptions,
    json_value: anytype,
) (std.mem.Allocator.Error || error{SystemIoError})!void {
    const json_stringify_opts: std.json.StringifyOptions = .{};

    const content_length = blk: {
        var cw = std.io.countingWriter(std.io.null_writer);
        var cjw = std.json.writeStream(cw.writer(), json_stringify_opts);
        cjw.write(json_value) catch |err| switch (err) {};
        break :blk cw.bytes_written;
    };

    var send_buffer: [4096]u8 = undefined;
    var response = request.respondStreaming(.{
        .send_buffer = &send_buffer,
        .content_length = content_length,
        .respond_options = http_respond_opts,
    });

    const resp_writer = httpResponseWriter(&response);
    var json_writer = std.json.writeStream(resp_writer, json_stringify_opts);
    json_writer.write(json_value) catch |err| switch (err) {
        error.ConnectionResetByPeer => return,
        else => return error.SystemIoError,
    };
    response.end() catch |err| switch (err) {
        error.ConnectionResetByPeer => return,
        else => return error.SystemIoError,
    };
}

const HttpResponseWriter = sig.utils.io.NarrowAnyWriter(std.http.Server.Response.WriteError);
fn httpResponseWriter(response: *std.http.Server.Response) HttpResponseWriter {
    return sig.utils.io.narrowAnyWriter(
        response.writer(),
        std.http.Server.Response.WriteError,
    );
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
    const have_accept4 = comptime !builtin.target.os.tag.isDarwin();

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
    const FlagsInt = @typeInfo(std.posix.O).@"struct".backing_integer.?;
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
