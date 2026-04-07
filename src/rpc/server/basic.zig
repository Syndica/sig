const builtin = @import("builtin");
const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../sig.zig");
const rpc = sig.rpc;

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;

const Logger = sig.trace.Logger("rpc.server.basic");

/// CORS headers included on every response.
/// Matches Agave which uses `AccessControlAllowOrigin::Any` with `cors_max_age(86400)`.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc_service.rs#L842-L845
const cors_headers: []const std.http.Header = &.{
    .{ .name = "Access-Control-Allow-Origin", .value = "*" },
    .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, HEAD, OPTIONS" },
    .{
        .name = "Access-Control-Allow-Headers",
        .value = "Content-Type, Authorization, Accept, Solana-Client",
    },
    .{ .name = "Access-Control-Max-Age", .value = "86400" },
};

/// Headers for JSON RPC responses: Content-Type + CORS.
const json_headers: []const std.http.Header = &.{
    .{ .name = "Content-Type", .value = "application/json" },
    .{ .name = "Access-Control-Allow-Origin", .value = "*" },
    .{ .name = "Access-Control-Allow-Methods", .value = "GET, POST, HEAD, OPTIONS" },
    .{
        .name = "Access-Control-Allow-Headers",
        .value = "Content-Type, Authorization, Accept, Solana-Client",
    },
    .{ .name = "Access-Control-Max-Age", .value = "86400" },
};

pub const AcceptAndServeConnectionError =
    error{AcceptError} ||
    error{SetSocketSyncError} ||
    error{SystemIoError} ||
    error{NoSpaceLeft} ||
    std.mem.Allocator.Error ||
    error{WriteFailed};

pub fn acceptAndServeConnection(server_ctx: *server.Context) AcceptAndServeConnectionError!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.accept" });
    defer zone.deinit();

    const logger = Logger.from(server_ctx.logger);

    const conn = acceptHandled(
        server_ctx.tcp,
        .blocking,
    ) catch |err| switch (err) {
        error.WouldBlock => return,
        else => return error.AcceptError,
    };
    var close_conn = true;
    defer if (close_conn) conn.stream.close();

    server_ctx.wait_group.start();
    defer server_ctx.wait_group.finish();

    const buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
    defer server_ctx.allocator.free(buffer);

    const write_buffer = try server_ctx.allocator.alloc(u8, server_ctx.read_buffer_size);
    defer server_ctx.allocator.free(write_buffer);

    var reader = conn.stream.reader(buffer);
    var writer = conn.stream.writer(write_buffer);

    var http_server = std.http.Server.init(reader.interface(), &writer.interface);
    var request = http_server.receiveHead() catch |err| {
        logger.err()
            .field("conn", conn.address)
            .logf("Receive head error: {s}", .{@errorName(err)});
        return;
    };
    const head_info = try parseAndHandleHead(&request, conn.address, logger) orelse return;

    logger.debug().field("conn", conn.address).logf(
        "Responding to request: {f} {s}",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
    );

    if (head_info.method == .GET and isWebSocketUpgrade(&request)) {
        if (server_ctx.ws_server) |ws_server| {
            // head buffer is just prefix slice of reader buffer
            // so handoff is just head len + reader buffered len
            const handoff_len = request.head_buffer.len + reader.interface().bufferedLen();
            const handoff_data = request.head_buffer.ptr[0..handoff_len];
            ws_server.feedConnection(conn.stream.handle, handoff_data) catch {
                try respondSimpleErrorStatusBody(&request, logger, .internal_server_error, "");
                try writer.interface.flush();
                return;
            };
            close_conn = false;
            return;
        }
    }

    switch (head_info.method) {
        .HEAD => try handleGetOrHead(.HEAD, server_ctx, &request, logger),
        .GET => try handleGetOrHead(.GET, server_ctx, &request, logger),
        .POST => try handlePost(server_ctx, &request, logger, head_info, conn.address),
        .OPTIONS => {
            // CORS preflight response.
            // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc_service.rs#L842-L845
            request.respond("", .{
                .status = .no_content,
                .keep_alive = false,
                .extra_headers = cors_headers,
            }) catch {
                return error.SystemIoError;
            };
        },
        else => try respondSimpleErrorStatusBody(&request, logger, .not_found, ""),
    }

    try writer.interface.flush();
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

    logger.err().logf(
        "Unrecognized request '{f} {s}'",
        .{ requests.httpMethodFmt(request.head.method), request.head.target },
    );
    request.respond(body, .{
        .status = status,
        .keep_alive = false,
        .extra_headers = cors_headers,
    }) catch {
        return error.SystemIoError;
    };
}

fn parseAndHandleHead(
    request: *std.http.Server.Request,
    conn_address: std.net.Address,
    logger: Logger,
) !?requests.HeadInfo {
    return requests.HeadInfo.parseFromStdHead(request.head) catch |err| switch (err) {
        error.RequestTargetTooLong => {
            logger.err().field("conn", conn_address).logf(
                "Request target was too long: '{s}'",
                .{request.head.target},
            );
            return null;
        },
        error.UnexpectedTransferEncoding => {
            if (request.head.content_length == null) {
                logger.err().field("conn", conn_address).log("Request missing Content-Length");
                try respondSimpleErrorStatusBody(request, logger, .length_required, "");
            } else {
                logger.err().field("conn", conn_address).log("Transfer-Encoding & Content-Length");
                try respondSimpleErrorStatusBody(request, logger, .bad_request, "");
            }
            return null;
        },
        error.RequestContentTypeUnrecognized => {
            logger.err().field("conn", conn_address).log(
                "Request content type unrecognized",
            );
            try respondSimpleErrorStatusBody(request, logger, .not_acceptable, "");
            return null;
        },
    };
}

fn isWebSocketUpgrade(request: *const std.http.Server.Request) bool {
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "upgrade")) {
            continue;
        }

        var tokens = std.mem.tokenizeScalar(u8, header.value, ',');
        while (tokens.next()) |token_raw| {
            const token = std.mem.trim(u8, token_raw, " \t");
            if (std.ascii.eqlIgnoreCase(token, "websocket")) {
                return true;
            }
        }
    }
    return false;
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
            // HTTP GET /health always returns 200 OK with a plain-text status string.
            // This matches agave's behavior:
            // See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc_service.rs#L332-L340
            const health_result = server_ctx.rpc_hooks.call(
                server_ctx.allocator,
                .getHealth,
                .{},
            ) catch |e| switch (e) {
                error.MethodNotImplemented => {
                    request.respond("unknown", .{
                        .status = .ok,
                        .keep_alive = false,
                        .extra_headers = cors_headers,
                    }) catch |err| switch (err) {
                        error.WriteFailed => return error.SystemIoError,
                        error.HttpExpectationFailed => return error.SystemIoError,
                    };
                    return;
                },
            };

            // The hooks system wraps the response in Result union
            const status_str = switch (health_result) {
                .ok => |response| response.httpStatusString(),
                .err => "unknown", // fallback for hook-level errors
            };

            request.respond(status_str, .{
                .status = .ok,
                .keep_alive = false,
                .extra_headers = cors_headers,
            }) catch |err| switch (err) {
                error.WriteFailed => return error.SystemIoError,
                error.HttpExpectationFailed => return error.SystemIoError,
            };
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
                    var response = request.respondStreaming(&send_buffer, .{
                        .content_length = archive_len,
                        .respond_options = .{
                            // This server currently serves a single request per accepted socket
                            // and closes the connection afterwards, so responses must advertise
                            // non-persistent semantics.
                            .keep_alive = false,
                            .extra_headers = cors_headers,
                        },
                    }) catch |err| switch (err) {
                        error.HttpExpectationFailed => return,
                        error.WriteFailed => return error.SystemIoError,
                    };
                    // flush the headers, so that if this is a head request, we can mock the response without doing unnecessary work
                    response.flush() catch {
                        return error.SystemIoError;
                    };

                    if (!response.isEliding()) {
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
                                archive_file.read(&read_buffer) catch {
                                    return error.SystemIoError;
                                };
                            if (file_data_len == 0) break;
                            const file_data = read_buffer[0..file_data_len];
                            response.writer.writeAll(file_data) catch {
                                return error.SystemIoError;
                            };
                        }
                    } else {
                        std.debug.assert(
                            response.state.content_length == archive_len,
                        );
                        // NOTE: in order to avoid needing to actually spend time writing the response body,
                        // just trick the API into thinking we already wrote the entire thing by setting this
                        // to 0.
                        response.state = .{ .content_length = 0 };
                    }

                    response.end() catch {
                        return error.SystemIoError;
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

/// Format the "Node is behind by N slots" message matching agave's format.
/// See: https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs#L153-L154
fn behindMessage(buf: *[64]u8, num_slots: u64) []const u8 {
    return std.fmt.bufPrint(buf, "Node is behind by {d} slots", .{num_slots}) catch "Node is behind";
}

/// Agave's NodeUnhealthy JSON-RPC error response structure.
/// Matches agave's error format exactly:
///   {"code": -32005, "message": "...", "data": {"numSlotsBehind": <n or null>}}
/// See: https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs#L149-L159
const NodeUnhealthyError = struct {
    code: i64 = rpc.methods.GetHealth.node_unhealthy_code,
    message: []const u8,
    data: NodeUnhealthyErrorData,

    const NodeUnhealthyErrorData = struct {
        numSlotsBehind: ?u64,
    };
};

/// Agave's SendTransactionPreflightFailure JSON-RPC error response structure.
/// Matches agave's error format:
///   {"code": -32002, "message": "Transaction simulation failed: ...", "data": {...}}
/// See: https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs#L130-L136
const SendTransactionPreflightError = struct {
    code: i64 = rpc.methods.SendTransaction.preflight_failure_code,
    message: []const u8,
    data: SendTransactionPreflightErrorData,

    const SendTransactionPreflightErrorData = struct {
        err: sig.ledger.transaction_status.TransactionError,
        logs: []const []const u8,
        unitsConsumed: u64,
        loadedAccountsDataSize: u32,
    };
};

fn handlePost(
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
    head_info: requests.HeadInfo,
    _: std.net.Address,
) !void {
    if (head_info.content_type != .@"application/json") {
        try respondSimpleErrorStatusBody(request, logger, .not_acceptable, "");
        return;
    }

    var reader_buffer: [4096]u8 = undefined;
    const req_reader = request.readerExpectContinue(&reader_buffer) catch |err| switch (err) {
        error.HttpExpectationFailed => return,
        error.WriteFailed => return error.SystemIoError,
    };

    const content_len = head_info.content_len orelse {
        try respondSimpleErrorStatusBody(request, logger, .length_required, "");
        return;
    };

    if (content_len > requests.MAX_REQUEST_BODY_SIZE) {
        try respondSimpleErrorStatusBody(request, logger, .payload_too_large, "");
        return;
    }

    const content_body = req_reader.allocRemaining(
        server_ctx.allocator,
        .limited(content_len + 1),
    ) catch |err| switch (err) {
        error.ReadFailed,
        => {
            try respondSimpleErrorStatusBody(request, logger, .bad_request, "");
            return;
        },

        error.StreamTooLong => {
            try respondSimpleErrorStatusBody(request, logger, .payload_too_large, "");
            return;
        },

        error.OutOfMemory => return error.OutOfMemory,
    };
    defer server_ctx.allocator.free(content_body);

    try handleRpcRequest(server_ctx, request, logger, content_body);
}

fn handleRpcRequest(
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
    content_body: []const u8,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.request" });
    defer zone.deinit();

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

                error.MethodNotImplemented,
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
        // getHealth requires special handling: unhealthy states must be returned as
        // JSON-RPC errors with code -32005, matching agave's behavior.
        // See: https://github.com/anza-xyz/agave/blob/master/rpc/src/rpc.rs#L2806-L2818
        // See: https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs#L149-L159
        .getHealth => {
            const allocator = json_arena;
            const result = server_ctx.rpc_hooks.call(
                allocator,
                .getHealth,
                .{},
            ) catch |e| switch (e) {
                error.MethodNotImplemented => {
                    try sendFinalMethodNotFound(request, logger, .getHealth, rpc_request.id);
                    return;
                },
            };

            return switch (result) {
                .ok => |health_status| switch (health_status) {
                    .ok => try writeFinalJsonResponse(request, .{}, .{
                        .jsonrpc = "2.0",
                        .id = rpc_request.id,
                        .result = "ok",
                    }),
                    .unknown => try writeFinalJsonResponse(request, .{}, .{
                        .jsonrpc = "2.0",
                        .id = rpc_request.id,
                        .@"error" = NodeUnhealthyError{
                            .message = "Node is unhealthy",
                            .data = .{ .numSlotsBehind = null },
                        },
                    }),
                    .behind => |num_slots| blk: {
                        var msg_buf: [64]u8 = undefined;
                        const message = behindMessage(&msg_buf, num_slots);
                        break :blk try writeFinalJsonResponse(request, .{}, .{
                            .jsonrpc = "2.0",
                            .id = rpc_request.id,
                            .@"error" = NodeUnhealthyError{
                                .message = message,
                                .data = .{ .numSlotsBehind = num_slots },
                            },
                        });
                    },
                },
                .err => |err| try writeFinalJsonResponse(request, .{}, .{
                    .jsonrpc = "2.0",
                    .id = rpc_request.id,
                    .@"error" = err,
                }),
            };
        },
        // sendTransaction requires special handling: preflight simulation failures must be
        // returned as JSON-RPC errors with code -32002, matching agave's behavior.
        // See: https://github.com/anza-xyz/agave/blob/master/rpc-client-api/src/custom_error.rs#L130-L136
        .sendTransaction => {
            const allocator = json_arena;
            const result = server_ctx.rpc_hooks.call(
                allocator,
                .sendTransaction,
                rpc_request.method.sendTransaction,
            ) catch |e| switch (e) {
                error.MethodNotImplemented => {
                    try sendFinalMethodNotFound(request, logger, .sendTransaction, rpc_request.id);
                    return;
                },
            };

            return switch (result) {
                .ok => |response| switch (response) {
                    .signature => |s| try writeFinalJsonResponse(request, .{}, .{
                        .jsonrpc = "2.0",
                        .id = rpc_request.id,
                        .result = s,
                    }),
                    .preflight_failure => |failure| blk: {
                        var msg_buf: [128]u8 = undefined;
                        const message = std.fmt.bufPrint(
                            &msg_buf,
                            "Transaction simulation failed: {s}",
                            .{@tagName(failure.err)},
                        ) catch "Transaction simulation failed";
                        break :blk try writeFinalJsonResponse(request, .{}, .{
                            .jsonrpc = "2.0",
                            .id = rpc_request.id,
                            .@"error" = SendTransactionPreflightError{
                                .message = message,
                                .data = .{
                                    .err = failure.err,
                                    .logs = failure.logs,
                                    .unitsConsumed = failure.units_consumed,
                                    .loadedAccountsDataSize = failure.loaded_accounts_data_size,
                                },
                            },
                        });
                    },
                },
                .err => |err| try writeFinalJsonResponse(request, .{}, .{
                    .jsonrpc = "2.0",
                    .id = rpc_request.id,
                    .@"error" = err,
                }),
            };
        },
        inline else => |method| {
            zone.name(@tagName(method));

            // For unimplemented methods, hard-code sending a not-found error.
            const FieldType = @FieldType(sig.rpc.methods.MethodAndParams, @tagName(method));
            if (comptime FieldType == noreturn) {
                try sendFinalMethodNotFound(request, logger, method, rpc_request.id);
                return;
            }

            const allocator = json_arena;
            const result = blk: {
                const handler_zone = tracy.Zone.init(@src(), .{ .name = "rpc.handler" });
                defer handler_zone.deinit();
                break :blk server_ctx.rpc_hooks.call(
                    allocator,
                    method,
                    @field(rpc_request.method, @tagName(method)),
                ) catch |e| switch (e) {
                    error.MethodNotImplemented => {
                        try sendFinalMethodNotFound(request, logger, method, rpc_request.id);
                        return;
                    },
                };
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
    const zone = tracy.Zone.init(@src(), .{ .name = "rpc.serialize" });
    defer zone.deinit();

    const content_length = blk: {
        var cw = std.io.Writer.Discarding.init(&.{});
        std.json.Stringify.value(json_value, .{}, &cw.writer) catch unreachable;
        break :blk cw.count;
    };

    var send_buffer: [4096]u8 = undefined;
    var response = request.respondStreaming(&send_buffer, .{
        .content_length = content_length,
        .respond_options = blk: {
            var opts = http_respond_opts;
            // The connection is closed at the end of request handling.
            // Keep-alive must be disabled to avoid clients reusing dead sockets.
            opts.keep_alive = false;
            opts.extra_headers = json_headers;
            break :blk opts;
        },
    }) catch |err| switch (err) {
        error.HttpExpectationFailed => return,
        error.WriteFailed => return error.SystemIoError,
    };

    std.json.Stringify.value(json_value, .{}, &response.writer) catch |err| switch (err) {
        error.WriteFailed => return error.SystemIoError,
    };
    response.end() catch |err| switch (err) {
        error.WriteFailed => return error.SystemIoError,
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
