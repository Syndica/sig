const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");
const rpc = sig.rpc;

const server = @import("server.zig");
const requests = server.requests;
const connection = server.connection;
const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;

const Logger = sig.trace.Logger("rpc.server.basic");

pub const AcceptAndServeConnectionError =
    error{AcceptError} ||
    error{SetSocketSyncError} ||
    error{SystemIoError} ||
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
        .HEAD, .GET => try handleGetOrHead(server_ctx, &request, logger),
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
    server_ctx: *server.Context,
    request: *std.http.Server.Request,
    logger: Logger,
) !void {
    const conn = request.server.connection;
    switch (requests.getRequestTargetResolve(
        .from(logger),
        request.head.target,
        &server_ctx.accountsdb.latest_snapshot_gen_info,
    )) {
        inline .full_snapshot, .inc_snapshot => |pair| {
            const snap_info, var full_info_lg = pair;
            defer full_info_lg.unlock();

            const archive_name_bounded = snap_info.snapshotArchiveName();
            const archive_name = archive_name_bounded.constSlice();

            const archive_file = server_ctx.accountsdb.snapshot_dir.openFile(
                archive_name,
                .{},
            ) catch |err| {
                switch (err) {
                    error.FileNotFound => {
                        logger.err().logf("not found: {s}\n", .{sig.utils.fmt.tryRealPath(
                            server_ctx.accountsdb.snapshot_dir,
                            archive_name,
                        )});
                    },
                    else => {},
                }
                return error.SystemIoError;
            };
            defer archive_file.close();

            const archive_len = archive_file.getEndPos() catch
                return error.SystemIoError;

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

                while (true) {
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
                std.debug.assert(response.transfer_encoding.content_length == archive_len);
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

        .health => {
            request.respond("unknown", .{
                .status = .ok,
                .keep_alive = false,
            }) catch |err| switch (err) {
                error.ConnectionResetByPeer => return,
                else => return error.SystemIoError,
            };
            return;
        },

        .genesis_file => {
            logger.err()
                .field("conn", conn.address)
                .logf("Attempt to get our genesis file", .{});
            try respondSimpleErrorStatusBody(request, logger, .service_unavailable,
                \\Genesis file get is not yet implemented
            );
            return;
        },

        .not_found => {},
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

    switch (rpc_request.method) {
        .getAccountInfo => |params| {
            const config: rpc.methods.GetAccountInfo.Config = params.config orelse .{};
            const encoding = config.encoding orelse .base64;
            if (config.commitment) |commitment| {
                std.debug.panic("TODO: handle commitment={s}", .{@tagName(commitment)});
            }

            const account: sig.accounts_db.AccountsDB.AccountInCacheOrFile, //
            const account_slot: sig.core.Slot, //
            var account_lg: sig.accounts_db.AccountsDB.AccountInCacheOrFileLock //
            = (server_ctx.accountsdb.getSlotAndAccountInSlotRangeWithReadLock(
                &params.pubkey,
                // if it's null, it's null, there's no floor to the query.
                config.minContextSlot orelse null,
                null,
            ) catch return error.AccountsDbError) orelse {
                try respondSimpleErrorStatusBody(request, logger, .range_not_satisfiable, "");
                return;
            };
            defer account_lg.unlock();

            const Facts = struct {
                executable: bool,
                lamports: u64,
                owner: sig.core.Pubkey,
                rent_epoch: u64,
                space: u64,
            };

            const data_handle: AccountDataHandle, //
            const facts: Facts //
            = switch (account) {
                .file => |aif| .{ aif.data, .{
                    .executable = aif.account_info.executable,
                    .lamports = aif.account_info.lamports,
                    .owner = aif.account_info.owner,
                    .rent_epoch = aif.account_info.rent_epoch,
                    .space = aif.data.len(),
                } },
                .unrooted_map => |um| .{ um.data, .{
                    .executable = um.executable,
                    .lamports = um.lamports,
                    .owner = um.owner,
                    .rent_epoch = um.rent_epoch,
                    .space = um.data.len(),
                } },
            };

            const account_data_base64 = blk: {
                var account_data_base64: std.ArrayListUnmanaged(u8) = .{};
                defer account_data_base64.deinit(server_ctx.allocator);
                try base64EncodeAccount(
                    account_data_base64.writer(server_ctx.allocator),
                    data_handle,
                    config.dataSlice,
                );
                break :blk try account_data_base64.toOwnedSlice(server_ctx.allocator);
            };
            defer server_ctx.allocator.free(account_data_base64);

            const response_result: rpc.methods.GetAccountInfo.Response = .{
                .context = .{
                    .slot = account_slot,
                    .apiVersion = "2.0.15",
                },
                .value = .{
                    .data = .{ .encoded = .{
                        account_data_base64,
                        encoding,
                    } },
                    .executable = facts.executable,
                    .lamports = facts.lamports,
                    .owner = facts.owner,
                    .rentEpoch = facts.rent_epoch,
                    .space = facts.space,
                },
            };

            try writeFinalJsonResponse(request, .{}, .{
                .jsonrpc = "2.0",
                .id = rpc_request.id,
                .result = response_result,
            });
            return;
        },
        else => {
            try respondSimpleErrorStatusBody(request, logger, .not_implemented, "");
            return;
        },
    }
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

fn base64EncodeAccount(
    writer: anytype,
    data_handle: AccountDataHandle,
    data_slice: ?rpc.methods.common.DataSlice,
) !void {
    const acc_data_handle = if (data_slice) |ds|
        // TODO: handle potental integer overflow properly here
        data_handle.slice(
            @intCast(ds.offset),
            @intCast(ds.offset + ds.length),
        )
    else
        data_handle;

    var b64_enc_stream = sig.utils.base64.EncodingStream.init(std.base64.standard.Encoder);
    const b64_enc_writer_ctx = b64_enc_stream.writerCtx(writer);
    const b64_enc_writer = b64_enc_writer_ctx.writer();

    var frame_iter = acc_data_handle.iterator();
    while (frame_iter.nextFrame()) |frame_bytes| {
        try b64_enc_writer.writeAll(frame_bytes);
    }
    try b64_enc_writer_ctx.flush();
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
