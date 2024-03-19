const httpz = @import("httpz");
const std = @import("std");
const GossipService = @import("../gossip/service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;
const testing = std.testing;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const t = @import("types.zig");
const RpcRequestProcessor = @import("processor.zig").RpcRequestProcessor;
const Uuid = @import("../common/uuid.zig").Uuid;

pub const State = struct {
    rpc_request_processor: *RpcRequestProcessor,

    pub fn init(rpc_request_processor: *RpcRequestProcessor) State {
        return State{
            .rpc_request_processor = rpc_request_processor,
        };
    }
};

pub const ReqCtx = struct {
    id: Uuid,
    state: State,

    pub fn init(state: State) ReqCtx {
        return ReqCtx{
            .id = Uuid.init(),
            .state = state,
        };
    }
};

pub const JsonRpcServer = struct {
    server: Server,
    logger: Logger,
    port: u16,

    const Self = @This();
    const Server = httpz.ServerCtx(State, ReqCtx);

    pub fn init(alloc: std.mem.Allocator, state: State, logger: Logger, port: u16) !Self {
        var server = try Server.init(alloc, .{ .port = port }, state);

        server.notFound(notFound);
        server.errorHandler(errorHandler);

        // set a global dispatch for any routes defined from this point on
        server.dispatcher(dispatcher);

        var router = server.router();
        router.get("/", getHandler);
        router.options("/", optionsHandler);
        router.post("/", rpcHandler);

        return Self{
            .server = server,
            .logger = logger,
            .port = port,
        };
    }

    pub fn deinit(self: *Self) void {
        self.server.deinit();
    }

    pub fn listenAndServe(self: *Self) !void {
        self.logger.debugf("started rpc server listener on 0.0.0.0:{d}", .{self.port});
        return self.server.listen();
    }
};

fn dispatcher(global: State, action: httpz.Action(ReqCtx), req: *httpz.Request, res: *httpz.Response) !void {
    // If needed, req.arena is an std.mem.Allocator than can be used to allocate memory
    // and it'll exist for the life of this request.
    const context = ReqCtx.init(global);
    return action(context, req, res);
}

fn rpcHandler(ctx: ReqCtx, req: *httpz.Request, response: *httpz.Response) !void {
    if (req.body()) |body| {
        var jrpc_request = std.json.parseFromSlice(t.JsonRpcRequest, req.arena, body, .{}) catch |err| {
            return respondJsonRpcError(
                .null,
                response,
                t.jrpc_error_code_invalid_params,
                std.fmt.allocPrint(req.arena, "Invalid request body, expected type JsonRpcRequest: {any}", .{err}) catch unreachable,
            );
        };

        defer jrpc_request.deinit();
        return methodCall(req.arena, ctx.state.rpc_request_processor, &jrpc_request.value, response);
    } else {
        // return no body
        return respondJsonRpcError(
            .null,
            response,
            t.jrpc_error_code_invalid_request,
            "Missing request body, expected type JsonRpcRequest",
        );
    }
}

fn optionsHandler(ctx: ReqCtx, req: *httpz.Request, response: *httpz.Response) !void {
    _ = ctx;
    var allowed_origin = if (req.headers.get("Origin")) |v| v else "*";
    response.header("access-control-allow-origin", allowed_origin);
    response.header("access-control-allow-methods", "POST, GET, OPTIONS");
    response.header("access-control-max-age", "86400");
    response.header("connection", "Close");
    response.header("cache-control", "no-cache");
    response.status = 200;
    try response.write();
}

fn getHandler(ctx: ReqCtx, req: *httpz.Request, response: *httpz.Response) !void {
    _ = ctx;
    _ = req;
    response.status = 200;
    try response.writer().writeAll("Used HTTP Method is not allowed. POST or OPTIONS is required");
    try response.write();
}

inline fn methodCall(allocator: std.mem.Allocator, processor: *RpcRequestProcessor, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
    inline for (@typeInfo(t.RpcServiceImpl(RpcRequestProcessor, t.Result)).Struct.fields) |field| {
        if (strEquals(request.method, field.name)) {
            return RpcFunc(@field(RpcRequestProcessor, field.name)).call(allocator, processor, request, response);
        }
    }

    return respondJsonRpcError(
        request.id,
        response,
        t.jrpc_error_code_internal_error,
        "not implemented",
    );
}

inline fn strEquals(value: []const u8, other: []const u8) bool {
    return std.mem.eql(u8, value, other);
}

pub fn RpcFunc(comptime func: anytype) type {
    const S = struct {
        fn call(allocator: std.mem.Allocator, processor: *RpcRequestProcessor, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
            if (request.params != .array) {
                return respondJsonRpcError(
                    request.id,
                    response,
                    t.jrpc_error_code_invalid_params,
                    std.fmt.allocPrint(allocator, "Invalid params, expected type: array, got: {s} ", .{@tagName(request.params)}) catch unreachable,
                );
            }

            const Args = std.meta.ArgsTuple(@TypeOf(func));
            var args: Args = undefined;

            // first two func args are *Self and std.mem.Allocator so we don't count those
            const args_len = args.len - 2;

            if (request.params.array.items.len > args_len) {
                return respondJsonRpcError(
                    request.id,
                    response,
                    t.jrpc_error_code_invalid_params,
                    std.fmt.allocPrint(allocator, "Invalid params, expected {any} params, got: {any} ", .{ args_len, request.params.array.items.len }) catch unreachable,
                );
            }

            args[0] = processor;
            args[1] = allocator;
            inline for (std.meta.fields(Args)[2..], 2.., 0..) |field, argIndex, valueIndex| {
                if (valueIndex >= request.params.array.items.len) {
                    // if type is nullable, set to null
                    if (@typeInfo(field.type) == .Optional) {
                        args[argIndex] = null;
                    } else {
                        const type_name = switch (field.type) {
                            []const u8 => "string",
                            else => @typeName(field.type),
                        };

                        return respondJsonRpcError(
                            request.id,
                            response,
                            t.jrpc_error_code_invalid_params,
                            std.fmt.allocPrint(allocator, "Missing paramater position {any}, expected type: {s}", .{ valueIndex, type_name }) catch unreachable,
                        );
                    }
                } else {
                    var parsed = std.json.parseFromValue(field.type, allocator, request.params.array.items[valueIndex], .{}) catch |err| {
                        const type_name = switch (field.type) {
                            []const u8 => "string",
                            else => @typeName(field.type),
                        };

                        return respondJsonRpcError(
                            request.id,
                            response,
                            t.jrpc_error_code_invalid_params,
                            std.fmt.allocPrint(allocator, "Invalid paramater position {any}, expected type {s}: {any}", .{ valueIndex, type_name, err }) catch unreachable,
                        );
                    };

                    args[argIndex] = parsed.value;
                }
            }

            return respondWithJsonRpcResponse(allocator, @call(.auto, func, args), request, response);
        }
    };

    return S;
}

inline fn respondWithJsonRpcResponse(allocator: std.mem.Allocator, result: anytype, request: *t.JsonRpcRequest, response: *httpz.Response) !void {
    switch (result) {
        .Ok => |v| {
            var success_response: t.JsonRpcResponse(@TypeOf(result.Ok)) = .{
                .id = request.id,
                .jsonrpc = "2.0",
                .result = v,
                .@"error" = null,
            };

            return response.json(success_response, .{
                .emit_null_optional_fields = false,
                .emit_strings_as_arrays = false,
            });
        },
        .Err => |err| {
            var error_response: t.JsonRpcResponse(u0) = .{
                .id = request.id,
                .jsonrpc = "2.0",
                .@"error" = err.toErrorObject(allocator),
                .result = null,
            };

            return response.json(error_response, .{
                .emit_null_optional_fields = false,
                .emit_strings_as_arrays = false,
            });
        },
    }
}

inline fn respondJsonRpcError(request_id: t.Id, response: *httpz.Response, code: i32, message: []const u8) !void {
    var error_object = t.ErrorObject.init(code, message);

    var error_response: t.JsonRpcResponse(u0) = .{
        .id = request_id,
        .jsonrpc = "2.0",
        .@"error" = error_object,
        .result = null,
    };

    return response.json(error_response, .{
        .emit_null_optional_fields = false,
        .emit_strings_as_arrays = false,
    });
}

fn notFound(_: State, _: *httpz.Request, res: *httpz.Response) anyerror!void {
    res.status = 404;
    res.body = "Not Found";
}

// note that the error handler return `void` and not `!void`
fn errorHandler(_: State, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
    res.status = 500;
    res.body = "Internal Server Error";
    std.log.warn("unhandled exception for request: {s}\nErr: {}", .{ req.url.raw, err });
}
