const httpz = @import("httpz");
const std = @import("std");
const GossipService = @import("../gossip/gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;
const testing = std.testing;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const t = @import("types.zig");
const RpcServiceProcessor = @import("service.zig").RpcServiceProcessor;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub const State = struct {
    rpc_service_processor: *RpcServiceProcessor,

    pub fn init(rpc_service_processor: *RpcServiceProcessor) State {
        return State{
            .rpc_service_processor = rpc_service_processor,
        };
    }
};

pub const ReqCtx = struct {
    id: []const u8,
    state: State,
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

    const context = ReqCtx{
        .id = "",
        .state = global,
    };

    return action(context, req, res);
}

const get_account_info = "getAccountInfo";

fn rpcHandler(ctx: ReqCtx, req: *httpz.Request, res: *httpz.Response) !void {
    // status code 200 is implicit.

    // The json helper will automatically set the res.content_type = httpz.ContentType.JSON;
    // Here we're passing an inferred anonymous structure, but you can pass anytype
    // (so long as it can be serialized using std.json.stringify)

    if (req.body()) |body| {
        var jrpc_request = try std.json.parseFromSlice(t.JsonRpcRequest, allocator, body, .{});
        defer jrpc_request.deinit();

        if (std.mem.eql(u8, jrpc_request.value.method, "getIdentity")) {
            var result = ctx.state.rpc_service_processor.getIdentity();
            switch (result) {
                .Err => {
                    var error_response: t.JsonRpcResponse(t.RpcIdentity) = .{
                        .id = "1",
                        .jsonrpc = "2.0",
                        .@"error" = t.ErrorObject{
                            .code = -32000,
                            .message = "Not implemented",
                        },
                        .result = null,
                    };
                    return try res.json(error_response, .{});
                },
                .Ok => |value| {
                    var success_response: t.JsonRpcResponse(t.RpcIdentity) = .{
                        .id = "1",
                        .jsonrpc = "2.0",
                        .result = value,
                        .@"error" = null,
                    };

                    return try res.json(success_response, .{
                        .emit_null_optional_fields = false,
                        .emit_strings_as_arrays = false,
                    });
                },
            }
        } else if (std.mem.eql(u8, jrpc_request.value.method, "getClusterNodes")) {
            var result = ctx.state.rpc_service_processor.getClusterNodes();
            switch (result) {
                .Err => |err| {
                    _ = err;

                    var error_response: t.JsonRpcResponse([]t.RpcContactInfo) = .{
                        .id = "1",
                        .jsonrpc = "2.0",
                        .@"error" = t.ErrorObject{
                            .code = -32000,
                            .message = "error",
                        },
                        .result = null,
                    };
                    return try res.json(error_response, .{});
                },
                .Ok => |value| {
                    var success_response: t.JsonRpcResponse([]t.RpcContactInfo) = .{
                        .id = "1",
                        .jsonrpc = "2.0",
                        .result = value,
                        .@"error" = null,
                    };

                    return try res.json(success_response, .{
                        .emit_null_optional_fields = false,
                        .emit_strings_as_arrays = false,
                    });
                },
            }
        } else {
            var error_response: t.JsonRpcResponse([]t.RpcContactInfo) = .{
                .id = "1",
                .jsonrpc = "2.0",
                .@"error" = t.ErrorObject{
                    .code = -32000,
                    .message = "Not implemented!",
                },
                .result = null,
            };
            return try res.json(error_response, .{});
        }
    }

    try res.json(.{ .id = "1", .jsonrpc = "2.0", .result = true }, .{});
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

// test "rpc.server: json rpc server inits" {
//     var rpc_service_processor = RpcServiceProcessor.init();
//     var state = State.init(null, &rpc_service_processor);

//     var logger = Logger.init(testing.allocator, .debug);
//     defer logger.deinit();

//     var server = try JsonRpcServer.init(testing.allocator, state, logger, 3000);
//     defer server.deinit();

//     try server.listenAndServe();
// }
