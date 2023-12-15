const httpz = @import("httpz");
const std = @import("std");
const GossipService = @import("../gossip/gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;

pub const State = struct {
    gossip_service: *GossipService,

    const Self = @This();

    pub fn init(gossip_service: *GossipService) Self {
        return Self{
            .gossip_service = gossip_service,
        };
    }
};

pub const ReqCtx = struct {
    id: []const u8,
};

pub const JsonRpcServer = struct {
    server: Server,
    logger: Logger,
    port: u16,

    const Self = @This();
    const Server = httpz.ServerCtx(State, ReqCtx);

    pub fn init(allocator: std.mem.Allocator, state: State, logger: Logger, port: u16) !Self {
        var server = try Server.init(allocator, .{ .port = port }, state);

        server.notFound(notFound);
        server.errorHandler(errorHandler);

        var router = server.router();
        router.post("/rpc", rpcHandler);

        return Self{
            .server = server,
            .logger = logger,
            .port = port,
        };
    }

    pub fn listenAndServe(self: *Self) !void {
        self.logger.debugf("started rpc server listener on 0.0.0.0:{d}", .{self.port});
        return self.server.listen();
    }
};

fn rpcHandler(_: ReqCtx, _: *httpz.Request, res: *httpz.Response) !void {
    // status code 200 is implicit.

    // The json helper will automatically set the res.content_type = httpz.ContentType.JSON;
    // Here we're passing an inferred anonymous structure, but you can pass anytype
    // (so long as it can be serialized using std.json.stringify)

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
    std.log.warn("httpz: unhandled exception for request: {s}\nErr: {}", .{ req.url.raw, err });
}
