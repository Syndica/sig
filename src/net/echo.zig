const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");
const ShredVersion = @import("../core/shred.zig").ShredVersion;
const SocketAddr = @import("net.zig").SocketAddr;
const logger = @import("../trace/log.zig").default_logger;
const Channel = @import("../sync/channel.zig").Channel;
const Atomic = std.atomic.Value;
const assert = std.debug.assert;
const testing = std.testing;
const http = std.http;
const bincode = @import("../bincode/bincode.zig");
const httpz = @import("httpz");

const MAX_PORT_COUNT_PER_MSG: usize = 4;
const MAX_REQ_HEADER_SIZE = 8192;
const SERVER_LISTENER_LINGERING_TIMEOUT: u64 = std.time.ns_per_s * 1;
const HEADER_LENGTH: usize = 4;

const IpEchoServerMessage = struct {
    tcp_ports: [MAX_PORT_COUNT_PER_MSG]u16 = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,
    udp_ports: [MAX_PORT_COUNT_PER_MSG]u16 = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,

    const Self = @This();

    pub fn init(tcp_ports: []u16, udp_ports: []u16) Self {
        assert(tcp_ports.len <= MAX_PORT_COUNT_PER_MSG and udp_ports.len <= MAX_PORT_COUNT_PER_MSG);
        var self = Self{};

        std.mem.copyForwards(u16, &self.tcp_ports, tcp_ports);
        std.mem.copyForwards(u16, &self.udp_ports, udp_ports);

        return self;
    }
};

const IpEchoServerResponse = struct {
    // Public IP address of request echoed back to the node.
    address: net.IpAddr,
    // Cluster shred-version of the node running the server.
    shred_version: ?ShredVersion,

    const Self = @This();

    pub fn init(addr: net.IpAddr) Self {
        return Self{
            .address = addr,
            .shred_version = ShredVersion{ .value = 0 },
        };
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    server: httpz.ServerCtx(void, void),
    exit: *const Atomic(bool),

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        exit: *const Atomic(bool),
    ) Self {
        return Self{
            .allocator = allocator,
            .server = httpz.Server().init(allocator, .{ .port = port }) catch unreachable,
            .exit = exit,
        };
    }

    pub fn deinit(
        self: *Self,
    ) void {
        self.kill();
    }

    pub fn kill(
        self: *Self,
    ) void {
        self.server.stop();
        logger.debug("closing server");
    }

    pub fn listenAndServe(
        self: *Self,
    ) !void {
        var router = self.server.router();
        router.post("/", handleEchoRequest);
        return self.server.listen();
    }
};

pub fn handleEchoRequest(req: *httpz.Request, res: *httpz.Response) !void {
    const body = req.body() orelse return error.NoBody;
    var ip_echo_server_message = try std.json.parseFromSlice(IpEchoServerMessage, res.arena, body, .{});
    defer ip_echo_server_message.deinit();

    logger.debugf("ip echo server message: {any}", .{ip_echo_server_message.value});

    // convert a u32 to Ipv4
    const socket_addr = SocketAddr.fromIpV4Address(res.conn.address);

    std.json.stringify(IpEchoServerResponse.init(net.IpAddr{ .ipv4 = socket_addr.V4.ip }), .{}, res.writer()) catch |err| {
        logger.errf("could not json stringify IpEchoServerResponse: {any}", .{err});
        return try returnBadRequest(res);
    };
}

pub fn returnBadRequest(
    resp: *httpz.Response,
) !void {
    resp.status = 400;
    resp.headers.add("content-type", "application/json");
    resp.body =
        \\ "{\"error\":\"bad request.\"}"
    ;
}

pub fn returnNotFound(
    resp: *httpz.Response,
) !void {
    resp.status = 404;
}

pub fn requestIpEcho(
    allocator: std.mem.Allocator,
    addr: std.net.Address,
    message: IpEchoServerMessage,
) !IpEchoServerResponse {
    // connect + send
    const conn = try std.net.tcpConnectToAddress(addr);
    defer conn.close();
    try conn.writeAll(&(.{0} ** HEADER_LENGTH));
    try bincode.write(conn.writer(), message, .{});
    try conn.writeAll("\n");

    // get response
    var buff: [32]u8 = undefined;
    const len = try conn.readAll(&buff);
    var bufferStream = std.io.fixedBufferStream(buff[HEADER_LENGTH..len]);
    return try bincode.read(allocator, IpEchoServerResponse, bufferStream.reader(), .{});
}

// TODO: FIX ME
// test "net.echo: Server works" {
//     const port: u16 = 34333;

//     var exit = Atomic(bool).init(false);

//     var server = Server.init(testing.allocator, port, logger(), &exit);
//     defer server.deinit();
//     var server_thread_handle = try std.Thread.spawn(.{}, Server.listenAndServe, .{&server});
//     if (builtin.os.tag == .linux) try server_thread_handle.setName("server_thread");

//     var client = std.http.Client{ .allocator = testing.allocator };
//     defer client.deinit();

//     // create request
//     const headers = std.http.Headers.init(testing.allocator);
//     var req = try client.request(.POST, try std.Uri.parse("http://localhost:34333/"), headers, .{});
//     defer req.deinit();
//     defer req.headers.deinit(); // we have to do this otherwise leaks (not sure why)
//     req.transfer_encoding = .chunked;
//     try req.headers.append("content-type", "text/plain");
//     try req.headers.append("accept", "*/*");

//     // tell server we want connection closed after response
//     try req.headers.append("connection", "close");

//     // start the request
//     try req.start();

//     var tcp_ports = [4]u16{ 1000, 2000, 3000, 4000 };
//     var udp_port = [4]u16{ 1000, 2000, 3000, 4000 };
//     const ip_echo_server_msg = IpEchoServerMessage.init(&tcp_ports, &udp_port);

//     // json stringify
//     var buff = [_]u8{0} ** 128;
//     var buffer = std.io.fixedBufferStream(&buff);
//     try std.json.stringify(ip_echo_server_msg, .{}, buffer.writer());

//     // write body
//     try req.writeAll(buffer.getWritten());
//     try req.finish();
//     try req.wait();

//     if (req.response.status != .ok) {
//         std.debug.print("req.response.status: {any}", .{req.response.status});
//         return error.ResponseStatusNot200;
//     }

//     // read body
//     const body = try req.reader().readAllAlloc(testing.allocator, 819200);
//     defer testing.allocator.free(body);
//     logger.field("body_length", body.len).field("body", body).debugf("received body", .{});

//     // deserialize json into type
//     var resp = try std.json.parseFromSlice(IpEchoServerResponse, testing.allocator, body, .{});
//     defer resp.deinit();

//     try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, resp.value.address.asV4());
//     try testing.expectEqual(@as(u16, 0), resp.value.shred_version.?.value);

//     server.kill();
//     server_thread_handle.join();
// }
