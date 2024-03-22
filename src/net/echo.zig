const std = @import("std");
const builtin = @import("builtin");
const net = @import("net.zig");
const ShredVersion = @import("../core/shred.zig").ShredVersion;
const SocketAddr = @import("net.zig").SocketAddr;
const Logger = @import("../trace/log.zig").Logger;
const Channel = @import("../sync/channel.zig").Channel;
const Atomic = std.atomic.Atomic;
const assert = std.debug.assert;
const testing = std.testing;
const http = std.http;
const bincode = @import("../bincode/bincode.zig");

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
            .shred_version = ShredVersion.init_manually_set(0),
        };
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    logger: Logger,
    server: http.Server,
    port: u16,
    conns: *Channel(*Response),
    conns_in_flight: Atomic(usize),
    exit: *const Atomic(bool),

    const Self = @This();
    const Response = http.Server.Response;
    const Request = http.Server.Request;

    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        logger: Logger,
        exit: *const Atomic(bool),
    ) Self {
        return Self{
            .allocator = allocator,
            .server = http.Server.init(allocator, .{ .kernel_backlog = 1024 }),
            .port = port,
            .logger = logger,
            .conns = Channel(*Response).init(allocator, 1024),
            .conns_in_flight = Atomic(usize).init(0),
            .exit = exit,
        };
    }

    pub fn deinit(
        self: *Self,
    ) void {
        self.conns.deinit();
        self.server.deinit();
    }

    pub fn kill(
        self: *Self,
    ) void {
        self.logger.debug("closing server");
        self.conns.close();
        // trigger acceptor loop to get new conn
        const conn = std.net.tcpConnectToAddress(
            std.net.Address.parseIp4("127.0.0.1", self.port) catch unreachable,
        ) catch return;
        conn.close();
    }

    fn handleConn(
        self: *Self,
        response: *Response,
    ) void {
        self.logger.debug("handling new connection");
        defer {
            self.logger.debug("connection done");
            response.deinit();
            self.allocator.destroy(response);
            _ = self.conns_in_flight.fetchSub(1, .SeqCst);
        }

        // if "Connection" header is "keep-alive", we don't close conn
        while (response.reset() != .closing and !self.conns.isClosed()) {
            // Handle errors during request processing.
            response.wait() catch |err| switch (err) {
                error.HttpHeadersInvalid => return,
                error.EndOfStream => continue,
                else => {
                    self.logger.errf("error waiting: {any}\n", .{err});
                    return;
                },
            };

            // Process the request.
            handleRequest(self.allocator, self.logger, response) catch |err| {
                self.logger.errf("error trying to handle req: {any}", .{err});
                return;
            };
        }
    }

    fn acceptorThread(
        self: *Self,
    ) !void {
        self.logger.debug("accepting new connections");
        while (!self.conns.isClosed() and !self.exit.load(std.atomic.Ordering.Unordered)) {
            // TODO: change to non-blocking socket
            var response = self.server.accept(.{
                .allocator = self.allocator,
                .header_strategy = .{ .dynamic = MAX_REQ_HEADER_SIZE },
            }) catch |err| {
                switch (err) {
                    error.ConnectionAborted => {
                        continue;
                    },
                    else => {
                        self.logger.errf("error trying to accept new conn: {any}\n", .{err});
                        return err;
                    },
                }
            };

            var resp = try self.allocator.create(Response);
            resp.* = response;

            // we track how many conns in flight
            _ = self.conns_in_flight.fetchAdd(1, .SeqCst);

            self.conns.send(resp) catch |err| {
                // in any error case, we destroy Response and decrement conns in flight
                self.allocator.destroy(resp);
                _ = self.conns_in_flight.fetchSub(1, .SeqCst);

                switch (err) {
                    error.ChannelClosed => {
                        return;
                    },
                    else => {
                        self.logger.errf("error sending Response to conns channel: {any}\n", .{err});
                        return err;
                    },
                }
            };
        }
    }

    pub fn listenAndServe(
        self: *Self,
    ) !void {
        try self.server.listen(std.net.Address.initIp4(.{ 0, 0, 0, 0 }, self.port));
        self.logger.debugf("started server listener on 0.0.0.0:{d}", .{self.port});

        // launch acceptor thread
        var acceptor_thread_handle = try std.Thread.spawn(.{}, Self.acceptorThread, .{self});

        // listen for conns, as we receive we handle them in own threads
        while (self.conns.receive()) |conn| {
            var handle = try std.Thread.spawn(.{}, Self.handleConn, .{ self, conn });
            handle.detach();
        }

        acceptor_thread_handle.join();

        var acceptor_closed_at = std.time.Instant.now() catch unreachable;
        // wait for connections in flight to complete before exiting listener
        while (self.conns_in_flight.load(.SeqCst) != 0) {
            var now = std.time.Instant.now() catch unreachable;

            // we wait for N time before breaking out of conns_in_flight wait guard
            if (now.since(acceptor_closed_at) > SERVER_LISTENER_LINGERING_TIMEOUT) {
                break;
            }

            // sleep 1ms to give conns in flight time
            std.time.sleep(std.time.ns_per_ms * 5);
        }

        self.logger.debug("listener done");
    }
};

pub fn returnBadRequest(
    resp: *http.Server.Response,
    logger: Logger,
) !void {
    resp.status = .bad_request;
    try resp.headers.append("content-type", "application/json");
    try resp.do();
    resp.writeAll("{\"error\":\"bad request.\"}") catch |err| {
        logger.errf("could not return bad request: {any}", .{err});
    };
    try resp.finish();
}

pub fn returnNotFound(
    resp: *http.Server.Response,
    logger: Logger,
) !void {
    _ = logger;
    resp.status = .not_found;
    try resp.headers.append("content-type", "text/plain");
    try resp.do();
    try resp.finish();
}

pub fn handleRequest(
    alloc: std.mem.Allocator,
    logger: Logger,
    resp: *http.Server.Response,
) !void {
    logger.debug("starting handling request");

    var req = resp.request;
    // Read the request body.
    const body = try resp.reader().readAllAlloc(alloc, 8192);
    defer alloc.free(body);

    // Route: POST /
    if (req.method == .POST and std.mem.eql(u8, req.target, "/")) {
        var ip_echo_server_message = try std.json.parseFromSlice(IpEchoServerMessage, alloc, body, .{});
        defer ip_echo_server_message.deinit();

        logger.debugf("ip echo server message: {any}", .{ip_echo_server_message.value});

        var buff = [_]u8{0} ** 1024;
        var buffer = std.io.fixedBufferStream(&buff);
        var addr: std.net.Ip4Address = resp.address.in;

        // convert a u32 to Ipv4
        var socket_addr = SocketAddr.initIpv4(.{
            @as(u8, @intCast(addr.sa.addr >> 24 & 0xFF)),
            @as(u8, @intCast(addr.sa.addr >> 16 & 0xFF)),
            @as(u8, @intCast(addr.sa.addr >> 8 & 0xFF)),
            @as(u8, @intCast(addr.sa.addr & 0xFF)),
        }, addr.getPort());

        std.json.stringify(IpEchoServerResponse.init(net.IpAddr{ .ipv4 = socket_addr.V4.ip }), .{}, buffer.writer()) catch |err| {
            logger.errf("could not json stringify IpEchoServerResponse: {any}", .{err});
            return try returnBadRequest(resp, logger);
        };

        resp.status = .ok;

        var chunked = false;
        try resp.headers.append("content-type", "application/json");
        if (req.headers.getFirstValue("transfer-encoding")) |connection_header_val| {
            if (std.mem.indexOf(u8, connection_header_val, "chunked") != null) {
                chunked = true;
                resp.transfer_encoding = .chunked;
            }
        }

        if (!chunked) {
            var content_length = try std.fmt.allocPrint(alloc, "{d}", .{buffer.getWritten().len});
            try resp.headers.append("content-length", content_length);
            alloc.free(content_length);
        }
        // write response body
        try resp.do();
        resp.writeAll(buffer.getWritten()) catch |err| {
            logger.errf("could not write all buffer: {any}\n", .{err});
            return try returnBadRequest(resp, logger);
        };
        try resp.finish();
    } else {
        try returnNotFound(resp, logger);
    }

    logger.debug("done handling request");
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
    try bincode.write(allocator, conn.writer(), message, .{});
    try conn.writeAll("\n");

    // get response
    var buff: [32]u8 = undefined;
    const len = try conn.readAll(&buff);
    var bufferStream = std.io.fixedBufferStream(buff[HEADER_LENGTH..len]);
    return try bincode.read(allocator, IpEchoServerResponse, bufferStream.reader(), .{});
}

test "net.echo: Server works" {
    const port: u16 = 34333;

    // initialize logger
    var logger = Logger.init(testing.allocator, Logger.TEST_DEFAULT_LEVEL);
    defer logger.deinit();
    logger.spawn();

    var exit = Atomic(bool).init(false);

    var server = Server.init(testing.allocator, port, logger, &exit);
    defer server.deinit();
    var server_thread_handle = try std.Thread.spawn(.{}, Server.listenAndServe, .{&server});
    if (builtin.os.tag == .linux) try server_thread_handle.setName("server_thread");

    var client = std.http.Client{ .allocator = testing.allocator };
    defer client.deinit();

    // create request
    var headers = std.http.Headers.init(testing.allocator);
    var req = try client.request(.POST, try std.Uri.parse("http://localhost:34333/"), headers, .{});
    defer req.deinit();
    defer req.headers.deinit(); // we have to do this otherwise leaks (not sure why)
    req.transfer_encoding = .chunked;
    try req.headers.append("content-type", "text/plain");
    try req.headers.append("accept", "*/*");

    // tell server we want connection closed after response
    try req.headers.append("connection", "close");

    // start the request
    try req.start();

    var tcp_ports = [4]u16{ 1000, 2000, 3000, 4000 };
    var udp_port = [4]u16{ 1000, 2000, 3000, 4000 };
    var ip_echo_server_msg = IpEchoServerMessage.init(&tcp_ports, &udp_port);

    // json stringify
    var buff = [_]u8{0} ** 128;
    var buffer = std.io.fixedBufferStream(&buff);
    try std.json.stringify(ip_echo_server_msg, .{}, buffer.writer());

    // write body
    try req.writeAll(buffer.getWritten());
    try req.finish();
    try req.wait();

    if (req.response.status != .ok) {
        std.debug.print("req.response.status: {any}", .{req.response.status});
        return error.ResponseStatusNot200;
    }

    // read body
    const body = try req.reader().readAllAlloc(testing.allocator, 819200);
    defer testing.allocator.free(body);
    logger.field("body_length", body.len).field("body", body).debugf("received body", .{});

    // deserialize json into type
    var resp = try std.json.parseFromSlice(IpEchoServerResponse, testing.allocator, body, .{});
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 0), resp.value.shred_version.?.value);

    server.kill();
    server_thread_handle.join();
}
