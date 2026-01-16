const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const ShredVersion = sig.core.shred.ShredVersion;
const SocketAddr = sig.net.SocketAddr;
const IpAddr = sig.net.IpAddr;

const MAX_PORT_COUNT_PER_MSG: usize = 4;
const SERVER_LISTENER_LINGERING_TIMEOUT: u64 = std.time.ns_per_s * 1;
const HEADER_LENGTH: usize = 4;

const Logger = sig.trace.Logger("net.echo");

/// determine our shred version and ip. in the solana-labs client, the shred version
/// comes from the snapshot, and ip echo is only used to validate it.
pub fn getShredAndIPFromEchoServer(
    logger: Logger,
    socket_addresses: []const SocketAddr,
) !struct { shred_version: ?u16, ip: ?IpAddr } {
    var my_ip: ?IpAddr = null;
    var my_shred_version: ?u16 = null;

    for (socket_addresses) |socket_addr| {
        const response = requestIpEcho(socket_addr.toAddress(), .{}) catch continue;
        my_ip = my_ip orelse response.address;

        if (response.shred_version) |shred_version| {
            logger.info()
                .field("shred_version", shred_version.value)
                .field("ip", socket_addr)
                .log("ip echo response");
            my_shred_version = shred_version.value;
        }

        // fully break when we have both
        if (my_shred_version != null and my_ip != null) break;
    }

    return .{
        .shred_version = my_shred_version,
        .ip = my_ip,
    };
}

pub fn requestIpEcho(
    addr: std.net.Address,
    message: IpEchoRequest,
) !IpEchoResponse {
    // connect + send
    const conn = try std.net.tcpConnectToAddress(addr);
    defer conn.close();
    try conn.writeAll(&(.{0} ** HEADER_LENGTH));
    try sig.bincode.write(conn.writer(), message, .{});
    try conn.writeAll("\n");

    // get response
    var buff: [32]u8 = undefined;
    const len = try conn.readAll(&buff);
    var fbs = std.io.fixedBufferStream(buff[HEADER_LENGTH..len]);
    const assert_allocator = sig.utils.allocators.failing.allocator(.{
        .alloc = .assert,
        .resize = .assert,
        .free = .assert,
    });
    return try sig.bincode.read(assert_allocator, IpEchoResponse, fbs.reader(), .{});
}

const IpEchoRequest = struct {
    tcp_ports: [MAX_PORT_COUNT_PER_MSG]u16 = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,
    udp_ports: [MAX_PORT_COUNT_PER_MSG]u16 = [_]u16{0} ** MAX_PORT_COUNT_PER_MSG,
};

const IpEchoResponse = struct {
    /// Public IP address of request echoed back to the node.
    address: IpAddr,
    /// Cluster shred-version of the node running the server.
    shred_version: ?ShredVersion,
};

pub const Server = struct {
    logger: Logger,
    allocator: std.mem.Allocator,
    tcp: std.net.Server,
    thread_pool: *std.Thread.Pool,

    pub const InitError =
        std.net.Address.ListenError ||
        std.Thread.SpawnError ||
        std.mem.Allocator.Error;
    pub fn init(
        allocator: std.mem.Allocator,
        port: u16,
        logger: Logger,
    ) InitError!Server {
        const our_ip = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
        var tcp = try our_ip.listen(.{
            .force_nonblocking = true,
            .reuse_address = true,
        });
        errdefer tcp.deinit();

        const thread_pool = try allocator.create(std.Thread.Pool);
        errdefer allocator.destroy(thread_pool);
        try thread_pool.init(.{
            .allocator = allocator,
            .n_jobs = null,
        });
        errdefer thread_pool.deinit();

        return .{
            .logger = logger,
            .allocator = allocator,
            .tcp = tcp,
            .thread_pool = thread_pool,
        };
    }

    pub fn deinit(self: *Server) void {
        self.thread_pool.deinit(); // this will wait for all running jobs to complete
        self.allocator.destroy(self.thread_pool);
        self.tcp.stream.close();
    }

    pub fn spawnServe(self: *Server, exit: *std.atomic.Value(bool)) std.Thread.SpawnError!void {
        const thread = try std.Thread.spawn(.{}, serve, .{ self, exit });
        thread.detach();
    }

    pub fn serve(self: *Server, exit: *std.atomic.Value(bool)) !void {
        while (!exit.load(.acquire)) {
            const conn = self.tcp.accept() catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| return e,
            };
            errdefer conn.stream.close();

            // TODO: unify this with the code for the RPC server
            if (comptime builtin.target.os.tag.isDarwin()) set_flags: {
                const FlagsInt = @typeInfo(std.posix.O).@"struct".backing_integer.?;
                var flags_int: FlagsInt =
                    @intCast(try std.posix.fcntl(conn.stream.handle, std.posix.F.GETFL, 0));
                const flags: *std.posix.O =
                    std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));
                if (flags.NONBLOCK == false and flags.CLOEXEC == true) break :set_flags;
                flags.NONBLOCK = false;
                flags.CLOEXEC = true;
                _ = try std.posix.fcntl(conn.stream.handle, std.posix.F.SETFL, flags_int);
            }

            const hct = try ConnectionTask.create(
                self.allocator,
                conn,
                self.logger,
            );
            errdefer hct.deinitAndDestroy();

            try self.thread_pool.spawn(ConnectionTask.handleNoError, .{hct});
        }
    }
};

const ConnectionTask = struct {
    allocator: std.mem.Allocator,
    read_buffer: [4096]u8,
    server: std.http.Server,
    logger: Logger,

    fn create(
        allocator: std.mem.Allocator,
        connection: std.net.Server.Connection,
        logger: Logger,
    ) std.mem.Allocator.Error!*ConnectionTask {
        const hct = try allocator.create(ConnectionTask);
        errdefer allocator.destroy(hct);

        hct.* = .{
            .allocator = allocator,
            .read_buffer = undefined,
            .server = std.http.Server.init(connection, &hct.read_buffer),
            .logger = logger,
        };
        return hct;
    }

    fn deinitAndDestroy(
        self: *ConnectionTask,
    ) void {
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    fn handleNoError(hct: *ConnectionTask) void {
        handle(hct) catch |err| {
            if (@errorReturnTrace()) |st| {
                std.log.err("{s}:\n{}", .{ @errorName(err), st });
            } else {
                std.log.err("{s}", .{@errorName(err)});
            }
        };
    }

    fn handle(hct: *ConnectionTask) !void {
        defer hct.deinitAndDestroy();

        var request = try hct.server.receiveHead();
        const reader = sig.utils.io.narrowAnyReader(
            try request.reader(),
            std.http.Server.Request.ReadError,
        );

        if (request.head.method != .POST or
            !std.mem.eql(u8, request.head.target, "/"))
        {
            try httpRespondError(&request, .not_found, "");
            return;
        }

        hct.logger.debug().log("handling echo request");

        var request_buf: [256]u8 = undefined;
        const request_byte_count = try reader.readAll(&request_buf);
        const request_bytes = request_buf[0..request_byte_count];

        const ip_echo_request_result = std.json.parseFromSlice(
            IpEchoRequest,
            hct.allocator,
            request_bytes,
            .{ .allocate = .alloc_if_needed },
        ) catch |err| return switch (err) {
            error.OutOfMemory => try httpRespondError(&request, .insufficient_storage, ""),
            else => try httpRespondError(&request, .bad_request, ""),
        };
        const ip_echo_request = ip_echo_request_result.value;
        _ = ip_echo_request;
        ip_echo_request_result.deinit();

        const socket_addr: SocketAddr = .initAddress(request.server.connection.address);
        const ip_echo_response: IpEchoResponse = .{
            .address = socket_addr.ip(),
            // TODO: correct shred version needs to be propagated here
            .shred_version = .{ .value = 0 },
        };

        const content_len = blk: {
            var counter = std.io.countingWriter(std.io.null_writer);
            try std.json.stringify(ip_echo_response, .{}, counter.writer());
            break :blk counter.bytes_written;
        };

        var send_buffer: [4096]u8 = undefined;
        var response = request.respondStreaming(.{
            .send_buffer = &send_buffer,
            .content_length = content_len,
            .respond_options = .{
                .version = .@"HTTP/1.0",
                .status = .ok,
                .keep_alive = false,
            },
        });
        const writer = sig.utils.io.narrowAnyWriter(
            response.writer(),
            std.http.Server.Response.WriteError,
        );
        try std.json.stringify(ip_echo_response, .{}, writer);
        try response.end();
    }
};

fn httpRespondError(
    request: *std.http.Server.Request,
    status: std.http.Status,
    content: []const u8,
) !void {
    std.debug.assert( //
        status.class() == .client_error or
            status.class() == .server_error //
    );
    try request.respond(content, .{
        .version = .@"HTTP/1.0",
        .status = status,
        .keep_alive = false,
    });
}

test "net.echo: Server works" {
    if (sig.build_options.no_network_tests) return error.SkipZigTest;

    const port: u16 = 34333;

    var server = try Server.init(std.testing.allocator, port, .noop);
    defer server.deinit();

    var exit = std.atomic.Value(bool).init(false);
    defer exit.store(true, .release);
    try server.spawnServe(&exit);

    var client: std.http.Client = .{ .allocator = std.testing.allocator };
    defer client.deinit();

    var server_header_buff: [4096]u8 = undefined;

    // create request
    var request = try client.open(.POST, try std.Uri.parse("http://127.0.0.1:34333/"), .{
        .server_header_buffer = &server_header_buff,
        .version = .@"HTTP/1.0",
        .keep_alive = false,
    });
    defer request.deinit();

    const ip_echo_request: IpEchoRequest = .{
        .tcp_ports = .{ 1000, 2000, 3000, 4000 },
        .udp_ports = .{ 1000, 2000, 3000, 4000 },
    };
    const request_bytes = try std.json.stringifyAlloc(
        std.testing.allocator,
        ip_echo_request,
        .{},
    );
    defer std.testing.allocator.free(request_bytes);

    request.transfer_encoding = .{ .content_length = request_bytes.len };
    try request.send();
    try request.writeAll(request_bytes);
    try request.finish();
    try request.wait();

    try std.testing.expectEqual(.ok, request.response.status);

    // read body
    const body = try request.reader().readAllAlloc(std.testing.allocator, 819_200);
    defer std.testing.allocator.free(body);

    // deserialize json into type
    const resp = try std.json.parseFromSlice(IpEchoResponse, std.testing.allocator, body, .{});
    defer resp.deinit();

    try std.testing.expectEqual(IpAddr.initIpv4(.{ 127, 0, 0, 1 }), resp.value.address);
    try std.testing.expectEqual(ShredVersion{ .value = 0 }, resp.value.shred_version);
}
