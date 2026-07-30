const std = @import("std");
const std14 = @import("std14");
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
        const response = requestIpEcho(socket_addr.toAddress(), .{}) catch |e| {
            logger.err().logf("failed ip echo: {}", .{e});
            continue;
        };
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
    const conn = try std.net.tcpConnectToAddress(addr);
    defer conn.close();

    { // send request
        var write_buf: [256]u8 = undefined;
        var conn_writer = conn.writer(&write_buf);
        const writer: *std.io.Writer = &conn_writer.interface;
        try writer.writeAll(&(.{0} ** HEADER_LENGTH));
        try sig.bincode.write(std14.deprecatedWriter(writer), message, .{});
        try writer.writeAll("\n");
        try writer.flush();
    }

    // receive response
    var read_buf: [64]u8 = undefined;
    var reader = conn.reader(&read_buf);
    if (HEADER_LENGTH != try reader.interface().discard(.limited(HEADER_LENGTH))) {
        return error.InsufficientData;
    }
    const assert_allocator = sig.utils.allocators.failing.allocator(.{
        .alloc = .assert,
        .resize = .assert,
        .free = .assert,
    });
    return try sig.bincode.read(
        assert_allocator,
        IpEchoResponse,
        std14.deprecatedReader(reader.interface()),
        .{},
    );
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
    write_buffer: [4096]u8,
    stream: std.net.Stream,
    stream_reader: std.net.Stream.Reader,
    stream_writer: std.net.Stream.Writer,
    server: std.http.Server,
    connection_address: std.net.Address,
    logger: Logger,

    fn create(
        allocator: std.mem.Allocator,
        connection: std.net.Server.Connection,
        logger: Logger,
    ) std.mem.Allocator.Error!*ConnectionTask {
        const hct = try allocator.create(ConnectionTask);
        errdefer allocator.destroy(hct);

        // first init fields that don't depend on self-referential pointers
        hct.* = .{
            .allocator = allocator,
            .stream = connection.stream,
            .connection_address = connection.address,
            .logger = logger,
            .stream_reader = undefined,
            .stream_writer = undefined,
            .read_buffer = undefined,
            .write_buffer = undefined,
            .server = undefined,
        };

        // now init the reader/writer that reference our buffers
        hct.stream_reader = .init(connection.stream, &hct.read_buffer);
        hct.stream_writer = .init(connection.stream, &hct.write_buffer);
        hct.server = .init(
            hct.stream_reader.interface(),
            &hct.stream_writer.interface,
        );

        return hct;
    }

    fn deinitAndDestroy(
        self: *ConnectionTask,
    ) void {
        self.stream_writer.interface.flush() catch {};
        self.stream.close();
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    fn handleNoError(hct: *ConnectionTask) void {
        handle(hct) catch |err| {
            if (@errorReturnTrace()) |st| {
                std.log.err("{s}:\n{f}", .{ @errorName(err), st });
            } else {
                std.log.err("{s}", .{@errorName(err)});
            }
        };
    }

    fn handle(hct: *ConnectionTask) !void {
        defer hct.deinitAndDestroy();

        var request = try hct.server.receiveHead();

        if (request.head.method != .POST or
            !std.mem.eql(u8, request.head.target, "/"))
        {
            try httpRespondError(&request, .not_found, "");
            return;
        }

        // save content_length before readerExpectNone invalidates head strings
        const content_length = request.head.content_length;

        hct.logger.debug().log("handling echo request");

        var reader_buf: [4096]u8 = undefined;
        const reader = request.readerExpectNone(&reader_buf);

        var request_buf: [256]u8 = undefined;
        const request_bytes = if (content_length) |len| blk: {
            const read_len: usize = @min(len, request_buf.len);
            reader.readSliceAll(request_buf[0..read_len]) catch break :blk &[_]u8{};
            break :blk request_buf[0..read_len];
        } else blk: {
            // no content-length, read what's available
            const n = reader.readSliceShort(&request_buf) catch break :blk &[_]u8{};
            break :blk request_buf[0..n];
        };

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

        const socket_addr: SocketAddr = .initAddress(hct.connection_address);
        const ip_echo_response: IpEchoResponse = .{
            .address = socket_addr.ip(),
            // TODO: correct shred version needs to be propagated here
            .shred_version = .{ .value = 0 },
        };

        // compute content length by serializing to a buffer first
        var json_buffer: [512]u8 = undefined;
        var stream = std.io.Writer.fixed(&json_buffer);
        try std.json.fmt(ip_echo_response, .{}).format(&stream);
        const content_len = stream.end;

        var send_buffer: [4096]u8 = undefined;
        var response = try request.respondStreaming(&send_buffer, .{
            .content_length = content_len,
            .respond_options = .{
                .version = .@"HTTP/1.0",
                .status = .ok,
                .keep_alive = false,
            },
        });
        // write directly to the Writer using the pre-serialized JSON
        try response.writer.writeAll(json_buffer[0..content_len]);
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

    // create request
    var request = try client.request(.POST, try std.Uri.parse("http://127.0.0.1:34333/"), .{
        .version = .@"HTTP/1.0",
        .keep_alive = false,
    });
    defer request.deinit();

    const ip_echo_request: IpEchoRequest = .{
        .tcp_ports = .{ 1000, 2000, 3000, 4000 },
        .udp_ports = .{ 1000, 2000, 3000, 4000 },
    };
    // std.json.fmt(value: anytype, options: Options).format(writer: *Writer)
    var w = std.io.Writer.Allocating.init(std.testing.allocator);
    defer w.deinit();
    try std.json.fmt(ip_echo_request, .{}).format(&w.writer);
    const request_bytes = w.written();

    // must set content_length before calling sendBody
    request.transfer_encoding = .{ .content_length = request_bytes.len };

    var body_buf: [4096]u8 = undefined;
    var body_writer = try request.sendBody(&body_buf);
    try body_writer.writer.writeAll(request_bytes);
    try body_writer.end();

    var server_header_buff: [4096]u8 = undefined;
    var response = try request.receiveHead(&server_header_buff);

    try std.testing.expectEqual(.ok, response.head.status);

    // read body
    var transfer_buffer: [4096]u8 = undefined;
    const body = try response.reader(&transfer_buffer).allocRemaining(
        std.testing.allocator,
        .limited(819_200),
    );
    defer std.testing.allocator.free(body);

    // deserialize json into type
    const resp = try std.json.parseFromSlice(IpEchoResponse, std.testing.allocator, body, .{});
    defer resp.deinit();

    try std.testing.expectEqual(IpAddr.initIpv4(.{ 127, 0, 0, 1 }), resp.value.address);
    try std.testing.expectEqual(ShredVersion{ .value = 0 }, resp.value.shred_version);
}
