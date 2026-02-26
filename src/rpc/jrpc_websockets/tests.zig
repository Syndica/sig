const std = @import("std");
const sig = @import("sig");
const xev = @import("xev");
const ws = @import("webzockets");

const lib = @import("lib.zig");
const types = lib.types;
const sub_map_mod = lib.sub_map;
const handler_mod = lib.handler;
const runtime_mod = lib.runtime;
const metrics_mod = lib.metrics;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Account = sig.core.Account;

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;

const JRPCHandler = handler_mod.JRPCHandler;
const WebSocketServer = JRPCHandler.WebSocketServer;
const RuntimeContext = runtime_mod.RuntimeContext;

// Re-export all module tests.
test {
    _ = lib;
}

/// Bundles all server-side state needed for an in-process test server.
const TestServer = struct {
    allocator: std.mem.Allocator,
    metrics: metrics_mod.Metrics,
    inbound_event_queue: Channel(types.EventMsg),
    commit_queue: Channel(types.CommitMsg),
    loop: xev.Loop,
    loop_async: xev.Async,
    xev_pool: xev.ThreadPool,
    ser_pool: ThreadPool,
    sub_map: sub_map_mod.RPCSubMap,
    ctx: RuntimeContext,
    server: WebSocketServer,
    port: u16,

    fn start(allocator: std.mem.Allocator) !*TestServer {
        const self = try allocator.create(TestServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.metrics = .{};

        self.inbound_event_queue = try Channel(types.EventMsg).init(allocator);
        errdefer self.inbound_event_queue.deinit();

        self.commit_queue = try Channel(types.CommitMsg).init(allocator);
        errdefer self.commit_queue.deinit();

        self.xev_pool = xev.ThreadPool.init(.{});

        self.loop = try xev.Loop.init(.{ .thread_pool = &self.xev_pool });
        errdefer self.loop.deinit();

        self.loop_async = try xev.Async.init();
        errdefer self.loop_async.deinit();

        self.ser_pool = ThreadPool.init(.{ .max_threads = 2 });

        self.sub_map = sub_map_mod.RPCSubMap.init(allocator, 1024);
        errdefer self.sub_map.deinit();

        self.ctx = .{
            .allocator = allocator,
            .sub_map = &self.sub_map,
            .inbound_event_queue = &self.inbound_event_queue,
            .commit_queue = &self.commit_queue,
            .loop_async = &self.loop_async,
            .serialization_pool = &self.ser_pool,
            .metrics = &self.metrics,
            .max_batch_bytes = 64 * 1024,
            .loop = &self.loop,
        };
        self.ctx.armAsyncWait();

        // Bind to port 0 to get an OS-assigned ephemeral port.
        const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        self.server = try WebSocketServer.init(allocator, &self.loop, .{
            .address = address,
            .handler_context = &self.ctx,
        });
        self.server.accept();

        // Get the OS-assigned ephemeral port from the bound socket.
        var addr: std.posix.sockaddr.storage = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
        std.posix.getsockname(self.server.listen_socket.fd, @ptrCast(&addr), &addr_len) catch
            return error.GetSockNameFailed;
        // Extract port from the sockaddr_in (IPv4).
        const sa_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&addr));
        self.port = std.mem.bigToNative(u16, sa_in.port);
        return self;
    }

    /// Inject an event into the inbound queue and wake the loop.
    fn injectEvent(self: *TestServer, event: types.EventMsg) void {
        self.inbound_event_queue.send(event) catch return;
        self.ctx.requestWakeup();
    }

    /// Run the loop for a bounded number of ticks. Returns when no more
    /// work is available or the tick limit is hit.
    fn tick(self: *TestServer, max_ticks: usize) void {
        for (0..max_ticks) |_| {
            self.loop.run(.no_wait) catch break;
        }
    }

    fn stop(self: *TestServer) void {
        self.ctx.running = false;
        self.server.shutdown(0, void, null, struct {
            fn onShutdown(_: ?*void, _: WebSocketServer.ShutdownResult) void {}
        }.onShutdown);

        // Drain remaining loop work for shutdown.
        for (0..500) |_| {
            self.loop.run(.no_wait) catch break;
            if (self.server.listen_socket_closed) {
                break;
            }
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }
    }

    fn deinit(self: *TestServer) void {
        const allocator = self.allocator;
        self.server.deinit();
        self.ctx.deinit();
        self.sub_map.deinit();
        self.ser_pool.shutdown();
        self.ser_pool.deinit();
        self.xev_pool.shutdown();
        self.xev_pool.deinit();
        self.loop_async.deinit();
        self.loop.deinit();
        self.commit_queue.deinit();
        self.inbound_event_queue.deinit();
        allocator.destroy(self);
    }
};

/// Client-side WebSocket handler for e2e tests.
/// Collects all received messages (text frames) and supports a scripted
/// sequence of messages to send on open / after each response.
///
/// Messages are queued before connecting. On open, the first message is sent.
/// Each time a response/notification arrives, the next queued message is sent.
/// When the last queued message has been sent and its response received, the
/// handler closes the connection. `close_after` controls how many received
/// messages trigger the close (defaults to total queued sends).
const TestClientHandler = struct {
    received: std.ArrayList([]const u8),
    to_send: std.ArrayList([]const u8),
    send_index: usize = 0,
    sent_buf: ?[]u8 = null,
    open_called: bool = false,
    close_called: bool = false,
    /// Close the connection after receiving this many messages.
    /// 0 means never auto-close (test must close manually or rely on server).
    close_after: usize = 0,
    allocator: std.mem.Allocator,
    conn_ref: ?*TestClient.Conn = null,

    fn init(allocator: std.mem.Allocator) TestClientHandler {
        return .{
            .received = .{},
            .to_send = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *TestClientHandler) void {
        for (self.received.items) |data| {
            self.allocator.free(data);
        }
        self.received.deinit(self.allocator);
        self.to_send.deinit(self.allocator);
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }

    /// Queue a text message to be sent in order.
    fn queueSend(self: *TestClientHandler, msg: []const u8) void {
        self.to_send.append(self.allocator, msg) catch {};
    }

    /// Queue a message and immediately try to send it (for mid-test sends).
    fn queueSendNow(self: *TestClientHandler, msg: []const u8) void {
        self.to_send.append(self.allocator, msg) catch {};
        if (self.conn_ref) |c| {
            self.maybeSendNext(c);
        }
    }

    fn maybeSendNext(self: *TestClientHandler, conn: anytype) void {
        if (self.sent_buf != null) {
            return;
        }
        if (self.send_index >= self.to_send.items.len) {
            return;
        }

        const msg = self.to_send.items[self.send_index];
        const copy = self.allocator.dupe(u8, msg) catch return;
        conn.sendText(copy) catch {
            self.allocator.free(copy);
            return;
        };
        self.sent_buf = copy;
        self.send_index += 1;
    }

    pub fn onOpen(self: *TestClientHandler, conn: *TestClient.Conn) void {
        self.open_called = true;
        self.conn_ref = conn;
        self.maybeSendNext(conn);
    }

    pub fn onMessage(self: *TestClientHandler, conn: *TestClient.Conn, message: ws.Message) void {
        const data = switch (message.type) {
            .text => message.data,
            else => return,
        };
        const copy = self.allocator.dupe(u8, data) catch return;
        self.received.append(self.allocator, copy) catch {
            self.allocator.free(copy);
            return;
        };

        // Try to send the next queued message.
        self.maybeSendNext(conn);

        // Auto-close when we've received enough messages.
        if (self.close_after > 0 and self.received.items.len >= self.close_after) {
            conn.close(.normal, "");
        }
    }

    pub fn onWriteComplete(self: *TestClientHandler, _: *TestClient.Conn) void {
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }

    pub fn onClose(self: *TestClientHandler, _: *TestClient.Conn) void {
        self.close_called = true;
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }
};

const TestClient = ws.Client(TestClientHandler, 4096);

/// Bundles client-side xev resources for e2e tests.
const TestClientEnv = struct {
    tp: xev.ThreadPool,
    loop: xev.Loop,
    csprng: ws.ClientMaskPRNG,

    fn start(self: *TestClientEnv) !void {
        self.tp = xev.ThreadPool.init(.{});
        self.loop = try xev.Loop.init(.{ .thread_pool = &self.tp });
        var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        self.csprng = ws.ClientMaskPRNG.init(seed);
    }

    fn deinit(self: *TestClientEnv) void {
        self.loop.deinit();
        self.tp.shutdown();
        self.tp.deinit();
    }
};

/// Run server and client loops together for a bounded number of iterations.
/// Interleaves ticks to allow the async wakeup / event delivery cycle.
/// Stops early if the handler's close callback has fired.
fn runBothLoops(
    server: *TestServer,
    client_env: *TestClientEnv,
    handler: *TestClientHandler,
    max_iters: usize,
) void {
    for (0..max_iters) |_| {
        if (handler.close_called) {
            break;
        }
        server.tick(50);
        client_env.loop.run(.no_wait) catch break;
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

/// Run loops until a condition is met or a timeout is reached.
fn runBothLoopsUntil(
    server: *TestServer,
    client_env: *TestClientEnv,
    comptime predicate: fn (*TestClientHandler) bool,
    handler: *TestClientHandler,
    timeout_ms: u32,
) void {
    const deadline = @as(u64, @intCast(std.time.milliTimestamp())) + timeout_ms;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline) {
        server.tick(50);
        client_env.loop.run(.no_wait) catch {};
        if (predicate(handler)) {
            return;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

/// Wait until the handler has received at least `count` messages.
fn waitForMessages(
    server: *TestServer,
    client_env: *TestClientEnv,
    handler: *TestClientHandler,
    count: usize,
    timeout_ms: u32,
) void {
    const deadline = @as(u64, @intCast(std.time.milliTimestamp())) + timeout_ms;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline) {
        server.tick(50);
        client_env.loop.run(.no_wait) catch {};
        if (handler.received.items.len >= count) {
            return;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

fn parseResultU64(response: []const u8) ?u64 {
    const needle = "\"result\":";
    const start = std.mem.indexOf(u8, response, needle) orelse {
        return null;
    };

    var i = start + needle.len;
    while (i < response.len and std.ascii.isWhitespace(response[i])) : (i += 1) {}

    var end = i;
    while (end < response.len and std.ascii.isDigit(response[end])) : (end += 1) {}
    if (end == i) {
        return null;
    }

    return std.fmt.parseUnsigned(u64, response[i..end], 10) catch null;
}

/// Parameterized e2e test: subscribe → inject event → verify notification → unsubscribe.
fn subNotifUnsubTest(
    subscribe_msg: []const u8,
    unsubscribe_msg: []const u8,
    event: types.EventMsg,
    expected_in_notif: []const []const u8,
) !void {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(subscribe_msg);
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = TestClient.init(
        allocator,
        &client_env.loop,
        &handler,
        &conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null,
    );

    server.injectEvent(event);

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(
        std.mem.indexOf(u8, notif, "Notification\"") != null,
    );
    for (expected_in_notif) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, notif, needle) != null);
    }

    handler.queueSendNow(unsubscribe_msg);

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"result\":true") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "e2e: client subscribes to slot, receives notification, unsubscribes" {
    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
    ,
        .{
            .method = .slot,
            .event_data = .{ .slot = .{ .slot = 100, .parent = 99, .root = 68 } },
        },
        &.{ "\"slot\":100", "\"parent\":99", "\"root\":68" },
    );
}

test "e2e: client subscribes to account, receives notification, unsubscribes" {
    const allocator = std.testing.allocator;
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xAA);
    var owner_pk: Pubkey = undefined;
    @memset(&owner_pk.data, 0xBB);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xDE;
    data_buf[1] = 0xAD;
    const account = Account{
        .lamports = 42_000,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = owner_pk,
        .executable = false,
        .rent_epoch = 0,
    };
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);

    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    ,
        .{
            .method = .account,
            .event_data = .{ .account = .{ .rc = rc, .slot = 55 } },
        },
        &.{ "\"lamports\":42000", "\"slot\":55" },
    );
}

test "e2e: client subscribes to logs, receives notification, unsubscribes" {
    var sig_bytes: [64]u8 = undefined;
    @memset(&sig_bytes, 0xBE);

    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all"]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"logsUnsubscribe","params":[1]}
    ,
        .{
            .method = .logs,
            .event_data = .{ .logs = .{
                .signature = Signature.fromBytes(sig_bytes),
                .num_logs = 3,
                .slot = 77,
            } },
        },
        &.{ "\"log line 0\"", "\"log line 1\"", "\"log line 2\"", "\"slot\":77" },
    );
}

test "e2e: duplicate subscribe returns error" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // Subscribe twice with the same params.
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":2,"method":"slotSubscribe","params":[]}
    );
    handler.close_after = 2;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = TestClient.init(
        allocator,
        &client_env.loop,
        &handler,
        &conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client.connect();

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    // First response: success.
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

    // Second response: duplicate error.
    const dup = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, dup, "\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, dup, "\"code\":-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, dup, "duplicate subscription") != null);

    runBothLoops(server, &client_env, &handler, 100);
}

test "e2e: unsubscribe unknown sub_id returns error" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotUnsubscribe","params":[999]}
    );
    handler.close_after = 1;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = TestClient.init(
        allocator,
        &client_env.loop,
        &handler,
        &conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    const resp = handler.received.items[0];
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"code\":-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "subscription not found") != null);

    runBothLoops(server, &client_env, &handler, 100);
}

test "e2e: json-rpc request error codes follow spec" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // -32601 method not found
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"nonexistentMethod","params":[]}
    );
    // -32600 invalid request (missing params)
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":2,"method":"slotSubscribe"}
    );
    // -32602 invalid params (wrong param count)
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":3,"method":"accountSubscribe","params":[]}
    );
    // -32700 parse error (malformed JSON)
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":4,"method":"slotSubscribe","params":[]
    );
    handler.close_after = 4;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = TestClient.init(
        allocator,
        &client_env.loop,
        &handler,
        &conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client.connect();

    waitForMessages(server, &client_env, &handler, 4, 5000);
    try std.testing.expect(handler.received.items.len >= 4);

    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[0], "\"code\":-32601") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[0], "\"id\":1") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[1], "\"code\":-32600") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[1], "\"id\":2") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"code\":-32602") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"id\":3") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[3], "\"code\":-32700") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[3], "\"id\":null") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "e2e: multiple clients receive independent notifications" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    // Client 1: subscribes to slot.
    var handler1 = TestClientHandler.init(allocator);
    defer handler1.deinit();
    handler1.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    );
    handler1.close_after = 3;

    // Client 2: subscribes to logs.
    var handler2 = TestClientHandler.init(allocator);
    defer handler2.deinit();
    handler2.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all"]}
    );
    handler2.close_after = 3;

    var env1: TestClientEnv = undefined;
    try env1.start();
    defer env1.deinit();

    var env2: TestClientEnv = undefined;
    try env2.start();
    defer env2.deinit();

    var conn1: TestClient.Conn = undefined;
    var client1 = TestClient.init(
        allocator,
        &env1.loop,
        &handler1,
        &conn1,
        &env1.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client1.connect();

    var conn2: TestClient.Conn = undefined;
    var client2 = TestClient.init(
        allocator,
        &env2.loop,
        &handler2,
        &conn2,
        &env2.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client2.connect();

    // Wait for both subscribe responses.
    const deadline_sub = @as(u64, @intCast(std.time.milliTimestamp())) + 5000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline_sub) {
        server.tick(50);
        env1.loop.run(.no_wait) catch {};
        env2.loop.run(.no_wait) catch {};
        if (handler1.received.items.len >= 1 and handler2.received.items.len >= 1) {
            break;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    try std.testing.expect(handler1.received.items.len >= 1);
    try std.testing.expect(handler2.received.items.len >= 1);

    const sub_id1 = parseResultU64(handler1.received.items[0]) orelse {
        return error.TestUnexpectedResult;
    };
    const sub_id2 = parseResultU64(handler2.received.items[0]) orelse {
        return error.TestUnexpectedResult;
    };

    // Inject a slot event — only client 1 should get it.
    server.injectEvent(.{
        .method = .slot,
        .event_data = .{ .slot = .{ .slot = 200, .parent = 199, .root = 168 } },
    });

    // Inject a logs event — only client 2 should get it.
    var sig_bytes: [64]u8 = undefined;
    @memset(&sig_bytes, 0xAB);
    server.injectEvent(.{
        .method = .logs,
        .event_data = .{ .logs = .{
            .signature = Signature.fromBytes(sig_bytes),
            .num_logs = 1,
            .slot = 201,
        } },
    });

    // Wait for notifications on both.
    const deadline_notif = @as(u64, @intCast(std.time.milliTimestamp())) + 5000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline_notif) {
        server.tick(50);
        env1.loop.run(.no_wait) catch {};
        env2.loop.run(.no_wait) catch {};
        if (handler1.received.items.len >= 2 and handler2.received.items.len >= 2) {
            break;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    try std.testing.expect(handler1.received.items.len >= 2);
    try std.testing.expect(handler2.received.items.len >= 2);

    // Client 1 got a slot notification.
    const notif1 = handler1.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif1, "\"slot\":200") != null);

    // Client 2 got a logs notification.
    const notif2 = handler2.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"log line 0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"slot\":201") != null);

    // Now send unsubscribes after notifications are confirmed received.
    handler1.queueSendNow(switch (sub_id1) {
        1 =>
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
        ,
        2 =>
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[2]}
        ,
        else => return error.TestUnexpectedResult,
    });
    handler2.queueSendNow(switch (sub_id2) {
        1 =>
        \\{"jsonrpc":"2.0","id":2,"method":"logsUnsubscribe","params":[1]}
        ,
        2 =>
        \\{"jsonrpc":"2.0","id":2,"method":"logsUnsubscribe","params":[2]}
        ,
        else => return error.TestUnexpectedResult,
    });

    // Wait for unsubscribe responses on both.
    const deadline_done = @as(u64, @intCast(std.time.milliTimestamp())) + 5000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < deadline_done) {
        server.tick(50);
        env1.loop.run(.no_wait) catch {};
        env2.loop.run(.no_wait) catch {};
        if (handler1.received.items.len >= 3 and handler2.received.items.len >= 3) {
            break;
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }

    try std.testing.expect(handler1.received.items.len >= 3);
    try std.testing.expect(handler2.received.items.len >= 3);

    // Both got unsubscribe success.
    const unsub1 = handler1.received.items[2];
    const unsub2 = handler2.received.items[2];
    try std.testing.expect(std.mem.indexOf(u8, unsub1, "\"result\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsub2, "\"result\":true") != null);

    // Let close handshakes finish.
    for (0..200) |_| {
        if (handler1.close_called and handler2.close_called) {
            break;
        }
        server.tick(50);
        if (!handler1.close_called) {
            env1.loop.run(.no_wait) catch {};
        }
        if (!handler2.close_called) {
            env2.loop.run(.no_wait) catch {};
        }
        std.Thread.sleep(1 * std.time.ns_per_ms);
    }
}

test "e2e: no notifications after unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    // Subscribe then immediately unsubscribe. No auto-close so we can
    // verify no further notifications arrive.
    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
    );
    // Don't auto-close — we want to keep listening to verify silence.
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = TestClient.init(
        allocator,
        &client_env.loop,
        &handler,
        &conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, server.port) },
    );
    try client.connect();

    // Wait for subscribe response + unsubscribe response.
    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const unsub_resp = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, unsub_resp, "\"result\":true") != null);

    // Now inject an event AFTER unsubscribe.
    server.injectEvent(.{
        .method = .slot,
        .event_data = .{ .slot = .{ .slot = 300, .parent = 299, .root = 268 } },
    });

    // Give some time for the event to be processed.
    runBothLoops(server, &client_env, &handler, 200);

    // Should still have only 2 messages — no notification arrived.
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    // Explicitly close the connection since close_after is 0.
    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "e2e: client subscribes to program, receives notification, unsubscribes" {
    // Program subscriptions match account events where owner == subscribed program_id.
    // The subscribed program_id is CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB (0xAA * 32).
    const allocator = std.testing.allocator;
    var owner_pk: Pubkey = undefined;
    @memset(&owner_pk.data, 0xAA);
    var pk: Pubkey = undefined;
    @memset(&pk.data, 0xBB);
    const data_buf = try allocator.alloc(u8, 2);
    data_buf[0] = 0xCA;
    data_buf[1] = 0xFE;
    const account = Account{
        .lamports = 12345,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(data_buf),
        .owner = owner_pk,
        .executable = false,
        .rent_epoch = 0,
    };
    const rc = try types.RcAccountWithPubkey.init(allocator, pk, account);

    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"programUnsubscribe","params":[1]}
    ,
        .{
            .method = .account,
            .event_data = .{ .account = .{ .rc = rc, .slot = 88 } },
        },
        &.{
            "\"lamports\":12345",
            "\"slot\":88",
        },
    );
}

test "e2e: client subscribes to root, receives notification, unsubscribes" {
    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"rootUnsubscribe","params":[1]}
    ,
        .{
            .method = .root,
            .event_data = .{ .root = .{ .root = 256 } },
        },
        &.{"\"result\":256"},
    );
}
