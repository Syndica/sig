const std = @import("std");
pub const sig = @import("../../../../sig.zig");
const xev = @import("xev");
const ws = @import("webzockets");

const lib = @import("../../lib.zig");
const types = lib.types;
const sub_map_mod = lib.sub_map;
const handler_mod = lib.handler;
const Runtime = lib.Runtime;
const metrics_mod = lib.metrics;

pub const Pubkey = sig.core.Pubkey;
pub const Signature = sig.core.Signature;
pub const Account = sig.core.Account;

pub fn filledPubkey(fill: u8) Pubkey {
    var pubkey: Pubkey = undefined;
    @memset(&pubkey.data, fill);
    return pubkey;
}

pub fn createAccountShared(
    allocator: std.mem.Allocator,
    owner: Pubkey,
    lamports: u64,
    data: []const u8,
) !sig.runtime.AccountSharedData {
    const owned_data = try allocator.dupe(u8, data);
    var account = Account{
        .lamports = lamports,
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocatedOwned(owned_data),
        .owner = owner,
        .executable = false,
        .rent_epoch = 0,
    };
    defer account.deinit(allocator);

    return try sig.runtime.AccountSharedData.fromAccount(allocator, &account);
}

pub fn putAccountAtSlot(
    server: *TestServer,
    slot: u64,
    pubkey: Pubkey,
    owner: Pubkey,
    lamports: u64,
    data: []const u8,
) !sig.runtime.AccountSharedData {
    const account_shared = try createAccountShared(server.allocator, owner, lamports, data);
    errdefer account_shared.deinit(server.allocator);

    try server.account_db.db.put(slot, pubkey, account_shared);
    return account_shared;
}

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;

const JRPCHandler = handler_mod.JRPCHandler;
const WebSocketServer = JRPCHandler.WebSocketServer;
const SlotReadContext = Runtime.SlotReadContext;
const runtime_deinit_timeout_ms = 5 * std.time.ms_per_s;

/// Bundles all server-side state needed for an in-process test server.
pub const TestServer = struct {
    allocator: std.mem.Allocator,
    metrics: metrics_mod.Metrics,
    event_sink: *types.EventSink,
    commit_queue: Channel(types.CommitMsg),
    loop: xev.Loop,
    xev_pool: xev.ThreadPool,
    ser_pool: ThreadPool,
    sub_map: sub_map_mod.RPCSubMap,
    account_db: sig.accounts_db.Db.TestContext,
    slot_tracker: sig.replay.trackers.SlotTracker,
    ctx: Runtime,
    server: WebSocketServer,
    port: u16,

    pub fn start(allocator: std.mem.Allocator) !*TestServer {
        const self = try allocator.create(TestServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.metrics = .{};

        self.event_sink = try types.EventSink.create(allocator);
        errdefer self.event_sink.destroy();

        self.commit_queue = try Channel(types.CommitMsg).init(allocator);
        errdefer self.commit_queue.deinit();

        self.xev_pool = xev.ThreadPool.init(.{});

        self.loop = try xev.Loop.init(.{ .thread_pool = &self.xev_pool });
        errdefer self.loop.deinit();

        self.ser_pool = ThreadPool.init(.{ .max_threads = 2 });

        self.sub_map = sub_map_mod.RPCSubMap.init(allocator, 1024);
        errdefer self.sub_map.deinit();

        self.account_db = try sig.accounts_db.Db.initTest(allocator);
        errdefer self.account_db.deinit();

        self.slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
        errdefer self.slot_tracker.deinit(allocator);

        const slot_read_ctx: SlotReadContext = .{
            .slot_tracker = &self.slot_tracker,
            .account_reader = .{ .accounts_db = &self.account_db.db },
        };
        const logger: sig.trace.Logger("jrpc_ws_integration_tests") = .FOR_TESTS;
        self.ctx = Runtime.init(.{
            .allocator = allocator,
            .logger = .from(logger),
            .sub_map = &self.sub_map,
            .slot_read_ctx = slot_read_ctx,
            .event_sink = self.event_sink,
            .commit_queue = &self.commit_queue,
            .threadpool = &self.ser_pool,
            .metrics = &self.metrics,
            .max_batch_bytes = 64 * 1024,
            .loop = &self.loop,
        });
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
    pub fn injectEvent(self: *TestServer, inbound_event: types.InboundEvent) void {
        var event = inbound_event;
        switch (event) {
            .slot_frozen => |*slot_data| {
                slot_data.accounts.deinit();
                slot_data.accounts = self.event_sink.materializeSlotModifiedAccounts(
                    @as(sig.trace.Logger("jrpc_ws_integration_tests"), .FOR_TESTS),
                    .{ .accounts_db = &self.account_db.db },
                    slot_data.slot,
                ) catch {
                    return;
                };
            },
            else => {},
        }
        self.event_sink.send(event) catch {
            event.deinit(self.event_sink.channel.allocator);
        };
    }

    /// Run the loop for a bounded number of ticks. Returns when no more
    /// work is available or the tick limit is hit.
    pub fn tick(self: *TestServer, max_ticks: usize) void {
        for (0..max_ticks) |_| {
            self.loop.run(.no_wait) catch break;
        }
    }

    pub fn stop(self: *TestServer) void {
        self.ctx.running = false;
        self.event_sink.channel.close();
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

    pub fn deinit(self: *TestServer) void {
        const allocator = self.allocator;
        self.server.deinit();
        self.ctx.deinit(runtime_deinit_timeout_ms) catch unreachable;
        self.slot_tracker.deinit(allocator);
        self.account_db.deinit();
        self.sub_map.deinit();
        self.ser_pool.shutdown();
        self.ser_pool.deinit();
        self.xev_pool.shutdown();
        self.xev_pool.deinit();
        self.loop.deinit();
        self.commit_queue.deinit();
        self.event_sink.destroy();
        allocator.destroy(self);
    }
};

const PendingConnection = struct {
    fd: std.posix.fd_t,
    initial_data: []u8,
};

const WsBridge = struct {
    allocator: std.mem.Allocator,
    pending_connections: *Channel(PendingConnection),
    runtime_ctx: *Runtime,
    ws_server: *WebSocketServer,

    fn feedConnection(ptr: *anyopaque, fd: std.posix.fd_t, initial_data: []const u8) !void {
        const self: *WsBridge = @ptrCast(@alignCast(ptr));
        const data_copy = try self.allocator.dupe(u8, initial_data);
        self.pending_connections.send(.{ .fd = fd, .initial_data = data_copy }) catch |err| {
            self.allocator.free(data_copy);
            return err;
        };
        self.runtime_ctx.requestWakeup();
    }

    fn onWake(ptr: *anyopaque) void {
        const self: *WsBridge = @ptrCast(@alignCast(ptr));
        while (self.pending_connections.tryReceive()) |pending| {
            defer self.allocator.free(pending.initial_data);

            setSocketNonBlocking(pending.fd) catch {
                std.posix.close(pending.fd);
                continue;
            };

            self.ws_server.feedConnection(pending.fd, pending.initial_data) catch {
                std.posix.close(pending.fd);
                continue;
            };
        }
    }
};

pub const IntegratedTestServer = struct {
    allocator: std.mem.Allocator,
    metrics: metrics_mod.Metrics,
    event_sink: *types.EventSink,
    commit_queue: Channel(types.CommitMsg),
    loop: xev.Loop,
    xev_pool: xev.ThreadPool,
    ser_pool: ThreadPool,
    sub_map: sub_map_mod.RPCSubMap,
    account_db: sig.accounts_db.Db.TestContext,
    slot_tracker: sig.replay.trackers.SlotTracker,
    ctx: Runtime,
    ws_server: WebSocketServer,
    pending_connections: Channel(PendingConnection),
    bridge: WsBridge,
    rpc_hooks: sig.rpc.Hooks,
    rpc_server_ctx: sig.rpc.server.Context,
    rpc_exit: std.atomic.Value(bool),
    rpc_thread: std.Thread,
    port: u16,

    pub fn start(allocator: std.mem.Allocator) !*IntegratedTestServer {
        const self = try allocator.create(IntegratedTestServer);
        errdefer allocator.destroy(self);

        self.allocator = allocator;
        self.metrics = .{};

        self.event_sink = try types.EventSink.create(allocator);
        errdefer self.event_sink.destroy();

        self.commit_queue = try Channel(types.CommitMsg).init(allocator);
        errdefer self.commit_queue.deinit();

        self.xev_pool = xev.ThreadPool.init(.{});

        self.loop = try xev.Loop.init(.{ .thread_pool = &self.xev_pool });
        errdefer self.loop.deinit();

        self.ser_pool = ThreadPool.init(.{ .max_threads = 2 });

        self.sub_map = sub_map_mod.RPCSubMap.init(allocator, 1024);
        errdefer self.sub_map.deinit();

        self.account_db = try sig.accounts_db.Db.initTest(allocator);
        errdefer self.account_db.deinit();

        self.slot_tracker = try sig.replay.trackers.SlotTracker.initEmpty(allocator, 0);
        errdefer self.slot_tracker.deinit(allocator);

        const slot_read_ctx: SlotReadContext = .{
            .slot_tracker = &self.slot_tracker,
            .account_reader = .{ .accounts_db = &self.account_db.db },
        };
        const logger: sig.trace.Logger("jrpc_ws_integration_tests") = .FOR_TESTS;
        self.ctx = Runtime.init(.{
            .allocator = allocator,
            .logger = .from(logger),
            .sub_map = &self.sub_map,
            .slot_read_ctx = slot_read_ctx,
            .event_sink = self.event_sink,
            .commit_queue = &self.commit_queue,
            .threadpool = &self.ser_pool,
            .metrics = &self.metrics,
            .max_batch_bytes = 64 * 1024,
            .loop = &self.loop,
        });

        self.ws_server = try WebSocketServer.initNoListen(allocator, &self.loop, .{
            .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0),
            .handler_context = &self.ctx,
        });
        errdefer self.ws_server.deinit();

        self.pending_connections = try Channel(PendingConnection).init(allocator);
        errdefer self.pending_connections.deinit();

        self.bridge = .{
            .allocator = allocator,
            .pending_connections = &self.pending_connections,
            .runtime_ctx = &self.ctx,
            .ws_server = &self.ws_server,
        };

        self.ctx.wakeup_hook = .{
            .ptr = &self.bridge,
            .onWake = WsBridge.onWake,
        };
        self.ctx.armAsyncWait();

        self.rpc_hooks = .{};
        errdefer self.rpc_hooks.deinit(allocator);

        try self.rpc_hooks.set(allocator, struct {
            pub fn getHealth(
                _: @This(),
                _: std.mem.Allocator,
                _: anytype,
            ) !sig.rpc.methods.GetHealth.Response {
                return .ok;
            }
        }{});

        self.rpc_server_ctx = try sig.rpc.server.Context.init(.{
            .allocator = allocator,
            .logger = .from(logger),
            .rpc_hooks = &self.rpc_hooks,
            .read_buffer_size = sig.rpc.server.MIN_READ_BUFFER_SIZE,
            .socket_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0),
            .reuse_address = true,
            .ws_server = .{
                .ptr = &self.bridge,
                .feedFn = WsBridge.feedConnection,
            },
        });
        errdefer self.rpc_server_ctx.joinDeinit();

        self.port = self.rpc_server_ctx.tcp.listen_address.getPort();

        self.rpc_exit = std.atomic.Value(bool).init(false);
        self.rpc_thread = try std.Thread.spawn(
            .{},
            runRPCServeThread,
            .{ &self.rpc_exit, &self.rpc_server_ctx },
        );

        return self;
    }

    pub fn injectEvent(self: *IntegratedTestServer, inbound_event: types.InboundEvent) void {
        var event = inbound_event;
        switch (event) {
            .slot_frozen => |*slot_data| {
                slot_data.accounts.deinit();
                slot_data.accounts = self.event_sink.materializeSlotModifiedAccounts(
                    @as(sig.trace.Logger("jrpc_ws_integration_tests"), .FOR_TESTS),
                    .{ .accounts_db = &self.account_db.db },
                    slot_data.slot,
                ) catch {
                    return;
                };
            },
            else => {},
        }
        self.event_sink.send(event) catch {
            event.deinit(self.event_sink.channel.allocator);
        };
    }

    pub fn tick(self: *IntegratedTestServer, max_ticks: usize) void {
        for (0..max_ticks) |_| {
            self.loop.run(.no_wait) catch break;
        }
    }

    pub fn postJsonRpc(self: *IntegratedTestServer, body: []const u8) ![]u8 {
        return postJsonRpcRequest(self.allocator, self.port, body);
    }

    pub fn stop(self: *IntegratedTestServer) void {
        self.rpc_exit.store(true, .release);
        self.rpc_thread.join();

        self.ctx.running = false;
        self.event_sink.channel.close();
        self.pending_connections.close();

        var shutdown_done = false;
        self.ws_server.shutdown(1000, bool, &shutdown_done, struct {
            fn onShutdown(done_opt: ?*bool, _: WebSocketServer.ShutdownResult) void {
                if (done_opt) |done| {
                    done.* = true;
                }
            }
        }.onShutdown);

        const deadline = @as(u64, @intCast(std.time.milliTimestamp())) + 2000;
        while (!shutdown_done and @as(u64, @intCast(std.time.milliTimestamp())) < deadline) {
            self.tick(50);
            std.Thread.sleep(1 * std.time.ns_per_ms);
        }

        while (self.pending_connections.tryReceive()) |pending| {
            self.allocator.free(pending.initial_data);
            std.posix.close(pending.fd);
        }
    }

    pub fn deinit(self: *IntegratedTestServer) void {
        const allocator = self.allocator;

        self.ws_server.deinit();
        self.ctx.deinit(runtime_deinit_timeout_ms) catch unreachable;
        self.slot_tracker.deinit(allocator);
        self.account_db.deinit();
        self.sub_map.deinit();
        self.ser_pool.shutdown();
        self.ser_pool.deinit();
        self.xev_pool.shutdown();
        self.xev_pool.deinit();
        self.loop.deinit();

        self.rpc_server_ctx.joinDeinit();
        self.rpc_hooks.deinit(allocator);

        self.pending_connections.deinit();
        self.commit_queue.deinit();
        self.event_sink.destroy();

        allocator.destroy(self);
    }
};

fn runRPCServeThread(exit: *std.atomic.Value(bool), server_ctx: *sig.rpc.server.Context) void {
    sig.rpc.server.serve(exit, server_ctx, .basic) catch {};
}

fn setSocketNonBlocking(fd: std.posix.fd_t) !void {
    const FlagsInt = @typeInfo(std.posix.O).@"struct".backing_integer.?;
    var flags_int: FlagsInt = @intCast(try std.posix.fcntl(fd, std.posix.F.GETFL, 0));
    const flags = std.mem.bytesAsValue(std.posix.O, std.mem.asBytes(&flags_int));
    if (!flags.NONBLOCK) {
        flags.NONBLOCK = true;
        _ = try std.posix.fcntl(fd, std.posix.F.SETFL, flags_int);
    }
}

fn postJsonRpcRequest(allocator: std.mem.Allocator, port: u16, body: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/", .{port});
    defer allocator.free(url);

    const uri = try std.Uri.parse(url);
    var request = try client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
        },
    });
    defer request.deinit();

    request.transfer_encoding = .{ .content_length = body.len };
    var send_buf: [4096]u8 = undefined;
    var body_writer = try request.sendBody(&send_buf);
    try body_writer.writer.writeAll(body);
    try body_writer.end();

    var recv_head_buf: [4096]u8 = undefined;
    var response = try request.receiveHead(&recv_head_buf);

    var recv_body_buf: [4096]u8 = undefined;
    const reader = response.reader(&recv_body_buf);
    return try reader.allocRemaining(allocator, .limited64(1 << 20));
}

/// Client-side WebSocket handler for e2e tests.
/// Collects all received messages (text frames) and supports a scripted
/// sequence of messages to send on open / after each response.
///
/// Messages are queued before connecting. On open, the first message is sent.
/// Each time a response/notification arrives, the next queued message is sent.
/// When the last queued message has been sent and its response received, the
/// handler closes the connection. `close_after` controls how many received
/// messages trigger the close (defaults to total queued sends).
pub const TestClientHandler = struct {
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

    pub fn init(allocator: std.mem.Allocator) TestClientHandler {
        return .{
            .received = .{},
            .to_send = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TestClientHandler) void {
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
    pub fn queueSend(self: *TestClientHandler, msg: []const u8) void {
        self.to_send.append(self.allocator, msg) catch {};
    }

    /// Queue a message and immediately try to send it (for mid-test sends).
    pub fn queueSendNow(self: *TestClientHandler, msg: []const u8) void {
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

pub const TestClient = ws.Client(TestClientHandler, 4096);

pub fn initTestClient(
    allocator: std.mem.Allocator,
    client_env: *TestClientEnv,
    handler: *TestClientHandler,
    conn: *TestClient.Conn,
    port: u16,
) TestClient {
    return TestClient.init(
        allocator,
        &client_env.loop,
        handler,
        conn,
        &client_env.csprng,
        .{ .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port) },
    );
}

/// Bundles client-side xev resources for e2e tests.
pub const TestClientEnv = struct {
    tp: xev.ThreadPool,
    loop: xev.Loop,
    csprng: ws.ClientMaskPRNG,

    pub fn start(self: *TestClientEnv) !void {
        self.tp = xev.ThreadPool.init(.{});
        self.loop = try xev.Loop.init(.{ .thread_pool = &self.tp });
        var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        self.csprng = ws.ClientMaskPRNG.init(seed);
    }

    pub fn deinit(self: *TestClientEnv) void {
        self.loop.deinit();
        self.tp.shutdown();
        self.tp.deinit();
    }
};

/// Run server and client loops together for a bounded number of iterations.
/// Interleaves ticks to allow the async wakeup / event delivery cycle.
/// Stops early if the handler's close callback has fired.
pub fn runBothLoops(
    server: anytype,
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

/// Wait until the handler has received at least `count` messages.
pub fn waitForMessages(
    server: anytype,
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

pub fn parseResultU64(response: []const u8) ?u64 {
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
pub fn subNotifUnsubTest(
    subscribe_msg: []const u8,
    unsubscribe_msg: []const u8,
    event: types.InboundEvent,
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
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
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

fn trackedSlotConstants(
    allocator: std.mem.Allocator,
    parent_slot: u64,
    ancestor_slots: []const u64,
) !sig.core.SlotConstants {
    return .{
        .parent_slot = parent_slot,
        .parent_hash = .ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = .ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = .DEFAULT,
        .ancestors = try sig.core.Ancestors.initWithSlots(allocator, ancestor_slots),
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };
}

pub fn addTrackedSlot(
    server: *TestServer,
    slot: u64,
    parent_slot: u64,
    ancestor_slots: []const u64,
) !void {
    const gop = try server.slot_tracker.getOrPut(server.allocator, slot, .{
        .constants = try trackedSlotConstants(server.allocator, parent_slot, ancestor_slots),
        .state = .GENESIS,
        .allocator = server.allocator,
    });
    gop.reference.release();
}
