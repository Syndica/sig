const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const IntegratedTestServer = helpers.IntegratedTestServer;
const JsonRpcResultString = helpers.JsonRpcResultString;
const parseResultBool = helpers.parseResultBool;
const RootNotification = helpers.RootNotification;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const initTestClient = helpers.initTestClient;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

test "websocket upgrade via HTTP server supports root subscription" {
    const allocator = std.testing.allocator;

    var server = try IntegratedTestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    );
    handler.close_after = 2;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_finalized_rooted = 500 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const parsed_notif = try std.json.parseFromSlice(
        RootNotification,
        allocator,
        handler.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("rootNotification", notification.method);
    try std.testing.expectEqual(500, notification.params.result);

    runBothLoops(server, &client_env, &handler, 100);
}

test "HTTP JSON-RPC and WebSocket run on same port" {
    const allocator = std.testing.allocator;

    var server = try IntegratedTestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    );
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    const http_resp = try server.postJsonRpc(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getHealth\",\"params\":[]}",
    );
    defer allocator.free(http_resp);
    const parsed_http_resp = try std.json.parseFromSlice(
        JsonRpcResultString,
        allocator,
        http_resp,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_http_resp.deinit();
    const response = parsed_http_resp.value;
    try std.testing.expectEqualStrings("ok", response.result);

    server.injectEvent(.{ .slot_finalized_rooted = 501 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"rootUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse return error.TestUnexpectedResult,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "multiple websocket clients receive root notifications via HTTP upgrade" {
    const allocator = std.testing.allocator;

    var server = try IntegratedTestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler1 = TestClientHandler.init(allocator);
    defer handler1.deinit();
    handler1.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    );
    handler1.close_after = 2;

    var handler2 = TestClientHandler.init(allocator);
    defer handler2.deinit();
    handler2.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    );
    handler2.close_after = 2;

    var env1: TestClientEnv = undefined;
    try env1.start();
    defer env1.deinit();

    var env2: TestClientEnv = undefined;
    try env2.start();
    defer env2.deinit();

    var conn1: TestClient.Conn = undefined;
    var client1 = initTestClient(allocator, &env1, &handler1, &conn1, server.port);
    try client1.connect();

    var conn2: TestClient.Conn = undefined;
    var client2 = initTestClient(allocator, &env2, &handler2, &conn2, server.port);
    try client2.connect();

    const sub_deadline = @as(u64, @intCast(std.time.milliTimestamp())) + 5000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < sub_deadline) {
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

    server.injectEvent(.{ .slot_finalized_rooted = 502 });

    const notif_deadline = @as(u64, @intCast(std.time.milliTimestamp())) + 5000;
    while (@as(u64, @intCast(std.time.milliTimestamp())) < notif_deadline) {
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
    const parsed_notif1 = try std.json.parseFromSlice(
        RootNotification,
        allocator,
        handler1.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;

    const parsed_notif2 = try std.json.parseFromSlice(
        RootNotification,
        allocator,
        handler2.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;

    try std.testing.expectEqualStrings("rootNotification", notif1.method);
    try std.testing.expectEqualStrings("rootNotification", notif2.method);
    try std.testing.expectEqual(502, notif1.params.result);
    try std.testing.expectEqual(502, notif2.params.result);

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
