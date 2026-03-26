const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const parseResultU64 = helpers.parseResultU64;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const initTestClient = helpers.initTestClient;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

const JsonRpcErrorResponse = struct {
    id: ?u64,
    @"error": struct {
        code: i64,
        message: []const u8,
    },
};

test "duplicate subscribe returns existing sub id" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

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
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const first_sub_id = parseResultU64(handler.received.items[0]) orelse
        return error.TestUnexpectedResult;
    const second_sub_id = parseResultU64(handler.received.items[1]) orelse
        return error.TestUnexpectedResult;

    try std.testing.expectEqual(first_sub_id, second_sub_id);

    runBothLoops(server, &client_env, &handler, 100);
}

test "unsubscribe unknown sub_id returns error" {
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
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    const parsed_resp = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[0],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp.deinit();
    const response = parsed_resp.value;

    try std.testing.expectEqual(1, response.id orelse return error.TestUnexpectedResult);
    try std.testing.expectEqual(-32602, response.@"error".code);
    try std.testing.expect(
        std.mem.indexOf(u8, response.@"error".message, "subscription not found") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "json-rpc request error codes follow spec" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"nonexistentMethod","params":[]}
    );
    handler.queueSend(
        \\{"id":2,"method":"slotSubscribe","params":[]}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":3,"method":"accountSubscribe","params":[]}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":4,"method":"slotSubscribe","params":[]
    );
    handler.close_after = 4;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 4, 5000);
    try std.testing.expect(handler.received.items.len >= 4);

    const parsed_resp1 = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[0],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp1.deinit();
    const response1 = parsed_resp1.value;

    const parsed_resp2 = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp2.deinit();
    const response2 = parsed_resp2.value;

    const parsed_resp3 = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[2],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp3.deinit();
    const response3 = parsed_resp3.value;

    const parsed_resp4 = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[3],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp4.deinit();
    const response4 = parsed_resp4.value;

    try std.testing.expectEqual(-32601, response1.@"error".code);
    try std.testing.expectEqual(1, response1.id orelse return error.TestUnexpectedResult);
    try std.testing.expectEqual(-32600, response2.@"error".code);
    try std.testing.expectEqual(2, response2.id orelse return error.TestUnexpectedResult);
    try std.testing.expectEqual(-32602, response3.@"error".code);
    try std.testing.expectEqual(3, response3.id orelse return error.TestUnexpectedResult);
    try std.testing.expectEqual(-32700, response4.@"error".code);
    try std.testing.expectEqual(@as(?u64, null), response4.id);

    runBothLoops(server, &client_env, &handler, 100);
}

test "programSubscribe rejects more than four filters" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"filters":[{"dataSize":1},{"dataSize":2},{"dataSize":3},{"dataSize":4},{"dataSize":5}]}]}
    );
    handler.close_after = 1;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    const parsed_resp = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[0],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_resp.deinit();
    const response = parsed_resp.value;

    try std.testing.expectEqual(-32602, response.@"error".code);
    try std.testing.expectEqual(1, response.id orelse return error.TestUnexpectedResult);

    runBothLoops(server, &client_env, &handler, 100);
}
