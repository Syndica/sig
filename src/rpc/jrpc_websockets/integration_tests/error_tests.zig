const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const initTestClient = helpers.initTestClient;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

test "duplicate subscribe returns error" {
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
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

    const dup = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, dup, "\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, dup, "\"code\":-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, dup, "duplicate subscription") != null);

    runBothLoops(server, &client_env, &handler, 100);
}

test "accountSubscribe ignores unknown config fields" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // Agave accepts unknown websocket subscription config fields and ignores them.
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"encoding":"jsonParsed","commitment":"confirmed","dataSlice":null,"definitelyUnknownField":true}]}
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
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

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
    const resp = handler.received.items[0];
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"code\":-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "subscription not found") != null);

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
    const resp = handler.received.items[0];
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"error\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"code\":-32602") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "\"id\":1") != null);

    runBothLoops(server, &client_env, &handler, 100);
}
