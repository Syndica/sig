const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const Pubkey = helpers.Pubkey;
const Signature = helpers.Signature;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const filledPubkey = helpers.filledPubkey;
const putAccountAtSlot = helpers.putAccountAtSlot;
const runBothLoops = helpers.runBothLoops;
const subNotifUnsubTest = helpers.subNotifUnsubTest;
const waitForMessages = helpers.waitForMessages;

test "client subscribes to slot, receives notification, unsubscribes" {
    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
    ,
        .{ .slot_frozen = .{ .slot = 100, .parent = 99, .root = 68 } },
        &.{ "\"slot\":100", "\"parent\":99", "\"root\":68" },
    );
}

test "client subscribes to account, receives notification, unsubscribes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const pubkey = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    const owner_pk = filledPubkey(0xBB);

    try addTrackedSlot(server, 1, 0, &.{1});
    try addTrackedSlot(server, 2, 1, &.{ 1, 2 });
    try addTrackedSlot(server, 3, 2, &.{ 1, 2, 3 });

    const account_shared = try putAccountAtSlot(
        server,
        2,
        pubkey,
        owner_pk,
        42_000,
        &.{ 0xDE, 0xAD },
    );
    defer account_shared.deinit(allocator);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
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
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

    server.injectEvent(.{ .slot_rooted = 2 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"accountNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":42000") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slot\":2") != null);

    server.injectEvent(.{ .slot_rooted = 3 });
    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"result\":true") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "client subscribes to logs, receives notification, unsubscribes" {
    var sig_bytes: [64]u8 = undefined;
    @memset(&sig_bytes, 0xBE);

    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all"]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"logsUnsubscribe","params":[1]}
    ,
        .{ .logs = .{
            .signature = Signature.fromBytes(sig_bytes),
            .num_logs = 3,
            .slot = 77,
        } },
        &.{ "\"log line 0\"", "\"log line 1\"", "\"log line 2\"", "\"slot\":77" },
    );
}

test "no notifications after unsubscribe" {
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
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const unsub_resp = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, unsub_resp, "\"result\":true") != null);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 300, .parent = 299, .root = 268 } });

    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "client subscribes to program, receives notification, unsubscribes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const owner_pk = filledPubkey(0xAA);
    const pk = filledPubkey(0xBB);

    try addTrackedSlot(server, 88, 0, &.{88});

    const account_shared = try putAccountAtSlot(server, 88, pk, owner_pk, 12345, &.{ 0xCA, 0xFE });
    defer account_shared.deinit(allocator);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"programSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB"]}
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
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 88, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 88 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"programNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":12345") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slot\":88") != null);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"programUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"result\":true") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "client subscribes to root, receives notification, unsubscribes" {
    try subNotifUnsubTest(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    ,
        \\{"jsonrpc":"2.0","id":2,"method":"rootUnsubscribe","params":[1]}
    ,
        .{ .slot_rooted = 256 },
        &.{"\"result\":256"},
    );
}
