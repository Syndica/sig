const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const Pubkey = helpers.Pubkey;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const filledPubkey = helpers.filledPubkey;
const putAccountAtSlot = helpers.putAccountAtSlot;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

test "accountSubscribe confirmed publishes on rooted without confirmed event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const pubkey = Pubkey.parse("CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB");
    const owner_pk = filledPubkey(0xBB);

    try addTrackedSlot(server, 2, 1, &.{ 1, 2 });

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
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"confirmed"}]}
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

    server.injectEvent(.{ .slot_rooted = 2 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"accountNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":42000") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slot\":2") != null);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
}

test "accountSubscribe processed publishes on tip change" {
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

    const account_shared = try putAccountAtSlot(
        server,
        1,
        pubkey,
        owner_pk,
        50_000,
        &.{ 0xDE, 0xAD },
    );
    defer account_shared.deinit(allocator);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["CVDFLCAjXhVWiPXH9nTCTpCgVzmDVoiPzNJYuccr1dqB",{"commitment":"processed"}]}
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

    server.slot_tracker.commitments.update(.processed, 2);
    server.injectEvent(.{ .tip_changed = 2 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"accountNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":50000") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slot\":2") != null);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    runBothLoops(server, &client_env, &handler, 100);
}

test "accountSubscribe dedups unchanged commitment advances" {
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
        1,
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
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);

    server.injectEvent(.{ .slot_rooted = 2 });
    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[1], "\"accountNotification\"") != null,
    );

    server.injectEvent(.{ .slot_rooted = 3 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(@as(usize, 2), handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "accountSubscribe deleted account returns zero-lamport placeholder" {
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

    const account_shared = try putAccountAtSlot(server, 1, pubkey, owner_pk, 0, &.{});
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

    server.injectEvent(.{ .slot_rooted = 2 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"accountNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"lamports\":0") != null);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    runBothLoops(server, &client_env, &handler, 100);
}
