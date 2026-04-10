const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const sig = helpers.sig;

const Pubkey = helpers.Pubkey;
const Signature = helpers.Signature;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const filledPubkey = helpers.filledPubkey;
const parseResultBool = helpers.parseResultBool;
const parseResultU64 = helpers.parseResultU64;
const putAccountAtSlot = helpers.putAccountAtSlot;
const RootNotification = helpers.RootNotification;
const runBothLoops = helpers.runBothLoops;
const SlotNotification = helpers.SlotNotification;
const waitForMessages = helpers.waitForMessages;

test "client subscribes to slot, receives notification, unsubscribes" {
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
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 100, .parent = 99, .root = 68 } });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const parsed_notif = try std.json.parseFromSlice(
        SlotNotification,
        allocator,
        handler.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("slotNotification", notification.method);
    try std.testing.expectEqual(100, notification.params.result.slot);
    try std.testing.expectEqual(99, notification.params.result.parent);
    try std.testing.expectEqual(68, notification.params.result.root);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"slotUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse return error.TestUnexpectedResult,
    );

    runBothLoops(server, &client_env, &handler, 100);
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
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    server.injectEvent(.{ .slot_finalized_rooted = 2 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    const AccountNotification = struct {
        method: []const u8,
        params: struct {
            result: struct {
                context: struct {
                    slot: u64,
                },
                value: struct {
                    lamports: u64,
                    data: []const u8,
                },
            },
        },
    };
    const parsed_notif = try std.json.parseFromSlice(
        AccountNotification,
        allocator,
        notif,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("accountNotification", notification.method);
    try std.testing.expectEqual(2, notification.params.result.context.slot);
    try std.testing.expectEqual(42_000, notification.params.result.value.lamports);
    try std.testing.expectEqualStrings("Hwr", notification.params.result.value.data);

    server.injectEvent(.{ .slot_finalized_rooted = 3 });
    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(2, handler.received.items.len);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"accountUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse return error.TestUnexpectedResult,
    );

    runBothLoops(server, &client_env, &handler, 100);
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
    try std.testing.expectEqual(
        true,
        parseResultBool(unsub_resp) orelse return error.TestUnexpectedResult,
    );

    server.injectEvent(.{ .slot_frozen = .{ .slot = 300, .parent = 299, .root = 268 } });

    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(2, handler.received.items.len);

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

    const account_shared = try putAccountAtSlot(server, 88, pk, owner_pk, 12345, &.{ 0xDE, 0xAD });
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
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 88, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_finalized_rooted = 88 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    const ProgramNotification = struct {
        method: []const u8,
        params: struct {
            result: struct {
                context: struct {
                    slot: u64,
                },
                value: struct {
                    account: struct {
                        lamports: u64,
                        data: []const u8,
                    },
                },
            },
        },
    };
    const parsed_notif = try std.json.parseFromSlice(
        ProgramNotification,
        allocator,
        notif,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("programNotification", notification.method);
    try std.testing.expectEqual(88, notification.params.result.context.slot);
    try std.testing.expectEqual(12_345, notification.params.result.value.account.lamports);
    try std.testing.expectEqualStrings("Hwr", notification.params.result.value.account.data);

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"programUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse return error.TestUnexpectedResult,
    );

    runBothLoops(server, &client_env, &handler, 100);
}

test "client subscribes to root, receives notification, unsubscribes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
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
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    server.injectEvent(.{ .slot_finalized_rooted = 256 });

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
    try std.testing.expectEqual(256, notification.params.result);

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

test "client subscribes to vote, receives notification, unsubscribes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"voteSubscribe"}
    );
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(
        allocator,
        &client_env,
        &handler,
        &conn,
        server.port,
    );
    try client.connect();

    // Wait for subscription confirmation.
    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(handler.received.items.len >= 1);
    try std.testing.expect(std.mem.indexOf(u8, handler.received.items[0], "\"result\":") != null);

    // Inject a vote event.
    const vote_pubkey = filledPubkey(0xAA);
    server.injectEvent(.{ .vote = try sig.rpc.jrpc_websockets.types.VoteEventData.initOwned(
        allocator,
        vote_pubkey,
        &.{ 42, 43 },
        sig.core.Hash.ZEROES,
        1234567890,
        Signature.ZEROES,
    ) });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    const notif = handler.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"voteNotification\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"votePubkey\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"slots\":[42,43]") != null);
    try std.testing.expect(std.mem.indexOf(u8, notif, "\"timestamp\":1234567890") != null);

    // Unsubscribe.
    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"voteUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expect(handler.received.items.len >= 3);
    try std.testing.expect(
        std.mem.indexOf(u8, handler.received.items[2], "\"result\":true") != null,
    );

    runBothLoops(server, &client_env, &handler, 100);
}
