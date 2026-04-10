const std = @import("std");

const helpers = @import("support/test_helpers.zig");

const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const parseResultBool = helpers.parseResultBool;
const parseResultU64 = helpers.parseResultU64;
const waitForMessages = helpers.waitForMessages;

/// blockNotification JSON shape for parsing test responses.
const BlockNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            context: struct {
                slot: u64,
            },
            value: struct {
                slot: u64,
                block: ?struct {},
                err: ?[]const u8,
            },
        },
    },
};

fn parseBlockNotification(
    allocator: std.mem.Allocator,
    msg: []const u8,
) !std.json.Parsed(BlockNotification) {
    return std.json.parseFromSlice(
        BlockNotification,
        allocator,
        msg,
        .{ .ignore_unknown_fields = true },
    );
}

test "blockSubscribe finalized: subscribe, notify, unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.startWithLedger(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 50, 0, &.{50});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // Default commitment is finalized.
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"blockSubscribe","params":["all"]}
    );
    handler.close_after = 0;

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
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    // Trigger finalized: frozen then rooted.
    server.injectEvent(.{ .slot_frozen = .{
        .slot = 50,
        .parent = 0,
        .root = 0,
    } });
    server.injectEvent(.{ .slot_finalized_rooted = 50 });

    // Wait for blockNotification.
    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseBlockNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();
    const notif = parsed.value;

    try std.testing.expectEqualStrings(
        "blockNotification",
        notif.method,
    );
    try std.testing.expectEqual(50, notif.params.result.context.slot);
    try std.testing.expectEqual(50, notif.params.result.value.slot);
    // Block data comes from cache (no ledger read); even with
    // zero transactions the block metadata is present.
    try std.testing.expect(notif.params.result.value.block != null);
    try std.testing.expect(notif.params.result.value.err == null);

    // Unsubscribe.
    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"blockUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse
            return error.TestUnexpectedResult,
    );
}

test "blockSubscribe confirmed: notifies on confirmed slot" {
    const allocator = std.testing.allocator;

    var server = try TestServer.startWithLedger(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 10, 0, &.{10});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"blockSubscribe","params":["all",{"commitment":"confirmed"}]}
    );
    handler.close_after = 0;

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

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    // Freeze then confirm (not root) — should trigger confirmed notification.
    server.injectEvent(.{ .slot_frozen = .{
        .slot = 10,
        .parent = 0,
        .root = 0,
    } });
    server.injectEvent(.{ .slot_confirmed = 10 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseBlockNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "blockNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(10, parsed.value.params.result.value.slot);
}

test "blockSubscribe without ledger: notification still sent from cache" {
    const allocator = std.testing.allocator;

    // Start without ledger — blockSubscribe now reads
    // from the slot state cache, so a notification is
    // still produced.
    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 50, 0, &.{50});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"blockSubscribe","params":["all"]}
    );
    handler.close_after = 0;

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

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    // Trigger finalized events — block notification now
    // comes from cache even without a ledger.
    server.injectEvent(.{ .slot_frozen = .{
        .slot = 50,
        .parent = 0,
        .root = 0,
    } });
    server.injectEvent(.{ .slot_finalized_rooted = 50 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expectEqual(2, handler.received.items.len);

    const parsed = try parseBlockNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "blockNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(
        50,
        parsed.value.params.result.value.slot,
    );
}
