const std = @import("std");

const helpers = @import("support/test_helpers.zig");

const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const initTestClient = helpers.initTestClient;
const parseResultBool = helpers.parseResultBool;
const parseResultU64 = helpers.parseResultU64;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

/// slotsUpdatesNotification JSON shape for parsing test responses.
/// The `type` field selects the event variant; extra fields (parent,
/// stats, err) are optional depending on variant.
const SlotsUpdatesNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            slot: u64,
            type: []const u8,
            timestamp: u64,
            parent: ?u64 = null,
            stats: ?SlotTransactionStats = null,
            err: ?[]const u8 = null,
        },
        subscription: u64,
    },
};

const SlotTransactionStats = struct {
    numTransactionEntries: u64,
    numSuccessfulTransactions: u64,
    numFailedTransactions: u64,
    maxTransactionsPerEntry: u64,
};

fn parseSlotsUpdatesNotification(
    allocator: std.mem.Allocator,
    msg: []const u8,
) !std.json.Parsed(SlotsUpdatesNotification) {
    return std.json.parseFromSlice(
        SlotsUpdatesNotification,
        allocator,
        msg,
        .{ .ignore_unknown_fields = true },
    );
}

test "slotsUpdatesSubscribe: subscribe, frozen notify, unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    // Trigger frozen event with mixed transaction stats.
    server.injectEvent(.{ .slot_frozen = .{
        .slot = 42,
        .parent = 41,
        .root = 0,
        .stats = .{
            .numTransactionEntries = 2,
            .numSuccessfulTransactions = 3,
            .numFailedTransactions = 2,
            .maxTransactionsPerEntry = 4,
        },
    } });

    // Wait for slotsUpdatesNotification.
    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();
    const notif = parsed.value;

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        notif.method,
    );
    try std.testing.expectEqual(42, notif.params.result.slot);
    try std.testing.expectEqualStrings(
        "frozen",
        notif.params.result.type,
    );
    try std.testing.expect(notif.params.result.timestamp > 0);
    try std.testing.expect(notif.params.result.stats != null);
    const stats = notif.params.result.stats.?;
    try std.testing.expectEqual(2, stats.numTransactionEntries);
    try std.testing.expectEqual(3, stats.numSuccessfulTransactions);
    try std.testing.expectEqual(2, stats.numFailedTransactions);
    try std.testing.expectEqual(4, stats.maxTransactionsPerEntry);

    // Unsubscribe.
    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"slotsUpdatesUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse
            return error.TestUnexpectedResult,
    );
}

test "slotsUpdatesSubscribe: optimistic confirmation event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    // slot_confirmed triggers optimisticConfirmation.
    server.injectEvent(.{ .slot_confirmed = 77 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(77, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "optimisticConfirmation",
        parsed.value.params.result.type,
    );
}

test "slotsUpdatesSubscribe: root event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    // slot_rooted triggers root event.
    server.injectEvent(.{ .slot_rooted = 200 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(200, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "root",
        parsed.value.params.result.type,
    );
}

test "slotsUpdatesSubscribe: dead slot event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    // slot_dead triggers dead event.
    server.injectEvent(.{ .slot_dead = .{
        .slot = 55,
        .err = ".{ .failed_to_load_entries = \"test error\" }",
    } });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(55, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "dead",
        parsed.value.params.result.type,
    );
    try std.testing.expectEqualStrings(
        ".{ .failed_to_load_entries = \"test error\" }",
        parsed.value.params.result.err.?,
    );
}

test "slotsUpdatesSubscribe: first shred received event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    server.injectEvent(.{ .first_shred_received = 88 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(88, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "firstShredReceived",
        parsed.value.params.result.type,
    );
}

test "slotsUpdatesSubscribe: completed slot event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    server.injectEvent(.{ .slot_completed = 99 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(99, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "completed",
        parsed.value.params.result.type,
    );
}

test "slotsUpdatesSubscribe: created bank event" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    server.injectEvent(.{ .bank_created = .{
        .slot = 101,
        .parent = 100,
    } });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);

    const parsed = try parseSlotsUpdatesNotification(
        allocator,
        handler.received.items[1],
    );
    defer parsed.deinit();

    try std.testing.expectEqualStrings(
        "slotsUpdatesNotification",
        parsed.value.method,
    );
    try std.testing.expectEqual(101, parsed.value.params.result.slot);
    try std.testing.expectEqualStrings(
        "createdBank",
        parsed.value.params.result.type,
    );
    try std.testing.expectEqual(100, parsed.value.params.result.parent.?);
}

test "slotsUpdatesSubscribe preserves enqueue order across mixed slot update event types" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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
    defer conn.deinit();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expect(parseResultU64(handler.received.items[0]) != null);

    // Make the dead-slot payload much larger than the later events so worker completion
    // would naturally favor the later jobs if queue commits were not ordered.
    const delayed_err = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(delayed_err);
    @memset(delayed_err, 'x');

    server.injectEvent(.{ .bank_created = .{ .slot = 700, .parent = 699 } });
    server.injectEvent(.{ .slot_dead = .{
        .slot = 700,
        .err = delayed_err,
    } });
    server.injectEvent(.{ .first_shred_received = 701 });
    server.injectEvent(.{ .slot_completed = 701 });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 701, .parent = 700, .root = 0 } });
    server.injectEvent(.{ .slot_confirmed = 701 });
    server.injectEvent(.{ .slot_rooted = 701 });

    waitForMessages(server, &client_env, &handler, 8, 15000);
    try std.testing.expectEqual(@as(usize, 8), handler.received.items.len);

    const expected = [_]struct { slot: u64, type: []const u8 }{
        .{ .slot = 700, .type = "createdBank" },
        .{ .slot = 700, .type = "dead" },
        .{ .slot = 701, .type = "firstShredReceived" },
        .{ .slot = 701, .type = "completed" },
        .{ .slot = 701, .type = "frozen" },
        .{ .slot = 701, .type = "optimisticConfirmation" },
        .{ .slot = 701, .type = "root" },
    };

    for (expected, 0..) |want, i| {
        const parsed = try parseSlotsUpdatesNotification(
            allocator,
            handler.received.items[i + 1],
        );
        defer parsed.deinit();

        try std.testing.expectEqualStrings(
            "slotsUpdatesNotification",
            parsed.value.method,
        );
        try std.testing.expectEqual(want.slot, parsed.value.params.result.slot);
        try std.testing.expectEqualStrings(want.type, parsed.value.params.result.type);
    }

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "slotsUpdatesSubscribe: no notifications after unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    // Subscribe then immediately unsubscribe.
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":2,"method":"slotsUpdatesUnsubscribe","params":[1]}
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

    // Wait for both subscribe + unsubscribe responses.
    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expect(handler.received.items.len >= 2);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[1]) orelse
            return error.TestUnexpectedResult,
    );

    // Inject events: should NOT produce notifications.
    server.injectEvent(.{ .slot_frozen = .{
        .slot = 300,
        .parent = 299,
        .root = 0,
    } });
    server.injectEvent(.{ .slot_rooted = 300 });

    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(2, handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}

test "slotsUpdatesSubscribe: tip_changed does not fire" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotsUpdatesSubscribe"}
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

    // tip_changed should NOT produce a slotsUpdatesNotification.
    server.injectEvent(.{ .tip_changed = 500 });

    runBothLoops(server, &client_env, &handler, 200);
    try std.testing.expectEqual(1, handler.received.items.len);

    if (handler.conn_ref) |c| {
        c.close(.normal, "");
    }
    runBothLoops(server, &client_env, &handler, 100);
}
