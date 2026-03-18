const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const initTestClient = helpers.initTestClient;
const parseResultU64 = helpers.parseResultU64;

test "multiple clients receive independent notifications" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler1 = TestClientHandler.init(allocator);
    defer handler1.deinit();
    handler1.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe","params":[]}
    );
    handler1.close_after = 3;

    var handler2 = TestClientHandler.init(allocator);
    defer handler2.deinit();
    handler2.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"rootSubscribe","params":[]}
    );
    handler2.close_after = 3;

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

    server.injectEvent(.{ .slot_frozen = .{ .slot = 200, .parent = 199, .root = 168 } });
    server.injectEvent(.{ .slot_rooted = 201 });

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

    const notif1 = handler1.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif1, "\"slot\":200") != null);

    const notif2 = handler2.received.items[1];
    try std.testing.expect(std.mem.indexOf(u8, notif2, "\"result\":201") != null);

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
        \\{"jsonrpc":"2.0","id":2,"method":"rootUnsubscribe","params":[1]}
        ,
        2 =>
        \\{"jsonrpc":"2.0","id":2,"method":"rootUnsubscribe","params":[2]}
        ,
        else => return error.TestUnexpectedResult,
    });

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

    const unsub1 = handler1.received.items[2];
    const unsub2 = handler2.received.items[2];
    try std.testing.expect(std.mem.indexOf(u8, unsub1, "\"result\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, unsub2, "\"result\":true") != null);

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
