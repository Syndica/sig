const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const sig = helpers.sig;
const lib = @import("../lib.zig");

const Pubkey = helpers.Pubkey;
const Signature = helpers.Signature;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const parseResultBool = helpers.parseResultBool;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

const LogsNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            context: struct {
                slot: u64,
            },
            value: struct {
                logs: []const []const u8,
            },
        },
    },
};

fn parseLogsNotification(
    allocator: std.mem.Allocator,
    msg: []const u8,
) !std.json.Parsed(LogsNotification) {
    return std.json.parseFromSlice(
        LogsNotification,
        allocator,
        msg,
        .{ .ignore_unknown_fields = true },
    );
}

const types = lib.types;
const TransactionError = sig.ledger.transaction_status.TransactionError;

fn signatureWithFill(fill: u8) Signature {
    var sig_value = Signature.ZEROES;
    @memset(&sig_value.r, fill);
    @memset(&sig_value.s, fill);
    return sig_value;
}

const LogsEventSpec = struct {
    signature_fill: u8,
    tx_err: ?TransactionError,
    is_vote: bool,
    log_lines: []const []const u8,
    mentioned_pubkeys: []const Pubkey,
};

fn makeLogsEvent(
    allocator: std.mem.Allocator,
    slot: u64,
    specs: []const LogsEventSpec,
) !types.InboundEvent {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const entries = try arena_allocator.alloc(types.TransactionLogsEntry, specs.len);
    for (specs, 0..) |spec, index| {
        const owned_logs = try arena_allocator.alloc([]const u8, spec.log_lines.len);
        for (spec.log_lines, 0..) |line, log_index| {
            owned_logs[log_index] = try arena_allocator.dupe(u8, line);
        }

        entries[index] = .{
            .signature = signatureWithFill(spec.signature_fill),
            .err = if (spec.tx_err) |err| try err.clone(arena_allocator) else null,
            .is_vote = spec.is_vote,
            .logs = owned_logs,
            .mentioned_pubkeys = try arena_allocator.dupe(Pubkey, spec.mentioned_pubkeys),
        };
    }

    return .{ .logs = .{
        .slot = slot,
        .entries = entries,
        .arena = arena,
    } };
}

test "logsSubscribe basic subscribe notify unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 50, 0, &.{50});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 50, &.{.{
        .signature_fill = 0x11,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: basic"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 50, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 50 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    const parsed_notif = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("logsNotification", notification.method);
    try std.testing.expectEqual(50, notification.params.result.context.slot);
    try std.testing.expectEqual(1, notification.params.result.value.logs.len);
    try std.testing.expectEqualStrings(
        "Program log: basic",
        notification.params.result.value.logs[0],
    );

    handler.queueSendNow(
        \\{"jsonrpc":"2.0","id":2,"method":"logsUnsubscribe","params":[1]}
    );

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expectEqual(
        true,
        parseResultBool(handler.received.items[2]) orelse return error.TestUnexpectedResult,
    );
}

test "logsSubscribe all excludes vote transactions" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 60, 0, &.{60});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 60, &.{
        .{
            .signature_fill = 0x12,
            .tx_err = null,
            .is_vote = true,
            .log_lines = &.{"Program log: vote tx"},
            .mentioned_pubkeys = &.{},
        },
        .{
            .signature_fill = 0x13,
            .tx_err = null,
            .is_vote = false,
            .log_lines = &.{"Program log: non vote tx"},
            .mentioned_pubkeys = &.{},
        },
    }));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 60, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 60 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expectEqual(2, handler.received.items.len);
    const parsed_notif = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqualStrings("logsNotification", notification.method);
    try std.testing.expectEqual(60, notification.params.result.context.slot);
    try std.testing.expectEqual(1, notification.params.result.value.logs.len);
    try std.testing.expectEqualStrings(
        "Program log: non vote tx",
        notification.params.result.value.logs[0],
    );
}

test "logsSubscribe allWithVotes includes vote transactions" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 61, 0, &.{61});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["allWithVotes"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 61, &.{
        .{
            .signature_fill = 0x14,
            .tx_err = null,
            .is_vote = true,
            .log_lines = &.{"Program log: vote tx"},
            .mentioned_pubkeys = &.{},
        },
        .{
            .signature_fill = 0x15,
            .tx_err = null,
            .is_vote = false,
            .log_lines = &.{"Program log: non vote tx"},
            .mentioned_pubkeys = &.{},
        },
    }));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 61, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 61 });

    waitForMessages(server, &client_env, &handler, 3, 5000);
    const parsed_notif1 = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;

    const parsed_notif2 = try parseLogsNotification(allocator, handler.received.items[2]);
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;

    try std.testing.expectEqualStrings(
        "Program log: vote tx",
        notif1.params.result.value.logs[0],
    );
    try std.testing.expectEqualStrings(
        "Program log: non vote tx",
        notif2.params.result.value.logs[0],
    );
}

test "logsSubscribe mentions matches relevant transactions including votes" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const target_pubkey = Pubkey.parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    var other_pubkey: Pubkey = undefined;
    @memset(&other_pubkey.data, 0xBB);

    try addTrackedSlot(server, 70, 0, &.{70});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":[{"mentions":["vinesvinesvinesvinesvinesvinesvinesvinesvin"]}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 70, &.{
        .{
            .signature_fill = 0x16,
            .tx_err = null,
            .is_vote = true,
            .log_lines = &.{"Program log: mentions vote"},
            .mentioned_pubkeys = &.{ target_pubkey, other_pubkey },
        },
        .{
            .signature_fill = 0x17,
            .tx_err = null,
            .is_vote = false,
            .log_lines = &.{"Program log: mentions miss"},
            .mentioned_pubkeys = &.{other_pubkey},
        },
    }));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 70, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 70 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expectEqual(2, handler.received.items.len);
    const parsed_notif = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif.deinit();
    const notification = parsed_notif.value;

    try std.testing.expectEqual(70, notification.params.result.context.slot);
    try std.testing.expectEqual(1, notification.params.result.value.logs.len);
    try std.testing.expectEqualStrings(
        "Program log: mentions vote",
        notification.params.result.value.logs[0],
    );
}

test "logsSubscribe processed publishes current tip slot if frozen before tip change" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 10, 0, &.{10});
    try addTrackedSlot(server, 20, 0, &.{20});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all",{"commitment":"processed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 10, &.{.{
        .signature_fill = 0x18,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: current tip"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(try makeLogsEvent(allocator, 20, &.{.{
        .signature_fill = 0x19,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: other fork"},
        .mentioned_pubkeys = &.{},
    }}));

    server.injectEvent(.{ .slot_frozen = .{ .slot = 10, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 20, .parent = 0, .root = 0 } });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(1, handler.received.items.len);

    server.slot_tracker.commitments.update(.processed, 10);
    server.injectEvent(.{ .tip_changed = 10 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    try std.testing.expectEqual(2, handler.received.items.len);
    const parsed_notif1 = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;
    try std.testing.expectEqualStrings(
        "Program log: current tip",
        notif1.params.result.value.logs[0],
    );

    server.slot_tracker.commitments.update(.processed, 20);
    server.injectEvent(.{ .tip_changed = 20 });

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expectEqual(3, handler.received.items.len);
    const parsed_notif2 = try parseLogsNotification(allocator, handler.received.items[2]);
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;
    try std.testing.expectEqualStrings(
        "Program log: other fork",
        notif2.params.result.value.logs[0],
    );
}

test "logsSubscribe processed does not publish frozen off-fork slot" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 10, 0, &.{10});
    try addTrackedSlot(server, 20, 0, &.{20});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all",{"commitment":"processed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    try std.testing.expectEqual(1, handler.received.items.len);

    server.slot_tracker.commitments.update(.processed, 10);
    server.injectEvent(.{ .tip_changed = 10 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(1, handler.received.items.len);

    server.injectEvent(try makeLogsEvent(allocator, 20, &.{.{
        .signature_fill = 0x1A,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: off fork"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 20, .parent = 0, .root = 0 } });

    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(1, handler.received.items.len);
}

test "logsSubscribe confirmed flushes ancestors in order and does not duplicate on root" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 1, 0, &.{1});
    try addTrackedSlot(server, 2, 1, &.{ 1, 2 });
    try addTrackedSlot(server, 3, 2, &.{ 1, 2, 3 });

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all",{"commitment":"confirmed"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 1, &.{.{
        .signature_fill = 0x1A,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: slot 1"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(try makeLogsEvent(allocator, 2, &.{.{
        .signature_fill = 0x1B,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: slot 2"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(try makeLogsEvent(allocator, 3, &.{.{
        .signature_fill = 0x1C,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: slot 3"},
        .mentioned_pubkeys = &.{},
    }}));

    server.injectEvent(.{ .slot_frozen = .{ .slot = 1, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 2, .parent = 1, .root = 0 } });
    server.injectEvent(.{ .slot_confirmed = 3 });
    runBothLoops(server, &client_env, &handler, 300);

    try std.testing.expectEqual(1, handler.received.items.len);

    server.injectEvent(.{ .slot_frozen = .{ .slot = 3, .parent = 2, .root = 0 } });

    waitForMessages(server, &client_env, &handler, 4, 5000);
    const parsed_notif1 = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;

    const parsed_notif2 = try parseLogsNotification(allocator, handler.received.items[2]);
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;

    const parsed_notif3 = try parseLogsNotification(allocator, handler.received.items[3]);
    defer parsed_notif3.deinit();
    const notif3 = parsed_notif3.value;

    try std.testing.expectEqualStrings("Program log: slot 1", notif1.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: slot 2", notif2.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: slot 3", notif3.params.result.value.logs[0]);

    server.injectEvent(.{ .slot_rooted = 3 });
    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(4, handler.received.items.len);
}

test "logsSubscribe finalized publishes rooted slots in order" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 4, 0, &.{4});
    try addTrackedSlot(server, 5, 4, &.{ 4, 5 });
    try addTrackedSlot(server, 6, 5, &.{ 4, 5, 6 });

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["all",{"commitment":"finalized"}]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 4, &.{.{
        .signature_fill = 0x1D,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: root 4"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(try makeLogsEvent(allocator, 5, &.{.{
        .signature_fill = 0x1E,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: root 5"},
        .mentioned_pubkeys = &.{},
    }}));
    server.injectEvent(try makeLogsEvent(allocator, 6, &.{.{
        .signature_fill = 0x1F,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: root 6"},
        .mentioned_pubkeys = &.{},
    }}));

    server.injectEvent(.{ .slot_frozen = .{ .slot = 4, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 5, .parent = 4, .root = 0 } });
    server.injectEvent(.{ .slot_frozen = .{ .slot = 6, .parent = 5, .root = 0 } });

    server.injectEvent(.{ .slot_rooted = 4 });
    server.injectEvent(.{ .slot_rooted = 5 });
    server.injectEvent(.{ .slot_rooted = 6 });

    waitForMessages(server, &client_env, &handler, 4, 5000);
    const parsed_notif1 = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;

    const parsed_notif2 = try parseLogsNotification(allocator, handler.received.items[2]);
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;

    const parsed_notif3 = try parseLogsNotification(allocator, handler.received.items[3]);
    defer parsed_notif3.deinit();
    const notif3 = parsed_notif3.value;

    try std.testing.expectEqualStrings("Program log: root 4", notif1.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: root 5", notif2.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: root 6", notif3.params.result.value.logs[0]);
}

test "logsSubscribe preserves transaction log order across batches within a slot" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    try addTrackedSlot(server, 80, 0, &.{80});

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();

    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"logsSubscribe","params":["allWithVotes"]}
    );
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);

    server.injectEvent(try makeLogsEvent(allocator, 80, &.{
        .{
            .signature_fill = 0x20,
            .tx_err = null,
            .is_vote = false,
            .log_lines = &.{"Program log: first"},
            .mentioned_pubkeys = &.{},
        },
        .{
            .signature_fill = 0x21,
            .tx_err = null,
            .is_vote = false,
            .log_lines = &.{"Program log: second"},
            .mentioned_pubkeys = &.{},
        },
    }));
    server.injectEvent(try makeLogsEvent(allocator, 80, &.{.{
        .signature_fill = 0x22,
        .tx_err = null,
        .is_vote = false,
        .log_lines = &.{"Program log: third"},
        .mentioned_pubkeys = &.{},
    }}));

    server.injectEvent(.{ .slot_frozen = .{ .slot = 80, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 80 });

    waitForMessages(server, &client_env, &handler, 4, 5000);
    const parsed_notif1 = try parseLogsNotification(allocator, handler.received.items[1]);
    defer parsed_notif1.deinit();
    const notif1 = parsed_notif1.value;

    const parsed_notif2 = try parseLogsNotification(allocator, handler.received.items[2]);
    defer parsed_notif2.deinit();
    const notif2 = parsed_notif2.value;

    const parsed_notif3 = try parseLogsNotification(allocator, handler.received.items[3]);
    defer parsed_notif3.deinit();
    const notif3 = parsed_notif3.value;

    try std.testing.expectEqualStrings("Program log: first", notif1.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: second", notif2.params.result.value.logs[0]);
    try std.testing.expectEqualStrings("Program log: third", notif3.params.result.value.logs[0]);
}
