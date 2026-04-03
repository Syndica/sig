const std = @import("std");

const helpers = @import("support/test_helpers.zig");
const sig = helpers.sig;
const lib = @import("../lib.zig");

const Hash = sig.core.Hash;
const Signature = helpers.Signature;
const TestClient = helpers.TestClient;
const TestClientEnv = helpers.TestClientEnv;
const TestClientHandler = helpers.TestClientHandler;
const TestServer = helpers.TestServer;
const addTrackedSlot = helpers.addTrackedSlot;
const initTestClient = helpers.initTestClient;
const insertSignatureStatus = helpers.insertSignatureStatus;
const parseResultU64 = helpers.parseResultU64;
const runBothLoops = helpers.runBothLoops;
const waitForMessages = helpers.waitForMessages;

const types = lib.types;

const SignatureNotification = struct {
    method: []const u8,
    params: struct {
        result: struct {
            context: struct {
                slot: u64,
            },
            value: std.json.Value,
        },
        subscription: u64,
    },
};

const JsonRpcErrorResponse = struct {
    id: ?u64,
    @"error": struct {
        code: i64,
        message: []const u8,
    },
};

fn signatureWithFill(fill: u8) Signature {
    var signature = Signature.ZEROES;
    @memset(&signature.r, fill);
    @memset(&signature.s, fill);
    return signature;
}

fn signatureSubscribeRequest(
    allocator: std.mem.Allocator,
    id: u64,
    signature: Signature,
    maybe_config_json: ?[]const u8,
) ![]u8 {
    const signature_str = signature.base58String().slice();
    return if (maybe_config_json) |config_json|
        std.fmt.allocPrint(
            allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":{d}," ++
                "\"method\":\"signatureSubscribe\",\"params\":[\"{s}\",{s}]}}",
            .{ id, signature_str, config_json },
        )
    else
        std.fmt.allocPrint(
            allocator,
            "{{\"jsonrpc\":\"2.0\",\"id\":{d}," ++
                "\"method\":\"signatureSubscribe\",\"params\":[\"{s}\"]}}",
            .{ id, signature_str },
        );
}

fn makeReceivedSignaturesEvent(
    allocator: std.mem.Allocator,
    slot: u64,
    signatures: []const Signature,
) !types.InboundEvent {
    return .{ .received_signatures = .{
        .slot = slot,
        .signatures = try allocator.dupe(Signature, signatures),
    } };
}

fn parseSignatureNotification(
    allocator: std.mem.Allocator,
    msg: []const u8,
) !std.json.Parsed(SignatureNotification) {
    return std.json.parseFromSlice(
        SignatureNotification,
        allocator,
        msg,
        .{ .ignore_unknown_fields = true },
    );
}

fn expectReceivedNotification(
    notification: SignatureNotification,
    slot: u64,
    sub_id: u64,
) !void {
    try std.testing.expectEqualStrings("signatureNotification", notification.method);
    try std.testing.expectEqual(slot, notification.params.result.context.slot);
    try std.testing.expectEqual(sub_id, notification.params.subscription);
    try std.testing.expect(notification.params.result.value == .string);
    try std.testing.expectEqualStrings(
        "receivedSignature",
        notification.params.result.value.string,
    );
}

fn expectFinalNotificationNullErr(
    notification: SignatureNotification,
    slot: u64,
    sub_id: u64,
) !void {
    try std.testing.expectEqualStrings("signatureNotification", notification.method);
    try std.testing.expectEqual(slot, notification.params.result.context.slot);
    try std.testing.expectEqual(sub_id, notification.params.subscription);
    try std.testing.expect(notification.params.result.value == .object);
    const err_value = notification.params.result.value.object.get("err") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(err_value == .null);
}

fn mustParseSubId(response: []const u8) !u64 {
    return parseResultU64(response) orelse error.TestUnexpectedResult;
}

test "signatureSubscribe basic response and distinct keying" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const signature = signatureWithFill(0x31);
    const req_processed = try signatureSubscribeRequest(
        allocator,
        1,
        signature,
        "{\"commitment\":\"processed\"}",
    );
    defer allocator.free(req_processed);

    const req_confirmed = try signatureSubscribeRequest(
        allocator,
        2,
        signature,
        "{\"commitment\":\"confirmed\"}",
    );
    defer allocator.free(req_confirmed);

    const req_received = try signatureSubscribeRequest(
        allocator,
        3,
        signature,
        "{\"commitment\":\"processed\",\"enableReceivedNotification\":true}",
    );
    defer allocator.free(req_received);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(req_processed);
    handler.queueSend(req_confirmed);
    handler.queueSend(req_received);
    handler.close_after = 3;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 3, 5000);
    try std.testing.expectEqual(3, handler.received.items.len);

    const first_sub_id = try mustParseSubId(handler.received.items[0]);
    const second_sub_id = try mustParseSubId(handler.received.items[1]);
    const third_sub_id = try mustParseSubId(handler.received.items[2]);

    try std.testing.expect(first_sub_id != second_sub_id);
    try std.testing.expect(first_sub_id != third_sub_id);
    try std.testing.expect(second_sub_id != third_sub_id);
}

test "signatureSubscribe received notification ignores commitment and does not auto-unsubscribe" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const signature = signatureWithFill(0x41);
    const request = try signatureSubscribeRequest(
        allocator,
        1,
        signature,
        "{\"commitment\":\"finalized\",\"enableReceivedNotification\":true}",
    );
    defer allocator.free(request);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(request);
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    const sub_id = try mustParseSubId(handler.received.items[0]);

    server.injectEvent(try makeReceivedSignaturesEvent(allocator, 55, &.{signature}));

    waitForMessages(server, &client_env, &handler, 2, 5000);
    const parsed_received = try parseSignatureNotification(allocator, handler.received.items[1]);
    defer parsed_received.deinit();
    try expectReceivedNotification(parsed_received.value, 55, sub_id);

    try addTrackedSlot(server, 55, 0, &.{55});
    try addTrackedSlot(server, 56, 55, &.{ 55, 56 });
    try insertSignatureStatus(server, 55, Hash.ZEROES, signature, null);
    server.commitments.update(.finalized, 56);
    server.injectEvent(.{ .slot_frozen = .{ .slot = 56, .parent = 55, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 56 });

    waitForMessages(server, &client_env, &handler, 3, 5000);
    const parsed_final = try parseSignatureNotification(allocator, handler.received.items[2]);
    defer parsed_final.deinit();
    try expectFinalNotificationNullErr(parsed_final.value, 56, sub_id);
}

test "signatureSubscribe received notification is gated by enableReceivedNotification" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const signature = signatureWithFill(0x42);
    const request = try signatureSubscribeRequest(
        allocator,
        1,
        signature,
        "{\"commitment\":\"processed\",\"enableReceivedNotification\":false}",
    );
    defer allocator.free(request);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(request);
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    server.injectEvent(try makeReceivedSignaturesEvent(allocator, 60, &.{signature}));

    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(1, handler.received.items.len);
}

test "signatureSubscribe orders received before final and auto-unsubscribes after final" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const signature = signatureWithFill(0x51);
    try addTrackedSlot(server, 70, 0, &.{70});
    try addTrackedSlot(server, 71, 70, &.{ 70, 71 });
    try insertSignatureStatus(server, 70, Hash.ZEROES, signature, null);

    const request = try signatureSubscribeRequest(
        allocator,
        1,
        signature,
        "{\"commitment\":\"processed\",\"enableReceivedNotification\":true}",
    );
    defer allocator.free(request);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(request);
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    const sub_id = try mustParseSubId(handler.received.items[0]);

    server.commitments.update(.processed, 71);
    server.injectEvent(try makeReceivedSignaturesEvent(allocator, 70, &.{signature}));
    server.injectEvent(.{ .slot_frozen = .{ .slot = 71, .parent = 70, .root = 0 } });
    server.injectEvent(.{ .tip_changed = 71 });

    waitForMessages(server, &client_env, &handler, 3, 5000);
    const parsed_received = try parseSignatureNotification(allocator, handler.received.items[1]);
    defer parsed_received.deinit();
    try expectReceivedNotification(parsed_received.value, 70, sub_id);

    const parsed_final = try parseSignatureNotification(allocator, handler.received.items[2]);
    defer parsed_final.deinit();
    try expectFinalNotificationNullErr(parsed_final.value, 71, sub_id);

    server.injectEvent(try makeReceivedSignaturesEvent(allocator, 72, &.{signature}));
    server.injectEvent(.{ .tip_changed = 71 });
    runBothLoops(server, &client_env, &handler, 300);

    try std.testing.expectEqual(3, handler.received.items.len);
    try std.testing.expectEqual(0, server.sub_map.entries.items.len);
}

test "signatureSubscribe final notifications honor processed confirmed and finalized transitions" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const processed_sig = signatureWithFill(0x61);
    const confirmed_sig = signatureWithFill(0x62);
    const finalized_sig = signatureWithFill(0x63);

    try addTrackedSlot(server, 80, 0, &.{80});
    try addTrackedSlot(server, 81, 80, &.{ 80, 81 });
    try addTrackedSlot(server, 82, 81, &.{ 80, 81, 82 });
    try insertSignatureStatus(server, 80, Hash.ZEROES, processed_sig, null);
    try insertSignatureStatus(server, 81, Hash.ZEROES, confirmed_sig, null);
    try insertSignatureStatus(server, 82, Hash.ZEROES, finalized_sig, null);

    const processed_request = try signatureSubscribeRequest(
        allocator,
        1,
        processed_sig,
        "{\"commitment\":\"processed\"}",
    );
    defer allocator.free(processed_request);
    const confirmed_request = try signatureSubscribeRequest(
        allocator,
        2,
        confirmed_sig,
        "{\"commitment\":\"confirmed\"}",
    );
    defer allocator.free(confirmed_request);
    const finalized_request = try signatureSubscribeRequest(
        allocator,
        3,
        finalized_sig,
        "{\"commitment\":\"finalized\"}",
    );
    defer allocator.free(finalized_request);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(processed_request);
    handler.queueSend(confirmed_request);
    handler.queueSend(finalized_request);
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 3, 5000);
    const processed_sub_id = try mustParseSubId(handler.received.items[0]);
    const confirmed_sub_id = try mustParseSubId(handler.received.items[1]);
    const finalized_sub_id = try mustParseSubId(handler.received.items[2]);

    server.commitments.update(.processed, 80);
    server.injectEvent(.{ .slot_frozen = .{ .slot = 80, .parent = 0, .root = 0 } });
    server.injectEvent(.{ .tip_changed = 80 });

    waitForMessages(server, &client_env, &handler, 4, 5000);
    const processed_notif = try parseSignatureNotification(allocator, handler.received.items[3]);
    defer processed_notif.deinit();
    try expectFinalNotificationNullErr(processed_notif.value, 80, processed_sub_id);

    try std.testing.expectEqual(4, handler.received.items.len);
    server.commitments.update(.confirmed, 81);
    server.injectEvent(.{ .slot_frozen = .{ .slot = 81, .parent = 80, .root = 0 } });
    server.injectEvent(.{ .slot_confirmed = 81 });

    waitForMessages(server, &client_env, &handler, 5, 5000);
    const confirmed_notif = try parseSignatureNotification(allocator, handler.received.items[4]);
    defer confirmed_notif.deinit();
    try expectFinalNotificationNullErr(confirmed_notif.value, 81, confirmed_sub_id);

    try std.testing.expectEqual(5, handler.received.items.len);
    server.commitments.update(.finalized, 82);
    server.injectEvent(.{ .slot_frozen = .{ .slot = 82, .parent = 81, .root = 0 } });
    server.injectEvent(.{ .slot_rooted = 82 });

    waitForMessages(server, &client_env, &handler, 6, 5000);
    const finalized_notif = try parseSignatureNotification(allocator, handler.received.items[5]);
    defer finalized_notif.deinit();
    try expectFinalNotificationNullErr(finalized_notif.value, 82, finalized_sub_id);
}

test "signatureSubscribe already-landed signatures notify asynchronously and suppress duplicates" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    const signature = signatureWithFill(0x71);
    try addTrackedSlot(server, 90, 0, &.{90});
    try addTrackedSlot(server, 91, 90, &.{ 90, 91 });
    try insertSignatureStatus(server, 90, Hash.ZEROES, signature, .AccountInUse);

    const request = try signatureSubscribeRequest(
        allocator,
        1,
        signature,
        "{\"commitment\":\"processed\"}",
    );
    defer allocator.free(request);

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(request);
    handler.close_after = 0;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 1, 5000);
    const sub_id = try mustParseSubId(handler.received.items[0]);

    server.commitments.update(.processed, 91);
    server.injectEvent(.{ .slot_frozen = .{ .slot = 91, .parent = 90, .root = 0 } });
    server.injectEvent(.{ .tip_changed = 91 });
    server.injectEvent(.{ .tip_changed = 91 });

    waitForMessages(server, &client_env, &handler, 2, 5000);
    const parsed_notif = try parseSignatureNotification(allocator, handler.received.items[1]);
    defer parsed_notif.deinit();

    try std.testing.expectEqualStrings("signatureNotification", parsed_notif.value.method);
    try std.testing.expectEqual(91, parsed_notif.value.params.result.context.slot);
    try std.testing.expectEqual(sub_id, parsed_notif.value.params.subscription);
    try std.testing.expect(parsed_notif.value.params.result.value == .object);
    const err_value = parsed_notif.value.params.result.value.object.get("err") orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(err_value == .string);
    try std.testing.expectEqualStrings("AccountInUse", err_value.string);

    runBothLoops(server, &client_env, &handler, 300);
    try std.testing.expectEqual(2, handler.received.items.len);
}

test "signatureSubscribe invalid signature gets invalid params error" {
    const allocator = std.testing.allocator;

    var server = try TestServer.start(allocator);
    defer {
        server.stop();
        server.deinit();
    }

    var handler = TestClientHandler.init(allocator);
    defer handler.deinit();
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":1,"method":"signatureSubscribe","params":["not-a-signature"]}
    );
    handler.queueSend(
        \\{"jsonrpc":"2.0","id":2,"method":"accountSubscribe","params":[]}
    );
    handler.close_after = 2;

    var client_env: TestClientEnv = undefined;
    try client_env.start();
    defer client_env.deinit();

    var conn: TestClient.Conn = undefined;
    var client = initTestClient(allocator, &client_env, &handler, &conn, server.port);
    try client.connect();

    waitForMessages(server, &client_env, &handler, 2, 5000);

    const parsed_signature_error = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[0],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_signature_error.deinit();
    try std.testing.expectEqual(
        1,
        parsed_signature_error.value.id orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(-32602, parsed_signature_error.value.@"error".code);
    try std.testing.expectEqualStrings(
        "invalid params",
        parsed_signature_error.value.@"error".message,
    );

    const parsed_generic_error = try std.json.parseFromSlice(
        JsonRpcErrorResponse,
        allocator,
        handler.received.items[1],
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_generic_error.deinit();
    try std.testing.expectEqual(
        2,
        parsed_generic_error.value.id orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(-32602, parsed_generic_error.value.@"error".code);
    try std.testing.expectEqualStrings(
        "invalid params",
        parsed_generic_error.value.@"error".message,
    );
}
