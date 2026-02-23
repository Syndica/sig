const std = @import("std");
const ws = @import("webzockets_lib");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

test "medium message requiring pooled buffer (8KB)" {
    try runBufferTierTest(8 * 1024, null);
}

test "large message requiring pooled buffer (32KB)" {
    try runBufferTierTest(32 * 1024, null);
}

test "message at pool buffer boundary (64KB)" {
    try runBufferTierTest(64 * 1024, 128 * 1024);
}

test "large message requiring dynamic allocation (128KB)" {
    try runBufferTierTest(128 * 1024, 256 * 1024);
}

test "very large message requiring dynamic allocation (256KB)" {
    try runBufferTierTest(256 * 1024, 512 * 1024);
}

test "buffer tier retained after large messages" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const medium_size = 8 * 1024;
    const medium_msg = try testing.allocator.alloc(u8, medium_size);
    defer testing.allocator.free(medium_msg);
    @memset(medium_msg, 'M');

    const large_size = 100 * 1024;
    const large_msg = try testing.allocator.alloc(u8, large_size);
    defer testing.allocator.free(large_msg);
    @memset(large_msg, 'L');

    const messages = [_]clients.SequenceHandler.MsgSpec{
        .{ .data = "small", .is_binary = false },
        .{ .data = medium_msg, .is_binary = true },
        .{ .data = "still pooled", .is_binary = false },
        .{ .data = large_msg, .is_binary = true },
        .{ .data = "still dynamic", .is_binary = false },
    };

    var handler: clients.SequenceHandler = .{
        .messages = &messages,
        .results = std.ArrayList(clients.SequenceHandler.RecvResult).init(testing.allocator),
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: TestLargeSeqClient.Conn = undefined;
    var client = env.initClient(TestLargeSeqClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .max_message_size = 128 * 1024,
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 5), handler.results.items.len);
    try testing.expectEqualSlices(u8, "small", handler.results.items[0].data);
    try testing.expectEqual(medium_size, handler.results.items[1].len);
    try testing.expectEqualSlices(u8, "still pooled", handler.results.items[2].data);
    try testing.expectEqual(large_size, handler.results.items[3].len);
    try testing.expectEqualSlices(u8, "still dynamic", handler.results.items[4].data);
}

/// Send a binary message of `msg_size` bytes (filled with a repeating index
/// pattern) via the library client, verify the echo matches byte-for-byte.
/// If `max_message_size` is non-null it is forwarded to the client config.
fn runBufferTierTest(msg_size: usize, max_message_size: ?usize) !void {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const msg = try testing.allocator.alloc(u8, msg_size);
    defer testing.allocator.free(msg);
    for (msg, 0..) |*byte, i| byte.* = @truncate(i);

    var handler: LargeMessageHandler = .{
        .send_data = msg,
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: TestLargeClient.Conn = undefined;
    var config: TestLargeClient.Config = .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    };
    if (max_message_size) |mms| {
        config.max_message_size = mms;
    }
    var client = env.initClient(TestLargeClient, &handler, &conn, config);
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(msg_size, handler.received_len);
    const received = handler.received_data orelse return error.NoData;
    for (received, 0..) |byte, i| {
        try testing.expectEqual(@as(u8, @truncate(i)), byte);
    }
}

/// Client-side handler for large message tests.
/// Sends binary data on open, captures response, then closes.
const LargeMessageHandler = struct {
    send_data: []const u8,
    received_data: ?[]const u8 = null,
    received_len: usize = 0,
    open_called: bool = false,
    allocator: std.mem.Allocator,
    sent_data: ?[]const u8 = null,

    pub fn deinit(self: *LargeMessageHandler) void {
        if (self.received_data) |data| {
            self.allocator.free(data);
            self.received_data = null;
        }
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onOpen(self: *LargeMessageHandler, conn: anytype) void {
        self.open_called = true;
        const copy = self.allocator.dupe(u8, self.send_data) catch return;
        conn.sendBinary(copy) catch {
            self.allocator.free(copy);
            return;
        };
        self.sent_data = copy;
    }

    pub fn onMessage(self: *LargeMessageHandler, conn: anytype, message: ws.Message) void {
        self.received_data = self.allocator.dupe(u8, message.data) catch null;
        self.received_len = message.data.len;
        conn.close(.normal, "");
    }

    pub fn onWriteComplete(self: *LargeMessageHandler, _: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onClose(self: *LargeMessageHandler, _: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Single client type with large buffer for all buffer tier tests.
const TestLargeClient = ws.Client(LargeMessageHandler, 256 * 1024);

/// Large sequence client for mixed message sequence tests.
const TestLargeSeqClient = ws.Client(clients.SequenceHandler, 128 * 1024);
