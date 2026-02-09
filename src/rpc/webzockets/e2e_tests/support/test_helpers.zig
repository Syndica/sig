const std = @import("std");
const testing = std.testing;
const RawClient = @import("raw_client.zig").RawClient;

/// Connect to the server, complete a WebSocket handshake, send a text message,
/// verify the echo, and close. Used to confirm the server is still functional
/// after stress or error scenarios.
pub fn verifyServerFunctional(port: u16) !void {
    var client = try RawClient.connect(testing.allocator, port);
    defer client.deinit();

    var msg = "hi".*;
    try client.write(&msg);

    const response = (try client.read()) orelse return error.NoResponse;
    defer client.done(response);
    try testing.expectEqualSlices(u8, "hi", response.data);

    try client.close(.{ .code = 1000 });
    if (try client.read()) |close_resp| client.done(close_resp);
}

/// Read a close frame from the client and assert the close code matches.
pub fn expectCloseWithCode(client: *RawClient, expected_code: u16) !void {
    const response = (try client.read()) orelse return error.NoResponse;
    defer client.done(response);
    try testing.expectEqual(.close, response.type);
    try testing.expect(response.data.len >= 2);
    const code = std.mem.readInt(u16, response.data[0..2], .big);
    try testing.expectEqual(expected_code, code);
}

/// Read a close frame and assert both the close code and reason match.
pub fn expectCloseWithCodeAndReason(
    client: *RawClient,
    expected_code: u16,
    expected_reason: []const u8,
) !void {
    const response = (try client.read()) orelse return error.NoResponse;
    defer client.done(response);
    try testing.expectEqual(.close, response.type);
    try testing.expect(response.data.len >= 2);
    const code = std.mem.readInt(u16, response.data[0..2], .big);
    try testing.expectEqual(expected_code, code);
    try testing.expectEqualSlices(u8, expected_reason, response.data[2..]);
}
