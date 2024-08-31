const std = @import("std");

/// Request is a struct that represents a JSON-RPC request.
/// It is used to build a JSON-RPC request and serialize it to a string.
/// Parameters and config added must contain primitive types, or types
/// implementing jsonStringify (see std.json.Value.jsonStringify for example)
pub const Request = struct {
    id: u64,
    jsonrpc: []const u8,
    method: []const u8,
    params: std.ArrayList(u8),

    pub fn init(
        allocator: std.mem.Allocator,
        method: []const u8,
    ) !Request {
        var params = std.ArrayList(u8).init(allocator);
        try params.append('[');
        return .{
            .id = 1,
            .jsonrpc = "2.0",
            .method = method,
            .params = params,
        };
    }

    pub fn deinit(self: Request) void {
        self.params.deinit();
    }

    pub fn addParameter(self: *Request, param: anytype) !void {
        try std.json.stringify(param, .{}, self.params.writer());
        try self.params.append(',');
    }

    pub fn addOptionalParameter(self: *Request, maybe_param: anytype) !void {
        if (maybe_param) |param| try self.addParameter(param);
    }

    pub fn addConfig(self: *Request, config: anytype) !void {
        const default = @TypeOf(config){};
        if (!std.meta.eql(default, config)) {
            try std.json.stringify(config, .{ .emit_null_optional_fields = true }, self.params.writer());
            try self.params.append(',');
        }
    }

    pub fn toJsonString(self: Request, allocator: std.mem.Allocator) ![]const u8 {
        if (self.params.items.len > 1) {
            self.params.items[self.params.items.len - 1] = ']';
            return try std.fmt.allocPrint(
                allocator,
                "{{\"id\":{},\"jsonrpc\":\"{s}\",\"method\":\"{s}\",\"params\":{s}}}",
                .{
                    self.id,
                    self.jsonrpc,
                    self.method,
                    self.params.items,
                },
            );
        } else {
            return try std.fmt.allocPrint(
                allocator,
                "{{\"id\":{d},\"jsonrpc\":\"{s}\",\"method\":\"{s}\"}}",
                .{
                    self.id,
                    self.jsonrpc,
                    self.method,
                },
            );
        }
    }
};

test "Request.toJsonString" {
    const allocator = std.testing.allocator;

    const Config = struct {
        key: []const u8 = "default",
    };

    var request = try Request.init(allocator, "getAccountInfo");
    defer request.deinit();

    var signatures = std.ArrayList([]const u8).init(allocator);
    defer signatures.deinit();
    try signatures.append("signature1");
    try signatures.append("signature2");

    try request.addParameter("mypubkey");
    try request.addParameter(35);
    try request.addParameter(true);
    try request.addParameter(null);
    try request.addParameter(signatures.items);
    try request.addConfig(Config{});
    try request.addConfig(Config{ .key = "non-default" });

    const expected = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getAccountInfo\",\"params\":[\"mypubkey\",35,true,null,[\"signature1\",\"signature2\"],{\"key\":\"non-default\"}]}";
    const actual = try request.toJsonString(allocator);
    defer allocator.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);
}
