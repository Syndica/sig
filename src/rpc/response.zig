const std = @import("std");

pub fn Response(comptime T: type) type {
    return struct {
        id: ?u64,
        jsonrpc: []const u8,
        result: ?T = null,
        @"error": ?Error = null,

        const Error = struct {
            code: i64,
            message: []const u8,

            pub fn toJsonString(self: Error, allocator: std.mem.Allocator) ![]const u8 {
                return try std.json.stringifyAlloc(allocator, self, .{});
            }
        };
    };
}
