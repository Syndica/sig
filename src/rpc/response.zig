const std = @import("std");

const Allocator = std.mem.Allocator;

/// Wraps a parsed response from the RPC server with an arena that owns all
/// contained pointers.
pub fn Response(comptime Method: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        id: u64,
        jsonrpc: []const u8,
        payload: Payload,

        pub const Payload = union(enum) {
            result: Method.Response,
            err: Error,
        };

        pub fn fromJson(allocator: Allocator, response_json: []const u8) !Response(Method) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(arena);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();
            const raw_response = try std.json.parseFromSliceLeaky(
                struct {
                    id: u64,
                    jsonrpc: []const u8,
                    result: ?Method.Response = null,
                    @"error": ?Error = null,
                },
                arena.allocator(),
                response_json,
                .{},
            );
            return .{
                .arena = arena,
                .id = raw_response.id,
                .jsonrpc = raw_response.jsonrpc,
                .payload = if (raw_response.@"error") |err| .{
                    .err = err,
                } else .{
                    .result = raw_response.result orelse return error.MissingResult,
                },
            };
        }

        pub fn deinit(self: Response(Method)) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn result(self: Response(Method)) !Method.Response {
            return switch (self.payload) {
                .result => |r| r,
                .err => error.RpcRequestFailed,
            };
        }
    };
}

pub const Error = struct {
    code: i64,
    message: []const u8,
    data: ?std.json.Value = null,

    // TODO: Replace data with structured data
    pub fn dataAsString(self: *const Error, allocator: std.mem.Allocator) ![]const u8 {
        return std.json.stringifyAlloc(allocator, self.data.?, .{});
    }
};
