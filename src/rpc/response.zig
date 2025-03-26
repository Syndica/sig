const std = @import("std");

pub const ParseError = std.json.ParseError(std.json.Scanner) || error{MissingResult};

/// Wraps a parsed response from the RPC server with an arena that owns all
/// contained pointers.
pub fn Response(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        id: u64,
        jsonrpc: []const u8,
        payload: Payload,
        const Self = @This();

        pub const Payload = union(enum) {
            result: T,
            err: Error,
        };

        pub fn fromJson(
            allocator: std.mem.Allocator,
            response_json: []const u8,
        ) ParseError!Response(T) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(arena);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();
            const raw_response = try std.json.parseFromSliceLeaky(
                struct {
                    id: u64,
                    jsonrpc: []const u8,
                    result: ?T = null,
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

        pub fn deinit(self: Self) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn result(self: Self) !T {
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

    pub fn eql(self: Error, other: Error) bool {
        return self.code == other.code and std.mem.eql(u8, self.message, other.message);
    }
};
