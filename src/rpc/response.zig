const std = @import("std");

/// Wraps a parsed response from the RPC server with an arena
/// used for request, response, and json parsing allocations
/// The bytes field contains the raw bytes from the response
/// The value field contains a ParsedResponse which may reference
/// memory from the bytes field to avoid copying and hence the
/// bytes field must remain valid for the lifetime of the value field.
pub fn Response(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        bytes: std.ArrayList(u8),
        parsed: ParsedResponse(T),

        pub fn init(allocator: std.mem.Allocator) !Response(T) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            return .{
                .arena = arena,
                .bytes = std.ArrayList(u8).init(arena.allocator()),
                .parsed = undefined,
            };
        }

        pub fn deinit(self: *const Response(T)) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }

        pub fn parse(self: *Response(T)) !void {
            self.parsed = try std.json.parseFromSliceLeaky(
                ParsedResponse(T),
                self.arena.allocator(),
                self.bytes.items,
                .{},
            );
        }

        pub fn result(self: *const Response(T)) !T {
            return if (self.parsed.result) |res| res else error.RpcRequestFailed;
        }
    };
}

pub fn ParsedResponse(comptime T: type) type {
    return struct {
        id: ?u64,
        jsonrpc: []const u8,
        result: ?T = null,
        @"error": ?Error = null,

        const Error = struct {
            code: i64,
            message: []const u8,
        };
    };
}
