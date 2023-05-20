const std = @import("std");
const json = std.json;

pub fn ResponsePayload(comptime Result: type) type {
    return struct {
        jsonrpc: []const u8,
        id: []const u8,
        result: ?Result = null,
        @"error": ?ErrorObject = null,
    };
}

pub fn Response(comptime Result: type) type {
    return struct {
        alloc: std.mem.Allocator,
        response: ResponsePayload(Result),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, resp: ResponsePayload(Result)) Self {
            return Self{
                .alloc = allocator,
                .response = resp,
            };
        }

        pub fn deinit(self: *Self) void {
            json.parseFree(ResponsePayload(Result), self.alloc, self.response);
        }

        /// ***err*** func will return an optional `ErrorObject` from the JsonRpc response payload.
        ///
        /// *Example usage:*
        /// ```zig
        /// if(resp.err()) |err| {
        ///     // handle err
        /// }
        /// ```
        pub fn err(self: *const Self) ?ErrorObject {
            return self.response.@"error";
        }

        /// ***result*** func returns the `result` field from a JsonRpc response payload.
        /// Note: this will panic if `err()` func is not called first to check if an error
        /// response was sent resulting in the `result` field being null.
        ///
        /// *Example usage:*
        /// ```zig
        /// if(resp.err()) |err| {
        ///     // handle err
        /// }
        ///
        /// const aField = resp.result().someField;
        ///
        /// ```
        pub fn result(self: *const Self) Result {
            return self.response.result.?;
        }

        /// ***result*** func returns the `result` field from a JsonRpc response payload which
        /// maybe null.
        pub fn resultOption(self: *const Self) ?Result {
            return self.response.result;
        }
    };
}

pub fn ResponseAlt(comptime Result: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        tree: json.ValueTree,
        response: ResponsePayload(Result),

        const Self = @This();

        pub fn init(
            arena: std.heap.ArenaAllocator,
            resp: ResponsePayload(Result),
            tree: json.ValueTree,
        ) Self {
            return Self{
                .arena = arena,
                .tree = tree,
                .response = resp,
            };
        }

        pub fn deinit(self: *Self) void {
            self.tree.deinit();
            self.arena.deinit();
        }

        /// ***err*** func will return an optional `ErrorObject` from the JsonRpc response payload.
        ///
        /// *Example usage:*
        /// ```zig
        /// if(resp.err()) |err| {
        ///     // handle err
        /// }
        /// ```
        pub fn err(self: *const Self) ?ErrorObject {
            return self.response.@"error";
        }

        /// ***result*** func returns the `result` field from a JsonRpc response payload.
        /// Note: this will panic if `err()` func is not called first to check if an error
        /// response was sent resulting in the `result` field being null.
        ///
        /// *Example usage:*
        /// ```zig
        /// if(resp.err()) |err| {
        ///     // handle err
        /// }
        ///
        /// const aField = resp.result().someField;
        ///
        /// ```
        pub fn result(self: *const Self) Result {
            return self.response.result.?;
        }

        /// ***result*** func returns the `result` field from a JsonRpc response payload which
        /// maybe null.
        pub fn resultOption(self: *const Self) ?Result {
            return self.response.result;
        }
    };
}

pub fn Request(comptime params: anytype) type {
    return struct {
        jsonrpc: []const u8,
        id: []const u8,
        method: []const u8,
        params: ?params,
    };
}

pub const ErrorObject = struct { code: i64, message: []const u8 };
