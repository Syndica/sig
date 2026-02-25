const std = @import("std");
const sig = @import("../sig.zig");

pub const ParseError = std.json.ParseError(std.json.Scanner) || error{MissingResult};

/// Wraps a parsed response from the RPC server with an arena that owns all
/// contained pointers.
pub fn Response(comptime T: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        id: sig.rpc.request.Id,
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
                    id: sig.rpc.request.Id,
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
    code: ErrorCode,
    message: []const u8,
    data: ?std.json.Value = null,

    // TODO: Replace data with structured data
    pub fn dataAsString(self: *const Error, allocator: std.mem.Allocator) ![]const u8 {
        var w = std.io.Writer.Allocating.init(allocator);
        try std.json.fmt(self.data.?, .{}).format(&w.writer);
        return try w.toOwnedSlice();
    }

    pub fn eql(self: Error, other: Error) bool {
        return self.code == other.code and std.mem.eql(u8, self.message, other.message);
    }
};

pub const ErrorCode = enum(i64) {
    /// Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.
    parse_error = -32700,
    /// The JSON sent is not a valid Request object.
    invalid_request = -32600,
    /// The method does not exist / is not available.
    method_not_found = -32601,
    /// Invalid method parameter(s).
    invalid_params = -32602,
    /// Internal JSON-RPC error.
    internal_error = -32603,

    _,

    pub const server_error_first: ErrorCode = @enumFromInt(-32_000);
    pub const server_error_last: ErrorCode = @enumFromInt(-32_099);

    pub const reserved_error_first: ErrorCode = @enumFromInt(-32_100);
    pub const reserved_error_last: ErrorCode = @enumFromInt(-32_768);

    pub fn isServerError(code: ErrorCode) bool {
        return switch (code) {
            server_error_first...server_error_last => true,
            else => false,
        };
    }

    pub fn isAppError(code: ErrorCode) bool {
        return switch (code) {
            server_error_first...server_error_last => false,
            reserved_error_first...reserved_error_last => false,
            else => true,
        };
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        /// * `std.json.Scanner`
        /// * `std.json.Reader(...)`
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!ErrorCode {
        return @enumFromInt(try std.json.innerParse(i64, allocator, source, options));
    }

    pub fn jsonStringify(
        self: ErrorCode,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        try jw.write(@intFromEnum(self));
    }
};

test testErrorCodeParse {
    try testErrorCodeParse(.{}, .parse_error, "-32700");
    try testErrorCodeParse(.{}, .invalid_request, "-32600");
    try testErrorCodeParse(.{}, .method_not_found, "-32601");
    try testErrorCodeParse(.{}, .invalid_params, "-32602");
    try testErrorCodeParse(.{}, .internal_error, "-32603");
    try testErrorCodeParse(.{}, @enumFromInt(-1), "-1");
    try testErrorCodeParse(.{}, error.Overflow, "999999999999999999999999999999999999999999");
}

fn testErrorCodeParse(
    options: std.json.ParseOptions,
    expected: std.json.ParseError(std.json.Scanner)!ErrorCode,
    str: []const u8,
) !void {
    const allocator = std.testing.allocator;
    const actual_res = std.json.parseFromSlice(ErrorCode, allocator, str, options) catch |err| {
        try std.testing.expectEqual(expected, err);
        return;
    };
    defer actual_res.deinit();
    const actual = actual_res.value;
    try std.testing.expectEqual(expected, actual);
}

test testErrorCodeStringify {
    try testErrorCodeStringify(.{}, .parse_error, "-32700");
    try testErrorCodeStringify(.{}, .invalid_request, "-32600");
    try testErrorCodeStringify(.{}, .method_not_found, "-32601");
    try testErrorCodeStringify(.{}, .invalid_params, "-32602");
    try testErrorCodeStringify(.{}, .internal_error, "-32603");
    try testErrorCodeStringify(.{}, @enumFromInt(-1), "-1");
}

fn testErrorCodeStringify(
    options: std.json.Stringify.Options,
    value: ErrorCode,
    expected: []const u8,
) !void {
    const allocator = std.testing.allocator;
    var w = std.io.Writer.Allocating.init(allocator);
    defer w.deinit();
    try std.json.fmt(value, options).format(&w.writer);
    try std.testing.expectEqualStrings(expected, w.written());
}
