const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BlockstoreReader = sig.ledger.BlockstoreReader;

const GetTransaction = rpc.methods.GetTransaction;

pub fn Response(comptime Method: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        id: u64,
        jsonrpc: []const u8,
        payload: union(enum) {
            result: Method.Response,
            err: Error,
        },

        pub fn fromJson(
            allocator: Allocator,
            response_json: []const u8,
        ) !Response(Method) {
            const arena = try allocator.create(std.heap.ArenaAllocator);
            arena.* = std.heap.ArenaAllocator.init(allocator);
            const raw_response = try std.json.parseFromSliceLeaky(
                struct {
                    id: u64,
                    jsonrpc: []const u8,
                    result: ?Method.Response = null,
                    @"error": ?Error = null,
                },
                allocator,
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
                    .result = raw_response.result orelse return error.MalformedResponse,
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

pub fn serializeRequest(allocator: Allocator, request: anytype) ![]const u8 {
    return try std.json.stringifyAlloc(
        allocator,
        .{
            .id = 1,
            .jsonrpc = "2.0",
            .method = methodName(request),
            .params = asTuple(request),
        },
        .{ .emit_null_optional_fields = false },
    );
}

fn asTuple(item: anytype) AsTuple(@TypeOf(item)) {
    var tuple: AsTuple(@TypeOf(item)) = undefined;
    inline for (@typeInfo(@TypeOf(item)).Struct.fields, 0..) |*field, i| {
        tuple[i] = @field(item, field.name);
    }
    return tuple;
}

fn methodName(request: anytype) []const u8 {
    const method_name = comptime blk: {
        const struct_name = @typeName(@TypeOf(request));
        var num_chars = 0;
        for (struct_name) |char| {
            num_chars += 1;
            if (char == '.') num_chars = 0;
        }
        var method_name: [num_chars]u8 = undefined;
        @memcpy(&method_name, struct_name[struct_name.len - num_chars .. struct_name.len]);
        method_name[0] = method_name[0] + 0x20;
        break :blk method_name;
    };
    return &method_name;
}

pub fn AsTuple(comptime Struct: type) type {
    var info = @typeInfo(Struct).Struct;
    // const new_fields: [info.fields.len]std.builtin.Type.StructField = info.fields[0..];
    var new_fields: [info.fields.len]std.builtin.Type.StructField = undefined;
    inline for (&new_fields, 0..) |*field, i| {
        field.* = info.fields[i];
        field.name = std.fmt.comptimePrint("{}", .{i});
    }
    info.fields = &new_fields;
    info.is_tuple = true;
    info.decls = &.{};
    return @Type(.{ .Struct = info });
}

fn reqrap(request: anytype) struct {} {
    _ = request; // autofix
}

test "serializeRequest" {
    const allocator = std.testing.allocator;

    const Config = struct {
        key: []const u8 = "default",
    };

    var signatures = std.ArrayList([]const u8).init(allocator);
    defer signatures.deinit();
    try signatures.append("signature1");
    try signatures.append("signature2");

    const GetAccountInfo = struct {
        pubkey: []const u8,
        num: u64,
        bool: bool,
        opt: ?u64,
        sigs: []const []const u8,
        empty_conf: ?Config,
        conf: ?Config,

        const method = "getAccountInfo";
    };

    const my_request = GetAccountInfo{
        .pubkey = "mypubkey",
        .num = 35,
        .bool = true,
        .opt = null,
        .sigs = signatures.items,
        .empty_conf = null,
        .conf = Config{ .key = "non-default" },
    };

    const expected = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"getAccountInfo\",\"params\":" ++
        "[\"mypubkey\",35,true,[\"signature1\",\"signature2\"],{\"key\":\"non-default\"}]}";
    const actual = try serializeRequest(allocator, my_request);
    defer allocator.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);
}
