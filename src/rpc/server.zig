const std = @import("std");
const sig = @import("../sig.zig");
const rpc = @import("lib.zig");

const Allocator = std.mem.Allocator;

const BlockstoreReader = sig.ledger.BlockstoreReader;

const GetTransaction = rpc.methods.GetTransaction;

pub const RpcService = struct {
    blockstore: BlockstoreReader,

    const Self = @This();

    pub fn getTransaction(self: Self, request: GetTransaction) ?GetTransaction.Response {
        _ = self; // autofix
        _ = request; // autofix
        // self.blockstore.getCompleteTransaction(signature: Signature, highest_confirmed_slot: Slot)
        return undefined;
    }
};

pub fn Request(comptime MethodRequest: type) type {
    return struct {
        id: u64,
        jsonrpc: []const u8,
        method: []const u8,
        params: AsTuple(MethodRequest),
    };
}

pub const RawRequest = struct {
    id: u64,
    jsonrpc: []const u8,
    method: []const u8,
    params: []const u8,
};

pub const RawResponse = struct {
    id: u64,
    jsonrpc: []const u8,
    result: ?[]const u8,
    @"error": ?Error,
};

pub fn Response(comptime MethodResponse: type) type {
    return struct {
        id: u64,
        jsonrpc: []const u8,
        method: []const u8,
        result: MethodResponse,
    };
}

pub const Error = struct {
    code: i64,
    message: []const u8,
};

fn serializeRequest(request: anytype, writer: anytype) !void {
    try std.json.stringify(.{.{
        .id = 1,
        .jsonrpc = "2.0",
        .method = @TypeOf(request).method,
        .request = asTuple(request),
    }}, .{}, writer);
}

fn serializeRequestAlloc(allocator: Allocator, request: anytype, method: []const u8) ![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    try std.json.stringifyAlloc(.{
        .id = 1,
        .jsonrpc = "2.0",
        .method = method,
        .params = asTuple(request),
    }, .{ .emit_null_optional_fields = false }, buf.writer());
    return buf.toOwnedSlice();
}

pub fn asTuple(item: anytype) AsTuple(@TypeOf(item)) {
    var tuple: AsTuple(@TypeOf(item)) = undefined;
    inline for (@typeInfo(@TypeOf(item)).Struct.fields, 0..) |*field, i| {
        tuple[i] = @field(item, field.name);
    }
    return tuple;
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

    const MyRequest = struct {
        pubkey: []const u8,
        num: u64,
        bool: bool,
        opt: ?u64,
        sigs: []const []const u8,
        empty_conf: ?Config,
        conf: ?Config,

        const method = "getAccountInfo";
    };

    const my_request = MyRequest{
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
    const actual = try serializeRequestAlloc(allocator, my_request, "getAccountInfo");
    defer allocator.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);
}
