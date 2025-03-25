const std = @import("std");

const Allocator = std.mem.Allocator;

pub fn serialize(allocator: Allocator, request: anytype) Allocator.Error![]const u8 {
    const formatted = if (@hasDecl(@TypeOf(request), "jsonStringify"))
        request
    else
        asTuple(request);

    return try serializeTuple(allocator, methodName(request), formatted);
}

pub fn serializeTuple(
    allocator: Allocator,
    method: []const u8,
    params: anytype,
) Allocator.Error![]const u8 {
    return try std.json.stringifyAlloc(
        allocator,
        .{
            .id = 1, //TODO allow customization?
            .jsonrpc = "2.0",
            .method = method,
            .params = params,
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

fn AsTuple(comptime Struct: type) type {
    var info = @typeInfo(Struct).Struct;
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

test "serialize" {
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
    const actual = try serialize(allocator, my_request);
    defer allocator.free(actual);

    try std.testing.expectEqualSlices(u8, expected, actual);
}
