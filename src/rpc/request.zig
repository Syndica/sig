const std = @import("std");
const sig = @import("../sig.zig");

const rpc = sig.rpc;
const Allocator = std.mem.Allocator;
const MethodAndParams = rpc.methods.MethodAndParams;

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

/// NOTE: for the sake of simplicity, we only support `method: ..., params: ...`,
/// and reject `params: ..., method: ...`; this is a reasonable expectation for
/// clients to satisfy.
pub const Request = struct {
    id: Id,
    method: MethodAndParams,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        /// * `std.json.Scanner`
        /// * `std.json.Reader(...)`
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Request {
        const Partial = struct {
            jsonrpc: enum { @"2.0" },
            id: Id,
            method: MethodAndParams.Tag,
            params: []const std.json.Value,
        };
        const partial = try std.json.innerParse(Partial, allocator, source, options);

        @setEvalBranchQuota(
            // <method count> * <param count upper bound> + <generic function call>
            @typeInfo(MethodAndParams).Union.fields.len * 3 + 1,
        );
        const method = switch (partial.method) {
            inline else => |method| blk: {
                const Params = std.meta.FieldType(rpc.methods.MethodAndParams, method);
                if (Params == noreturn) std.debug.panic("TODO: implement {s}", .{@tagName(method)});

                var params: Params = undefined;

                inline for (@typeInfo(Params).Struct.fields, 0..) |field, i| {
                    if (i >= partial.params.len) {
                        if (@typeInfo(field.type) != .Optional) {
                            return error.LengthMismatch;
                        }
                        @field(params, field.name) = null;
                    } else {
                        @field(params, field.name) = try std.json.innerParseFromValue(
                            field.type,
                            allocator,
                            partial.params[i],
                            options,
                        );
                    }
                }

                break :blk @unionInit(MethodAndParams, @tagName(method), params);
            },
        };

        return .{
            .id = partial.id,
            .method = method,
        };
    }

    pub fn jsonStringify(
        self: Request,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        try jw.write(.{
            .jsonrpc = "2.0",
            .id = self.id,
            .method = @tagName(self.method),
            .params = self.method.jsonStringifyAsParamsArray(),
        });
    }
};

pub const Id = union(enum) {
    null,
    int: i128,
    str: []const u8,

    pub fn jsonStringify(
        self: Id,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        switch (self) {
            .null => try jw.write(null),
            .int => |int| try jw.write(int),
            .str => |str| try jw.write(str),
        }
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        /// * `std.json.Scanner`
        /// * `std.json.Reader(...)`
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Id {
        const TokType = enum { null, number, string };
        const tok_type: TokType = switch (try source.peekNextTokenType()) {
            .null => .null,
            .number => .number,
            .string => .string,
            else => {
                try source.skipValue();
                return error.UnexpectedToken;
            },
        };

        return switch (tok_type) {
            .null => id: {
                std.debug.assert(try source.next() == .null);
                break :id .null;
            },
            .number, .string => id: {
                var id_buf = std.ArrayList(u8).init(allocator);
                defer id_buf.deinit();

                const maybe_str = try source.allocNextIntoArrayList(&id_buf, options.allocate.?);
                if (std.fmt.parseInt(i128, maybe_str orelse id_buf.items, 10)) |int|
                    break :id .{ .int = int }
                else |err| switch (err) {
                    error.Overflow, error.InvalidCharacter => {},
                }
                const str = maybe_str orelse try id_buf.toOwnedSlice();
                break :id .{ .str = str };
            },
        };
    }
};

test Request {
    const test_pubkey1 = comptime sig.core.Pubkey.parseBase58String(
        "vinesvinesvinesvinesvinesvinesvinesvinesvin",
    ) catch unreachable;
    const test_pubkey2 = comptime sig.core.Pubkey.ZEROES;

    try testParseCall(
        .{},
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": 123,
        \\  "method": "getAccountInfo",
        \\  "params": [
        \\    "vinesvinesvinesvinesvinesvinesvinesvinesvin",
        \\    {
        \\      "encoding": "base58"
        \\    }
        \\  ]
        \\}
    ,
        .{
            .id = .{ .int = 123 },
            .method = .{ .getAccountInfo = .{
                .pubkey = test_pubkey1,
                .config = .{
                    .encoding = .base58,
                },
            } },
        },
    );

    try testParseCall(
        .{},
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": "a44",
        \\  "method": "getBalance",
        \\  "params": [
        \\    "11111111111111111111111111111111",
        \\    {
        \\      "commitment": "processed",
        \\      "minContextSlot": 64
        \\    }
        \\  ]
        \\}
    ,
        .{
            .id = .{ .str = "a44" },
            .method = .{ .getBalance = .{
                .pubkey = test_pubkey2,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );

    try testParseCall(
        .{ .duplicate_field_behavior = .use_first, .ignore_unknown_fields = true },
        \\{
        \\  "jsonrpc": "2.0",
        \\  "jsonrpc": "2.0",
        \\  "id": "a33",
        \\  "method": "getBalance",
        \\  "params": [
        \\    "11111111111111111111111111111111",
        \\    {
        \\      "commitment": "processed",
        \\      "minContextSlot": 64
        \\    }
        \\  ],
        \\  "ignored": "foo"
        \\}
    ,
        .{
            .id = .{ .str = "a33" },
            .method = .{ .getBalance = .{
                .pubkey = test_pubkey2,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":42,"id":"33","method":"getBalance","method":"getAccountInfo"}
        , .{ .duplicate_field_behavior = .use_first }),
    );
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getBalance"}
        , .{}),
    );
    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getBalance","method":"getAccountInfo"}
        , .{}),
    );
    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":42,"id":"33"}
        , .{ .duplicate_field_behavior = .@"error" }),
    );

    try std.testing.expectError(
        error.DuplicateField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","jsonrpc":"2.0"}
        , .{}),
    );
    try std.testing.expectError(
        error.UnexpectedToken,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","method":null}
        , .{}),
    );

    try std.testing.expectError(
        error.UnknownField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"unexpected":"foo"}
        , .{}),
    );
}

fn testParseCall(
    options: std.json.ParseOptions,
    actual_str: []const u8,
    expected_call: Request,
) !void {
    const actual_call = try std.json.parseFromSlice(
        Request,
        std.testing.allocator,
        actual_str,
        options,
    );
    defer actual_call.deinit();
    try std.testing.expectEqualDeep(expected_call, actual_call.value);
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
