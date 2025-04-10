const std = @import("std");
const sig = @import("../sig.zig");

const rpc = sig.rpc;
const MethodAndParams = rpc.methods.MethodAndParams;

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
                // NOTE: using `std.meta.FieldType` here hits eval branch quota, hack until `@FieldType`
                const Params = @typeInfo(MethodAndParams).Union.fields[@intFromEnum(method)].type;
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
    number: []const u8,
    str: []const u8,

    pub fn jsonStringify(
        self: Id,
        /// `*std.json.WriteStream(...)`
        jw: anytype,
    ) @TypeOf(jw.*).Error!void {
        switch (self) {
            .null => try jw.write(null),
            .int => |int| try jw.write(int),
            .number => |number| try jw.print("{s}", .{number}),
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
        return switch (try source.peekNextTokenType()) {
            .null => id: {
                std.debug.assert(try source.next() == .null);
                break :id .null;
            },
            .string => id: {
                var id_buf = std.ArrayList(u8).init(allocator);
                defer id_buf.deinit();
                const maybe_str = try source.allocNextIntoArrayList(&id_buf, options.allocate.?);
                const str = maybe_str orelse try id_buf.toOwnedSlice();
                break :id .{ .str = str };
            },
            .number => id: {
                var id_buf = std.ArrayList(u8).init(allocator);
                defer id_buf.deinit();

                const maybe_str = try source.allocNextIntoArrayList(&id_buf, options.allocate.?);
                if (std.fmt.parseInt(i128, maybe_str orelse id_buf.items, 10)) |int|
                    break :id .{ .int = int }
                else |err| switch (err) {
                    error.Overflow, error.InvalidCharacter => {},
                }
                const str = maybe_str orelse try id_buf.toOwnedSlice();
                break :id .{ .number = str };
            },
            .object_end => {
                std.debug.assert(try source.next() == .object_end);
                return error.UnexpectedToken;
            },
            .array_end => {
                std.debug.assert(try source.next() == .array_end);
                return error.UnexpectedToken;
            },
            else => {
                try source.skipValue();
                return error.UnexpectedToken;
            },
        };
    }
};

test "Request encoding" {
    const test_pubkey = sig.core.Pubkey.parseBase58String(
        "vinesvinesvinesvinesvinesvinesvinesvinesvin",
    ) catch unreachable;
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
                .pubkey = test_pubkey,
                .config = .{
                    .encoding = .base58,
                },
            } },
        },
    );
}

test "Request commitment minContextSlot" {
    const test_pubkey = sig.core.Pubkey.ZEROES;
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
                .pubkey = test_pubkey,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );
}

test "Request duplicate & ignored fields (non-standard)" {
    const test_pubkey = comptime sig.core.Pubkey.ZEROES;
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
                .pubkey = test_pubkey,
                .config = .{
                    .commitment = .processed,
                    .minContextSlot = 64,
                },
            } },
        },
    );
}

test "Request parse errors" {
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
        , .{}),
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
