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
        return switch (try std.json.innerParse(JsonParseResult, allocator, source, options)) {
            .ok => |res| res,
            .invalid_request => error.UnexpectedToken,
            .method_not_found => error.UnexpectedToken,
            .invalid_params => error.UnexpectedToken,
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

    pub const JsonParseResult = union(enum) {
        ok: Request,
        invalid_request: ?Id,
        method_not_found: ?Id,
        invalid_params: ?Id,

        pub fn jsonParse(
            allocator: std.mem.Allocator,
            /// * `std.json.Scanner`
            /// * `std.json.Reader(...)`
            source: anytype,
            options: std.json.ParseOptions,
        ) std.json.ParseError(@TypeOf(source.*))!JsonParseResult {
            var jsonrpc_field_set = false;
            var maybe_id: ?Id = null;
            var maybe_method: ?MethodAndParams.Tag = null;
            var maybe_params: ?[]const std.json.Value = null;

            if (try source.next() != .object_begin) {
                return error.UnexpectedToken;
            }

            while (true) {
                switch (try source.peekNextTokenType()) {
                    .string => {},
                    else => break,
                }

                const FieldName = enum { jsonrpc, id, method, params };
                const field_name = try jsonParseEnumStr(source, FieldName) orelse {
                    if (options.ignore_unknown_fields) continue;
                    return error.UnknownField;
                };

                switch (field_name) {
                    .jsonrpc => {
                        if (jsonrpc_field_set) switch (options.duplicate_field_behavior) {
                            .use_first => {
                                try source.skipValue();
                                continue;
                            },
                            .@"error" => return error.DuplicateField,
                            .use_last => {},
                        };
                        jsonrpc_field_set = true;
                        if (try jsonParseEnumStr(source, enum { @"2.0" }) == null) {
                            if (!try skipToEndOfCurrentObject(source)) {
                                return error.UnexpectedToken;
                            }
                            return .{ .invalid_request = maybe_id };
                        }
                    },
                    .id => {
                        if (maybe_id != null) switch (options.duplicate_field_behavior) {
                            .use_first => {
                                try source.skipValue();
                                continue;
                            },
                            .@"error" => return error.DuplicateField,
                            .use_last => {},
                        };
                        maybe_id = try std.json.innerParse(Id, allocator, source, options);
                    },
                    .method => {
                        if (maybe_method != null) switch (options.duplicate_field_behavior) {
                            .use_first => {
                                try source.skipValue();
                                continue;
                            },
                            .@"error" => return error.DuplicateField,
                            .use_last => {},
                        };
                        maybe_method = try jsonParseEnumStr(source, MethodAndParams.Tag) orelse {
                            if (!try skipToEndOfCurrentObject(source)) {
                                return error.UnexpectedToken;
                            }
                            return .{ .method_not_found = maybe_id };
                        };
                    },
                    .params => {
                        if (maybe_params != null) switch (options.duplicate_field_behavior) {
                            .use_first => {
                                try source.skipValue();
                                continue;
                            },
                            .@"error" => return error.DuplicateField,
                            .use_last => {},
                        };
                        const value = try std.json.innerParse(
                            std.json.Value,
                            allocator,
                            source,
                            options,
                        );
                        maybe_params = switch (value) {
                            .array => |array| array.items,
                            else => {
                                if (!try skipToEndOfCurrentObject(source)) {
                                    return error.UnexpectedToken;
                                }
                                return .{ .invalid_request = maybe_id };
                            },
                        };
                    },
                }
            }

            if (try source.next() != .object_end) {
                return error.UnexpectedToken;
            }

            if (!jsonrpc_field_set) return error.MissingField;
            const id = maybe_id orelse return error.MissingField;
            const method = maybe_method orelse return error.MissingField;
            const params = maybe_params orelse return error.MissingField;

            const method_and_params = switch (method) {
                inline else => |tag| @unionInit(MethodAndParams, @tagName(tag), params: {
                    // NOTE: using `std.meta.FieldType` here hits eval branch quota, hack until `@FieldType`
                    const Params =
                        @typeInfo(MethodAndParams).Union.fields[@intFromEnum(tag)].type;
                    if (Params == noreturn) {
                        std.debug.panic("TODO: implement {s}", .{@tagName(method)});
                    }
                    break :params jsonParseValuesAsParamsArray(
                        allocator,
                        params,
                        Params,
                        options,
                    ) catch return .{ .invalid_params = id };
                }),
            };

            return .{ .ok = .{
                .id = id,
                .method = method_and_params,
            } };
        }
    };
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

pub fn jsonParseValuesAsParamsArray(
    allocator: std.mem.Allocator,
    values: []const std.json.Value,
    comptime Params: type,
    options: std.json.ParseOptions,
) !Params {
    var params: Params = undefined;

    inline for (@typeInfo(Params).Struct.fields, 0..) |field, i| {
        if (i >= values.len) {
            if (@typeInfo(field.type) != .Optional) {
                return error.LengthMismatch;
            }
            @field(params, field.name) = null;
        } else {
            @field(params, field.name) = try std.json.innerParseFromValue(
                field.type,
                allocator,
                values[i],
                options,
            );
        }
    }

    return params;
}

fn jsonParseEnumStr(
    /// * `std.json.Scanner`
    /// * `std.json.Reader(...)`
    source: anytype,
    comptime E: type,
) std.json.ParseError(@TypeOf(source.*))!?E {
    const max_size = comptime max: {
        var max: usize = 0;
        for (@typeInfo(E).Enum.fields) |field| max = @max(max, field.name.len);
        break :max max;
    };
    const bstr = try jsonParseBoundedStr(source, max_size) orelse return null;
    return std.meta.stringToEnum(E, bstr.constSlice());
}

fn jsonParseBoundedStr(
    /// * `std.json.Scanner`
    /// * `std.json.Reader(...)`
    source: anytype,
    comptime max_size: usize,
) std.json.ParseError(@TypeOf(source.*))!?std.BoundedArray(u8, max_size) {
    switch (try source.peekNextTokenType()) {
        .string, .number => {},
        else => unreachable,
    }
    var str: std.BoundedArray(u8, max_size) = .{};
    while (true) {
        const tok = try source.next();
        const slice, const is_full = switch (tok) {
            .number => |slice| .{ slice, true },
            .partial_number => |slice| .{ slice, false },
            .allocated_number => unreachable,

            .string => |slice| .{ slice, true },
            .partial_string => |slice| .{ slice, false },
            .partial_string_escaped_1 => |*slice| .{ slice, false },
            .partial_string_escaped_2 => |*slice| .{ slice, false },
            .partial_string_escaped_3 => |*slice| .{ slice, false },
            .partial_string_escaped_4 => |*slice| .{ slice, false },
            .allocated_string => unreachable,

            else => return error.UnexpectedToken,
        };

        const is_first = str.len == 0;
        str.appendSlice(slice) catch return null;
        if (is_first and is_full) break;
    }
    return str;
}

fn skipToEndOfCurrentObject(source: anytype) !bool {
    while (true) switch (try source.peekNextTokenType()) {
        .object_end => {
            std.debug.assert(try source.next() == .object_end);
            return true;
        },
        .end_of_document => {
            return false;
        },
        else => try source.skipValue(),
    };
}

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
