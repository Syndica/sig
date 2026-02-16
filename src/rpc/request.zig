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
        const dyn = try std.json.innerParse(Dynamic, allocator, source, options);
        return dyn.parse(allocator, options, null) catch |err| switch (err) {
            error.OutOfMemory,
            => |e| e,

            error.MissingJsonRpcVersion,
            error.MissingMethod,
            error.MissingParams,
            => return error.MissingField,

            error.InvalidJsonRpcVersion,
            error.InvalidMethod,
            error.InvalidParams,
            error.MethodNotImplemented,
            => return error.UnexpectedToken,

            error.ParamsLengthMismatch,
            => return error.LengthMismatch,
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

    pub const Dynamic = struct {
        jsonrpc: ?[]const u8 = null,
        id: Id,
        method: ?[]const u8 = null,
        params: ?[]const std.json.Value = null,

        pub const ParseDiagnostic = union {
            ok: void,
            err: Err,

            pub const INIT: ParseDiagnostic = .{ .ok = {} };

            pub const Err = struct { id: ?Id };

            fn initErr(
                diag: *ParseDiagnostic,
                err: ParseError,
                value: Err,
            ) ParseError {
                diag.* = .{ .err = value };
                return err;
            }
        };

        pub const ParseError = error{
            MissingJsonRpcVersion,
            MissingMethod,
            MissingParams,

            InvalidJsonRpcVersion,
            InvalidMethod,
            InvalidParams,
            ParamsLengthMismatch,

            MethodNotImplemented,
        };

        pub fn parse(
            self: Dynamic,
            allocator: std.mem.Allocator,
            options: std.json.ParseOptions,
            /// Populated only if an error is returned.
            maybe_diag: ?*ParseDiagnostic,
        ) (std.mem.Allocator.Error || ParseError)!Request {
            var dummy_diag = ParseDiagnostic.INIT;
            const diag = maybe_diag orelse &dummy_diag;

            const id = self.id;
            const jsonrpc = self.jsonrpc orelse
                return diag.initErr(error.MissingJsonRpcVersion, .{ .id = id });
            const method_str = self.method orelse
                return diag.initErr(error.MissingMethod, .{ .id = id });
            const params_values = self.params orelse
                return diag.initErr(error.MissingParams, .{ .id = id });

            if (!std.mem.eql(u8, jsonrpc, "2.0")) {
                return diag.initErr(error.InvalidJsonRpcVersion, .{ .id = id });
            }

            const method = std.meta.stringToEnum(MethodAndParams.Tag, method_str) orelse
                return diag.initErr(error.InvalidMethod, .{ .id = id });

            const method_and_params = switch (method) {
                inline else => |tag| @unionInit(MethodAndParams, @tagName(tag), blk: {
                    const Params = @FieldType(MethodAndParams, @tagName(tag));
                    if (Params == noreturn) {
                        return diag.initErr(error.MethodNotImplemented, .{ .id = id });
                    }

                    break :blk jsonParseValuesAsParamsArray(
                        allocator,
                        params_values,
                        Params,
                        options,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => |e| return e,
                        error.ParamsLengthMismatch => {
                            return diag.initErr(error.ParamsLengthMismatch, .{ .id = id });
                        },
                        else => {
                            return diag.initErr(error.InvalidParams, .{ .id = id });
                        },
                    };
                }),
            };

            return .{
                .id = id,
                .method = method_and_params,
            };
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
) (std.json.ParseFromValueError || error{ParamsLengthMismatch})!Params {
    var params: Params = undefined;

    inline for (@typeInfo(Params).@"struct".fields, 0..) |field, i| {
        if (i >= values.len) {
            if (@typeInfo(field.type) != .optional) {
                return error.ParamsLengthMismatch;
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

test "Request simple" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseCall(
        .{},
        \\{
        \\  "jsonrpc": "2.0",
        \\  "id": 123,
        \\  "method": "getAccountInfo",
        \\  "params": [
        \\    "vinesvinesvinesvinesvinesvinesvinesvinesvin"
        \\  ]
        \\}
    ,
        .{
            .id = .{ .int = 123 },
            .method = .{ .getAccountInfo = .{
                .pubkey = test_pubkey,
                .config = null,
            } },
        },
    );
}

test "Request encoding" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
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
    const test_pubkey: sig.core.Pubkey = .ZEROES;
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
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"method":null}
        , .{}),
    );

    try std.testing.expectError(
        error.UnexpectedToken,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"1.0","id":null,"method":"foo","params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.UnexpectedToken,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"foo","params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"foo","params":null}
        , .{}),
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","method":"foo","params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"id":null,"method":"foo","params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"foo"}
        , .{}),
    );

    try std.testing.expectError(
        error.LengthMismatch,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getAccountInfo","params":[]}
        , .{}),
    );

    try std.testing.expectError(
        error.UnknownField,
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"unexpected":"foo"}
        , .{}),
    );

    try std.testing.expectError(
        error.UnexpectedToken, // due to not being implemented
        std.json.parseFromSliceLeaky(Request, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":null,"method":"getFeeForMessage","params":[]}
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
