// TODO: This duplicates the `src/rpc/request.zig` dispatch pattern for WebSocket methods.
// Future work should evaluate whether to merge WS methods into the existing MethodAndParams
// union, extract shared dispatch machinery into a generic helper, or keep them separate
// (HTTP vs WS are different server paths).

const std = @import("std");
const sig = @import("sig");

const methods = @import("methods.zig");

const request = sig.rpc.request;
const Id = request.Id;
const jsonParseValuesAsParamsArray = request.jsonParseValuesAsParamsArray;

pub const WsMethodAndParams = union(enum) {
    // Subscribe methods
    accountSubscribe: methods.AccountSubscribe,
    blockSubscribe: methods.BlockSubscribe,
    logsSubscribe: methods.LogsSubscribe,
    programSubscribe: methods.ProgramSubscribe,
    rootSubscribe: methods.RootSubscribe,
    signatureSubscribe: methods.SignatureSubscribe,
    slotSubscribe: methods.SlotSubscribe,
    slotsUpdatesSubscribe: methods.SlotsUpdatesSubscribe,
    voteSubscribe: methods.VoteSubscribe,

    // Unsubscribe methods (all take a single u64 sub ID)
    accountUnsubscribe: methods.Unsubscribe,
    blockUnsubscribe: methods.Unsubscribe,
    logsUnsubscribe: methods.Unsubscribe,
    programUnsubscribe: methods.Unsubscribe,
    rootUnsubscribe: methods.Unsubscribe,
    signatureUnsubscribe: methods.Unsubscribe,
    slotUnsubscribe: methods.Unsubscribe,
    slotsUpdatesUnsubscribe: methods.Unsubscribe,
    voteUnsubscribe: methods.Unsubscribe,

    pub const Tag = @typeInfo(WsMethodAndParams).@"union".tag_type.?;

    /// Returns a wrapper over `self` which will be stringified as an array.
    pub fn jsonStringifyAsParamsArray(self: WsMethodAndParams) JsonStringifiedAsParamsArray {
        return .{ .data = self };
    }

    pub const JsonStringifiedAsParamsArray = struct {
        data: WsMethodAndParams,

        pub fn jsonStringify(
            self: JsonStringifiedAsParamsArray,
            /// `*std.json.WriteStream(...)`
            jw: anytype,
        ) @TypeOf(jw.*).Error!void {
            switch (self.data) {
                inline else => |method| try jw.write(method),
            }
        }
    };
};

pub const WsRequest = struct {
    id: Id,
    method: WsMethodAndParams,

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        /// * `std.json.Scanner`
        /// * `std.json.Reader(...)`
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!WsRequest {
        const dyn = try std.json.innerParse(Dynamic, allocator, source, options);
        return dyn.parse(allocator, options, null) catch |err| switch (err) {
            error.OutOfMemory => |e| e,

            // JSON-RPC envelope errors
            error.MissingJsonRpcVersion,
            error.MissingMethod,
            error.MissingParams,
            error.InvalidJsonRpcVersion,
            => return error.MissingField,

            // Unknown method
            error.InvalidMethod,
            => return error.InvalidEnumTag,

            // Method params are present but invalid
            error.InvalidParams,
            error.ParamsLengthMismatch,
            => return error.LengthMismatch,
        };
    }

    pub fn jsonStringify(
        self: WsRequest,
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
        };

        pub fn parse(
            self: Dynamic,
            allocator: std.mem.Allocator,
            options: std.json.ParseOptions,
            /// Populated only if an error is returned.
            maybe_diag: ?*ParseDiagnostic,
        ) (std.mem.Allocator.Error || ParseError)!WsRequest {
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

            const method = std.meta.stringToEnum(WsMethodAndParams.Tag, method_str) orelse
                return diag.initErr(error.InvalidMethod, .{ .id = id });

            const method_and_params = switch (method) {
                inline else => |tag| @unionInit(WsMethodAndParams, @tagName(tag), blk: {
                    const Params = @FieldType(WsMethodAndParams, @tagName(tag));
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

test "WsRequest parse accountSubscribe" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":["vinesvinesvinesvinesvinesvinesvinesvinesvin"]}
    ,
        .{
            .id = .{ .int = 1 },
            .method = .{ .accountSubscribe = .{
                .pubkey = test_pubkey,
                .config = null,
            } },
        },
    );
}

test "WsRequest parse accountSubscribe with config" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":2,"method":"accountSubscribe","params":["vinesvinesvinesvinesvinesvinesvinesvinesvin",{"commitment":"confirmed","encoding":"base64"}]}
    ,
        .{
            .id = .{ .int = 2 },
            .method = .{ .accountSubscribe = .{
                .pubkey = test_pubkey,
                .config = .{
                    .commitment = .confirmed,
                    .encoding = .base64,
                },
            } },
        },
    );
}

test "WsRequest parse slotSubscribe (no params)" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":3,"method":"slotSubscribe","params":[]}
    ,
        .{
            .id = .{ .int = 3 },
            .method = .{ .slotSubscribe = .{} },
        },
    );
}

test "WsRequest parse accountUnsubscribe" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":4,"method":"accountUnsubscribe","params":[42]}
    ,
        .{
            .id = .{ .int = 4 },
            .method = .{ .accountUnsubscribe = .{ .sub_id = 42 } },
        },
    );
}

test "WsRequest parse logsSubscribe all" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":5,"method":"logsSubscribe","params":["all"]}
    ,
        .{
            .id = .{ .int = 5 },
            .method = .{ .logsSubscribe = .{
                .filter = .all,
                .config = null,
            } },
        },
    );
}

test "WsRequest parse logsSubscribe allWithVotes" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":5,"method":"logsSubscribe","params":["allWithVotes"]}
    ,
        .{
            .id = .{ .int = 5 },
            .method = .{ .logsSubscribe = .{
                .filter = .allWithVotes,
                .config = null,
            } },
        },
    );
}

test "WsRequest parse logsSubscribe mentions with config" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":5,"method":"logsSubscribe","params":[{"mentions":["vinesvinesvinesvinesvinesvinesvinesvinesvin"]},{"commitment":"processed"}]}
    ,
        .{
            .id = .{ .int = 5 },
            .method = .{ .logsSubscribe = .{
                .filter = .{ .mentions = .{ .mentions = &.{test_pubkey} } },
                .config = .{ .commitment = .processed },
            } },
        },
    );
}

test "WsRequest parse signatureSubscribe" {
    const test_sig: sig.core.Signature =
        .parse("1111111111111111111111111111111111111111111111111111111111111111");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":6,"method":"signatureSubscribe","params":["1111111111111111111111111111111111111111111111111111111111111111"]}
    ,
        .{
            .id = .{ .int = 6 },
            .method = .{ .signatureSubscribe = .{
                .signature = test_sig,
                .config = null,
            } },
        },
    );
}

test "WsRequest parse signatureSubscribe with config" {
    const test_sig: sig.core.Signature =
        .parse("1111111111111111111111111111111111111111111111111111111111111111");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":6,"method":"signatureSubscribe","params":["1111111111111111111111111111111111111111111111111111111111111111",{"commitment":"confirmed","enableReceivedNotification":true}]}
    ,
        .{
            .id = .{ .int = 6 },
            .method = .{ .signatureSubscribe = .{
                .signature = test_sig,
                .config = .{
                    .commitment = .confirmed,
                    .enableReceivedNotification = true,
                },
            } },
        },
    );
}

test "WsRequest parse blockSubscribe all" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":7,"method":"blockSubscribe","params":["all"]}
    ,
        .{
            .id = .{ .int = 7 },
            .method = .{ .blockSubscribe = .{
                .filter = .all,
                .config = null,
            } },
        },
    );
}

test "WsRequest parse blockSubscribe all with config" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":7,"method":"blockSubscribe","params":["all",{"commitment":"confirmed"}]}
    ,
        .{
            .id = .{ .int = 7 },
            .method = .{ .blockSubscribe = .{
                .filter = .all,
                .config = .{
                    .commitment = .confirmed,
                    .encoding = null,
                    .transactionDetails = null,
                    .maxSupportedTransactionVersion = null,
                    .showRewards = null,
                },
            } },
        },
    );
}

test "WsRequest parse blockSubscribe mentionsAccountOrProgram" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":7,"method":"blockSubscribe","params":[{"mentionsAccountOrProgram":"vinesvinesvinesvinesvinesvinesvinesvinesvin"}]}
    ,
        .{
            .id = .{ .int = 7 },
            .method = .{ .blockSubscribe = .{
                .filter = .{ .mentionsAccountOrProgram = .{
                    .mentionsAccountOrProgram = test_pubkey,
                } },
                .config = null,
            } },
        },
    );
}

test "WsRequest parse programSubscribe with filters" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":8,"method":"programSubscribe","params":["vinesvinesvinesvinesvinesvinesvinesvinesvin",{"filters":[{"dataSize":100},{"memcmp":{"offset":0,"bytes":"abc"}}]}]}
    ,
        .{
            .id = .{ .int = 8 },
            .method = .{ .programSubscribe = .{
                .program_id = test_pubkey,
                .config = .{
                    .commitment = null,
                    .encoding = null,
                    .filters = &.{
                        .{ .dataSize = 100 },
                        .{ .memcmp = .{ .offset = 0, .bytes = "abc" } },
                    },
                },
            } },
        },
    );
}

test "WsRequest parse programSubscribe with tokenAccountState filter" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":8,"method":"programSubscribe","params":["vinesvinesvinesvinesvinesvinesvinesvinesvin",{"filters":[{"tokenAccountState":{}}]}]}
    ,
        .{
            .id = .{ .int = 8 },
            .method = .{ .programSubscribe = .{
                .program_id = test_pubkey,
                .config = .{
                    .commitment = null,
                    .encoding = null,
                    .filters = &.{
                        .{ .tokenAccountState = {} },
                    },
                },
            } },
        },
    );
}

test "WsRequest parse rootSubscribe (no params)" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":9,"method":"rootSubscribe","params":[]}
    ,
        .{
            .id = .{ .int = 9 },
            .method = .{ .rootSubscribe = .{} },
        },
    );
}

test "WsRequest parse slotsUpdatesSubscribe (no params)" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":10,"method":"slotsUpdatesSubscribe","params":[]}
    ,
        .{
            .id = .{ .int = 10 },
            .method = .{ .slotsUpdatesSubscribe = .{} },
        },
    );
}

test "WsRequest parse voteSubscribe (no params)" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":11,"method":"voteSubscribe","params":[]}
    ,
        .{
            .id = .{ .int = 11 },
            .method = .{ .voteSubscribe = .{} },
        },
    );
}

test "WsRequest parse slotUnsubscribe" {
    try testParseRequest(
        .{},
        \\{"jsonrpc":"2.0","id":12,"method":"slotUnsubscribe","params":[7]}
    ,
        .{
            .id = .{ .int = 12 },
            .method = .{ .slotUnsubscribe = .{ .sub_id = 7 } },
        },
    );
}

test "WsRequest parse errors" {
    // Missing jsonrpc version
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"id":1,"method":"slotSubscribe","params":[]}
        , .{}),
    );

    // Invalid jsonrpc version
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"jsonrpc":"1.0","id":1,"method":"slotSubscribe","params":[]}
        , .{}),
    );

    // Unknown method
    try std.testing.expectError(
        error.InvalidEnumTag,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":1,"method":"nonexistentMethod","params":[]}
        , .{}),
    );

    // Missing method
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":1,"params":[]}
        , .{}),
    );

    // Missing params
    try std.testing.expectError(
        error.MissingField,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":1,"method":"slotSubscribe"}
        , .{}),
    );

    // Params length mismatch (accountSubscribe needs at least 1 param)
    try std.testing.expectError(
        error.LengthMismatch,
        std.json.parseFromSliceLeaky(WsRequest, std.testing.allocator,
            \\{"jsonrpc":"2.0","id":1,"method":"accountSubscribe","params":[]}
        , .{}),
    );
}

test "WsRequest.Dynamic parse diagnostic captures request id" {
    {
        const dyn = try std.json.parseFromSlice(
            WsRequest.Dynamic,
            std.testing.allocator,
            \\{"jsonrpc":"2.0","id":11,"method":"nonexistentMethod","params":[]}
        ,
            .{},
        );
        defer dyn.deinit();

        var diag = WsRequest.Dynamic.ParseDiagnostic.INIT;
        try std.testing.expectError(
            error.InvalidMethod,
            dyn.value.parse(std.testing.allocator, .{}, &diag),
        );
        try std.testing.expectEqual(@as(Id, .{ .int = 11 }), diag.err.id.?);
    }

    {
        const dyn = try std.json.parseFromSlice(
            WsRequest.Dynamic,
            std.testing.allocator,
            \\{"jsonrpc":"2.0","id":12,"method":"accountSubscribe","params":[]}
        ,
            .{},
        );
        defer dyn.deinit();

        var diag = WsRequest.Dynamic.ParseDiagnostic.INIT;
        try std.testing.expectError(
            error.ParamsLengthMismatch,
            dyn.value.parse(std.testing.allocator, .{}, &diag),
        );
        try std.testing.expectEqual(@as(Id, .{ .int = 12 }), diag.err.id.?);
    }
}

test "WsRequest roundtrip accountSubscribe" {
    const test_pubkey: sig.core.Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");
    try testRoundtrip(.{ .accountSubscribe = .{
        .pubkey = test_pubkey,
        .config = .{ .commitment = .finalized, .encoding = .base64 },
    } });
}

test "WsRequest roundtrip logsSubscribe" {
    try testRoundtrip(.{ .logsSubscribe = .{
        .filter = .all,
        .config = .{ .commitment = .processed },
    } });
    try testRoundtrip(.{ .logsSubscribe = .{
        .filter = .allWithVotes,
        .config = null,
    } });
}

test "WsRequest roundtrip blockSubscribe" {
    try testRoundtrip(.{ .blockSubscribe = .{
        .filter = .all,
        .config = .{
            .commitment = .confirmed,
            .encoding = null,
            .transactionDetails = null,
            .maxSupportedTransactionVersion = null,
            .showRewards = null,
        },
    } });
}

test "WsRequest roundtrip signatureSubscribe" {
    const test_sig: sig.core.Signature =
        .parse("1111111111111111111111111111111111111111111111111111111111111111");
    try testRoundtrip(.{ .signatureSubscribe = .{
        .signature = test_sig,
        .config = .{ .commitment = .confirmed, .enableReceivedNotification = true },
    } });
}

test "WsRequest roundtrip slotSubscribe" {
    try testRoundtrip(.{ .slotSubscribe = .{} });
}

test "WsRequest roundtrip unsubscribe" {
    try testRoundtrip(.{ .accountUnsubscribe = .{ .sub_id = 42 } });
    try testRoundtrip(.{ .slotUnsubscribe = .{ .sub_id = 7 } });
}

fn testParseRequest(
    options: std.json.ParseOptions,
    json_str: []const u8,
    expected: WsRequest,
) !void {
    const actual = try std.json.parseFromSlice(WsRequest, std.testing.allocator, json_str, options);
    defer actual.deinit();
    try std.testing.expectEqualDeep(expected, actual.value);
}

fn testRoundtrip(method: WsMethodAndParams) !void {
    const req = WsRequest{ .id = .{ .int = 1 }, .method = method };

    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(std.testing.allocator);
    {
        var aw: std.Io.Writer.Allocating = .init(std.testing.allocator);
        errdefer aw.deinit();
        try std.json.Stringify.value(req, .{}, &aw.writer);
        buf = aw.toArrayList();
    }

    const parsed = try std.json.parseFromSlice(WsRequest, std.testing.allocator, buf.items, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(req.id, parsed.value.id);
    try std.testing.expectEqual(
        @as(WsMethodAndParams.Tag, req.method),
        @as(WsMethodAndParams.Tag, parsed.value.method),
    );
}
