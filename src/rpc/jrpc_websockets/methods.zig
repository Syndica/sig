const std = @import("std");
const base58 = @import("base58");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Commitment = enum { finalized, confirmed, processed };
pub const AccountEncoding = enum { base58, base64, @"base64+zstd", jsonParsed };
pub const TransactionEncoding = enum { base58, base64, json, jsonParsed };
pub const DataSlice = sig.rpc.account_codec.DataSlice;
pub const TransactionDetails = enum { full, accounts, signatures, none };

pub const MAX_PROGRAM_FILTERS: usize = 4;
const MAX_MEMCMP_BYTES = 128;

pub const LogsFilter = union(enum) {
    all,
    allWithVotes,
    mentions: struct { mentions: []const Pubkey },

    const Mentions = @FieldType(LogsFilter, "mentions");

    pub fn jsonParseFromValue(
        allocator: Allocator,
        source: std.json.Value,
        options: ParseOptions,
    ) std.json.ParseFromValueError!LogsFilter {
        return switch (source) {
            .string => |s| {
                if (std.mem.eql(u8, s, "all")) {
                    return .all;
                }
                if (std.mem.eql(u8, s, "allWithVotes")) {
                    return .allWithVotes;
                }
                return error.InvalidEnumTag;
            },
            .object => .{ .mentions = try std.json.innerParseFromValue(
                Mentions,
                allocator,
                source,
                options,
            ) },
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonStringify(self: LogsFilter, jw: anytype) @TypeOf(jw.*).Error!void {
        switch (self) {
            .all => try jw.write("all"),
            .allWithVotes => try jw.write("allWithVotes"),
            .mentions => |v| try jw.write(v),
        }
    }
};

pub const BlockFilter = union(enum) {
    all,
    mentionsAccountOrProgram: struct { mentionsAccountOrProgram: Pubkey },

    const MentionsAccountOrProgram = @FieldType(BlockFilter, "mentionsAccountOrProgram");

    pub fn jsonParseFromValue(
        allocator: Allocator,
        source: std.json.Value,
        options: ParseOptions,
    ) std.json.ParseFromValueError!BlockFilter {
        return switch (source) {
            .string => |s| {
                if (std.mem.eql(u8, s, "all")) {
                    return .all;
                }
                return error.InvalidEnumTag;
            },
            .object => .{ .mentionsAccountOrProgram = try std.json.innerParseFromValue(
                MentionsAccountOrProgram,
                allocator,
                source,
                options,
            ) },
            else => error.UnexpectedToken,
        };
    }

    pub fn jsonStringify(self: BlockFilter, jw: anytype) @TypeOf(jw.*).Error!void {
        switch (self) {
            .all => try jw.write("all"),
            .mentionsAccountOrProgram => |v| try jw.write(v),
        }
    }
};

const ParameterlessSubscribe = struct {
    pub fn jsonStringify(_: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        try jw.endArray();
    }
};

pub const RootSubscribe = ParameterlessSubscribe;
pub const SlotSubscribe = ParameterlessSubscribe;
pub const SlotsUpdatesSubscribe = ParameterlessSubscribe;
pub const VoteSubscribe = ParameterlessSubscribe;

fn writeParamsArray(jw: anytype, first: anytype, config: anytype) @TypeOf(jw.*).Error!void {
    try jw.beginArray();
    try jw.write(first);
    if (config) |c| {
        try jw.write(c);
    }
    try jw.endArray();
}

pub const AccountSubscribe = struct {
    pubkey: Pubkey,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?Commitment = null,
        encoding: ?AccountEncoding = null,
        /// Undocumented in official WS docs but accepted and working in Agave.
        dataSlice: ?DataSlice = null,
    };

    pub fn jsonStringify(self: AccountSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.pubkey, self.config);
    }
};

pub const BlockSubscribe = struct {
    filter: BlockFilter,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?Commitment = null,
        encoding: ?TransactionEncoding = null,
        transactionDetails: ?TransactionDetails = null,
        maxSupportedTransactionVersion: ?u64 = null,
        showRewards: ?bool = null,
    };

    pub fn jsonStringify(self: BlockSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.filter, self.config);
    }
};

pub const LogsSubscribe = struct {
    filter: LogsFilter,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?Commitment = null,
    };

    pub fn jsonStringify(self: LogsSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.filter, self.config);
    }
};

pub const SignatureSubscribe = struct {
    signature: Signature,
    config: ?Config = null,

    pub const Config = struct {
        commitment: ?Commitment = null,
        enableReceivedNotification: ?bool = null,
    };

    pub fn jsonStringify(self: SignatureSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.signature, self.config);
    }
};

pub const ProgramSubscribe = struct {
    program_id: Pubkey,
    config: ?Config = null,

    pub const Memcmp = struct {
        offset: usize,
        bytes: []const u8,

        pub const BytesEncoding = enum { base58, base64 };
        const Parsed = struct {
            offset: usize,
            bytes: []const u8,
            encoding: ?BytesEncoding = null,
        };

        pub fn jsonParseFromValue(
            allocator: Allocator,
            source: std.json.Value,
            options: ParseOptions,
        ) std.json.ParseFromValueError!Memcmp {
            const parsed = try std.json.innerParseFromValue(Parsed, allocator, source, options);
            const enc = parsed.encoding orelse .base58;
            return .{
                .offset = parsed.offset,
                .bytes = try decodeFilterBytes(allocator, parsed.bytes, enc),
            };
        }

        pub fn jsonStringify(self: Memcmp, jw: anytype) @TypeOf(jw.*).Error!void {
            var encoded_buf: [base58.encodedMaxSize(MAX_MEMCMP_BYTES)]u8 = undefined;
            const encoded_len = base58.Table.BITCOIN.encode(&encoded_buf, self.bytes);
            try jw.write(.{
                .offset = self.offset,
                .bytes = encoded_buf[0..encoded_len],
            });
        }
    };

    pub const Filter = union(enum) {
        dataSize: u64,
        memcmp: Memcmp,
        /// Undocumented in the official Solana RPC filter criteria docs.
        /// Filters for accounts owned by a token program whose data parses as a token account.
        tokenAccountState: void,
    };

    pub const Config = struct {
        commitment: ?Commitment = null,
        encoding: ?AccountEncoding = null,
        filters: ?[]const Filter = null,
        /// Undocumented in official WS docs but accepted and working in Agave.
        dataSlice: ?DataSlice = null,
    };

    pub fn jsonStringify(self: ProgramSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.program_id, self.config);
    }
};

fn decodeFilterBytes(
    allocator: Allocator,
    encoded: []const u8,
    encoding: ProgramSubscribe.Memcmp.BytesEncoding,
) (Allocator.Error || error{ InvalidCharacter, LengthMismatch })![]const u8 {
    return switch (encoding) {
        .base58 => blk: {
            var decoded_tmp = try allocator.alloc(u8, base58.decodedMaxSize(encoded.len));
            defer allocator.free(decoded_tmp);

            const decoded_len = base58.Table.BITCOIN.decode(decoded_tmp, encoded) catch {
                return error.InvalidCharacter;
            };
            if (decoded_len > MAX_MEMCMP_BYTES) {
                return error.LengthMismatch;
            }
            break :blk try allocator.dupe(u8, decoded_tmp[0..decoded_len]);
        },
        .base64 => blk: {
            const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch {
                return error.InvalidCharacter;
            };
            if (decoded_len > MAX_MEMCMP_BYTES) {
                return error.LengthMismatch;
            }
            const decoded = try allocator.alloc(u8, decoded_len);
            errdefer allocator.free(decoded);
            std.base64.standard.Decoder.decode(decoded, encoded) catch {
                return error.InvalidCharacter;
            };
            break :blk decoded;
        },
    };
}

pub const Unsubscribe = struct {
    sub_id: u64,

    pub fn jsonStringify(self: Unsubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        try jw.write(self.sub_id);
        try jw.endArray();
    }
};

pub fn verifyProgramFilters(filters: []const ProgramSubscribe.Filter) error{TooManyFilters}!void {
    if (filters.len > MAX_PROGRAM_FILTERS) {
        return error.TooManyFilters;
    }
}

const testing = std.testing;

test "Commitment parse" {
    try expectParsesTo(Commitment, "\"finalized\"", .finalized);
    try expectParsesTo(Commitment, "\"confirmed\"", .confirmed);
    try expectParsesTo(Commitment, "\"processed\"", .processed);
}

test "Commitment roundtrip" {
    try testRoundtripViaValue(Commitment, .finalized);
    try testRoundtripViaValue(Commitment, .confirmed);
    try testRoundtripViaValue(Commitment, .processed);
}

test "AccountEncoding parse" {
    try expectParsesTo(AccountEncoding, "\"base58\"", .base58);
    try expectParsesTo(AccountEncoding, "\"base64\"", .base64);
    try expectParsesTo(AccountEncoding, "\"base64+zstd\"", .@"base64+zstd");
    try expectParsesTo(AccountEncoding, "\"jsonParsed\"", .jsonParsed);
}

test "AccountEncoding roundtrip" {
    try testRoundtripViaValue(AccountEncoding, .base58);
    try testRoundtripViaValue(AccountEncoding, .base64);
    try testRoundtripViaValue(AccountEncoding, .@"base64+zstd");
    try testRoundtripViaValue(AccountEncoding, .jsonParsed);
}

test "TransactionEncoding parse" {
    try expectParsesTo(TransactionEncoding, "\"base58\"", .base58);
    try expectParsesTo(TransactionEncoding, "\"base64\"", .base64);
    try expectParsesTo(TransactionEncoding, "\"json\"", .json);
    try expectParsesTo(TransactionEncoding, "\"jsonParsed\"", .jsonParsed);
}

test "TransactionEncoding roundtrip" {
    try testRoundtripViaValue(TransactionEncoding, .base58);
    try testRoundtripViaValue(TransactionEncoding, .base64);
    try testRoundtripViaValue(TransactionEncoding, .json);
    try testRoundtripViaValue(TransactionEncoding, .jsonParsed);
}

test "LogsFilter parse" {
    const test_pubkey: Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    try expectParsesTo(LogsFilter, "\"all\"", .all);
    try expectParsesTo(LogsFilter, "\"allWithVotes\"", .allWithVotes);

    const parsed = try parseFromValue(LogsFilter,
        \\{"mentions":["vinesvinesvinesvinesvinesvinesvinesvinesvin"]}
    , .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .mentions);
    try testing.expectEqual(@as(usize, 1), parsed.value.mentions.mentions.len);
    try testing.expectEqual(test_pubkey, parsed.value.mentions.mentions[0]);
}

test "LogsFilter parse error" {
    try expectParseError(LogsFilter, "\"invalid\"", error.InvalidEnumTag);
}

test "LogsFilter roundtrip" {
    const test_pubkey: Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    try testRoundtripViaValue(LogsFilter, .all);
    try testRoundtripViaValue(LogsFilter, .allWithVotes);
    try testRoundtripViaValue(LogsFilter, .{
        .mentions = .{ .mentions = &.{test_pubkey} },
    });
}

test "BlockFilter parse" {
    const test_pubkey: Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    try expectParsesTo(BlockFilter, "\"all\"", .all);
    try expectParsesTo(BlockFilter,
        \\{"mentionsAccountOrProgram":"vinesvinesvinesvinesvinesvinesvinesvinesvin"}
    , .{ .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = test_pubkey } });
}

test "BlockFilter parse error" {
    try expectParseError(BlockFilter, "\"invalid\"", error.InvalidEnumTag);
}

test "BlockFilter roundtrip" {
    const test_pubkey: Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    try testRoundtripViaValue(BlockFilter, .all);
    try testRoundtripViaValue(BlockFilter, .{
        .mentionsAccountOrProgram = .{ .mentionsAccountOrProgram = test_pubkey },
    });
}

test "ProgramSubscribe.Filter parse" {
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"dataSize":100}
    , .{ .dataSize = 100 });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"ZiCa"}}
    , .{ .memcmp = .{ .offset = 0, .bytes = "abc" } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"base64"}}
    , .{ .memcmp = .{ .offset = 0, .bytes = "abc" } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"tokenAccountState":{}}
    , .{ .tokenAccountState = {} });
}

test "ProgramSubscribe.Filter parse invalid memcmp encoding" {
    try expectParseError(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"hex"}}
    , error.InvalidEnumTag);
}

test "ProgramSubscribe.Filter parse invalid memcmp bytes" {
    try expectParseError(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"!!!","encoding":"base64"}}
    , error.InvalidCharacter);
}

test "ProgramSubscribe.Filter roundtrip" {
    try testRoundtripViaValue(ProgramSubscribe.Filter, .{ .dataSize = 100 });
    try testRoundtripViaValue(
        ProgramSubscribe.Filter,
        .{ .memcmp = .{ .offset = 0, .bytes = "abc" } },
    );
    try testRoundtripViaValue(ProgramSubscribe.Filter, .{ .tokenAccountState = {} });
}

test "AccountSubscribe.Config parse" {
    try expectParsesTo(AccountSubscribe.Config,
        \\{"commitment":"finalized","encoding":"base64","dataSlice":{"offset":1,"length":2}}
    , .{
        .commitment = .finalized,
        .encoding = .base64,
        .dataSlice = .{ .offset = 1, .length = 2 },
    });

    try expectParsesTo(AccountSubscribe.Config, "{}", .{});

    try expectParsesToOpts(AccountSubscribe.Config,
        \\{"commitment":"finalized","unknownField":true}
    , .{ .commitment = .finalized, .encoding = null }, .{ .ignore_unknown_fields = true });
}

test "AccountSubscribe.Config roundtrip" {
    try testRoundtripViaValue(AccountSubscribe.Config, .{});
    try testRoundtripViaValue(AccountSubscribe.Config, .{
        .commitment = .finalized,
        .encoding = .base64,
        .dataSlice = .{ .offset = 1, .length = 2 },
    });
}

test "ProgramSubscribe.Config parse" {
    try expectParsesTo(ProgramSubscribe.Config,
        \\{"commitment":"processed","encoding":"base64","filters":[{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"base64"}}],"dataSlice":{"offset":3,"length":4}}
    , .{
        .commitment = .processed,
        .encoding = .base64,
        .filters = &.{.{ .memcmp = .{ .offset = 0, .bytes = "abc" } }},
        .dataSlice = .{ .offset = 3, .length = 4 },
    });
}

test "ProgramSubscribe.Config roundtrip" {
    try testRoundtripViaValue(ProgramSubscribe.Config, .{});
    try testRoundtripViaValue(ProgramSubscribe.Config, .{
        .commitment = .processed,
        .encoding = .base64,
        .filters = &.{
            .{ .dataSize = 64 },
            .{ .memcmp = .{ .offset = 1, .bytes = "abc" } },
        },
        .dataSlice = .{ .offset = 3, .length = 4 },
    });
}

test "BlockSubscribe.Config parse" {
    try expectParsesTo(BlockSubscribe.Config,
        \\{"commitment":"confirmed","encoding":"base64","transactionDetails":"full","maxSupportedTransactionVersion":0,"showRewards":true}
    , .{
        .commitment = .confirmed,
        .encoding = .base64,
        .transactionDetails = .full,
        .maxSupportedTransactionVersion = 0,
        .showRewards = true,
    });
    try expectParsesTo(BlockSubscribe.Config,
        \\{"transactionDetails":"accounts"}
    , .{
        .transactionDetails = .accounts,
    });
}

test "BlockSubscribe.Config roundtrip" {
    try testRoundtripViaValue(BlockSubscribe.Config, .{});
    try testRoundtripViaValue(BlockSubscribe.Config, .{
        .commitment = .confirmed,
        .encoding = .base64,
        .transactionDetails = .full,
        .maxSupportedTransactionVersion = 0,
        .showRewards = true,
    });
    try testRoundtripViaValue(BlockSubscribe.Config, .{
        .transactionDetails = .accounts,
    });
}

test "SignatureSubscribe.Config parse" {
    try expectParsesTo(SignatureSubscribe.Config,
        \\{"commitment":"confirmed","enableReceivedNotification":true}
    , .{ .commitment = .confirmed, .enableReceivedNotification = true });
}

test "SignatureSubscribe.Config roundtrip" {
    try testRoundtripViaValue(SignatureSubscribe.Config, .{});
    try testRoundtripViaValue(SignatureSubscribe.Config, .{
        .commitment = .confirmed,
        .enableReceivedNotification = true,
    });
}

fn expectParsesTo(comptime T: type, json: []const u8, expected: T) !void {
    try expectParsesToOpts(T, json, expected, .{});
}

fn expectParsesToOpts(
    comptime T: type,
    json: []const u8,
    expected: T,
    options: std.json.ParseOptions,
) !void {
    const parsed = try parseFromValue(T, json, options);
    defer parsed.deinit();
    try testing.expectEqualDeep(expected, parsed.value);
}

fn expectParseError(comptime T: type, json: []const u8, parse_error: anytype) !void {
    try testing.expectError(parse_error, parseFromValue(T, json, .{}));
}

fn parseFromValue(
    comptime T: type,
    json: []const u8,
    options: std.json.ParseOptions,
) !std.json.Parsed(T) {
    const val = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer val.deinit();
    return try std.json.parseFromValue(T, testing.allocator, val.value, options);
}

fn testRoundtripViaValue(comptime T: type, original: T) !void {
    var buf: std.ArrayList(u8) = .{};
    defer buf.deinit(testing.allocator);
    {
        var aw: std.Io.Writer.Allocating = .init(testing.allocator);
        errdefer aw.deinit();
        try std.json.Stringify.value(original, .{}, &aw.writer);
        buf = aw.toArrayList();
    }

    const parsed = try parseFromValue(T, buf.items, .{});
    defer parsed.deinit();
    try testing.expectEqualDeep(original, parsed.value);
}
