const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;
const rpc_filters = sig.rpc.filters;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Commitment = sig.rpc.methods.common.Commitment;
pub const AccountEncoding = sig.rpc.account_codec.AccountEncoding;
pub const TransactionEncoding = sig.rpc.methods.common.TransactionEncoding;
pub const DataSlice = sig.rpc.account_codec.DataSlice;
pub const TransactionDetails = sig.rpc.methods.common.TransactionDetails;

pub const LogsFilter = union(enum) {
    all,
    allWithVotes,
    // Array of length 1 since only 1 Pubkey is allowed in the mentions filter (Agave parity).
    mentions: struct { mentions: [1]Pubkey },

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

    pub const Memcmp = rpc_filters.Memcmp;
    pub const Filter = rpc_filters.RpcFilterType;

    pub const Config = struct {
        commitment: ?Commitment = null,
        encoding: ?AccountEncoding = null,
        filters: ?[]const Filter = null,
        /// Undocumented in official WS docs but accepted and working in Agave.
        dataSlice: ?DataSlice = null,
    };

    pub fn validateParams(
        self: *const ProgramSubscribe,
    ) error{ TooManyFilters, MemcmpBytesTooLarge }!void {
        const config = self.config orelse return;
        try rpc_filters.verifyFilters(config.filters orelse &.{});
    }

    pub fn jsonStringify(self: ProgramSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.program_id, self.config);
    }
};

pub const Unsubscribe = struct {
    sub_id: u64,

    pub fn jsonStringify(self: Unsubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginArray();
        try jw.write(self.sub_id);
        try jw.endArray();
    }
};

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
    try testing.expectEqual(test_pubkey, parsed.value.mentions.mentions[0]);
}

test "LogsFilter parse error" {
    try expectParseError(LogsFilter, "\"invalid\"", error.InvalidEnumTag);
    try expectParseError(LogsFilter,
        \\{"mentions":[]}
    , error.LengthMismatch);
    try expectParseError(LogsFilter,
        \\{"mentions":["vinesvinesvinesvinesvinesvinesvinesvinesvin","11111111111111111111111111111111"]}
    , error.LengthMismatch);
}

test "LogsFilter roundtrip" {
    const test_pubkey: Pubkey = .parse("vinesvinesvinesvinesvinesvinesvinesvinesvin");

    try testRoundtripViaValue(LogsFilter, .all);
    try testRoundtripViaValue(LogsFilter, .allWithVotes);
    try testRoundtripViaValue(LogsFilter, .{
        .mentions = .{ .mentions = .{test_pubkey} },
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
        \\{"memcmp":{"offset":42,"bytes":[0,1,2,3],"encoding":null}}
    , .{ .memcmp = .{ .offset = 42, .bytes = &.{ 0, 1, 2, 3 } } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":42,"bytes":[0,1,2,3],"encoding":"bytes"}}
    , .{ .memcmp = .{ .offset = 42, .bytes = &.{ 0, 1, 2, 3 } } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":42,"bytes":[0,1,2,3]}}
    , .{ .memcmp = .{ .offset = 42, .bytes = &.{ 0, 1, 2, 3 } } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":42,"bytes":[0,1,2,3],"encoding":"base64"}}
    , .{ .memcmp = .{ .offset = 42, .bytes = &.{ 0, 1, 2, 3 } } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":42,"bytes":"ZiCa","encoding":"bytes"}}
    , .{ .memcmp = .{ .offset = 42, .bytes = "abc" } });
    try expectParsesTo(ProgramSubscribe.Filter,
        \\{"tokenAccountState":{}}
    , .{ .tokenAccountState = {} });
}

test "ProgramSubscribe.Filter parse invalid memcmp" {
    { // unknown string encoding
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"hex"}}
        , error.UnexpectedToken);
    }

    { // deprecated binary encoding
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"binary"}}
        , error.UnexpectedToken);
    }

    { // unknown encoding with raw bytes
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":[0,1],"encoding":"hex"}}
        , error.UnexpectedToken);
    }

    { // invalid base64 bytes
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":"!!!","encoding":"base64"}}
        , error.InvalidCharacter);
    }

    { // value above u8 max
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":[256],"encoding":"bytes"}}
        , error.Overflow);
    }

    { // negative value
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":[-1],"encoding":"bytes"}}
        , error.Overflow);
    }

    { // float value
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":[1.5],"encoding":"bytes"}}
        , error.UnexpectedToken);
    }

    { // string value
        try expectParseError(ProgramSubscribe.Filter,
            \\{"memcmp":{"offset":0,"bytes":["1"],"encoding":"bytes"}}
        , error.UnexpectedToken);
    }

    const oversized_base58 = "1" ** (sig.rpc.filters.MAX_DATA_BASE58_SIZE + 1);
    const base58_json = std.fmt.comptimePrint(
        \\{{"memcmp":{{"offset":0,"bytes":"{s}"}}}}
    , .{oversized_base58});
    try expectParseError(ProgramSubscribe.Filter, base58_json, error.LengthMismatch);

    const oversized_base64 = "A" ** (sig.rpc.filters.MAX_DATA_BASE64_SIZE + 1);
    const base64_json = std.fmt.comptimePrint(
        \\{{"memcmp":{{"offset":0,"bytes":"{s}","encoding":"base64"}}}}
    , .{oversized_base64});
    try expectParseError(ProgramSubscribe.Filter, base64_json, error.LengthMismatch);

    const oversized_raw_json = std.fmt.comptimePrint(
        \\{{"memcmp":{{"offset":0,"bytes":[{s}0],"encoding":"bytes"}}}}
    , .{"0," ** sig.rpc.filters.MAX_DATA_SIZE});
    try expectParseError(ProgramSubscribe.Filter, oversized_raw_json, error.LengthMismatch);
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
    const parsed = try parseFromValue(T, json, .{});
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
