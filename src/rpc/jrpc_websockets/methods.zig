const std = @import("std");
const base58 = @import("base58");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const ParseOptions = std.json.ParseOptions;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;

pub const Commitment = sig.rpc.methods.common.Commitment;
pub const AccountEncoding = sig.rpc.account_codec.AccountEncoding;
pub const TransactionEncoding = sig.rpc.methods.common.TransactionEncoding;
pub const DataSlice = sig.rpc.account_codec.DataSlice;
pub const TransactionDetails = sig.rpc.methods.common.TransactionDetails;

pub const MAX_PROGRAM_FILTERS: usize = 4;
const MAX_MEMCMP_BYTES = 128;

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

    pub const Memcmp = struct {
        offset: usize,
        bytes: []const u8,

        pub const BytesEncoding = enum { base58, base64, bytes };

        pub fn jsonParseFromValue(
            allocator: Allocator,
            source: std.json.Value,
            _: ParseOptions,
        ) std.json.ParseFromValueError!Memcmp {
            if (source != .object) return error.UnexpectedToken;
            const obj = source.object;

            const offset: usize = blk: {
                const val = obj.get("offset") orelse return error.MissingField;
                break :blk switch (val) {
                    .integer => |i| std.math.cast(usize, i) orelse return error.Overflow,
                    else => return error.UnexpectedToken,
                };
            };
            const bytes_val = obj.get("bytes") orelse return error.MissingField;
            const enc: BytesEncoding = blk: {
                const val = obj.get("encoding") orelse break :blk .base58;
                break :blk switch (val) {
                    .null => .base58,
                    .string => |s| {
                        if (std.mem.eql(u8, s, "base58")) break :blk .base58;
                        if (std.mem.eql(u8, s, "base64")) break :blk .base64;
                        if (std.mem.eql(u8, s, "bytes")) break :blk .bytes;
                        return error.UnexpectedToken;
                    },
                    else => return error.UnexpectedToken,
                };
            };

            return .{
                .offset = offset,
                .bytes = try decodeFilterBytes(allocator, bytes_val, enc),
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

    pub fn validateParams(self: *const ProgramSubscribe) error{TooManyFilters}!void {
        const config = self.config orelse return;
        if (config.filters) |filters| {
            if (filters.len > MAX_PROGRAM_FILTERS) {
                return error.TooManyFilters;
            }
        }
    }

    pub fn jsonStringify(self: ProgramSubscribe, jw: anytype) @TypeOf(jw.*).Error!void {
        return writeParamsArray(jw, self.program_id, self.config);
    }
};

fn decodeFilterBytes(
    allocator: Allocator,
    bytes_val: std.json.Value,
    encoding: ProgramSubscribe.Memcmp.BytesEncoding,
) (Allocator.Error || error{
    InvalidCharacter,
    LengthMismatch,
    Overflow,
    UnexpectedToken,
})![]const u8 {
    return switch (bytes_val) {
        .string => |encoded| switch (encoding) {
            .base58, .bytes => blk: {
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
        },
        .array => |array| blk: {
            if (array.items.len > MAX_MEMCMP_BYTES) {
                return error.LengthMismatch;
            }
            const decoded = try allocator.alloc(u8, array.items.len);
            errdefer allocator.free(decoded);
            for (array.items, decoded) |byte_val, *byte| {
                byte.* = switch (byte_val) {
                    .integer => |i| std.math.cast(u8, i) orelse return error.Overflow,
                    else => return error.UnexpectedToken,
                };
            }
            break :blk decoded;
        },
        else => error.UnexpectedToken,
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

test "ProgramSubscribe.Filter parse invalid memcmp encoding" {
    try expectParseError(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"YWJj","encoding":"hex"}}
    , error.UnexpectedToken);
}

test "ProgramSubscribe.Filter parse invalid memcmp bytes" {
    try expectParseError(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":"!!!","encoding":"base64"}}
    , error.InvalidCharacter);
    try expectParseError(ProgramSubscribe.Filter,
        \\{"memcmp":{"offset":0,"bytes":[256],"encoding":"bytes"}}
    , error.Overflow);
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
