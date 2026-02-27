/// Filter types for scanning RPC methods (`getProgramAccounts`, `getTokenAccountsByOwner`, etc.).
///
/// Handles JSON wire format parsing, validation, and runtime matching against account data.
/// Shared across all 6 scanning methods.
const std = @import("std");
const base58 = @import("base58");

const parse_token = @import("account_codec/parse_token.zig");

const Allocator = std.mem.Allocator;

const BASE58_ENDEC = base58.Table.BITCOIN;

/// [agave] MAX_GET_PROGRAM_ACCOUNT_FILTERS
/// https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L150
pub const MAX_FILTERS: usize = 4;
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L8
pub const MAX_DATA_SIZE: usize = 128;
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L9
pub const MAX_DATA_BASE58_SIZE: usize = 175;
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L10
pub const MAX_DATA_BASE64_SIZE: usize = 172;

/// SPL Token account length.
const TOKEN_ACCOUNT_LEN: usize = parse_token.TokenAccount.LEN;
/// Offset of the `AccountState` byte within an SPL Token account.
/// [spl] https://github.com/solana-program/token-2022/blob/main/interface/src/generic_token_account.rs#L56
const TOKEN_ACCOUNT_STATE_OFFSET: usize = parse_token.ACCOUNT_INITIALIZED_INDEX;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L12-L18
pub const RpcFilterType = union(enum) {
    dataSize: u64,
    memcmp: Memcmp,
    tokenAccountState,

    /// Returns `true` if `account_data` passes this filter.
    pub fn allows(self: RpcFilterType, account_data: []const u8) bool {
        return switch (self) {
            .dataSize => |size| account_data.len == size,
            .memcmp => |m| m.matches(account_data),
            .tokenAccountState => {
                // [agave] Account::valid_account_data: data.len == TokenAccount::LEN (165)
                // and AccountState byte at offset 108 is Initialized (1) or Frozen (2), not
                // Uninitialized (0).
                // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/filter.rs#L11
                return account_data.len == TOKEN_ACCOUNT_LEN and
                    account_data[TOKEN_ACCOUNT_STATE_OFFSET] != 0;
            },
        };
    }

    /// Custom parser for RPC param path (`jsonParseValuesAsParamsArray` in `request.zig`
    /// calls `std.json.innerParseFromValue`, which dispatches here).
    /// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L12-L18
    pub fn jsonParseFromValue(
        allocator: Allocator,
        source: std.json.Value,
        options: std.json.ParseOptions,
    ) std.json.ParseFromValueError!RpcFilterType {
        if (source != .object) return error.UnexpectedToken;
        const obj = source.object;

        if (obj.get("dataSize")) |val| {
            return .{ .dataSize = try std.json.innerParseFromValue(u64, allocator, val, options) };
        }
        if (obj.get("memcmp")) |val| {
            return .{ .memcmp = try Memcmp.jsonParseFromValue(allocator, val, options) };
        }
        // [agave] The value for tokenAccountState is ignored — only key presence matters.
        if (obj.contains("tokenAccountState")) {
            return .tokenAccountState;
        }

        return error.UnexpectedToken;
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L114-L120
pub const Memcmp = struct {
    offset: usize,
    /// Raw decoded bytes. Owned by the allocator passed to `jsonParseFromValue`.
    bytes: []const u8,

    /// Returns `true` if the account data matches at the specified offset.
    pub fn matches(self: Memcmp, data: []const u8) bool {
        if (self.offset +| self.bytes.len > data.len) return false;
        return std.mem.eql(u8, data[self.offset..][0..self.bytes.len], self.bytes);
    }

    pub fn jsonParseFromValue(
        allocator: Allocator,
        source: std.json.Value,
        _: std.json.ParseOptions,
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

        const bytes_str: []const u8 = blk: {
            const val = obj.get("bytes") orelse return error.MissingField;
            break :blk switch (val) {
                .string => |s| s,
                else => return error.UnexpectedToken,
            };
        };

        const Encoding = enum { base58, base64 };
        const encoding: Encoding = blk: {
            const val = obj.get("encoding") orelse break :blk .base58;
            break :blk switch (val) {
                .string => |s| {
                    if (std.mem.eql(u8, s, "base58")) break :blk .base58;
                    if (std.mem.eql(u8, s, "base64")) break :blk .base64;
                    return error.UnexpectedToken;
                },
                else => return error.UnexpectedToken,
            };
        };

        const decoded: []const u8 = switch (encoding) {
            .base58 => blk: {
                const max_decoded_len = base58.decodedMaxSize(bytes_str.len);
                const buf = try allocator.alloc(u8, max_decoded_len);
                defer allocator.free(buf);
                const decoded_len = BASE58_ENDEC.decode(buf, bytes_str) catch
                    return error.InvalidCharacter;
                break :blk try allocator.dupe(u8, buf[0..decoded_len]);
            },
            .base64 => blk: {
                const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(bytes_str) catch
                    return error.InvalidCharacter;
                const result = try allocator.alloc(u8, decoded_len);
                std.base64.standard.Decoder.decode(result, bytes_str) catch {
                    allocator.free(result);
                    return error.InvalidCharacter;
                };
                break :blk result;
            },
        };

        return .{
            .offset = offset,
            .bytes = decoded,
        };
    }
};

/// Validates filters according to Agave's rules. Call after parsing, before scanning.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2413-L2423
pub fn verifyFilters(filters_slice: []const RpcFilterType) error{ TooManyFilters, MemcmpBytesTooLarge }!void {
    if (filters_slice.len > MAX_FILTERS) return error.TooManyFilters;
    for (filters_slice) |f| {
        switch (f) {
            .memcmp => |m| {
                if (m.bytes.len > MAX_DATA_SIZE) return error.MemcmpBytesTooLarge;
            },
            else => {},
        }
    }
}

/// Returns `true` if account data passes all filters (conjunction).
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/filter.rs#L7-L12
pub fn filtersAllow(filters_slice: []const RpcFilterType, account_data: []const u8) bool {
    for (filters_slice) |f| {
        if (!f.allows(account_data)) return false;
    }
    return true;
}

test "rpc.filters" {
    const testing = std.testing;

    // allows: dataSize matches exact length
    {
        const filter = RpcFilterType{ .dataSize = 10 };
        try testing.expect(filter.allows(&.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
        try testing.expect(!filter.allows(&.{ 0, 1, 2 }));
        try testing.expect(!filter.allows(&.{}));
    }

    // allows: memcmp matches at offset
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 2, .bytes = &.{ 0xAA, 0xBB } } };
        try testing.expect(filter.allows(&.{ 0, 0, 0xAA, 0xBB, 0 }));
        try testing.expect(!filter.allows(&.{ 0, 0, 0xAA, 0xCC, 0 }));
        // Too short — offset + bytes extends past end.
        try testing.expect(!filter.allows(&.{ 0, 0, 0xAA }));
        try testing.expect(!filter.allows(&.{}));
    }

    // allows: memcmp offset at boundary
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 3, .bytes = &.{0xFF} } };
        // Exactly fits.
        try testing.expect(filter.allows(&.{ 0, 0, 0, 0xFF }));
        // One byte short.
        try testing.expect(!filter.allows(&.{ 0, 0, 0 }));
    }

    // allows: memcmp empty bytes always matches
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 0, .bytes = &.{} } };
        try testing.expect(filter.allows(&.{}));
        try testing.expect(filter.allows(&.{42}));
    }

    // allows: memcmp saturating offset overflow
    {
        // offset near maxInt(usize) should not wrap, just fail to match.
        const filter = RpcFilterType{ .memcmp = .{ .offset = std.math.maxInt(usize), .bytes = &.{1} } };
        try testing.expect(!filter.allows(&.{1}));
    }

    // allows: tokenAccountState initialized
    {
        var data = [_]u8{0} ** 165;
        data[108] = 1; // Initialized
        try testing.expect((RpcFilterType{ .tokenAccountState = {} }).allows(&data));
    }

    // allows: tokenAccountState frozen
    {
        var data = [_]u8{0} ** 165;
        data[108] = 2; // Frozen
        try testing.expect((RpcFilterType{ .tokenAccountState = {} }).allows(&data));
    }

    // allows: tokenAccountState rejects uninitialized
    {
        var data = [_]u8{0} ** 165;
        data[108] = 0; // Uninitialized
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&data));
    }

    // allows: tokenAccountState rejects wrong length
    {
        var data = [_]u8{0} ** 100;
        data[99] = 1;
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&data));
        // Also 166 bytes (too long).
        var data2 = [_]u8{0} ** 166;
        data2[108] = 1;
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&data2));
    }

    // filtersAllow: conjunction of multiple filters
    {
        const f = &[_]RpcFilterType{
            .{ .dataSize = 5 },
            .{ .memcmp = .{ .offset = 0, .bytes = &.{0xAA} } },
        };
        try testing.expect(filtersAllow(f, &.{ 0xAA, 0, 0, 0, 0 }));
        // Right length but wrong byte.
        try testing.expect(!filtersAllow(f, &.{ 0xBB, 0, 0, 0, 0 }));
        // Right byte but wrong length.
        try testing.expect(!filtersAllow(f, &.{ 0xAA, 0, 0 }));
    }

    // filtersAllow: empty filters allows everything
    {
        try testing.expect(filtersAllow(&.{}, &.{}));
        try testing.expect(filtersAllow(&.{}, &.{ 1, 2, 3 }));
    }

    // verifyFilters: accepts valid filters
    {
        const f = &[_]RpcFilterType{
            .{ .dataSize = 165 },
            .{ .memcmp = .{ .offset = 0, .bytes = &([_]u8{0} ** 128) } },
            .tokenAccountState,
        };
        try verifyFilters(f);
    }

    // verifyFilters: rejects too many filters
    {
        const f = &[_]RpcFilterType{
            .{ .dataSize = 1 },
            .{ .dataSize = 2 },
            .{ .dataSize = 3 },
            .{ .dataSize = 4 },
            .{ .dataSize = 5 },
        };
        try testing.expectError(error.TooManyFilters, verifyFilters(f));
    }

    // verifyFilters: rejects oversized memcmp bytes
    {
        const f = &[_]RpcFilterType{
            .{ .memcmp = .{ .offset = 0, .bytes = &([_]u8{0} ** 129) } },
        };
        try testing.expectError(error.MemcmpBytesTooLarge, verifyFilters(f));
    }

    // verifyFilters: allows exactly MAX_DATA_SIZE bytes
    {
        const f = &[_]RpcFilterType{
            .{ .memcmp = .{ .offset = 0, .bytes = &([_]u8{0} ** MAX_DATA_SIZE) } },
        };
        try verifyFilters(f);
    }

    // parse: dataSize
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"dataSize": 165}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqual(RpcFilterType{ .dataSize = 165 }, filter);
    }

    // parse: tokenAccountState
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"tokenAccountState": true}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqual(RpcFilterType.tokenAccountState, filter);
    }

    // parse: tokenAccountState ignores value
    {
        const allocator = testing.allocator;
        // Agave ignores the value — should accept any value.
        const json_str =
            \\{"tokenAccountState": 42}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqual(RpcFilterType.tokenAccountState, filter);
    }

    // parse: memcmp with base58 default encoding
    {
        // Use arena to mirror real RPC parsing; decoded bytes are owned by the arena.
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const expected_bytes = [_]u8{ 1, 2, 3, 4 };
        const base58_str = comptime blk: {
            var buf: [base58.encodedMaxSize(expected_bytes.len)]u8 = undefined;
            const len = BASE58_ENDEC.encode(&buf, &expected_bytes);
            break :blk buf[0..len];
        };
        const json_str = std.fmt.comptimePrint(
            \\{{"memcmp": {{"offset": 10, "bytes": "{s}"}}}}
        , .{base58_str});
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqual(@as(usize, 10), filter.memcmp.offset);
        try testing.expectEqualSlices(u8, &expected_bytes, filter.memcmp.bytes);
        // Verify the filter actually works.
        var data = [_]u8{0} ** 20;
        @memcpy(data[10..14], &expected_bytes);
        try testing.expect(filter.allows(&data));
    }

    // parse: memcmp with explicit base58 encoding
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const expected_bytes = [_]u8{ 1, 2, 3, 4 };
        const base58_str = comptime blk: {
            var buf: [base58.encodedMaxSize(expected_bytes.len)]u8 = undefined;
            const len = BASE58_ENDEC.encode(&buf, &expected_bytes);
            break :blk buf[0..len];
        };
        const json_str = std.fmt.comptimePrint(
            \\{{"memcmp": {{"offset": 0, "bytes": "{s}", "encoding": "base58"}}}}
        , .{base58_str});
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqualSlices(u8, &expected_bytes, filter.memcmp.bytes);
    }

    // parse: memcmp with base64 encoding
    {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        // "AQIDBA==" is base64 for [1, 2, 3, 4].
        const json_str =
            \\{"memcmp": {"offset": 5, "bytes": "AQIDBA==", "encoding": "base64"}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});

        const filter = try RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{});
        try testing.expectEqual(@as(usize, 5), filter.memcmp.offset);
        try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, filter.memcmp.bytes);
    }

    // parse: memcmp rejects invalid base58
    {
        const allocator = testing.allocator;
        // '0' is not a valid base58 character (Bitcoin alphabet starts at '1').
        const json_str =
            \\{"memcmp": {"offset": 0, "bytes": "0invalid"}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.InvalidCharacter,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: memcmp rejects invalid base64
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"memcmp": {"offset": 0, "bytes": "!!!notbase64", "encoding": "base64"}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.InvalidCharacter,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: memcmp rejects unknown encoding
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"memcmp": {"offset": 0, "bytes": "abc", "encoding": "base32"}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.UnexpectedToken,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: memcmp missing offset
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"memcmp": {"bytes": "3Mc6vR"}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.MissingField,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: memcmp missing bytes
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"memcmp": {"offset": 0}}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.MissingField,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: rejects unknown filter key
    {
        const allocator = testing.allocator;
        const json_str =
            \\{"unknownFilter": 42}
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.UnexpectedToken,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }

    // parse: rejects non-object
    {
        const allocator = testing.allocator;
        const json_str =
            \\42
        ;
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        try testing.expectError(
            error.UnexpectedToken,
            RpcFilterType.jsonParseFromValue(allocator, parsed.value, .{}),
        );
    }
}
