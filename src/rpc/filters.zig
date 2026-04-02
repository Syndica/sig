//! Filter types for scanning RPC methods (`getProgramAccounts`, `getTokenAccountsByOwner`, etc.).
//!
//! Handles JSON wire format parsing, validation, and runtime matching against account data.
//! Shared across all 6 scanning methods.
//! TODO: Move all this into methods.zig and move the unit tests into test_serialize.zig.
const std = @import("std");
const sig = @import("../sig.zig");
const base58 = @import("base58");

const parse_token = @import("account_codec/parse_token.zig");

const Allocator = std.mem.Allocator;
const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;

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

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/filter.rs#L12-L18
pub const RpcFilterType = union(enum) {
    dataSize: u64,
    memcmp: Memcmp,
    tokenAccountState,

    /// Returns `true` if `account_data` passes this filter.
    pub fn allows(self: RpcFilterType, account_data: *const AccountDataHandle) bool {
        return switch (self) {
            .dataSize => |size| account_data.len() == size,
            .memcmp => |m| m.matches(account_data),
            .tokenAccountState => {
                // Delegate to parse_token's shared validation which handles both
                // standard SPL Token (165 bytes) and Token-2022 extended accounts.
                // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/filter.rs#L11
                const data_len = account_data.len();
                if (data_len < TOKEN_ACCOUNT_LEN) return false;
                var state_buf: [1]u8 = undefined;
                _ = account_data.read(parse_token.ACCOUNT_INITIALIZED_INDEX, &state_buf);
                var disc_buf: [1]u8 = .{0};
                if (data_len > TOKEN_ACCOUNT_LEN) {
                    _ = account_data.read(TOKEN_ACCOUNT_LEN, &disc_buf);
                }
                return parse_token.isValidTokenAccount(data_len, state_buf[0], disc_buf[0]);
            },
        };
    }

    /// The default std.json union parser rejects non-object values for void fields,
    /// but Agave expects `{"tokenAccountState": null}` (serde unit type). We accept
    /// any value here to be permissive, since only key presence matters for matching.
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
        // [agave] Agave deserializes tokenAccountState as serde unit (`null` in JSON).
        // We accept any value since only key presence matters for this filter.
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
    pub fn matches(self: Memcmp, data: *const AccountDataHandle) bool {
        if (self.offset +| self.bytes.len > data.len()) return false;
        const sub = data.slice(@intCast(self.offset), @intCast(self.offset + self.bytes.len));
        return sub.eql(AccountDataHandle.initAllocated(self.bytes));
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
pub fn verifyFilters(
    filters_slice: []const RpcFilterType,
) error{ TooManyFilters, MemcmpBytesTooLarge }!void {
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
pub fn filtersAllow(
    filters_slice: []const RpcFilterType,
    account_data: *const AccountDataHandle,
) bool {
    for (filters_slice) |f| {
        if (!f.allows(account_data)) return false;
    }
    return true;
}

test "rpc.filters" {
    const testing = std.testing;
    const h = AccountDataHandle.initAllocated;

    // allows: dataSize matches exact length
    {
        const filter = RpcFilterType{ .dataSize = 10 };
        const d1 = h(&.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 });
        const d2 = h(&.{ 0, 1, 2 });
        const d3 = h(&.{});
        try testing.expect(filter.allows(&d1));
        try testing.expect(!filter.allows(&d2));
        try testing.expect(!filter.allows(&d3));
    }

    // allows: memcmp matches at offset
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 2, .bytes = &.{ 0xAA, 0xBB } } };
        const d1 = h(&.{ 0, 0, 0xAA, 0xBB, 0 });
        const d2 = h(&.{ 0, 0, 0xAA, 0xCC, 0 });
        const d3 = h(&.{ 0, 0, 0xAA });
        const d4 = h(&.{});
        try testing.expect(filter.allows(&d1));
        try testing.expect(!filter.allows(&d2));
        // Too short — offset + bytes extends past end.
        try testing.expect(!filter.allows(&d3));
        try testing.expect(!filter.allows(&d4));
    }

    // allows: memcmp offset at boundary
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 3, .bytes = &.{0xFF} } };
        // Exactly fits.
        const d1 = h(&.{ 0, 0, 0, 0xFF });
        const d2 = h(&.{ 0, 0, 0 });
        try testing.expect(filter.allows(&d1));
        // One byte short.
        try testing.expect(!filter.allows(&d2));
    }

    // allows: memcmp empty bytes always matches
    {
        const filter = RpcFilterType{ .memcmp = .{ .offset = 0, .bytes = &.{} } };
        const d1 = h(&.{});
        const d2 = h(&.{42});
        try testing.expect(filter.allows(&d1));
        try testing.expect(filter.allows(&d2));
    }

    // allows: memcmp saturating offset overflow
    {
        // offset near maxInt(usize) should not wrap, just fail to match.
        const filter = RpcFilterType{
            .memcmp = .{
                .offset = std.math.maxInt(usize),
                .bytes = &.{1},
            },
        };
        const d1 = h(&.{1});
        try testing.expect(!filter.allows(&d1));
    }

    // allows: tokenAccountState initialized
    {
        var data = [_]u8{0} ** 165;
        data[108] = 1; // Initialized
        const d = h(&data);
        try testing.expect((RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // allows: tokenAccountState frozen
    {
        var data = [_]u8{0} ** 165;
        data[108] = 2; // Frozen
        const d = h(&data);
        try testing.expect((RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // allows: tokenAccountState rejects uninitialized
    {
        var data = [_]u8{0} ** 165;
        data[108] = 0; // Uninitialized
        const d = h(&data);
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // allows: tokenAccountState rejects too-short data
    {
        var data = [_]u8{0} ** 100;
        data[99] = 1;
        const d1 = h(&data);
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&d1));
    }

    // allows: tokenAccountState accepts Token-2022 extended account (170 bytes with correct discriminator)
    {
        var data = [_]u8{0} ** 170;
        data[108] = 1; // Initialized
        data[165] = 2; // AccountTypeDiscriminator.account
        const d = h(&data);
        try testing.expect((RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // allows: tokenAccountState rejects Token-2022 without account discriminator
    {
        var data = [_]u8{0} ** 170;
        data[108] = 1; // Initialized
        data[165] = 0; // Uninitialized discriminator
        const d = h(&data);
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // allows: tokenAccountState rejects multisig-sized data (355 bytes)
    {
        var data = [_]u8{0} ** 355;
        data[108] = 1; // Initialized
        const d = h(&data);
        try testing.expect(!(RpcFilterType{ .tokenAccountState = {} }).allows(&d));
    }

    // filtersAllow: conjunction of multiple filters
    {
        const f = &[_]RpcFilterType{
            .{ .dataSize = 5 },
            .{ .memcmp = .{ .offset = 0, .bytes = &.{0xAA} } },
        };
        const d1 = h(&.{ 0xAA, 0, 0, 0, 0 });
        const d2 = h(&.{ 0xBB, 0, 0, 0, 0 });
        const d3 = h(&.{ 0xAA, 0, 0 });
        try testing.expect(filtersAllow(f, &d1));
        // Right length but wrong byte.
        try testing.expect(!filtersAllow(f, &d2));
        // Right byte but wrong length.
        try testing.expect(!filtersAllow(f, &d3));
    }

    // filtersAllow: empty filters allows everything
    {
        const d1 = h(&.{});
        const d2 = h(&.{ 1, 2, 3 });
        try testing.expect(filtersAllow(&.{}, &d1));
        try testing.expect(filtersAllow(&.{}, &d2));
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
        const handle = h(&data);
        try testing.expect(filter.allows(&handle));
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
