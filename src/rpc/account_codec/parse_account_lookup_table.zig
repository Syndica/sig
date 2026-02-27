//! Types for parsing a address lookup table accounts for RPC responses using the `jsonParsed` encoding.
//! [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs
const std = @import("std");
const sig = @import("../../sig.zig");

const account_codec = sig.rpc.account_codec;
const address_lookup_table = sig.runtime.program.address_lookup_table;

const AddressLookupTable = sig.runtime.program.address_lookup_table.AddressLookupTable;
const Allocator = std.mem.Allocator;
const LookupTableMeta = address_lookup_table.LookupTableMeta;
const ParseError = account_codec.ParseError;
const ProgramState = address_lookup_table.ProgramState;
const Pubkey = sig.core.Pubkey;

const LOOKUP_TABLE_META_SIZE = address_lookup_table.state.LOOKUP_TABLE_META_SIZE;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L7-L20
///
/// Caller owns the returned `.addresses` allocation and must free it.
pub fn parseAddressLookupTable(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
) ParseError!LookupTableAccountType {
    // Read all data into buffer since the AddressLookupTable deserialize impl doesn't support borrowing from the reader.
    const data = try allocator.alloc(u8, data_len);
    defer allocator.free(data);

    const bytes_read = reader.readAll(data) catch return ParseError.InvalidAccountData;
    if (bytes_read != data_len) return ParseError.InvalidAccountData;

    const lookup_table = AddressLookupTable.deserialize(data) catch |err| switch (err) {
        error.UninitializedAccount => return .uninitialized,
        error.InvalidAccountData => return ParseError.InvalidAccountData,
    };

    const addresses = try allocator.alloc(Pubkey, lookup_table.addresses.len);
    errdefer allocator.free(addresses);
    @memcpy(addresses, lookup_table.addresses);

    return .{ .lookup_table = .{
        .deactivationSlot = .{ .value = lookup_table.meta.deactivation_slot },
        .lastExtendedSlot = .{ .value = lookup_table.meta.last_extended_slot },
        .lastExtendedSlotStartIndex = lookup_table.meta.last_extended_slot_start_index,
        .authority = lookup_table.meta.authority,
        .addresses = addresses,
    } };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L22-L27
pub const LookupTableAccountType = union(enum) {
    uninitialized,
    lookup_table: UiLookupTable,

    pub fn jsonStringify(self: LookupTableAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            inline else => |v, tag| {
                try jw.write(typeNameFromTag(tag));
                if (@TypeOf(v) != void) {
                    try jw.objectField("info");
                    try v.jsonStringify(jw);
                }
            },
        }
        try jw.endObject();
    }

    fn typeNameFromTag(comptime tag: std.meta.Tag(LookupTableAccountType)) []const u8 {
        return switch (tag) {
            .uninitialized => "uninitialized",
            .lookup_table => "lookupTable",
        };
    }
};
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L29-L38
pub const UiLookupTable = struct {
    deactivationSlot: account_codec.Stringified(u64),
    lastExtendedSlot: account_codec.Stringified(u64),
    lastExtendedSlotStartIndex: u8,
    authority: ?Pubkey,
    addresses: []const Pubkey,

    pub fn jsonStringify(self: UiLookupTable, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("deactivationSlot");
        try jw.write(self.deactivationSlot);
        try jw.objectField("lastExtendedSlot");
        try jw.write(self.lastExtendedSlot);
        try jw.objectField("lastExtendedSlotStartIndex");
        try jw.write(self.lastExtendedSlotStartIndex);
        // Skip authority if null to match Agave behavior
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L36
        if (self.authority) |auth| {
            try jw.objectField("authority");
            try jw.write(auth);
        }
        try jw.objectField("addresses");
        try jw.write(self.addresses);
        try jw.endObject();
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L49-L103
test "rpc.account_codec.parse_account_lookup_table: parse lookup tables" {
    const allocator = std.testing.allocator;

    // Parse valid lookup table with addresses
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L49-L81
    {
        const authority = Pubkey{ .data = [_]u8{1} ** 32 };
        const addr1 = Pubkey{ .data = [_]u8{2} ** 32 };
        const addr2 = Pubkey{ .data = [_]u8{3} ** 32 };

        const meta = LookupTableMeta{
            .deactivation_slot = std.math.maxInt(u64), // Not deactivated
            .last_extended_slot = 12345,
            .last_extended_slot_start_index = 0,
            .authority = authority,
            ._padding = 0,
        };

        const program_state = ProgramState{ .LookupTable = meta };

        // Build the account data: metadata + addresses
        var data: [LOOKUP_TABLE_META_SIZE + 64]u8 = undefined; // 56 bytes meta + 2 * 32 bytes addresses

        // Serialize the metadata
        _ = sig.bincode.writeToSlice(&data, program_state, .{}) catch unreachable;

        // Append addresses after metadata
        @memcpy(data[LOOKUP_TABLE_META_SIZE..][0..32], &addr1.data);
        @memcpy(data[LOOKUP_TABLE_META_SIZE + 32 ..][0..32], &addr2.data);

        // Parse the lookup table
        var stream = std.io.fixedBufferStream(&data);
        const result = try parseAddressLookupTable(allocator, stream.reader(), @intCast(data.len));
        defer allocator.free(result.lookup_table.addresses);

        // Verify the parsed result
        const lt = result.lookup_table;
        try std.testing.expectEqual(std.math.maxInt(u64), lt.deactivationSlot.value);
        try std.testing.expectEqual(@as(u64, 12345), lt.lastExtendedSlot.value);
        try std.testing.expectEqual(@as(u8, 0), lt.lastExtendedSlotStartIndex);
        try std.testing.expectEqual(authority, lt.authority.?);
        try std.testing.expectEqual(@as(usize, 2), lt.addresses.len);
        try std.testing.expectEqual(addr1, lt.addresses[0]);
        try std.testing.expectEqual(addr2, lt.addresses[1]);
    }

    // Parse table without authority (frozen)
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L49-L81
    {
        const meta = LookupTableMeta{
            .deactivation_slot = 99999,
            .last_extended_slot = 50000,
            .last_extended_slot_start_index = 5,
            .authority = null, // No authority = frozen
            ._padding = 0,
        };

        const program_state = ProgramState{ .LookupTable = meta };

        var data: [LOOKUP_TABLE_META_SIZE]u8 = undefined;
        _ = sig.bincode.writeToSlice(&data, program_state, .{}) catch unreachable;

        // Parse the lookup table
        var stream = std.io.fixedBufferStream(&data);
        const result = try parseAddressLookupTable(allocator, stream.reader(), @intCast(data.len));
        defer allocator.free(result.lookup_table.addresses);

        // Verify the parsed result
        const lt = result.lookup_table;
        try std.testing.expectEqual(@as(u64, 99999), lt.deactivationSlot.value);
        try std.testing.expectEqual(@as(u64, 50000), lt.lastExtendedSlot.value);
        try std.testing.expectEqual(@as(u8, 5), lt.lastExtendedSlotStartIndex);
        try std.testing.expectEqual(@as(?Pubkey, null), lt.authority);
        try std.testing.expectEqual(@as(usize, 0), lt.addresses.len);
    }

    // Parse uninitialized table
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L83-L95
    {
        const program_state = ProgramState{ .Uninitialized = {} };

        var data: [LOOKUP_TABLE_META_SIZE]u8 = undefined;
        _ = sig.bincode.writeToSlice(&data, program_state, .{}) catch unreachable;

        // Parse should return uninitialized
        var stream = std.io.fixedBufferStream(&data);
        const result = try parseAddressLookupTable(allocator, stream.reader(), @intCast(data.len));

        try std.testing.expectEqual(LookupTableAccountType.uninitialized, result);
    }

    // Bad data returns error
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L97-L103
    {
        const bad_data = [_]u8{ 0, 1, 2, 3 };

        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseAddressLookupTable(allocator, stream.reader(), @intCast(bad_data.len));
        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }
}
