/// Types for parsing a address lookup table accounts for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const AddressLookupTable = sig.runtime.program.address_lookup_table.AddressLookupTable;
const ParseError = account_decoder.ParseError;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L7-L20
pub fn parse_address_lookup_table(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
    data_len: u32,
) ParseError!LookupTableAccountType {
    // Read all data into buffer since the AddressLookupTable deserialize impl doesn't support borrowing from the reader.
    const data = allocator.alloc(u8, data_len) catch return ParseError.OutOfMemory;
    defer allocator.free(data);

    const bytes_read = reader.readAll(data) catch return ParseError.InvalidAccountData;
    if (bytes_read != data_len) return ParseError.InvalidAccountData;

    const lookup_table = AddressLookupTable.deserialize(data) catch |err| switch (err) {
        error.UninitializedAccount => return .uninitialized,
        error.InvalidAccountData => return ParseError.InvalidAccountData,
    };

    const addresses = allocator.alloc(Pubkey.Base58String, lookup_table.addresses.len) catch return ParseError.OutOfMemory;
    for (addresses, lookup_table.addresses) |*addr, lkp_tbl_addr| {
        addr.* = lkp_tbl_addr.base58String();
    }

    return LookupTableAccountType{ .lookup_table = UiLookupTable{
        .deactivation_slot = lookup_table.meta.deactivation_slot,
        .last_extended_slot = lookup_table.meta.last_extended_slot,
        .last_extended_slot_start_index = lookup_table.meta.last_extended_slot_start_index,
        .maybe_authority = if (lookup_table.meta.authority) |auth| auth.base58String() else null,
        .addresses = addresses,
    } };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L22-L27
pub const LookupTableAccountType = union(enum) {
    uninitialized,
    lookup_table: UiLookupTable,

    pub fn jsonStringify(self: LookupTableAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        switch (self) {
            .uninitialized => {
                try jw.objectField("type");
                try jw.write("uninitialized");
            },
            .lookup_table => |table| {
                try jw.objectField("type");
                try jw.write("lookupTable");
                try jw.objectField("info");
                try table.jsonStringify(jw);
            },
        }
        try jw.endObject();
    }
};
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L29-L38
pub const UiLookupTable = struct {
    deactivation_slot: u64,
    last_extended_slot: u64,
    last_extended_slot_start_index: u8,
    maybe_authority: ?Pubkey.Base58String,
    addresses: []const Pubkey.Base58String,

    pub fn jsonStringify(self: UiLookupTable, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();

        try jw.objectField("deactivationSlot");
        try jw.print("\"{d}\"", .{self.deactivation_slot});

        try jw.objectField("lastExtendedSlot");
        try jw.print("\"{d}\"", .{self.last_extended_slot});

        try jw.objectField("lastExtendedSlotStartIndex");
        try jw.write(self.last_extended_slot_start_index);

        // Skip authority if null
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_address_lookup_table.rs#L36
        if (self.maybe_authority) |authority| {
            try jw.objectField("authority");
            try jw.write(authority.slice());
        }

        try jw.objectField("addresses");
        try jw.beginArray();
        for (self.addresses) |addr| {
            try jw.write(addr.slice());
        }
        try jw.endArray();

        try jw.endObject();
    }
};
