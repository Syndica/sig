//! Ported only what was needed for basic ALT parsing from shared/runtime/program/address_lookup_table/lib.zig
//!
//! TODO: we should get this from the shared runtime lib once it's ready for use with v2.
//! TODO: re-implement skipped portions as needed.
const std = @import("std");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

pub const ID: Pubkey = .parse("AddressLookupTab1e1111111111111111111111111");

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
// note - this is actually the size of ProgramState?
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L125
/// Program account states
pub const ProgramState = union(enum(u32)) {
    /// Account is not initialized.
    Uninitialized,
    /// Initialized `LookupTable` account.
    LookupTable: LookupTableMeta,
};

// [agave] https://github.com/anza-xyz/agave/blob/a00f1b5cdea9a7d5a70f8d24b86ea3ae66feff11/sdk/slot-hashes/src/lib.rs#L21
pub const MAX_ENTRIES: usize = 512; // about 2.5 minutes to get your vote in

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L46
// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L66
/// Address lookup table metadata
pub const LookupTableMeta = struct {
    /// Lookup tables cannot be closed until the deactivation slot is
    /// no longer "recent" (not accessible in the `SlotHashes` sysvar).
    deactivation_slot: Slot = std.math.maxInt(Slot),
    /// The slot that the table was last extended. Address tables may
    /// only be used to lookup addresses that were extended before
    /// the current bank's slot.
    last_extended_slot: Slot = 0,
    /// The start index where the table was last extended from during
    /// the `last_extended_slot`.
    last_extended_slot_start_index: u8 = 0,
    /// Authority address which must sign for each modification.
    authority: ?Pubkey = null,
    // Padding to keep addresses 8-byte aligned
    _padding: u16 = 0,
    // Raw list of addresses follows this serialized structure in
    // the account's data, starting from `LOOKUP_TABLE_META_SIZE`.
};

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L133-L134
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    addresses: []const Pubkey,

    pub const MAX_SERIALIZED_SIZE = LOOKUP_TABLE_META_SIZE + LOOKUP_TABLE_MAX_ADDRESSES * 32;

    pub const DeserializeError = error{
        UninitializedAccount,
        InvalidAccountData,
    };

    // [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L224
    pub fn deserialize(
        data: []const u8,
    ) DeserializeError!AddressLookupTable {
        if (data.len < LOOKUP_TABLE_META_SIZE)
            return error.InvalidAccountData;

        // ProgramState contains no slices or other allocating fields.
        var noalloc_memory: [0]u8 = .{};
        var noalloc = std.heap.FixedBufferAllocator.init(&noalloc_memory);

        var reader = std.Io.Reader.fixed(data);
        const state = lib.solana.bincode.read(
            &noalloc,
            &reader,
            ProgramState,
        ) catch return error.InvalidAccountData;

        const meta = switch (state) {
            .Uninitialized => return error.UninitializedAccount,
            .LookupTable => |meta| meta,
        };

        const address_bytes = data[LOOKUP_TABLE_META_SIZE..];
        if (address_bytes.len % Pubkey.SIZE != 0)
            return error.InvalidAccountData;

        return .{
            .meta = meta,
            .addresses = std.mem.bytesAsSlice(Pubkey, address_bytes),
        };
    }
};

fn writeProgramState(data: []u8, state: ProgramState) !void {
    std.debug.assert(data.len >= LOOKUP_TABLE_META_SIZE);

    @memset(data[0..LOOKUP_TABLE_META_SIZE], 0);
    var writer: std.Io.Writer = .fixed(data[0..LOOKUP_TABLE_META_SIZE]);
    try lib.solana.bincode.write(&writer, state);
}

fn writeLookupTableData(
    data: []u8,
    meta: LookupTableMeta,
    addresses: []const Pubkey,
) !void {
    std.debug.assert(data.len == LOOKUP_TABLE_META_SIZE + addresses.len * Pubkey.SIZE);

    try writeProgramState(data, .{ .LookupTable = meta });
    for (addresses, 0..) |address, i| {
        const start = LOOKUP_TABLE_META_SIZE + i * Pubkey.SIZE;
        @memcpy(data[start..][0..Pubkey.SIZE], &address.data);
    }
}

test "account lookup table deserializes initialized metadata and addresses" {
    const authority = Pubkey.parse("SyndicAgdEphcy5xhAKZAomTYhcF8xhC7za2UD9xeug");
    const addresses = [_]Pubkey{
        Pubkey.parse("11111111111111111111111111111111"),
        Pubkey.parse("ComputeBudget111111111111111111111111111111"),
        Pubkey.parse("SysvarRent111111111111111111111111111111111"),
    };
    const meta: LookupTableMeta = .{
        .deactivation_slot = 999,
        .last_extended_slot = 123,
        .last_extended_slot_start_index = 7,
        .authority = authority,
        ._padding = 0,
    };

    var data: [LOOKUP_TABLE_META_SIZE + addresses.len * Pubkey.SIZE]u8 = undefined;
    try writeLookupTableData(&data, meta, &addresses);

    const table = try AddressLookupTable.deserialize(&data);
    try std.testing.expectEqual(meta.deactivation_slot, table.meta.deactivation_slot);
    try std.testing.expectEqual(meta.last_extended_slot, table.meta.last_extended_slot);
    try std.testing.expectEqual(
        meta.last_extended_slot_start_index,
        table.meta.last_extended_slot_start_index,
    );
    try std.testing.expect(table.meta.authority.?.equals(&authority));
    try std.testing.expectEqualSlices(Pubkey, &addresses, table.addresses);
}

test "account lookup table deserializes zero and one address" {
    const no_addresses = [_]Pubkey{};
    var empty_data: [LOOKUP_TABLE_META_SIZE]u8 = undefined;
    try writeLookupTableData(&empty_data, .{}, &no_addresses);
    const empty_table = try AddressLookupTable.deserialize(&empty_data);
    try std.testing.expectEqual(@as(usize, 0), empty_table.addresses.len);

    const one_address = [_]Pubkey{
        Pubkey.parse("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    };
    var one_data: [LOOKUP_TABLE_META_SIZE + Pubkey.SIZE]u8 = undefined;
    try writeLookupTableData(&one_data, .{}, &one_address);
    const one_table = try AddressLookupTable.deserialize(&one_data);
    try std.testing.expectEqualSlices(Pubkey, &one_address, one_table.addresses);
}

test "account lookup table rejects uninitialized and invalid data" {
    var uninitialized: [LOOKUP_TABLE_META_SIZE]u8 = undefined;
    try writeProgramState(&uninitialized, .{ .Uninitialized = {} });
    try std.testing.expectError(
        error.UninitializedAccount,
        AddressLookupTable.deserialize(&uninitialized),
    );

    var too_short: [LOOKUP_TABLE_META_SIZE - 1]u8 = @splat(0);
    try std.testing.expectError(
        error.InvalidAccountData,
        AddressLookupTable.deserialize(&too_short),
    );

    var bad_trailing: [LOOKUP_TABLE_META_SIZE + 1]u8 = undefined;
    try writeProgramState(&bad_trailing, .{ .LookupTable = .{} });
    bad_trailing[LOOKUP_TABLE_META_SIZE] = 0;
    try std.testing.expectError(
        error.InvalidAccountData,
        AddressLookupTable.deserialize(&bad_trailing),
    );
}

test "account lookup table addresses borrow input buffer" {
    const original = Pubkey.parse("SysvarC1ock11111111111111111111111111111111");
    const replacement = Pubkey.parse("SysvarRent111111111111111111111111111111111");
    const addresses = [_]Pubkey{original};

    var data: [LOOKUP_TABLE_META_SIZE + Pubkey.SIZE]u8 = undefined;
    try writeLookupTableData(&data, .{}, &addresses);

    const table = try AddressLookupTable.deserialize(&data);
    try std.testing.expect(table.addresses[0].equals(&original));

    @memcpy(data[LOOKUP_TABLE_META_SIZE..][0..Pubkey.SIZE], &replacement.data);
    try std.testing.expect(table.addresses[0].equals(&replacement));
}
