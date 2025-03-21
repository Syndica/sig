const sig = @import("../../../sig.zig");
const std = @import("std");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const sysvar = sig.runtime.sysvar;
const InstructionError = sig.core.instruction.InstructionError;

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
// note - this is actually the size of ProgramState?
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L125
/// Program account states
pub const ProgramState = union(enum) {
    /// Account is not initialized.
    Uninitialized,
    /// Initialized `LookupTable` account.
    LookupTable: LookupTableMeta,
};

/// Activation status of a lookup table
pub const LookupTableStatus = union(enum) {
    Activated,
    Deactivating: Deactivating,
    Deactivated,
};

// [agave] https://github.com/anza-xyz/agave/blob/a00f1b5cdea9a7d5a70f8d24b86ea3ae66feff11/sdk/slot-hashes/src/lib.rs#L21
pub const MAX_ENTRIES: usize = 512; // about 2.5 minutes to get your vote in

const Deactivating = struct { remaining_blocks: usize };

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

    pub fn new(authority: Pubkey) LookupTableMeta {
        return .{
            .authority = authority,
        };
    }

    pub fn status(
        self: *const LookupTableMeta,
        current_slot: Slot,
        slot_hashes: sysvar.SlotHashes,
    ) LookupTableStatus {
        if (self.deactivation_slot == std.math.maxInt(Slot)) {
            return LookupTableStatus.Activated;
        }
        if (self.deactivation_slot == current_slot) {
            return LookupTableStatus{ .Deactivating = .{ .remaining_blocks = MAX_ENTRIES } };
        }
        if (slot_hashes.getIndex(self.deactivation_slot)) |slot_hash_position| {
            return LookupTableStatus{
                .Deactivating = .{ .remaining_blocks = MAX_ENTRIES -| slot_hash_position },
            };
        }
        return LookupTableStatus.Deactivated;
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L133-L134
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    addresses: []const Pubkey,

    pub fn overwriteMetaData(
        data: []u8,
        meta: LookupTableMeta,
    ) InstructionError!void {
        if (data.len < LOOKUP_TABLE_META_SIZE) return error.InvalidAccountData;
        const metadata = data[0..LOOKUP_TABLE_META_SIZE];
        @memset(metadata, 0);
        _ = sig.bincode.writeToSlice(metadata, &ProgramState{ .LookupTable = meta }, .{}) catch
            return error.GenericError;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L224
    pub fn deserialize(
        allocator: std.mem.Allocator,
        data: []const u8,
    ) (error{OutOfMemory} || InstructionError)!AddressLookupTable {
        const state = sig.bincode.readFromSlice(allocator, ProgramState, data, .{}) catch
            return error.InvalidAccountData;
        errdefer sig.bincode.free(allocator, state);

        if (state == .Uninitialized) return error.UninitializedAccount;

        if (data.len < LOOKUP_TABLE_META_SIZE) return error.InvalidAccountData;

        const addresses_data = data[LOOKUP_TABLE_META_SIZE..];
        if (addresses_data.len % 32 != 0) return error.InvalidAccountData;
        const addresses = std.mem.bytesAsSlice(Pubkey, addresses_data);

        return .{
            .meta = state.LookupTable,
            .addresses = addresses,
        };
    }
};
