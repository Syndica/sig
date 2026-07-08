const std = @import("std");
const sig = @import("../../../lib.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const sysvar = sig.runtime.sysvar;
const InstructionError = sig.core.instruction.InstructionError;

/// Self-referencing namespace for backward-compatible `address_lookup_table.state.*` paths.
pub const state = @This();

pub const ID: Pubkey = .parse("AddressLookupTab1e1111111111111111111111111");

// --- state types ---

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

    pub fn status(
        self: *const LookupTableMeta,
        current_slot: Slot,
        slot_hashes: sysvar.SlotHashes,
    ) LookupTableStatus {
        if (self.deactivation_slot == std.math.maxInt(Slot)) {
            return LookupTableStatus.Activated;
        }
        if (self.deactivation_slot == current_slot) {
            return LookupTableStatus{ .Deactivating = .{ .remaining_blocks = MAX_ENTRIES +| 1 } };
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

    pub const MAX_SERIALIZED_SIZE = LOOKUP_TABLE_META_SIZE + LOOKUP_TABLE_MAX_ADDRESSES * 32;

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
    /// NOTE: This AddressLookupTable's 'addresses' slice will point to inside 'data' - consider
    /// if you need to clone the buffer (see deserializeOwned).
    pub fn deserialize(
        data: []const u8,
    ) error{ UninitializedAccount, InvalidAccountData }!AddressLookupTable {
        const noalloc = sig.utils.allocators.failing.allocator(.{});
        const state_val = sig.bincode.readFromSlice(noalloc, ProgramState, data, .{}) catch
            return error.InvalidAccountData;

        if (state_val == .Uninitialized) return error.UninitializedAccount;

        if (data.len < LOOKUP_TABLE_META_SIZE) return error.InvalidAccountData;

        const addresses_data = data[LOOKUP_TABLE_META_SIZE..];
        if (addresses_data.len % 32 != 0) return error.InvalidAccountData;
        const addresses = std.mem.bytesAsSlice(Pubkey, addresses_data);

        return .{
            .meta = state_val.LookupTable,
            .addresses = addresses,
        };
    }

    /// Deserializes an AddressLookupTable, coping .addresses into a new buffer.
    pub fn deserializeOwned(
        allocator: std.mem.Allocator,
        data: []const u8,
    ) error{ OutOfMemory, UninitializedAccount, InvalidAccountData }!AddressLookupTable {
        var table = try AddressLookupTable.deserialize(data);
        table.addresses = try allocator.dupe(Pubkey, table.addresses);
        return table;
    }
};

// --- instruction types ---

// https://github.com/anza-xyz/agave/blob/7e8a1ddf86fa84b0ca4b64360af89399afd9de44/sdk/program/src/address_lookup_table/instruction.rs#L13
pub const Instruction = union(enum) {
    /// Create an address lookup table
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized address lookup table account
    ///   1. `[SIGNER]` Account used to derive and control the new address lookup table.
    ///   2. `[SIGNER, WRITE]` Account that will fund the new address lookup table.
    ///   3. `[]` System program for CPI.
    CreateLookupTable: CreateLookupTable,
    /// Permanently freeze an address lookup table, making it immutable.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to freeze
    ///   1. `[SIGNER]` Current authority
    FreezeLookupTable,

    /// Extend an address lookup table with new addresses. Funding account and
    /// system program account references are only required if the lookup table
    /// account requires additional lamports to cover the rent-exempt balance
    /// after being extended.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to extend
    ///   1. `[SIGNER]` Current authority
    ///   2. `[SIGNER, WRITE, OPTIONAL]` Account that will fund the table reallocation
    ///   3. `[OPTIONAL]` System program for CPI.
    ExtendLookupTable: ExtendLookupTable,

    /// Deactivate an address lookup table, making it unusable and
    /// eligible for closure after a short period of time.
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to deactivate
    ///   1. `[SIGNER]` Current authority
    DeactivateLookupTable,

    /// Close an address lookup table account
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to close
    ///   1. `[SIGNER]` Current authority
    ///   2. `[WRITE]` Recipient of closed account lamports
    CloseLookupTable,
};

// https://github.com/anza-xyz/agave/blob/7e8a1ddf86fa84b0ca4b64360af89399afd9de44/sdk/program/src/address_lookup_table/instruction.rs#L21
pub const CreateLookupTable = struct {
    /// A recent slot must be used in the derivation path
    /// for each initialized table. When closing table accounts,
    /// the initialization slot must no longer be "recent" to prevent
    /// address tables from being recreated with reordered or
    /// otherwise malicious addresses.
    recent_slot: Slot,
    /// Address tables are always initialized at program-derived
    /// addresses using the funding address, recent blockhash, and
    /// the user-passed `bump_seed`.
    bump_seed: u8,
};

// https://github.com/anza-xyz/agave/blob/7e8a1ddf86fa84b0ca4b64360af89399afd9de44/sdk/program/src/address_lookup_table/instruction.rs#L51
pub const ExtendLookupTable = struct {
    new_addresses: []const Pubkey,
};
