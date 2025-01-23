// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/sdk/program/src/address_lookup_table/error.rs
// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/sdk/program/src/address_lookup_table/instruction.rs
// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/sdk/program/src/address_lookup_table/state.rs

const sig = @import("../../sig.zig");

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;

pub const AddressLookupError = enum {
    /// Attempted to lookup addresses from a table that does not exist
    LookupTableAccountNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAccountOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAccountData,

    /// Address lookup contains an invalid index
    InvalidLookupIndex,
};

pub const AddressLookupTableInstruction = union(enum) {
    /// Create an address lookup table
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized address lookup table account
    ///   1. `[SIGNER]` Account used to derive and control the new address lookup table.
    ///   2. `[SIGNER, WRITE]` Account that will fund the new address lookup table.
    ///   3. `[]` System program for CPI.
    CreateLookupTable: struct {
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
    },

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
    ExtendLookupTable: struct { new_addresses: []const Pubkey },

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

/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

/// The serialized size of lookup table metadata
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Activation status of a lookup table
pub const LookupTableStatus = union(enum) {
    activated,
    deactivating: usize,
    deactivated,
};

/// Address lookup table metadata
pub const LookupTableMeta = struct {
    /// Lookup tables cannot be closed until the deactivation slot is
    /// no longer "recent" (not accessible in the `SlotHashes` sysvar).
    deactivation_slot: Slot,
    /// The slot that the table was last extended. Address tables may
    /// only be used to lookup addresses that were extended before
    /// the current bank's slot.
    last_extended_slot: Slot,
    /// The start index where the table was last extended from during
    /// the `last_extended_slot`.
    last_extended_slot_start_index: u8,
    /// Authority address which must sign for each modification.
    authority: ?Pubkey,
    // Padding to keep addresses 8-byte aligned
    _padding: u16,
    // Raw list of addresses follows this serialized structure in
    // the account's data, starting from `LOOKUP_TABLE_META_SIZE`.
};

/// Program account states
pub const ProgramState = union(enum) {
    /// Account is not initialized.
    uninitialized,
    /// Initialized `LookupTable` account.
    lookup_table: LookupTableMeta,
};

/// Address lookup table
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    addresses: []const Pubkey,
};
