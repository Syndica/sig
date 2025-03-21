const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

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
    FreezeLookupTable: FreezeLookupTable,

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
    DeactivateLookupTable: DeactivateLookupTable,

    /// Close an address lookup table account
    ///
    /// # Account references
    ///   0. `[WRITE]` Address lookup table account to close
    ///   1. `[SIGNER]` Current authority
    ///   2. `[WRITE]` Recipient of closed account lamports
    CloseLookupTable: CloseLookupTable,
};

const AccountIndexWithPayer = enum(u8) {
    lookup_table_account = 0,
    authority_account = 1,
    payer_account = 2,
};

const AccountIndexNoPayer = enum(u8) {
    lookup_table_account = 0,
    authority_account = 1,
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

    pub const AccountIndex = AccountIndexWithPayer;
};

pub const FreezeLookupTable = struct {
    pub const AccountIndex = AccountIndexNoPayer;
};

// https://github.com/anza-xyz/agave/blob/7e8a1ddf86fa84b0ca4b64360af89399afd9de44/sdk/program/src/address_lookup_table/instruction.rs#L51
pub const ExtendLookupTable = struct {
    new_addresses: []const Pubkey,

    pub const AccountIndex = AccountIndexWithPayer;
};

pub const DeactivateLookupTable = struct {
    pub const AccountIndex = AccountIndexNoPayer;
};

pub const CloseLookupTable = struct {
    pub const AccountIndex = AccountIndexWithPayer;
};
