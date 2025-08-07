const std = @import("std");
const sig = @import("../../../sig.zig");

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;

const MAX_SEED_LEN = sig.runtime.pubkey_utils.MAX_SEED_LEN;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#L80
pub const Instruction = union(enum) {
    /// Create a new account
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE, SIGNER]` New account
    create_account: struct {
        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Address of program that will own the new account
        owner: Pubkey,
    },

    /// Assign account to a program
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Assigned account public key
    assign: struct {
        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Recipient account
    transfer: struct {
        lamports: u64,
    },

    /// Create a new account at an address derived from a base pubkey and a seed
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Created account
    ///   2. `[SIGNER]` (optional) Base account; the account matching the base Pubkey below must be
    ///      provided as a signer, but may be the same as the funding account
    ///      and provided as account 0
    create_account_with_seed: struct {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `Pubkey::MAX_SEED_LEN`
        seed: []const u8,

        /// Number of lamports to transfer to the new account
        lamports: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account address
        owner: Pubkey,

        pub const @"!bincode-config:seed" = bincode.utf8StringCodec([]const u8, MAX_SEED_LEN);

        pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.seed);
        }
    },

    /// Consumes a stored nonce, replacing it with a successor
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[SIGNER]` Nonce authority
    advance_nonce_account,

    /// Withdraw funds from a nonce account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[WRITE]` Recipient account
    ///   2. `[]` RecentBlockhashes sysvar
    ///   3. `[]` Rent sysvar
    ///   4. `[SIGNER]` Nonce authority
    ///
    /// The `u64` parameter is the lamports to withdraw, which must leave the
    /// account balance above the rent exempt reserve or at zero.
    withdraw_nonce_account: u64,

    /// Drive state of Uninitialized nonce account to Initialized, setting the nonce value
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[]` Rent sysvar
    ///
    /// The `Pubkey` parameter specifies the entity authorized to execute nonce
    /// instruction on the account
    ///
    /// No signatures are required to execute this instruction, enabling derived
    /// nonce account addresses
    initialize_nonce_account: Pubkey,

    /// Change the entity authorized to execute nonce instructions on the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    ///
    /// The `Pubkey` parameter identifies the entity to authorize
    authorize_nonce_account: Pubkey,

    /// Allocate space in a (possibly new) account without funding
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` New account
    allocate: struct {
        /// Number of bytes of memory to allocate
        space: u64,
    },

    /// Allocate space for and assign an account at an address
    /// derived from a base public key and a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Allocated account
    ///   1. `[SIGNER]` Base account
    allocate_with_seed: struct {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: []const u8,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account
        owner: Pubkey,

        pub const @"!bincode-config:seed" = bincode.utf8StringCodec([]const u8, MAX_SEED_LEN);

        pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.seed);
        }
    },

    /// Assign account to a program based on a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Assigned account
    ///   1. `[SIGNER]` Base account
    assign_with_seed: struct {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: []const u8,

        /// Owner program account
        owner: Pubkey,

        pub const @"!bincode-config:seed" = bincode.utf8StringCodec([]const u8, MAX_SEED_LEN);

        pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.seed);
        }
    },

    /// Transfer lamports from a derived address
    ///
    /// # Account references
    ///   0. `[WRITE]` Funding account
    ///   1. `[SIGNER]` Base for funding account
    ///   2. `[WRITE]` Recipient account
    transfer_with_seed: struct {
        /// Amount to transfer
        lamports: u64,

        /// Seed to use to derive the funding account address
        from_seed: []const u8,

        /// Owner to use to derive the funding account address
        from_owner: Pubkey,

        pub const @"!bincode-config:from_seed" = bincode.utf8StringCodec([]const u8, MAX_SEED_LEN);

        pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.from_seed);
        }
    },

    /// One-time idempotent upgrade of legacy nonce versions in order to bump
    /// them out of chain blockhash domain.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    upgrade_nonce_account,

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        switch (self) {
            .create_account => {},
            .assign => {},
            .transfer => {},
            .advance_nonce_account => {},
            .withdraw_nonce_account => {},
            .initialize_nonce_account => {},
            .authorize_nonce_account => {},
            .allocate => {},
            .upgrade_nonce_account => {},

            inline //
            .create_account_with_seed,
            .allocate_with_seed,
            .assign_with_seed,
            .transfer_with_seed,
            => |inst| inst.deinit(allocator),
        }
    }
};
