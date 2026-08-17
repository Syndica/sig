const std = @import("std");
const sig = @import("../../../sig.zig");

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;

const SEED_FIELD_CONFIG = sig.runtime.program.SEED_FIELD_CONFIG;

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

        pub const @"!bincode-config:seed" = SEED_FIELD_CONFIG;

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

        pub const @"!bincode-config:seed" = SEED_FIELD_CONFIG;

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

        pub const @"!bincode-config:seed" = SEED_FIELD_CONFIG;

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

        pub const @"!bincode-config:from_seed" = SEED_FIELD_CONFIG;

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

    /// Create a new account without requiring its current lamport balance to be zero.
    ///
    /// # Account references
    /// When `lamports > 0`:
    ///   0. `[WRITE, SIGNER]` New account
    ///   1. `[WRITE, SIGNER]` Funding account
    ///
    /// When `lamports == 0`:
    ///   0. `[WRITE, SIGNER]` New account
    create_account_allow_prefund: struct {
        /// Number of additional lamports to transfer to the new account.
        lamports: u64,

        /// Number of bytes of memory to allocate.
        space: u64,

        /// Address of the program that will own the new account.
        owner: Pubkey,
    },

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
            .create_account_allow_prefund => {},

            inline //
            .create_account_with_seed,
            .allocate_with_seed,
            .assign_with_seed,
            .transfer_with_seed,
            => |inst| inst.deinit(allocator),
        }
    }
};

test "deserialize create account allow prefund mainnet instruction" {
    const bytes = [_]u8{
        0x0d, 0x00, 0x00, 0x00, // SystemInstruction tag 13
        0x10, 0x42, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, // 1_524_240 lamports
        0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 91 bytes
        0xa0, 0x93, 0x3e, 0xfd, 0x66, 0x5b, 0x34, 0x7f,
        0xad, 0x5c, 0x5a, 0xa0, 0xfb, 0x00, 0x79, 0xd2,
        0xf8, 0x3b, 0x36, 0xe9, 0x37, 0x17, 0xcd, 0xcb,
        0x1e, 0x8a, 0x9b, 0xd4, 0x6e, 0x08, 0xc5, 0xe8,
    };

    const instruction = try bincode.readFromSlice(
        std.testing.allocator,
        Instruction,
        &bytes,
        .{},
    );
    const args = instruction.create_account_allow_prefund;
    try std.testing.expectEqual(@as(u64, 1_524_240), args.lamports);
    try std.testing.expectEqual(@as(u64, 91), args.space);
    try std.testing.expectEqualSlices(u8, bytes[20..52], &args.owner.data);

    if (bincode.readFromSlice(
        std.testing.allocator,
        Instruction,
        bytes[0 .. bytes.len - 1],
        .{},
    )) |_| {
        return error.TestExpectedError;
    } else |_| {}
}
