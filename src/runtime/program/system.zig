// ################################################################################################
// REPLACE WITH SYSVAR IDS: START
// ################################################################################################
// Pubkey::from_str_const("SysvarRecentB1ockHashes11111111111111111111");
const RECENT_BLOCKHASHES_ID: Pubkey = .{ .data = [_]u8{0} ** Pubkey.size };

// Pubkey::from_str_const("SysvarRent111111111111111111111111111111111");
const RENT_ID: Pubkey = .{ .data = [_]u8{0} ** Pubkey.size };
// ################################################################################################
// REPLACE WITH SYSVAR IDS: START
// ################################################################################################

// https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L29
const ID: Pubkey = .{ .data = [_]u8{0} ** Pubkey.size };

// https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#L64
const NONCE_STATE_SIZE: u64 = 80;

// https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#80
pub const Instruction = union(enum) {
    /// Create a new account
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE, SIGNER]` New account
    CreateAccount: struct {
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
    Assign: struct {
        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Recipient account
    Transfer: struct {
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
    CreateAccountWithSeed: struct {
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
    },

    /// Consumes a stored nonce, replacing it with a successor
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[SIGNER]` Nonce authority
    AdvanceNonceAccount,

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
    WithdrawNonceAccount: u64,

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
    InitializeNonceAccount: Pubkey,

    /// Change the entity authorized to execute nonce instructions on the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    ///
    /// The `Pubkey` parameter identifies the entity to authorize
    AuthorizeNonceAccount: Pubkey,

    /// Allocate space in a (possibly new) account without funding
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` New account
    Allocate: struct {
        /// Number of bytes of memory to allocate
        space: u64,
    },

    /// Allocate space for and assign an account at an address
    /// derived from a base public key and a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Allocated account
    ///   1. `[SIGNER]` Base account
    AllocateWithSeed: struct {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: []const u8,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account
        owner: Pubkey,
    },

    /// Assign account to a program based on a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Assigned account
    ///   1. `[SIGNER]` Base account
    AssignWithSeed: struct {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: []const u8,

        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer lamports from a derived address
    ///
    /// # Account references
    ///   0. `[WRITE]` Funding account
    ///   1. `[SIGNER]` Base for funding account
    ///   2. `[WRITE]` Recipient account
    TransferWithSeed: struct {
        /// Amount to transfer
        lamports: u64,

        /// Seed to use to derive the funding account address
        from_seed: []const u8,

        /// Owner to use to derive the funding account address
        from_owner: Pubkey,
    },

    /// One-time idempotent upgrade of legacy nonce versions in order to bump
    /// them out of chain blockhash domain.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    UpgradeNonceAccount,
};

fn serialize(allocator: std.mem.Allocator, instruction: Instruction) ![]const u8 {
    return (try sig.bincode.writeToArray(allocator, instruction, .{})).toOwnedSlice();
}

/// Create a new account
///
/// # Account references
///   0. `[WRITE, SIGNER]` Funding account
///   1. `[WRITE, SIGNER]` New account
pub fn createAccount(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey,
    to_pubkey: Pubkey,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = from_pubkey, .is_signer = true, .is_writable = true },
            .{ .id = to_pubkey, .is_signer = true, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.CreateAccount{
                .lamports = lamports,
                .space = space,
                .owner = owner,
            },
        ),
    };
}

/// Create a new account at an address derived from a base pubkey and a seed
///
/// # Account references
///   0. `[WRITE, SIGNER]` Funding account
///   1. `[WRITE]` Created account
///   2. `[SIGNER]` (optional) Base account; the account matching the base Pubkey below must be
///      provided as a signer, but may be the same as the funding account
///      and provided as account 0
pub fn createAccountWithSeed(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey,
    to_pubkey: Pubkey, // must match create_with_seed(base, seed, owner)
    base: Pubkey,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = from_pubkey, .is_signer = true, .is_writable = true },
            .{ .id = to_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = base, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.CreateAccountWithSeed{
                .base = base,
                .seed = seed,
                .lamports = lamports,
                .space = space,
                .owner = owner,
            },
        ),
    };
}

/// Assign account to a program
///
/// # Account references
///   0. `[WRITE, SIGNER]` Assigned account public key
pub fn assign(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    owner: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = pubkey, .is_signer = true, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.Assign{
                .owner = owner,
            },
        ),
    };
}

/// Assign account to a program based on a seed
///
/// # Account references
///   0. `[WRITE]` Assigned account
///   1. `[SIGNER]` Base account
pub fn assignWithSeed(
    allocator: std.mem.Allocator,
    address: Pubkey, // must match create_with_seed(base, seed, owner)
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = address, .is_signer = false, .is_writable = true },
            .{ .id = base, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.AssignWithSeed{
                .base = base,
                .seed = seed,
                .owner = owner,
            },
        ),
    };
}

/// Transfer lamports
///
/// # Account references
///   0. `[WRITE, SIGNER]` Funding account
///   1. `[WRITE]` Recipient account
pub fn transfer(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey,
    to_pubkey: Pubkey,
    lamports: u64,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = from_pubkey, .is_signer = true, .is_writable = true },
            .{ .id = to_pubkey, .is_signer = false, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.Transfer{
                .lamports = lamports,
            },
        ),
    };
}

/// Transfer lamports from a derived address
///
/// # Account references
///   0. `[WRITE]` Funding account
///   1. `[SIGNER]` Base for funding account
///   2. `[WRITE]` Recipient account
pub fn transferWithSeed(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey, // must match create_with_seed(base, seed, owner)
    from_base: Pubkey,
    from_seed: []const u8,
    from_owner: Pubkey,
    to_pubkey: Pubkey,
    lamports: u64,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = from_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = from_base, .is_signer = true, .is_writable = false },
            .{ .id = to_pubkey, .is_signer = false, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.TransferWithSeed{
                .lamports = lamports,
                .from_seed = from_seed,
                .from_owner = from_owner,
            },
        ),
    };
}

/// Allocate space in a (possibly new) account without funding
///
/// # Account references
///   0. `[WRITE, SIGNER]` New account
pub fn allocate(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    space: u64,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = pubkey, .is_signer = true, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.Allocate{
                .space = space,
            },
        ),
    };
}

/// Allocate space for and assign an account at an address
/// derived from a base public key and a seed
///
/// # Account references
///   0. `[WRITE]` Allocated account
///   1. `[SIGNER]` Base account
pub fn allocateWithSeed(
    allocator: std.mem.Allocator,
    address: Pubkey, // must match create_with_seed(base, seed, owner)
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = address, .is_signer = false, .is_writable = true },
            .{ .id = base, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.AllocateWithSeed{
                .base = base,
                .seed = seed,
                .space = space,
                .owner = owner,
            },
        ),
    };
}

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
fn initializeNonceAccount(
    allocator: std.mem.Allocator,
    nonce_pubkey: Pubkey,
    authority: Pubkey,
) !Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = nonce_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = RECENT_BLOCKHASHES_ID, .is_signer = false, .is_writable = false },
            .{ .id = RENT_ID, .is_signer = false, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.InitializeNonceAccount{
                .authority = authority,
            },
        ),
    };
}

pub fn createNonceAccountWithSeed(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey,
    nonce_pubkey: Pubkey,
    base: Pubkey,
    seed: []const u8,
    authority: Pubkey,
    lamports: u64,
) ![2]Instruction {
    return .{
        try createAccountWithSeed(
            allocator,
            from_pubkey,
            nonce_pubkey,
            base,
            seed,
            lamports,
            NONCE_STATE_SIZE,
            &ID,
        ),
        try initializeNonceAccount(
            allocator,
            nonce_pubkey,
            authority,
        ),
    };
}

pub fn createNonceAccount(
    allocator: std.mem.Allocator,
    from_pubkey: Pubkey,
    nonce_pubkey: Pubkey,
    authority: Pubkey,
    lamports: u64,
) ![2]Instruction {
    return .{
        try createAccount(
            allocator,
            from_pubkey,
            nonce_pubkey,
            lamports,
            NONCE_STATE_SIZE,
            &ID,
        ),
        try initializeNonceAccount(
            allocator,
            nonce_pubkey,
            authority,
        ),
    };
}

/// Consumes a stored nonce, replacing it with a successor
///
/// # Account references
///   0. `[WRITE]` Nonce account
///   1. `[]` RecentBlockhashes sysvar
///   2. `[SIGNER]` Nonce authority
pub fn advanceNonceAccount(
    allocator: std.mem.Allocator,
    nonce_pubkey: Pubkey,
    authorized_pubkey: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = nonce_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = RECENT_BLOCKHASHES_ID, .is_signer = false, .is_writable = false },
            .{ .id = authorized_pubkey, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.AdvanceNonceAccount,
        ),
    };
}

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
pub fn withdrawNonceAccount(
    allocator: std.mem.Allocator,
    nonce_pubkey: Pubkey,
    authorized_pubkey: Pubkey,
    to_pubkey: Pubkey,
    lamports: u64,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = nonce_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = to_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = RECENT_BLOCKHASHES_ID, .is_signer = false, .is_writable = false },
            .{ .id = RENT_ID, .is_signer = false, .is_writable = false },
            .{ .id = authorized_pubkey, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.WithdrawNonceAccount(lamports),
        ),
    };
}

/// Change the entity authorized to execute nonce instructions on the account
///
/// # Account references
///   0. `[WRITE]` Nonce account
///   1. `[SIGNER]` Nonce authority
///
/// The `Pubkey` parameter identifies the entity to authorize
pub fn authorizeNonceAccount(
    allocator: std.mem.Allocator,
    nonce_pubkey: Pubkey,
    authorized_pubkey: Pubkey,
    new_authority: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = nonce_pubkey, .is_signer = false, .is_writable = true },
            .{ .id = authorized_pubkey, .is_signer = true, .is_writable = false },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.AuthorizeNonceAccount(new_authority),
        ),
    };
}

/// One-time idempotent upgrade of legacy nonce versions in order to bump
/// them out of chain blockhash domain.
///
/// # Account references
///   0. `[WRITE]` Nonce account
pub fn upgradeNonceAccount(
    allocator: std.mem.Allocator,
    nonce_pubkey: Pubkey,
) !sig.core.Instruction {
    return .{
        .program_id = ID,
        .accounts = &.{
            .{ .id = nonce_pubkey, .is_signer = false, .is_writable = true },
        },
        .data = try Instruction.writeToOwnedSlice(
            allocator,
            Instruction.UpgradeNonceAccount,
        ),
    };
}

// https://github.com/anza-xyz/agave/blob/df5c9ad28e76fb487514ab7719358df3c42cb1d5/programs/system/src/system_processor.rs#L301
pub fn execute(ctx: *sig.runtime.ExecuteInstructionContext) !void {
    _ = ctx;
    @panic("Program not implemented");
}

const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
