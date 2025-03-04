const std = @import("std");
const sig = @import("../../../sig.zig");

const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const nonce = sig.runtime.nonce;
const Pubkey = sig.core.Pubkey;
const pubkey_utils = sig.runtime.pubkey_utils;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const Slot = sig.core.Slot;
const system_program = sig.runtime.program.system_program;
const SystemProgramError = system_program.Error;
const SystemProgramInstruction = system_program.Instruction;
const SysvarCache = sig.runtime.SysvarCache;
const sysvar = sig.runtime.sysvar;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

//https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

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

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L25
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    // agave: consumed in declare_process_instruction
    try ic.tc.consumeCompute(system_program.COMPUTE_UNITS);

    const instruction = try ic.deserializeInstruction(allocator, Instruction);
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .CreateLookupTable => |args| try createLookupTable(ic, args.recent_slot, args.bump_seed),
        .FreezeLookupTable => try freezeLookupTable(allocator, ic),
        .ExtendLookupTable => |args| try extendLookupTable(allocator, ic, args.new_addresses),
        .DeactivateLookupTable => try deactivateLookupTable(allocator, ic),
        .CloseLookupTable => try closeLookupTable(allocator, ic),
    };
}

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L46
/// Address lookup table metadata
const LookupTableMeta = struct {
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

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L133-L134
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    addresses: []const Pubkey,
};

const relax_authority_signer_check_for_lookup_table_creation = Pubkey.parseBase58String(
    "relax_authority_signer_check_for_lookup_table_creation",
) catch unreachable;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L51
fn createLookupTable(
    ic: *InstructionContext,
    untrusted_recent_slot: Slot,
    bump_seed: u8,
) (error{OutOfMemory} | InstructionError)!void {
    const has_relax_authority_signer_check_for_lookup_table_creation =
        ic.tc.feature_set.active.contains(relax_authority_signer_check_for_lookup_table_creation);

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L59
    const lookup_table_lamports, const table_key, const lookup_table_owner = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!has_relax_authority_signer_check_for_lookup_table_creation and
            lookup_table_account.getData().len > 0)
        {
            ic.tc.log("Table account must not be allocated", .{});
            return error.AccountAlreadyInitialized;
        }

        break :blk .{
            lookup_table_account.account.lamports,
            lookup_table_account.pubkey,
            lookup_table_account.account.owner,
        };
    };

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L74
    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(1);
        defer authority_account.release();

        if (!has_relax_authority_signer_check_for_lookup_table_creation and
            !authority_account.borrow_context.is_signer)
        {
            ic.tc.log("Authority account must be a signer");
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L87
    const payer_key = blk: {
        const payer_account = try ic.borrowInstructionAccount(2);
        defer payer_account.release();

        if (!payer_account.borrow_context.is_signer) {
            ic.tc.log("Payer account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk payer_account.pubkey;
    };

    const derivation_slot = blk: {
        const slot_hashes = ic.tc.sysvar_cache.get(sysvar.SlotHashes) orelse
            return error.UnsupportedSysvar;

        break :blk slot_hashes.get(untrusted_recent_slot) orelse {
            ic.tc.log("{} is not a recent slot", .{untrusted_recent_slot});
            return error.InvalidInstructionIndex;
        };
    };

    const derived_table_key = try sig.runtime.pubkey_utils.createProgramAddress(
        &.{
            &authority_key.data,
            std.mem.asBytes(&std.mem.nativeToLittle(Slot, derivation_slot)),
        },
        bump_seed,
        ID,
    );

    if (table_key != derived_table_key) {
        ic.tc.log("Table address must mach derived address: {}", .{derived_table_key});
        return error.InvalidArgument;
    }

    if (has_relax_authority_signer_check_for_lookup_table_creation and lookup_table_owner == ID) {
        return; // success
    }

    const rent = ic.tc.sysvar_cache.get(sysvar.Rent) orelse return error.UnsupportedSysvar;
    const required_lamports = @max(
        rent.minimumBalance(LOOKUP_TABLE_META_SIZE),
        1,
    ) -| lookup_table_lamports;

    if (required_lamports > 0) {
        // TODO: CPI
        // invoke_context.native_invoke(
        //     system_instruction::transfer(&payer_key, &table_key, required_lamports).into(),
        //     &[payer_key],
        // )?;
        _ = payer_key;
    }

    // TODO: CPI
    // invoke_context.native_invoke(
    //     system_instruction::allocate(&table_key, table_account_data_len as u64).into(),
    //     &[table_key],
    // )?;
    // invoke_context.native_invoke(
    //     system_instruction::assign(&table_key, &id()).into(),
    //     &[table_key],
    // )?;

    {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        // TODO: set_state
        //         lookup_table_account.set_state(&ProgramState::LookupTable(LookupTableMeta::new(
        //     authority_key,
        // )))?;
    }

    // success
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L173
fn freezeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    _ = allocator;
    _ = ic;
    @panic("TODO");
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L224
fn extendLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    new_addresses: []const Pubkey,
) !void {
    _ = allocator;
    _ = ic;
    _ = new_addresses;
    @panic("TODO");
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L343
fn deactivateLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    _ = allocator;
    _ = ic;
    @panic("TODO");
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L392
fn closeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    _ = allocator;
    _ = ic;
    @panic("TODO");
}
