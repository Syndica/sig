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

const program = @import("lib.zig");

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L25
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    // agave: consumed in declare_process_instruction
    try ic.tc.consumeCompute(system_program.COMPUTE_UNITS);

    const instruction = try ic.info.deserializeInstruction(allocator, program.Instruction);
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .CreateLookupTable => |args| try createLookupTable(
            allocator,
            ic,
            args.recent_slot,
            args.bump_seed,
        ),
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

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L51
fn createLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    untrusted_recent_slot: Slot,
    bump_seed: u8,
) (error{OutOfMemory} || InstructionError)!void {
    const has_relax_authority_signer_check_for_lookup_table_creation =
        ic.tc.feature_set.active.contains(program.relax_authority_signer_check_for_lookup_table_creation);

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L59
    const lookup_table_lamports, const table_key: Pubkey, const lookup_table_owner: Pubkey = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!has_relax_authority_signer_check_for_lookup_table_creation and
            lookup_table_account.account.data.len > 0)
        {
            try ic.tc.log("Table account must not be allocated", .{});
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
            !authority_account.context.is_signer)
        {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L87
    const payer_key = blk: {
        const payer_account = try ic.borrowInstructionAccount(2);
        defer payer_account.release();

        if (!payer_account.context.is_signer) {
            try ic.tc.log("Payer account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk payer_account.pubkey;
    };

    const derivation_slot = blk: {
        const slot_hashes = ic.tc.sysvar_cache.get(sysvar.SlotHashes) orelse
            return error.UnsupportedSysvar;

        if (slot_hashes.get(untrusted_recent_slot)) |_| {
            break :blk untrusted_recent_slot;
        } else {
            try ic.tc.log("{} is not a recent slot", .{untrusted_recent_slot});
            return error.InvalidInstructionData;
        }
    };

    const derived_table_key = sig.runtime.pubkey_utils.createProgramAddress(
        &.{
            &authority_key.data,
            std.mem.asBytes(&std.mem.nativeToLittle(Slot, derivation_slot)),
        },
        &.{bump_seed},
        program.ID,
    ) catch @panic("todo: error handling");

    if (!table_key.equals(&derived_table_key)) {
        try ic.tc.log("Table address must mach derived address: {}", .{derived_table_key});
        return error.InvalidArgument;
    }

    if (has_relax_authority_signer_check_for_lookup_table_creation and
        lookup_table_owner.equals(&program.ID))
    {
        return; // success
    }

    const rent = ic.tc.sysvar_cache.get(sysvar.Rent) orelse return error.UnsupportedSysvar;
    const required_lamports = @max(
        rent.minimumBalance(program.LOOKUP_TABLE_META_SIZE),
        1,
    ) -| lookup_table_lamports;

    if (required_lamports > 0) {
        // const transfer_instruction = system_program.Instruction{
        //     .transfer = .{ .lamports = required_lamports },
        // };

        // sig.runtime.executor.executeNativeCpiInstruction(
        //     allocator,
        //     ic.tc,
        //     transfer_instruction,
        //     &.{&payer_key},
        // );

        _ = payer_key;
        _ = allocator;
        @panic("TODO");
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
