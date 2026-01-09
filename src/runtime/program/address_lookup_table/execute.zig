const std = @import("std");
const tracy = @import("tracy");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");
const program = @import("lib.zig");

const state = program.state;
const instruction = program.instruction;

const Instruction = program.Instruction;
const InstructionContext = runtime.InstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;
const runtime = sig.runtime;
const Slot = sig.core.Slot;
const system_program = runtime.program.system;
const sysvar = runtime.sysvar;

const LOOKUP_TABLE_META_SIZE = state.LOOKUP_TABLE_META_SIZE;
const AddressLookupTable = state.AddressLookupTable;

pub const ID = program.ID;

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L25
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "address_lookup_table: execute" });
    defer zone.deinit();

    // agave: consumed in declare_process_instruction
    try ic.tc.consumeCompute(program.COMPUTE_UNITS);

    const lookuptable_instruction = try ic.ixn_info.deserializeInstruction(
        allocator,
        Instruction,
    );
    defer sig.bincode.free(allocator, lookuptable_instruction);

    return switch (lookuptable_instruction) {
        .CreateLookupTable => |args| try createLookupTable(
            allocator,
            ic,
            args.recent_slot,
            args.bump_seed,
        ),
        .FreezeLookupTable => try freezeLookupTable(allocator, ic),
        .ExtendLookupTable => |args| try extendLookupTable(
            allocator,
            ic,
            args.new_addresses,
        ),
        .DeactivateLookupTable => try deactivateLookupTable(allocator, ic),
        .CloseLookupTable => try closeLookupTable(allocator, ic),
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L51
fn createLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    untrusted_recent_slot: Slot,
    bump_seed: u8,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = instruction.CreateLookupTable.AccountIndex;

    const has_relax_authority_signer_check_for_lookup_table_creation = ic.tc.feature_set.active(
        .relax_authority_signer_check_for_lookup_table_creation,
        ic.tc.slot,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L59
    const lookup_table_lamports, const table_key: Pubkey, const lookup_table_owner: Pubkey = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
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

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L74
    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.authority_account),
        );
        defer authority_account.release();

        if (!has_relax_authority_signer_check_for_lookup_table_creation and
            !authority_account.context.is_signer)
        {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L87
    const payer_key = blk: {
        const payer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.payer_account),
        );
        defer payer_account.release();

        if (!payer_account.context.is_signer) {
            try ic.tc.log("Payer account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk payer_account.pubkey;
    };

    const derivation_slot = blk: {
        const slot_hashes = try ic.tc.sysvar_cache.get(sysvar.SlotHashes);

        if (slot_hashes.get(untrusted_recent_slot)) |_| {
            break :blk untrusted_recent_slot;
        } else {
            try ic.tc.log("{} is not a recent slot", .{untrusted_recent_slot});
            return error.InvalidInstructionData;
        }
    };

    const derived_table_key = runtime.pubkey_utils.createProgramAddress(
        &.{
            &authority_key.data,
            std.mem.asBytes(&std.mem.nativeToLittle(Slot, derivation_slot)),
        },
        &.{bump_seed},
        program.ID,
    ) catch |err| {
        ic.tc.custom_error = runtime.pubkey_utils.mapError(err);
        return error.Custom;
    };
    if (!table_key.equals(&derived_table_key)) {
        try ic.tc.log(
            "Table address must mach derived address: {}",
            .{derived_table_key},
        );
        return error.InvalidArgument;
    }

    if (has_relax_authority_signer_check_for_lookup_table_creation and
        lookup_table_owner.equals(&program.ID))
    {
        return; // success
    }

    const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
    const required_lamports = @max(
        rent.minimumBalance(LOOKUP_TABLE_META_SIZE),
        1,
    ) -| lookup_table_lamports;

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L145
    if (required_lamports > 0) {
        const transfer_instruction = try system_program.transfer(
            allocator,
            payer_key,
            table_key,
            required_lamports,
        );
        defer allocator.free(transfer_instruction.data);
        try runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            transfer_instruction,
            &.{payer_key},
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L152
    {
        const allocate_instruction = try system_program.allocate(
            allocator,
            table_key,
            LOOKUP_TABLE_META_SIZE,
        );
        defer allocator.free(allocate_instruction.data);
        try runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            allocate_instruction,
            &.{table_key},
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L157
    {
        const assign_instruction = try system_program.assign(allocator, table_key, program.ID);
        defer allocator.free(assign_instruction.data);
        try runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            assign_instruction,
            &.{table_key},
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L164
    {
        var lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        const new_state: state.ProgramState = .{
            .LookupTable = state.LookupTableMeta.new(authority_key),
        };
        try lookup_table_account.serializeIntoAccountData(new_state);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L173
fn freezeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    _ = allocator; // autofix
    const AccountIndex = instruction.FreezeLookupTable.AccountIndex;

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L177-L182
    {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L184-L191
    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.authority_account),
        );
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    const lookup_table_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.lookup_table_account),
    );
    defer lookup_table_account.release();

    const lookup_table = try AddressLookupTable.deserialize(
        lookup_table_account.account.data,
    );

    if (lookup_table.meta.authority) |authority| {
        if (!authority.equals(&authority_key)) {
            return error.IncorrectAuthority;
        }
    } else {
        try ic.tc.log("Lookup table is already frozen", .{});
        return error.Immutable;
    }

    if (lookup_table.meta.deactivation_slot != std.math.maxInt(Slot)) {
        try ic.tc.log("Deactivated tables cannnot be frozen", .{});
        return error.InvalidArgument;
    }

    if (lookup_table.addresses.len == 0) {
        try ic.tc.log("Empty lookup tables cannot be frozen", .{});
        return error.InvalidInstructionData;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L214
    var lookup_table_meta = lookup_table.meta;
    lookup_table_meta.authority = null;
    try AddressLookupTable.overwriteMetaData(lookup_table_account.account.data, lookup_table_meta);
}

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L224
fn extendLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    new_addresses: []const Pubkey,
) !void {
    const AccountIndex = instruction.ExtendLookupTable.AccountIndex;

    const table_key = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
        break :blk lookup_table_account.pubkey;
    };

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.authority_account),
        );
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    const lookup_table_lamports, const new_table_data_len = blk: {
        var lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        var lookup_table = try AddressLookupTable.deserialize(
            lookup_table_account.account.data,
        );

        if (lookup_table.meta.authority) |authority| {
            if (!authority.equals(&authority_key)) {
                return error.IncorrectAuthority;
            }
        } else {
            return error.Immutable;
        }

        if (lookup_table.meta.deactivation_slot != std.math.maxInt(Slot)) {
            try ic.tc.log("Deactivated tables cannot be extended", .{});
            return error.InvalidArgument;
        }

        if (lookup_table.addresses.len >= state.LOOKUP_TABLE_MAX_ADDRESSES) {
            try ic.tc.log(
                "Lookup table is full and cannot contain more addresses",
                .{},
            );
            return error.InvalidArgument;
        }

        if (new_addresses.len == 0) {
            try ic.tc.log("Must extend with at least one address", .{});
            return error.InvalidInstructionData;
        }

        const new_table_addresses_len = lookup_table.addresses.len +| new_addresses.len;
        if (new_table_addresses_len >= state.LOOKUP_TABLE_MAX_ADDRESSES) {
            try ic.tc.log(
                "Extended lookup table length {} would exceed max capacity of {}",
                .{ new_table_addresses_len, state.LOOKUP_TABLE_MAX_ADDRESSES },
            );
            return error.InvalidInstructionData;
        }

        const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
        if (clock.slot != lookup_table.meta.last_extended_slot) {
            lookup_table.meta.last_extended_slot = clock.slot;
            lookup_table.meta.last_extended_slot_start_index = std.math.cast(
                u8,
                lookup_table.addresses.len,
            ) orelse
                // This is impossible as long as the length of new_addresses
                // is non-zero and state.LOOKUP_TABLE_MAX_ADDRESSES == u8::MAX + 1.
                return error.InvalidAccountData;
        }

        const lookup_table_meta = lookup_table.meta;
        const new_table_data_len = std.math.add(
            usize,
            LOOKUP_TABLE_META_SIZE,
            new_table_addresses_len *| Pubkey.SIZE,
        ) catch return InstructionError.ProgramArithmeticOverflow;

        // [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L307
        try AddressLookupTable.overwriteMetaData(
            lookup_table_account.account.data,
            lookup_table_meta,
        );

        try lookup_table_account.setDataLength(
            allocator,
            &ic.tc.accounts_resize_delta,
            new_table_data_len,
        );

        for (new_addresses, 0..) |new_address, i| {
            const lookup_mem = lookup_table_account.account.data[LOOKUP_TABLE_META_SIZE..];
            @memcpy(
                lookup_mem[i *| Pubkey.SIZE..][0..Pubkey.SIZE],
                std.mem.asBytes(&new_address),
            );
        }

        break :blk .{ lookup_table_account.account.lamports, new_table_data_len };
    };

    const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
    const required_lamports = @max(rent.minimumBalance(new_table_data_len), 1) -|
        lookup_table_lamports;

    if (required_lamports > 0) {
        const payer_key = blk: {
            const payer_account = try ic.borrowInstructionAccount(
                @intFromEnum(AccountIndex.payer_account),
            );
            defer payer_account.release();

            if (!payer_account.context.is_signer) {
                try ic.tc.log("Payer account must be a signer", .{});
                return error.MissingRequiredSignature;
            }
            break :blk payer_account.pubkey;
        };

        const transfer_instruction = try system_program.transfer(
            allocator,
            payer_key,
            table_key,
            required_lamports,
        );
        defer allocator.free(transfer_instruction.data);
        try runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            transfer_instruction,
            &.{payer_key},
        );
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L343
fn deactivateLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    _ = allocator; // autofix
    const AccountIndex = instruction.DeactivateLookupTable.AccountIndex;

    {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.authority_account),
        );
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    const lookup_table_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.lookup_table_account),
    );
    defer lookup_table_account.release();

    const lookup_table = try AddressLookupTable.deserialize(
        lookup_table_account.account.data,
    );

    if (lookup_table.meta.authority) |authority| {
        if (!authority.equals(&authority_key)) {
            return error.IncorrectAuthority;
        }
    } else {
        try ic.tc.log("Lookup table is frozen", .{});
        return error.Immutable;
    }

    if (lookup_table.meta.deactivation_slot != std.math.maxInt(Slot)) {
        try ic.tc.log("Lookup tble is already deactivated", .{});
        return error.InvalidArgument;
    }

    const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

    var lookup_table_meta = lookup_table.meta;
    lookup_table_meta.deactivation_slot = clock.slot;

    try AddressLookupTable.overwriteMetaData(lookup_table_account.account.data, lookup_table_meta);
}

// [agave] https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L392
fn closeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    const AccountIndex = instruction.CloseLookupTable.AccountIndex;

    {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.authority_account),
        );
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    try ic.ixn_info.checkNumberOfAccounts(3);

    const lookup_table_meta = ic.ixn_info.getAccountMetaAtIndex(0) orelse
        return error.NotEnoughAccountKeys;
    const payer_meta = ic.ixn_info.getAccountMetaAtIndex(2) orelse
        return error.NotEnoughAccountKeys;

    if (lookup_table_meta.pubkey.equals(&payer_meta.pubkey)) {
        try ic.tc.log(
            "Lookup table cannot be the recipient of reclaimed lamports",
            .{},
        );
        return error.InvalidArgument;
    }

    const withdrawn_lamports = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.lookup_table_account),
        );
        defer lookup_table_account.release();

        const lookup_table = try AddressLookupTable.deserialize(
            lookup_table_account.account.data,
        );

        if (lookup_table.meta.authority) |authority| {
            if (!authority.equals(&authority_key)) {
                return error.IncorrectAuthority;
            }
        } else {
            try ic.tc.log("Lookup table is frozen", .{});
            return error.Immutable;
        }

        const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
        const slot_hashes = try ic.tc.sysvar_cache.get(sysvar.SlotHashes);

        switch (lookup_table.meta.status(clock.slot, slot_hashes)) {
            .Activated => {
                try ic.tc.log("Lookup table is not deactivated", .{});
                return error.InvalidArgument;
            },
            .Deactivating => |args| {
                try ic.tc.log(
                    "Table cannot be closed until it's fully deactivated in {} blocks",
                    .{args.remaining_blocks},
                );
                return error.InvalidArgument;
            },
            .Deactivated => {}, // ok
        }

        break :blk lookup_table_account.account.lamports;
    };

    {
        var recipient_account = try ic.borrowInstructionAccount(2);
        defer recipient_account.release();
        try recipient_account.addLamports(withdrawn_lamports);
    }

    var lookup_table_account = try ic.borrowInstructionAccount(0);
    defer lookup_table_account.release();

    try lookup_table_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, 0);
    try lookup_table_account.setLamports(0);
}

pub fn deriveLookupTableAddress(
    authority_address: Pubkey,
    recent_block_slot: Slot,
) struct { Pubkey, u8 } {
    if (!builtin.is_test) @compileError("deriveLookupTableAddress is currently used in tests only");

    return runtime.pubkey_utils.findProgramAddress(
        &.{
            std.mem.asBytes(&authority_address),
            std.mem.asBytes(&std.mem.nativeToLittle(Slot, recent_block_slot)),
        },
        program.ID,
    ).?;
}

test "address-lookup-table missing accounts" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const expectProgramExecuteError = sig.runtime.program.testing.expectProgramExecuteError;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const recent_slot = std.math.maxInt(Slot);

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{ .pubkey = lookup_table_address },
    };

    const instructions: []const Instruction = &.{
        .{ .CreateLookupTable = .{ .bump_seed = 0, .recent_slot = 0 } },
        .FreezeLookupTable,
        .CloseLookupTable,
        .DeactivateLookupTable,
        .{ .ExtendLookupTable = .{ .new_addresses = &.{Pubkey.ZEROES} } },
    };

    for (instructions) |instr| {
        try expectProgramExecuteError(
            error.CouldNotFindProgramAccount,
            std.testing.allocator,
            @This().ID,
            instr,
            &.{},
            .{ .accounts = accounts },
            .{},
        );
    }
}

test "address-lookup-table create" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const InstructionInfoAccountMetaParams = sig.runtime.testing.InstructionInfoAccountMetaParams;
    const expectProgramExecuteResult = sig.runtime.program.testing.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer = Pubkey.initRandom(prng.random());
    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );

    const before_lamports = 9999999999999;
    // table meta (56 bytes) stored for a year. cross-verified with real instructions
    const required_lamports = 1280640;
    const after_lamports = before_lamports - required_lamports;

    const before_compute_meter = 9999999;
    const expected_used_compute = program.COMPUTE_UNITS +
        runtime.program.system.COMPUTE_UNITS + // transfer
        runtime.program.system.COMPUTE_UNITS + // allocate
        runtime.program.system.COMPUTE_UNITS; //  assign

    // cross-verified with real instructions
    // note: real instructions also call SetComputeUnitLimit and SetComputeUnitPrice,
    // which cost 150 each, for a total of 1500.
    try std.testing.expectEqual(expected_used_compute, 1200);
    const after_compute_meter = before_compute_meter - expected_used_compute;

    const new_state: state.ProgramState = .{
        .LookupTable = state.LookupTableMeta.new(unsigned_authority_address),
    };
    const expected_state = try sig.bincode.writeAlloc(std.testing.allocator, new_state, .{});
    defer std.testing.allocator.free(expected_state);

    const accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = runtime.program.system.ID,
            .lamports = 0,
            .data = &.{},
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = before_lamports, .owner = system_program.ID },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const accounts_after: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = required_lamports,
            .data = expected_state,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = after_lamports, .owner = system_program.ID },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const InstructionInfoAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
    };

    const sysvar_cache: ExecuteContextsParams.SysvarCacheParams = .{
        .clock = .INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = .INIT,
    };

    try expectProgramExecuteResult(
        allocator,
        @This().ID,
        Instruction{
            .CreateLookupTable = .{ .bump_seed = bump_seed, .recent_slot = recent_slot },
        },
        meta,
        .{
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = accounts_after,
            .accounts_resize_delta = 56,
            .compute_meter = after_compute_meter,
        },
        .{},
    );
}

test "address-lookup-table freeze" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const InstructionInfoAccountMetaParams = sig.runtime.testing.InstructionInfoAccountMetaParams;
    const expectProgramExecuteResult = sig.runtime.program.testing.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: state.ProgramState = .{
        .LookupTable = state.LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const after_lookup_table = try allocator.dupe(u8, before_lookup_table);
    defer allocator.free(after_lookup_table);
    // set authority to null
    @memset(after_lookup_table[21..][0 .. @sizeOf(Pubkey) + 1], 0);

    const accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 0,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 0,
            .data = after_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const InstructionInfoAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
    };

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
    };

    const expected_used_compute = program.COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try expectProgramExecuteResult(
        allocator,
        @This().ID,
        Instruction.FreezeLookupTable,
        meta,
        .{
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = 0,
            .compute_meter = after_compute_meter,
        },
        .{},
    );
}

test "address-lookup-table close" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const InstructionInfoAccountMetaParams = sig.runtime.testing.InstructionInfoAccountMetaParams;
    const expectProgramExecuteResult = sig.runtime.program.testing.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());
    const payer = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: state.ProgramState = .{
        .LookupTable = state.LookupTableMeta{
            .authority = unsigned_authority_address,
            .deactivation_slot = 1,
        },
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 100,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 0 },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 0,
            .data = &.{},
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 100 },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const InstructionInfoAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
    };

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
    };

    const expected_used_compute = program.COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try expectProgramExecuteResult(
        allocator,
        @This().ID,
        Instruction.CloseLookupTable,
        meta,
        .{
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = -@as(i64, @intCast(before_lookup_table.len)),
            .compute_meter = after_compute_meter,
        },
        .{},
    );
}

test "address-lookup-table deactivate" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const InstructionInfoAccountMetaParams = sig.runtime.testing.InstructionInfoAccountMetaParams;
    const expectProgramExecuteResult = sig.runtime.program.testing.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: state.ProgramState = .{
        .LookupTable = state.LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const after_lookup_table = try allocator.dupe(u8, before_lookup_table);
    defer allocator.free(after_lookup_table);
    // set deactivation slot to zero (same as clock)
    @memset(after_lookup_table[4..][0..8], 0);

    const accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 0,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const ExecuteContextsParams.AccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = program.ID,
            .lamports = 0,
            .data = after_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = program.ID, .owner = runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = runtime.program.system.ID,
            .owner = runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const InstructionInfoAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
    };

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
    };

    const expected_used_compute = program.COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try expectProgramExecuteResult(
        allocator,
        @This().ID,
        Instruction.DeactivateLookupTable,
        meta,
        .{
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = 0,
            .compute_meter = after_compute_meter,
        },
        .{},
    );
}

test "address-lookup-table extend" {
    const ExecuteContextsParams = sig.runtime.testing.ExecuteContextsParams;
    const InstructionInfoAccountMetaParams = sig.runtime.testing.InstructionInfoAccountMetaParams;
    const expectProgramExecuteResult = sig.runtime.program.testing.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());
    const payer = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: state.ProgramState = .{
        .LookupTable = state.LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE);
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );

    const after_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(after_lookup_table);
    @memcpy(after_lookup_table[0..LOOKUP_TABLE_META_SIZE], before_lookup_table);
    @memcpy(after_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    // can be derived from required_lamports for create (1280640) (128 = account overhead)
    // (1280640/(128+56))*(128+56+32) = 1503360
    const required_lamports = 1503360;

    inline for (.{ true, false }) |payer_required| {
        const accounts: []const ExecuteContextsParams.AccountParams = &.{
            .{
                .pubkey = lookup_table_address,
                .owner = program.ID,
                .lamports = if (payer_required) 0 else required_lamports,
                .data = before_lookup_table,
            },
            .{ .pubkey = unsigned_authority_address },
            .{
                .pubkey = payer,
                .lamports = if (payer_required) required_lamports else 0,
                .owner = system_program.ID,
            },
            .{
                .pubkey = program.ID,
                .owner = runtime.ids.NATIVE_LOADER_ID,
                .executable = true,
            },
            .{
                .pubkey = runtime.program.system.ID,
                .owner = runtime.ids.NATIVE_LOADER_ID,
                .executable = true,
            },
        };

        const expected_accounts: []const ExecuteContextsParams.AccountParams = &.{
            .{
                .pubkey = lookup_table_address,
                .owner = program.ID,
                .lamports = required_lamports,
                .data = after_lookup_table,
            },
            .{ .pubkey = unsigned_authority_address },
            .{
                .pubkey = payer,
                .lamports = 0,
                .owner = system_program.ID,
            },
            .{
                .pubkey = program.ID,
                .owner = runtime.ids.NATIVE_LOADER_ID,
                .executable = true,
            },
            .{
                .pubkey = runtime.program.system.ID,
                .owner = runtime.ids.NATIVE_LOADER_ID,
                .executable = true,
            },
        };

        const meta: []const InstructionInfoAccountMetaParams = &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
        };

        const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
            .clock = runtime.sysvar.Clock.INIT,
            .slot_hashes = .initWithEntries(&.{.{
                .slot = std.math.maxInt(Slot),
                .hash = sig.core.Hash.ZEROES,
            }}),
            .rent = runtime.sysvar.Rent.INIT,
        };

        const expected_used_compute = program.COMPUTE_UNITS +
            if (payer_required) runtime.program.system.COMPUTE_UNITS else 0;

        const before_compute_meter = 9999999;
        const after_compute_meter = before_compute_meter - expected_used_compute;

        try expectProgramExecuteResult(
            allocator,
            @This().ID,
            Instruction{ .ExtendLookupTable = .{ .new_addresses = &.{first_address} } },
            meta,
            .{
                .accounts = accounts,
                .compute_meter = before_compute_meter,
                .sysvar_cache = sysvar_cache,
            },
            .{
                .accounts = expected_accounts,
                .accounts_resize_delta = 32,
                .compute_meter = after_compute_meter,
            },
            .{},
        );
    }
}
