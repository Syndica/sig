const std = @import("std");
const sig = @import("../../../sig.zig");

const InstructionContext = sig.runtime.InstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const system_program = sig.runtime.program.system_program;
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

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L125
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

// https://github.com/anza-xyz/agave/blob/a00f1b5cdea9a7d5a70f8d24b86ea3ae66feff11/sdk/slot-hashes/src/lib.rs#L21
pub const MAX_ENTRIES: usize = 512; // about 2.5 minutes to get your vote in

const Deactivating = struct { remaining_blocks: usize };

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L46
// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L66
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

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L133-L134
pub const AddressLookupTable = struct {
    meta: LookupTableMeta,
    addresses: []const Pubkey,
    pub fn overwriteMetaData(
        data: []u8,
        meta: LookupTableMeta,
    ) InstructionError!void {
        if (data.len < program.LOOKUP_TABLE_META_SIZE) return error.InvalidAccountData;
        const metadata = data[0..program.LOOKUP_TABLE_META_SIZE];
        @memset(metadata, 0);
        _ = sig.bincode.writeToSlice(metadata, &ProgramState{ .LookupTable = meta }, .{}) catch
            return error.GenericError;
    }
};

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L51
fn createLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    untrusted_recent_slot: Slot,
    bump_seed: u8,
) (error{OutOfMemory} || InstructionError)!void {
    const has_relax_authority_signer_check_for_lookup_table_creation =
        ic.tc.feature_set.active.contains(
        program.relax_authority_signer_check_for_lookup_table_creation,
    );

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
    ) catch @panic("TODO: how do PubkeyErrors coerce to InstructionErrors in agave?");

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

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L145
    if (required_lamports > 0) {
        const transfer_instruction = try system_program.transfer(
            allocator,
            payer_key,
            table_key,
            required_lamports,
        );
        defer allocator.free(transfer_instruction.data);
        try sig.runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            transfer_instruction,
            &.{payer_key},
        );
    }

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L152
    {
        const allocate_instruction = try system_program.allocate(
            allocator,
            table_key,
            program.LOOKUP_TABLE_META_SIZE,
        );
        defer allocator.free(allocate_instruction.data);
        try sig.runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            allocate_instruction,
            &.{table_key},
        );
    }

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L157
    {
        const assign_instruction = try system_program.assign(allocator, table_key, program.ID);
        defer allocator.free(assign_instruction.data);
        try sig.runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            assign_instruction,
            &.{table_key},
        );
    }

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L164
    {
        var lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        const new_state: ProgramState = .{
            .LookupTable = LookupTableMeta.new(authority_key),
        };
        try lookup_table_account.serializeIntoAccountData(new_state);
    }
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L173
fn freezeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L177-L182
    {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L184-L191
    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(1);
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    const lookup_table_account = try ic.borrowInstructionAccount(0);
    defer lookup_table_account.release();

    if (!lookup_table_account.account.owner.equals(&program.ID)) {
        return error.InvalidAccountOwner;
    }

    const lookup_table = try lookup_table_account.deserializeFromAccountData(
        allocator,
        AddressLookupTable,
    );
    defer sig.bincode.free(allocator, lookup_table);

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

    // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L214
    var lookup_table_meta = lookup_table.meta;
    lookup_table_meta.authority = null;
    try AddressLookupTable.overwriteMetaData(lookup_table_account.account.data, lookup_table_meta);
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L224
fn extendLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    new_addresses: []const Pubkey,
) !void {
    const table_key = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
        break :blk lookup_table_account.pubkey;
    };

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(1);
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

        var lookup_table = try lookup_table_account.deserializeFromAccountData(
            allocator,
            AddressLookupTable,
        );
        defer sig.bincode.free(allocator, lookup_table);

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

        if (lookup_table.addresses.len >= program.LOOKUP_TABLE_MAX_ADDRESSES) {
            try ic.tc.log("Lookup table is full and cannot contain more addresses", .{});
            return error.InvalidArgument;
        }

        if (new_addresses.len == 0) {
            try ic.tc.log("Must extend with at least one address", .{});
            return error.InvalidInstructionData;
        }

        const new_table_addresses_len = lookup_table.addresses.len +| new_addresses.len;
        if (new_table_addresses_len >= program.LOOKUP_TABLE_MAX_ADDRESSES) {
            try ic.tc.log(
                "Extended lookup table length {} would exceed max capacity of {}",
                .{ new_table_addresses_len, program.LOOKUP_TABLE_MAX_ADDRESSES },
            );
            return error.InvalidInstructionData;
        }

        const clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse return error.UnsupportedSysvar;
        if (clock.slot != lookup_table.meta.last_extended_slot) {
            lookup_table.meta.last_extended_slot = clock.slot;
            lookup_table.meta.last_extended_slot_start_index = std.math.cast(
                u8,
                lookup_table.addresses.len,
            ) orelse
                // This is impossible as long as the length of new_addresses
                // is non-zero and LOOKUP_TABLE_MAX_ADDRESSES == u8::MAX + 1.
                return error.InvalidAccountData;
        }

        const lookup_table_meta = lookup_table.meta;
        const new_table_data_len = std.math.add(
            usize,
            program.LOOKUP_TABLE_META_SIZE,
            new_table_addresses_len *| Pubkey.SIZE,
        ) catch return error.ArithmeticOverflow;

        // https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L307
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
            const lookup_mem = lookup_table_account.account.data[program.LOOKUP_TABLE_META_SIZE..];
            @memcpy(
                lookup_mem[i *| Pubkey.SIZE..][0..Pubkey.SIZE],
                std.mem.asBytes(&new_address),
            );
        }

        break :blk .{ lookup_table_account.account.lamports, new_table_data_len };
    };

    const rent = ic.tc.sysvar_cache.get(sysvar.Rent) orelse return error.UnsupportedSysvar;
    const required_lamports = @max(rent.minimumBalance(new_table_data_len), 1) -|
        lookup_table_lamports;

    if (required_lamports > 0) {
        const payer_key = blk: {
            const payer_account = try ic.borrowInstructionAccount(2);
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
        try sig.runtime.executor.executeNativeCpiInstruction(
            allocator,
            ic.tc,
            transfer_instruction,
            &.{payer_key},
        );
    }
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L343
fn deactivateLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(1);
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    const lookup_table_account = try ic.borrowInstructionAccount(0);
    defer lookup_table_account.release();

    const lookup_table = try lookup_table_account.deserializeFromAccountData(
        allocator,
        AddressLookupTable,
    );
    defer sig.bincode.free(allocator, lookup_table);

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

    const clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse return error.UnsupportedSysvar;

    var lookup_table_meta = lookup_table.meta;
    lookup_table_meta.deactivation_slot = clock.slot;

    try AddressLookupTable.overwriteMetaData(lookup_table_account.account.data, lookup_table_meta);
}

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L392
fn closeLookupTable(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }
    }

    const authority_key = blk: {
        const authority_account = try ic.borrowInstructionAccount(1);
        defer authority_account.release();

        if (!authority_account.context.is_signer) {
            try ic.tc.log("Authority account must be a signer", .{});
            return error.MissingRequiredSignature;
        }

        break :blk authority_account.pubkey;
    };

    try ic.info.checkNumberOfAccounts(3);

    if ((ic.info.getAccountMetaAtIndex(0) orelse return error.NotEnoughAccountKeys).pubkey.equals(
        &(ic.info.getAccountMetaAtIndex(2) orelse return error.NotEnoughAccountKeys).pubkey,
    )) {
        try ic.tc.log("Lookup table cannot be the recipient of reclaimed lamports", .{});
        return error.InvalidArgument;
    }

    const withdrawn_lamports = blk: {
        const lookup_table_account = try ic.borrowInstructionAccount(0);
        defer lookup_table_account.release();

        if (!lookup_table_account.account.owner.equals(&program.ID)) {
            return error.InvalidAccountOwner;
        }

        const lookup_table = try lookup_table_account.deserializeFromAccountData(
            allocator,
            AddressLookupTable,
        );
        defer sig.bincode.free(allocator, lookup_table);

        if (lookup_table.meta.authority) |authority| {
            if (!authority.equals(&authority_key)) {
                return error.IncorrectAuthority;
            }
        } else {
            try ic.tc.log("Lookup table is frozen", .{});
            return error.Immutable;
        }

        const clock = ic.tc.sysvar_cache.get(sysvar.Clock) orelse
            return error.UnsupportedSysvar;
        const slot_hashes = ic.tc.sysvar_cache.get(sysvar.SlotHashes) orelse
            return error.UnsupportedSysvar;

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
