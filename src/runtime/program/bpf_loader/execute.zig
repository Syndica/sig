const builtin = @import("builtin");
const std = @import("std");
const tracy = @import("tracy");
const std14 = @import("std14");
const sig = @import("../../../sig.zig");

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const vm = sig.vm;
const bpf_serialize = sig.runtime.program.bpf.serialize;
const system_program = sig.runtime.program.system;
const bpf_loader_program = sig.runtime.program.bpf_loader;
const stable_log = sig.runtime.stable_log;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const ExecutionError = sig.vm.ExecutionError;

const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const V3State = sig.runtime.program.bpf_loader.v3.State;
const V4State = sig.runtime.program.bpf_loader.v4.State;

// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/lib.rs#L399-L401
const migration_authority: Pubkey = .parse("3Scf35jMNk2xXBD6areNjgMtXgp5ZspDhms8vdcbzC42");

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "bpf_loader: execute" });
    defer zone.deinit();

    // The borrowed program cannot be held during calls to other execute functions.
    // Agave originally drops it at the relevant sites, but we can just extract needed fields here.
    const program_owner = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        break :blk program_account.account.owner;
    };
    const program_id = &ic.ixn_info.program_meta.pubkey;

    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/programs/loader-v4/src/lib.rs
    // NOTE: The feature gate is already checked before we enter this function in `processNextInstruction`.
    if (bpf_loader_program.v4.ID.equals(program_id)) {
        try ic.tc.consumeCompute(bpf_loader_program.v4.COMPUTE_UNITS);
        return executeBpfLoaderV4ProgramInstruction(allocator, ic);
    } else if (ids.NATIVE_LOADER_ID.equals(&program_owner)) {
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/programs/bpf_loader/src/lib.rs#L394-L417
        if (bpf_loader_program.v3.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v3.COMPUTE_UNITS);
            return executeBpfLoaderV3ProgramInstruction(allocator, ic);
        } else if (bpf_loader_program.v2.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v2.COMPUTE_UNITS);
            try ic.tc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v1.ID.equals(program_id)) {
            try ic.tc.consumeCompute(bpf_loader_program.v1.COMPUTE_UNITS);
            try ic.tc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else {
            try ic.tc.log("Invalid BPF loader id", .{});
            return InstructionError.UnsupportedProgramId;
        }
    }

    // NOTE: We double borrow the program account within `executeBpfProgram`, which adds an
    // additional borrow relative to Agave. This difference should not cause any issues, but is worth noting.
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L458-L518
    executeBpfProgram(allocator, ic) catch |err| {
        const kind = sig.vm.getExecutionErrorKind(err);
        if (kind != .Instruction) {
            try stable_log.programFailure(
                ic.tc,
                ic.ixn_info.program_meta.pubkey,
                err,
            );
            return InstructionError.ProgramFailedToComplete;
        } else {
            return sig.vm.instructionErrorFromExecutionError(err);
        }
    };
}

fn executeBpfProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) ExecutionError!void {
    const executable = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();
        const program_key = program_account.pubkey;

        const loaded_program = ic.tc.program_map.get(program_key) orelse {
            try ic.tc.log("Program is not cached", .{});
            return InstructionError.UnsupportedProgramId;
        };
        switch (loaded_program) {
            .failed => {
                // For the `builtin` case in Agave, they skip the log message
                // and only return `UnsupportedProgramId`. We can emulate the
                // `builtin` program map entry by simply checking if the pubkey
                // is a "builtin program".
                if (program.NATIVE.get(&program_key) == null) {
                    try ic.tc.log("Program is not deployed", .{});
                }
                return InstructionError.UnsupportedProgramId;
            },
            .loaded => |entry| break :blk entry.executable,
        }
    };

    const account_data_direct_mapping = ic.tc.feature_set.active(
        .account_data_direct_mapping,
        ic.tc.slot,
    );
    const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        ic.tc.slot,
    );
    const mask_out_rent_epoch_in_vm_serialization = ic.tc.feature_set.active(
        .mask_out_rent_epoch_in_vm_serialization,
        ic.tc.slot,
    );
    const provide_instruction_data_offset = ic.tc.feature_set.active(
        .provide_instruction_data_offset_in_vm_r2,
        ic.tc.slot,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    var serialized = try bpf_serialize.serializeParameters(
        allocator,
        ic,
        account_data_direct_mapping,
        stricter_abi_and_runtime_constraints,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer serialized.deinit(allocator);

    // TODO: this is a heavy copy, can we avoid doing it?
    // [agave] https://github.com/anza-xyz/agave/blob/v3.0/programs/bpf_loader/src/lib.rs#L275
    const old_accounts = ic.tc.serialized_accounts;
    ic.tc.serialized_accounts = serialized.account_metas;
    defer ic.tc.serialized_accounts = old_accounts;

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1604-L1617
    // TODO: save account addresses for access violation errors resolution

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1621-L1640
    const compute_available = ic.tc.compute_meter;
    const result, const compute_consumed = blk: {
        var state = sig.vm.init(
            allocator,
            ic.tc,
            &executable,
            serialized.regions.items,
            &ic.tc.vm_environment.loader,
            if (provide_instruction_data_offset) serialized.instruction_data_offset else 0,
        ) catch |err| {
            try ic.tc.log("Failed to create SBPF VM: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer state.deinit(allocator);

        // Run our bpf program!
        const result = state.vm.run();

        break :blk result;
    };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1641-L1644
    // TODO: timings

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1646-L1653
    try ic.tc.log("Program {f} consumed {} of {} compute units", .{
        ic.ixn_info.program_meta.pubkey,
        compute_consumed,
        compute_available,
    });

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1653-L1657
    if (ic.tc.return_data.data.len != 0) {
        try stable_log.programReturn(
            ic.tc,
            ic.ixn_info.program_meta.pubkey,
            ic.tc.return_data.data.constSlice(),
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1658-L1731
    var maybe_execute_error: ?ExecutionError = handleExecutionResult(
        result,
        &ic.tc.custom_error,
        &ic.tc.compute_meter,
        stricter_abi_and_runtime_constraints,
        ic.tc.feature_set.active(.deplete_cu_meter_on_vm_failure, ic.tc.slot),
    );

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1750-L1756
    if (maybe_execute_error == null)
        bpf_serialize.deserializeParameters(
            allocator,
            ic,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
            serialized.memory.items,
            serialized.account_metas.constSlice(),
        ) catch |err| {
            maybe_execute_error = err;
        };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1757-L1761
    // TODO: update timings

    if (maybe_execute_error) |err| return err;
}

fn handleExecutionResult(
    result: sig.vm.interpreter.Result,
    custom_error: *?u32,
    compute_meter: *u64,
    stricter_abi_and_runtime_constraints: bool,
    deplete_cu_meter: bool,
) ?ExecutionError {
    switch (result) {
        .ok => |status| if (status != 0) {
            switch (sig.vm.executionErrorFromStatusCode(status)) {
                error.Custom => custom_error.* = @intCast(status),
                error.GenericError => custom_error.* = 0,
                else => |err| return err,
            }
            return error.Custom;
        },
        .err => |err| {
            const err_kind = sig.vm.getExecutionErrorKind(err);
            if (deplete_cu_meter and err_kind != .Syscall)
                compute_meter.* = 0;
            if (stricter_abi_and_runtime_constraints and err == error.AccessViolation)
                std.debug.print("TODO: Handle AccessViolation: {s}\n", .{@errorName(err)});
            return err;
        },
    }
    return null;
}

// [agave] https://github.com/anza-xyz/agave/blob/v3.0/programs/loader-v4/src/lib.rs#L88
pub fn executeBpfLoaderV4ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    var buf: [sig.net.Packet.DATA_SIZE]u8 = undefined;
    const instruction = try ic.ixn_info.limitedDeserializeInstruction(
        bpf_loader_program.v4.Instruction,
        &buf,
    );
    return switch (instruction) {
        .write => |args| executeV4Write(
            allocator,
            ic,
            args.offset,
            args.bytes,
        ),
        .copy => |args| executeV4Copy(
            allocator,
            ic,
            args.destination_offset,
            args.source_offset,
            args.length,
        ),
        .set_program_length => |args| executeV4SetProgramLength(
            allocator,
            ic,
            args.new_size,
        ),
        .deploy => executeV4Deploy(allocator, ic),
        .retract => executeV4Retract(allocator, ic),
        .transfer_authority => executeV4TransferAuthority(allocator, ic),
        .finalize => executeV4Finalize(allocator, ic),
    };
}

fn checkProgramAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    program_account: *const sig.runtime.BorrowedAccount,
    authority_address: Pubkey,
) (error{OutOfMemory} || InstructionError)!V4State {
    if (!program_account.account.owner.equals(&bpf_loader_program.v4.ID)) {
        try ic.tc.log("Program not owned by loader", .{});
        return error.InvalidAccountOwner;
    }

    const state = try program_account.deserializeFromAccountData(allocator, V4State);
    errdefer bincode.free(allocator, state);

    if (!program_account.context.is_writable) {
        try ic.tc.log("Program is not writeable", .{});
        return error.InvalidArgument;
    }
    if (!(try ic.ixn_info.isIndexSigner(1))) {
        try ic.tc.log("Authority did not sign", .{});
        return error.MissingRequiredSignature;
    }
    if (!state.authority_address_or_next_version.equals(&authority_address)) {
        try ic.tc.log("Incorrect authority provided", .{});
        return error.IncorrectAuthority;
    }
    if (state.status == .finalized) {
        try ic.tc.log("Program is finalized", .{});
        return error.Immutable;
    }

    return state;
}

pub fn executeV4Write(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    offset: u32,
    bytes: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.Write.AccountIndex;
    const program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();

    const authority_meta = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.authority),
    ) orelse return error.MissingAccount;

    const state = try checkProgramAccount(allocator, ic, &program_account, authority_meta.pubkey);
    defer bincode.free(allocator, state);

    if (state.status != .retracted) {
        try ic.tc.log("Program is not retracted", .{});
        return error.InvalidArgument;
    }

    const dst_offset = @as(usize, offset) +| V4State.PROGRAM_DATA_METADATA_SIZE;
    const data = try program_account.mutableAccountData();
    if (dst_offset +| bytes.len > data.len) {
        try ic.tc.log("Write out of bounds", .{});
        return error.AccountDataTooSmall;
    }

    @memcpy(data[dst_offset..][0..bytes.len], bytes);
}

pub fn executeV4Copy(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    dst_offset: u32,
    src_offset: u32,
    length: u32,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.Copy.AccountIndex;
    const dst_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.dst_account));
    defer dst_account.release();

    const authority_meta = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.authority),
    ) orelse return error.MissingAccount;

    const src_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.src_account));
    defer src_account.release();

    const state = try checkProgramAccount(allocator, ic, &dst_account, authority_meta.pubkey);
    defer bincode.free(allocator, state);

    if (state.status != .retracted) {
        try ic.tc.log("Program is not retracted", .{});
        return error.InvalidArgument;
    }

    const source_owner = src_account.account.owner;
    const source_offset = @as(usize, src_offset) +|
        (if (bpf_loader_program.v4.ID.equals(&source_owner))
            V4State.PROGRAM_DATA_METADATA_SIZE
        else if (bpf_loader_program.v3.ID.equals(&source_owner))
            bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE
        else if (bpf_loader_program.v2.ID.equals(&source_owner) or
            bpf_loader_program.v1.ID.equals(&source_owner))
            0
        else {
            try ic.tc.log("Source is not a program", .{});
            return error.InvalidArgument;
        });

    const source_data = src_account.constAccountData();
    if (source_offset +| length > source_data.len) {
        try ic.tc.log("Read out of bounds", .{});
        return error.AccountDataTooSmall;
    }

    const offset = @as(usize, dst_offset) +| V4State.PROGRAM_DATA_METADATA_SIZE;
    const data = try dst_account.mutableAccountData();
    if (offset +| length > data.len) {
        try ic.tc.log("Write out of bounds", .{});
        return error.AccountDataTooSmall;
    }

    @memcpy(data[offset..][0..length], source_data[source_offset..][0..length]);
}

pub fn executeV4SetProgramLength(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    new_size: u32,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.SetProgramLength.AccountIndex;
    var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();

    const authority_address = blk: {
        const meta = ic.ixn_info.getAccountMetaAtIndex(@intFromEnum(AccountIndex.authority)) orelse
            return InstructionError.MissingAccount;
        const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;
        break :blk txn_account.pubkey;
    };

    const is_initialization = program_account.constAccountData().len < @sizeOf(V4State);
    if (is_initialization) {
        if (!program_account.account.owner.equals(&bpf_loader_program.v4.ID)) {
            try ic.tc.log("Program not owned by loader", .{});
            return InstructionError.InvalidAccountOwner;
        }
        if (!program_account.context.is_writable) {
            try ic.tc.log("Program is not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
            try ic.tc.log("Authority did not sign", .{});
            return InstructionError.MissingRequiredSignature;
        }
    } else {
        const state = try checkProgramAccount(allocator, ic, &program_account, authority_address);
        defer bincode.free(allocator, state);

        if (state.status != .retracted) {
            try ic.tc.log("Program is not retracted", .{});
            return InstructionError.InvalidArgument;
        }
    }

    const required_lamports = if (new_size == 0) 0 else blk: {
        const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
        break :blk rent.minimumBalance(
            @as(usize, new_size) +| @sizeOf(V4State),
        );
    };

    switch (std.math.order(program_account.account.lamports, required_lamports)) {
        .eq => {},
        .lt => {
            try ic.tc.log("Insufficient lamports, {} are required", .{required_lamports});
            return InstructionError.InsufficientFunds;
        },
        .gt => {
            if (ic.borrowInstructionAccount(@intFromEnum(AccountIndex.recipient))) |*recipient| {
                defer recipient.release();
                if (!recipient.context.is_writable) {
                    try ic.tc.log("Recipient is not writeable", .{});
                    return InstructionError.InvalidArgument;
                }
                const lamports_to_recv = program_account.account.lamports -| required_lamports;
                try program_account.subtractLamports(lamports_to_recv);
                try recipient.addLamports(lamports_to_recv);
            } else |_| {
                if (new_size == 0) {
                    try ic.tc.log("Closing a program requires a recipient account", .{});
                    return InstructionError.InvalidArgument;
                }
            }
        },
    }

    if (new_size == 0) {
        try program_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, 0);
    } else {
        try program_account.setDataLength(
            allocator,
            &ic.tc.accounts_resize_delta,
            @as(usize, new_size) +| @sizeOf(V4State),
        );
        if (is_initialization) {
            try program_account.setExecutable(true, ic.tc.rent);
            try program_account.serializeIntoAccountData(V4State{
                .slot = 0,
                .status = .retracted,
                .authority_address_or_next_version = authority_address,
            });
        }
    }
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/vote-interface%40v3.0.0/loader-v4-interface/src/lib.rs#L11
const DEPLOYMENT_COOLDOWN_IN_SLOTS = 1;

pub fn executeV4Deploy(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.Deploy.AccountIndex;
    var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();

    const authority_address = blk: {
        const meta = ic.ixn_info.getAccountMetaAtIndex(@intFromEnum(AccountIndex.authority)) orelse
            return InstructionError.MissingAccount;
        const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;
        break :blk txn_account.pubkey;
    };

    const state = try checkProgramAccount(allocator, ic, &program_account, authority_address);
    defer bincode.free(allocator, state);

    const current_slot = (try ic.tc.sysvar_cache.get(sysvar.Clock)).slot;

    // Slot = 0 indicates program wasn't deployed yet, so need to check for cooldown slots.
    // Without this check, freshly started validators with slot = 0 can't deploy.
    if (state.slot != 0 and state.slot +| DEPLOYMENT_COOLDOWN_IN_SLOTS > current_slot) {
        try ic.tc.log("Program was deployed recently, cooldown still in effect", .{});
        return InstructionError.InvalidArgument;
    }
    if (state.status != .retracted) {
        try ic.tc.log("Destination program is not retracted", .{});
        return InstructionError.InvalidArgument;
    }

    const program_data =
        if (program_account.constAccountData().len < @sizeOf(V4State)) {
            return InstructionError.AccountDataTooSmall;
        } else program_account.constAccountData()[@sizeOf(V4State)..];

    try deployProgram(
        allocator,
        ic.tc,
        program_account.pubkey,
        bpf_loader_program.v4.ID,
        program_data,
        current_slot,
    );

    try program_account.serializeIntoAccountData(V4State{
        .slot = current_slot,
        .status = .deployed,
        .authority_address_or_next_version = state.authority_address_or_next_version,
    });
}

pub fn executeV4Retract(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.Retract.AccountIndex;
    var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();

    const authority_address = blk: {
        const meta = ic.ixn_info.getAccountMetaAtIndex(@intFromEnum(AccountIndex.authority)) orelse
            return InstructionError.MissingAccount;
        const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;
        break :blk txn_account.pubkey;
    };

    const state = try checkProgramAccount(allocator, ic, &program_account, authority_address);
    defer bincode.free(allocator, state);

    const current_slot = (try ic.tc.sysvar_cache.get(sysvar.Clock)).slot;
    if (state.slot +| DEPLOYMENT_COOLDOWN_IN_SLOTS > current_slot) {
        try ic.tc.log("Program was deployed recently, cooldown still in effect", .{});
        return InstructionError.InvalidArgument;
    }
    if (state.status != .deployed) {
        try ic.tc.log("Program is not deployed", .{});
        return InstructionError.InvalidArgument;
    }

    try program_account.serializeIntoAccountData(V4State{
        .slot = state.slot,
        .status = .retracted,
        .authority_address_or_next_version = state.authority_address_or_next_version,
    });

    const old_program = try ic.tc.program_map.fetchPut(allocator, program_account.pubkey, .failed);
    if (old_program) |p| p.deinit(allocator);
}

pub fn executeV4TransferAuthority(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.TransferAuthority.AccountIndex;
    var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();

    const authority_address = blk: {
        const meta = ic.ixn_info.getAccountMetaAtIndex(
            @intFromEnum(AccountIndex.authority),
        ) orelse return InstructionError.MissingAccount;
        const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;
        break :blk txn_account.pubkey;
    };

    const new_authority_address = blk: {
        const meta = ic.ixn_info.getAccountMetaAtIndex(
            @intFromEnum(AccountIndex.new_authority),
        ) orelse return InstructionError.MissingAccount;
        const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;
        break :blk txn_account.pubkey;
    };

    const state = try checkProgramAccount(allocator, ic, &program_account, authority_address);
    defer bincode.free(allocator, state);

    if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.new_authority)))) {
        try ic.tc.log("New authority did not sign", .{});
        return InstructionError.MissingRequiredSignature;
    }
    if (state.authority_address_or_next_version.equals(&new_authority_address)) {
        try ic.tc.log("No change", .{});
        return InstructionError.InvalidArgument;
    }

    try program_account.serializeIntoAccountData(V4State{
        .slot = state.slot,
        .status = state.status,
        .authority_address_or_next_version = new_authority_address,
    });
}

pub fn executeV4Finalize(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v4.instruction.Finalize.AccountIndex;
    const authority_address, const state_slot = blk: {
        var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
        defer program_account.release();

        const authority_address = b: {
            const meta = ic.ixn_info.getAccountMetaAtIndex(
                @intFromEnum(AccountIndex.authority),
            ) orelse return InstructionError.MissingAccount;
            const txn_account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
                return InstructionError.MissingAccount;
            break :b txn_account.pubkey;
        };

        const state = try checkProgramAccount(allocator, ic, &program_account, authority_address);
        defer bincode.free(allocator, state);
        if (state.status != .deployed) {
            try ic.tc.log("Program must be deployed to be finalized", .{});
            return InstructionError.InvalidArgument;
        }

        break :blk .{ authority_address, state.slot };
    };

    const next_address = blk: {
        const next_version =
            try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.new_authority));
        defer next_version.release();
        if (!next_version.account.owner.equals(&bpf_loader_program.v4.ID)) {
            try ic.tc.log("Next version is not owned by loader", .{});
            return InstructionError.InvalidAccountOwner;
        }

        const next_state = try next_version.deserializeFromAccountData(allocator, V4State);
        defer bincode.free(allocator, next_state);

        if (!next_state.authority_address_or_next_version.equals(&authority_address)) {
            try ic.tc.log("Next version has a different authority", .{});
            return InstructionError.IncorrectAuthority;
        }
        if (next_state.status == .finalized) {
            try ic.tc.log("Next version is finalized", .{});
            return InstructionError.Immutable;
        }

        break :blk next_version.pubkey;
    };

    var program_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer program_account.release();
    try program_account.serializeIntoAccountData(V4State{
        .slot = state_slot,
        .status = .finalized,
        .authority_address_or_next_version = next_address,
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L486
pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    var buf: [sig.net.Packet.DATA_SIZE]u8 = undefined;
    const instruction = try ic.ixn_info.limitedDeserializeInstruction(
        bpf_loader_program.v3.Instruction,
        &buf,
    );

    return switch (instruction) {
        .initialize_buffer => executeV3InitializeBuffer(
            allocator,
            ic,
        ),
        .write => |args| executeV3Write(
            allocator,
            ic,
            args.offset,
            args.bytes,
        ),
        .deploy_with_max_data_len => |args| executeV3DeployWithMaxDataLen(
            allocator,
            ic,
            args.max_data_len,
        ),
        .upgrade => executeV3Upgrade(
            allocator,
            ic,
        ),
        .set_authority => executeV3SetAuthority(
            allocator,
            ic,
        ),
        .set_authority_checked => executeV3SetAuthorityChecked(
            allocator,
            ic,
        ),
        .close => executeV3Close(
            allocator,
            ic,
        ),
        .extend_program => |args| executeV3ExtendProgram(
            allocator,
            ic,
            args.additional_bytes,
        ),
        .extend_program_checked => |args| executeV3ExtendProgramChecked(
            allocator,
            ic,
            args.additional_bytes,
        ),
        .migrate => executeV3Migrate(
            allocator,
            ic,
        ),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L496-L513
pub fn executeV3InitializeBuffer(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.InitializeBuffer.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var buffer_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer buffer_account.release();
    const buffer_account_state = try buffer_account.deserializeFromAccountData(
        allocator,
        V3State,
    );

    if (buffer_account_state != V3State.uninitialized) {
        try ic.tc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    const authority_key = ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.authority));
    try buffer_account.serializeIntoAccountData(V3State{
        .buffer = .{
            .authority_address = authority_key,
        },
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L514-L545
pub fn executeV3Write(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    offset: u32,
    bytes: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Write.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var buffer_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer buffer_account.release();

    switch (try buffer_account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |state| {
            if (state.authority_address) |buffer_authority| {
                if (!buffer_authority.equals(
                    &ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.authority)),
                )) {
                    try ic.tc.log("Incorrect buffer authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }

                if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
                    try ic.tc.log("Buffer authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            } else {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
        },
        else => {
            try ic.tc.log("Invalid Buffer account", .{});
            return InstructionError.InvalidAccountData;
        },
    }

    const data = try buffer_account.mutableAccountData();
    const start = V3State.BUFFER_METADATA_SIZE +| @as(usize, offset);
    const end = start +| bytes.len;

    if (data.len < end) {
        try ic.tc.log("Write overflow: {} < {}", .{ bytes.len, end });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(data[start..end], bytes);
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L546-L720
pub fn executeV3DeployWithMaxDataLen(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    max_data_len: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.DeployWithMaxDataLen.AccountIndex;
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565
    try ic.ixn_info.checkNumberOfAccounts(4);

    // Safety: at least 4 accounts are present
    const payer_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.payer));
    const program_data_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program_data));

    const rent = try ic.getSysvarWithAccountCheck(
        sysvar.Rent,
        @intFromEnum(AccountIndex.rent),
    );
    const clock = try ic.getSysvarWithAccountCheck(
        sysvar.Clock,
        @intFromEnum(AccountIndex.clock),
    );

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L575
    try ic.ixn_info.checkNumberOfAccounts(8);

    // Safety: at least 8 accounts are present
    const authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.authority),
    );

    // Verify program account and retrieve its program id
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L582-L597
    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        const program_state =
            try program_account.deserializeFromAccountData(allocator, V3State);

        if (program_state != V3State.uninitialized) {
            try ic.tc.log("Program account already initialized", .{});
            return InstructionError.AccountAlreadyInitialized;
        }

        if (program_account.constAccountData().len < V3State.PROGRAM_SIZE) {
            try ic.tc.log("Program account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_account.account.lamports <
            rent.minimumBalance(program_account.constAccountData().len))
        {
            try ic.tc.log("Program account not rent-exempt", .{});
            return InstructionError.ExecutableAccountNotRentExempt;
        }

        break :blk program_account.pubkey;
    };

    // Verify buffer account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L601-L638
    const program_data_len = V3State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    {
        const buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        switch (try buffer_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .buffer => |state| {
                if (state.authority_address == null or
                    !state.authority_address.?.equals(&authority_key))
                {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }

                // Safety: at least 8 accounts are present
                if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        const buffer_data = buffer_account.constAccountData();
        if (buffer_data.len <= V3State.BUFFER_METADATA_SIZE) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.InvalidAccountData;
        }

        const buffer_data_len = buffer_data.len -| V3State.BUFFER_METADATA_SIZE;

        if (max_data_len < buffer_data_len) {
            try ic.tc.log("Max data length is too small to hold Buffer data", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_data_len > system_program.MAX_PERMITTED_DATA_LENGTH) {
            try ic.tc.log("Max data length is too large", .{});
            return InstructionError.InvalidArgument;
        }
    }

    // Create the ProgramData account key
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L640-L646
    const derived_key, const bump_seed = pubkey_utils.findProgramAddress(
        &.{&new_program_id.data},
        bpf_loader_program.v3.ID,
    ) orelse {
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/pubkey/src/lib.rs#L611-L612
        @panic("Unable to find viable program address bump seed");
    };

    if (!derived_key.equals(&program_data_key)) {
        try ic.tc.log("ProgramData address is not derived", .{});
        return InstructionError.InvalidArgument;
    }

    // Drain the Buffer account to payer before paying for program data account
    {
        var buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        var payer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.payer),
        );
        defer payer_account.release();

        try payer_account.addLamports(buffer_account.account.lamports);
        try buffer_account.setLamports(0);
    }

    // Create the ProgramData account
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L658-L680
    const signer_derived_key = pubkey_utils.createProgramAddress(
        &.{&new_program_id.data},
        &.{bump_seed},
        ic.ixn_info.program_meta.pubkey,
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };

    try ic.nativeInvoke(
        allocator,
        system_program.ID,
        system_program.Instruction{
            .create_account = .{
                .lamports = @max(1, rent.minimumBalance(program_data_len)),
                .space = program_data_len,
                .owner = ic.ixn_info.program_meta.pubkey,
            },
        },
        &.{
            .{ .pubkey = payer_key, .is_signer = true, .is_writable = true },
            .{ .pubkey = program_data_key, .is_signer = true, .is_writable = true },
            // pass an extra account to avoid the overly strict UnbalancedInstruction error
            // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L668-L669
            .{
                .pubkey = ic.getAccountKeyByIndexUnchecked(
                    @intFromEnum(AccountIndex.buffer),
                ),
                .is_signer = false,
                .is_writable = true,
            },
        },
        &.{signer_derived_key},
    );

    // Load and verify the program bits and deploy the program
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L683-L698
    {
        const buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        const buffer_data = buffer_account.constAccountData();
        if (buffer_data.len < V3State.BUFFER_METADATA_SIZE)
            return InstructionError.AccountDataTooSmall;

        try deployProgram(
            allocator,
            ic.tc,
            new_program_id,
            ic.ixn_info.program_meta.pubkey,
            buffer_data[V3State.BUFFER_METADATA_SIZE..],
            clock.slot,
        );
    }

    // Update the ProgramData account and record the program bits
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L704-L726
    {
        var program_data_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer program_data_account.release();
        try program_data_account.serializeIntoAccountData(V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = authority_key,
            },
        });
        const program_data = try program_data_account.mutableAccountData();

        var buffer_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer_account.release();

        const bytes_to_copy = buffer_account.constAccountData().len - V3State.BUFFER_METADATA_SIZE;

        @memcpy(
            program_data[V3State.PROGRAM_DATA_METADATA_SIZE..][0..bytes_to_copy],
            buffer_account.constAccountData()[V3State.BUFFER_METADATA_SIZE..][0..bytes_to_copy],
        );

        try buffer_account.setDataLength(
            allocator,
            &ic.tc.accounts_resize_delta,
            V3State.BUFFER_METADATA_SIZE,
        );
    }

    // Update the program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L729-735
    {
        var program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();
        try program_account.serializeIntoAccountData(V3State{ .program = .{
            .programdata_address = program_data_key,
        } });
        try program_account.setExecutable(
            true,
            ic.tc.rent,
        );
    }

    try ic.tc.log("Deployed program {f}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L705-L894
pub fn executeV3Upgrade(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Upgrade.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(3);

    const programdata_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program_data));

    const rent = try ic.getSysvarWithAccountCheck(
        sysvar.Rent,
        @intFromEnum(AccountIndex.rent),
    );
    const clock = try ic.getSysvarWithAccountCheck(
        sysvar.Clock,
        @intFromEnum(AccountIndex.clock),
    );

    try ic.ixn_info.checkNumberOfAccounts(7);
    const authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.authority),
    );

    // Verify program account

    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        if (!program_account.account.executable) {
            try ic.tc.log("Program account not executable", .{});
            return InstructionError.AccountNotExecutable;
        }
        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }
        switch (try program_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program => |data| {
                if (!data.programdata_address.equals(&programdata_key)) {
                    try ic.tc.log("Program and ProgramData account mismatch", .{});
                    return InstructionError.InvalidArgument;
                }
            },
            else => {
                try ic.tc.log("Invalid Program account", .{});
                return InstructionError.InvalidAccountData;
            },
        }
        break :blk program_account.pubkey;
    };

    // Verify buffer account

    const buf = blk: {
        const buffer = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.buffer));
        defer buffer.release();

        switch (try buffer.deserializeFromAccountData(allocator, V3State)) {
            .buffer => |data| {
                if (data.authority_address == null or
                    !data.authority_address.?.equals(&authority_key))
                {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.ixn_info.isIndexSigner(6))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        const buf = .{
            .lamports = buffer.account.lamports,
            .data_offset = V3State.BUFFER_METADATA_SIZE,
            .data_len = buffer.constAccountData().len -|
                V3State.BUFFER_METADATA_SIZE,
        };
        if (buffer.constAccountData().len < buf.data_offset or buf.data_len == 0) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.InvalidAccountData;
        }
        break :blk buf;
    };

    // Verify ProgramData account

    const progdata = blk: {
        const programdata =
            try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.program_data));
        defer programdata.release();

        const offset = V3State.PROGRAM_DATA_METADATA_SIZE;
        const balance_required = @max(1, rent.minimumBalance(programdata.constAccountData().len));
        const progdata_size = V3State.sizeOfProgramData(buf.data_len);

        if (programdata.constAccountData().len < progdata_size) {
            try ic.tc.log("ProgramData account not large enough", .{});
            return InstructionError.AccountDataTooSmall;
        }
        if (programdata.account.lamports +| buf.lamports < balance_required) {
            try ic.tc.log("Buffer account balance too low to fund upgrade", .{});
            return InstructionError.InsufficientFunds;
        }

        switch (try programdata.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program_data => |data| {
                if (clock.slot == data.slot) {
                    try ic.tc.log("Program was deployed in this block already", .{});
                    return InstructionError.InvalidArgument;
                }
                if (data.upgrade_authority_address == null) {
                    try ic.tc.log("Program not upgradeable", .{});
                    return InstructionError.Immutable;
                }
                if (!data.upgrade_authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Incorrect upgrade authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.ixn_info.isIndexSigner(6))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid ProgramData account", .{});
                return InstructionError.InvalidAccountData;
            },
        }

        break :blk .{
            .len = programdata.constAccountData().len,
            .offset = offset,
            .balance_required = balance_required,
        };
    };

    // Load and verify the program bits

    {
        const buffer = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.buffer));
        defer buffer.release();

        if (buffer.constAccountData().len < buf.data_offset) {
            return InstructionError.AccountDataTooSmall;
        }

        try deployProgram(
            allocator,
            ic.tc,
            new_program_id,
            ic.ixn_info.program_meta.pubkey,
            buffer.constAccountData()[buf.data_offset..],
            clock.slot,
        );
    }

    // Update the ProgramData account, record the upgraded data, and zero the rest:

    var programdata = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.program_data),
    );
    defer programdata.release();

    {
        try programdata.serializeIntoAccountData(V3State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });

        const dst_slice = try programdata.mutableAccountData();
        if (dst_slice.len < progdata.offset +| buf.data_len) {
            return InstructionError.AccountDataTooSmall;
        }

        const buffer = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.buffer),
        );
        defer buffer.release();

        const src_slice = buffer.constAccountData();
        if (src_slice.len < buf.data_offset) {
            return InstructionError.AccountDataTooSmall;
        }

        // copy_from_slice (not using @memcpy as idk if they alias)
        std.mem.copyForwards(
            u8,
            dst_slice[progdata.offset..][0..buf.data_len],
            src_slice[buf.data_offset..],
        );

        // Happens outside this scope but should be the same thing.
        @memset(dst_slice[progdata.offset +| buf.data_len..], 0);
    }

    // Fund ProgramData to rent-exemption, spill the rest
    var buffer = try ic.borrowInstructionAccount(2);
    defer buffer.release();

    var spill = try ic.borrowInstructionAccount(3);
    defer spill.release();

    try spill.addLamports(
        programdata.account.lamports +| buf.lamports -| progdata.balance_required,
    );
    try buffer.setLamports(0);
    try programdata.setLamports(progdata.balance_required);
    try buffer.setDataLength(
        allocator,
        &ic.tc.accounts_resize_delta,
        V3State.sizeOfBuffer(0),
    );

    try ic.tc.log("Upgraded program {any}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L946-L1010
pub fn executeV3SetAuthority(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.SetAuthority.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    var account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer account.release();

    const present_authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.present_authority),
    );
    const new_authority = if (ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.new_authority),
    )) |meta| meta.pubkey else null;

    switch (try account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |buffer| {
            if (new_authority == null) {
                try ic.tc.log("Buffer authority is not optional", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(1))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .buffer = .{
                    .authority_address = new_authority,
                },
            });
        },
        .program_data => |data| {
            if (data.upgrade_authority_address == null) {
                try ic.tc.log("Program not upgradeable", .{});
                return InstructionError.Immutable;
            }
            if (!data.upgrade_authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .program_data = .{
                    .slot = data.slot,
                    .upgrade_authority_address = new_authority,
                },
            });
        },
        else => {
            try ic.tc.log("Account does not support authorities", .{});
            return InstructionError.InvalidArgument;
        },
    }

    if (new_authority) |some| {
        try ic.tc.log("New authority Some({f})", .{some});
    } else {
        try ic.tc.log("New authority None", .{});
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L1011-L1083
pub fn executeV3SetAuthorityChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.tc.feature_set.active(.enable_bpf_loader_set_authority_checked_ix, ic.tc.slot)) {
        return InstructionError.InvalidInstructionData;
    }

    const AccountIndex = bpf_loader_program.v3.instruction.SetAuthorityChecked.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(3);

    var account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    defer account.release();

    const present_authority_key = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.present_authority),
    );
    const new_authority = ic.getAccountKeyByIndexUnchecked(
        @intFromEnum(AccountIndex.new_authority),
    );

    switch (try account.deserializeFromAccountData(allocator, V3State)) {
        .buffer => |buffer| {
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.new_authority),
            ))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .buffer = .{
                    .authority_address = new_authority,
                },
            });
        },
        .program_data => |data| {
            if (data.upgrade_authority_address == null) {
                try ic.tc.log("Program not upgradeable", .{});
                return InstructionError.Immutable;
            }
            if (!data.upgrade_authority_address.?.equals(&present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.present_authority),
            ))) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!(try ic.ixn_info.isIndexSigner(
                @intFromEnum(AccountIndex.new_authority),
            ))) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(V3State{
                .program_data = .{
                    .slot = data.slot,
                    .upgrade_authority_address = new_authority,
                },
            });
        },
        else => {
            try ic.tc.log("Account does not support authorities", .{});
            return InstructionError.InvalidArgument;
        },
    }

    try ic.tc.log("New authority {f}", .{new_authority});
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L1033-L1138
pub fn executeV3Close(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = bpf_loader_program.v3.instruction.Close.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(2);

    const account_index_in_txn = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.account),
    ).?.index_in_transaction;
    const recipient_index_in_txn = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.recipient),
    ).?.index_in_transaction;

    if (account_index_in_txn == recipient_index_in_txn) {
        try ic.tc.log("Recipient is the same as the account being closed", .{});
        return InstructionError.InvalidArgument;
    }

    var close_account = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.account));
    var close_account_released = false; // NOTE: used to simulate drop(close_account) below.
    defer if (!close_account_released) close_account.release();

    const close_key = close_account.pubkey;
    const close_account_state = try close_account.deserializeFromAccountData(
        allocator,
        V3State,
    );
    try close_account.setDataLength(
        allocator,
        &ic.tc.accounts_resize_delta,
        V3State.UNINITIALIZED_SIZE,
    );
    switch (close_account_state) {
        .uninitialized => {
            var recipient_account = try ic.borrowInstructionAccount(
                @intFromEnum(AccountIndex.recipient),
            );
            defer recipient_account.release();

            try recipient_account.addLamports(close_account.account.lamports);
            try close_account.setLamports(0);
            try ic.tc.log("Closed Uninitialized {any}", .{close_key});
        },
        .buffer => |data| {
            try ic.ixn_info.checkNumberOfAccounts(3);
            close_account.release();
            close_account_released = true;

            try commonCloseAccount(ic, data.authority_address);
            try ic.tc.log("Closed Buffer {any}", .{close_key});
        },
        .program_data => |data| {
            try ic.ixn_info.checkNumberOfAccounts(4);
            close_account.release();
            close_account_released = true;

            var program_account = try ic.borrowInstructionAccount(
                @intFromEnum(AccountIndex.program),
            );
            var program_account_released = false; // NOTE: simulates drop(program_account) below.
            defer if (!program_account_released) program_account.release();

            const program_key = program_account.pubkey;
            const authority_address = data.upgrade_authority_address;

            if (!program_account.context.is_writable) {
                try ic.tc.log("Program account is not writable", .{});
                return InstructionError.InvalidArgument;
            }
            if (!program_account.isOwnedByCurrentProgram()) {
                try ic.tc.log("Program account is not owned by the loader", .{});
                return InstructionError.IncorrectProgramId;
            }

            var clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
            if (clock.slot == data.slot) {
                try ic.tc.log("Program was deployed in this block already", .{});
                return InstructionError.InvalidArgument;
            }

            switch (try program_account.deserializeFromAccountData(
                allocator,
                V3State,
            )) {
                .program => |program_data| {
                    if (!program_data.programdata_address.equals(&close_key)) {
                        try ic.tc.log(
                            "ProgramData account does not match ProgramData account",
                            .{},
                        );
                        return InstructionError.InvalidArgument;
                    }

                    program_account.release();
                    program_account_released = true;
                    try commonCloseAccount(ic, authority_address);

                    clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

                    // Remove from the program map if it was deployed.
                    const old_program = try ic.tc.program_map
                        .fetchPut(allocator, program_key, .failed);
                    if (old_program) |p| p.deinit(allocator);
                },
                else => {
                    try ic.tc.log("Invalid Program Account", .{});
                    return InstructionError.InvalidArgument;
                },
            }

            try ic.tc.log("Closed Program {any}", .{program_key});
        },
        else => {
            try ic.tc.log("Account does not support closing", .{});
            return InstructionError.InvalidArgument;
        },
    }
}

fn commonCloseAccount(
    ic: *InstructionContext,
    authority_address: ?Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (authority_address == null) {
        try ic.tc.log("Account is immutable", .{});
        return InstructionError.Immutable;
    }

    const AccountIndex = bpf_loader_program.v3.instruction.Close.AccountIndex;
    const auth_account = ic.ixn_info.getAccountMetaAtIndex(
        @intFromEnum(AccountIndex.authority),
    ) orelse return InstructionError.MissingAccount;

    if (!authority_address.?.equals(&auth_account.pubkey)) {
        try ic.tc.log("Incorrect authority provided", .{});
        return InstructionError.IncorrectAuthority;
    }
    if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
        try ic.tc.log("Authority did not sign", .{});
        return InstructionError.MissingRequiredSignature;
    }

    var close_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.account),
    );
    defer close_account.release();

    var recipient_account = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.recipient),
    );
    defer recipient_account.release();

    try recipient_account.addLamports(close_account.account.lamports);
    try close_account.setLamports(0);
    try close_account.serializeIntoAccountData(V3State{ .uninitialized = {} });
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L1158
pub fn executeV3ExtendProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
) (error{OutOfMemory} || InstructionError)!void {
    if (ic.tc.feature_set.active(.enable_extend_program_checked, ic.tc.slot)) {
        try ic.tc.log("ExtendProgram was superseded by ExtendProgramChecked", .{});
        return InstructionError.InvalidInstructionData;
    }
    try commonExtendProgram(allocator, ic, additional_bytes, false);
}

/// [agave] https://github.com/anza-xyz/agave/blob/94d70cdf40ab55a3f1c2099037cdb36276ef9032/programs/bpf_loader/src/lib.rs#L1171
pub fn executeV3ExtendProgramChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.tc.feature_set.active(.enable_extend_program_checked, ic.tc.slot)) {
        return InstructionError.InvalidInstructionData;
    }
    try commonExtendProgram(allocator, ic, additional_bytes, true);
}

fn commonExtendProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    additional_bytes: u32,
    comptime check_authority: bool,
) (error{OutOfMemory} || InstructionError)!void {
    const AccountIndex = switch (check_authority) {
        true => bpf_loader_program.v3.instruction.ExtendProgramChecked.AccountIndex,
        else => bpf_loader_program.v3.instruction.ExtendProgram.AccountIndex,
    };

    if (additional_bytes == 0) {
        try ic.tc.log("Additional bytes must be greater than 0", .{});
        return InstructionError.InvalidInstructionData;
    }

    var programdata = try ic.borrowInstructionAccount(
        @intFromEnum(AccountIndex.program_data),
    );
    var programdata_released = false; // simulate drop(program_data) down below.
    defer if (!programdata_released) programdata.release();

    const programdata_key = programdata.pubkey;
    if (!programdata.isOwnedByCurrentProgram()) {
        try ic.tc.log("ProgramData owner is invalid", .{});
        return InstructionError.InvalidAccountOwner;
    }
    if (!programdata.context.is_writable) {
        try ic.tc.log("ProgramData is not writable", .{});
        return InstructionError.InvalidArgument;
    }

    const program_key = blk: {
        var program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account is not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.InvalidAccountOwner;
        }

        switch (try program_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program => |data| {
                if (!data.programdata_address.equals(&programdata_key)) {
                    try ic.tc.log(
                        "Program account does not match ProgramData account",
                        .{},
                    );
                    return InstructionError.InvalidArgument;
                }
            },
            else => {
                try ic.tc.log("Invalid Program account", .{});
                return InstructionError.InvalidAccountData;
            },
        }

        break :blk program_account.pubkey;
    };

    const new_len = programdata.constAccountData().len +| additional_bytes;
    if (new_len > system_program.MAX_PERMITTED_DATA_LENGTH) {
        try ic.tc.log(
            "Extended ProgramData length of {} bytes exceeds max account data length of {}",
            .{ new_len, system_program.MAX_PERMITTED_DATA_LENGTH },
        );
        return InstructionError.InvalidRealloc;
    }

    const clock_slot = (try ic.tc.sysvar_cache.get(sysvar.Clock)).slot;

    const upgrade_authority_address = switch (try programdata.deserializeFromAccountData(
        allocator,
        V3State,
    )) {
        .program_data => |data| blk: {
            if (clock_slot == data.slot) {
                try ic.tc.log("Program was extended in this block already", .{});
                return InstructionError.InvalidArgument;
            }

            const upgrade_authority_address = data.upgrade_authority_address orelse {
                try ic.tc.log(
                    "Cannot extend ProgramData accounts that are not upgradeable",
                    .{},
                );
                return InstructionError.Immutable;
            };

            if (check_authority) {
                const authority = ic.ixn_info.getAccountMetaAtIndex(
                    @intFromEnum(AccountIndex.authority),
                ) orelse return InstructionError.MissingAccount;

                if (!upgrade_authority_address.equals(&authority.pubkey)) {
                    try ic.tc.log("Incorrect upgrade authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }
                if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            }
            break :blk upgrade_authority_address;
        },
        else => {
            try ic.tc.log("ProgramData state is invalid", .{});
            return InstructionError.InvalidAccountData;
        },
    };

    const required_payment = blk: {
        const balance = programdata.account.lamports;
        // [agave] https://github.com/anza-xyz/agave/blob/5fa721b3b27c7ba33e5b0e1c55326241bb403bb1/program-runtime/src/sysvar_cache.rs#L130-L141
        const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
        const min_balance = @max(1, rent.minimumBalance(new_len));
        break :blk min_balance -| balance;
    };

    // Borrowed accounts need to be dropped before native_invoke
    programdata.release();
    programdata_released = true;

    // Determine the program ID to prevent overlapping mutable/immutable borrow of invoke context.
    if (required_payment > 0) {
        // [agave] https://github.com/anza-xyz/agave/blob/ad0983afd4efa711cf2258aa9630416ed6716d2a/transaction-context/src/lib.rs#L260-L267
        const payer = ic.ixn_info.getAccountMetaAtIndex(
            @intFromEnum(AccountIndex.payer),
        ) orelse
            return InstructionError.MissingAccount;

        try ic.nativeInvoke(
            allocator,
            system_program.ID,
            system_program.Instruction{
                .transfer = .{ .lamports = required_payment },
            },
            &.{
                .{ .pubkey = payer.pubkey, .is_signer = true, .is_writable = true },
                .{ .pubkey = programdata_key, .is_signer = false, .is_writable = true },
            },
            &.{},
        );
    }

    {
        programdata = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer programdata.release();

        try programdata.setDataLength(allocator, &ic.tc.accounts_resize_delta, new_len);
        const data = programdata.constAccountData();

        try deployProgram(
            allocator,
            ic.tc,
            program_key,
            ic.ixn_info.program_meta.pubkey,
            data[V3State.PROGRAM_DATA_METADATA_SIZE..],
            clock_slot,
        );
    }

    programdata = try ic.borrowInstructionAccount(@intFromEnum(AccountIndex.program_data));
    defer programdata.release();

    try programdata.serializeIntoAccountData(V3State{
        .program_data = .{
            .slot = clock_slot,
            .upgrade_authority_address = upgrade_authority_address,
        },
    });

    try ic.tc.log("Extended ProgramData account by {} bytes", .{additional_bytes});
}

/// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/lib.rs#L1346-L1515
pub fn executeV3Migrate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.tc.feature_set.active(.enable_loader_v4, ic.tc.slot)) {
        return InstructionError.InvalidInstructionData;
    }

    const AccountIndex = bpf_loader_program.v3.instruction.Migrate.AccountIndex;
    try ic.ixn_info.checkNumberOfAccounts(3);

    const programdata_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program_data));
    const program_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.program));
    const provided_authority_key =
        ic.getAccountKeyByIndexUnchecked(@intFromEnum(AccountIndex.authority));

    // [agave] https://github.com/anza-xyz/agave/blob/5fa721b3b27c7ba33e5b0e1c55326241bb403bb1/program-runtime/src/sysvar_cache.rs#L130-L141
    const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

    // Verify ProgramData account.
    const progdata_info = info: {
        var programdata = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer programdata.release();

        if (!programdata.context.is_writable) {
            try ic.tc.log("ProgramData account not writeable", .{});
            return InstructionError.InvalidArgument;
        }

        const program_len, const upgrade_key = blk: {
            const state = programdata.deserializeFromAccountData(allocator, V3State) catch
                break :blk .{ 0, null };
            switch (state) {
                .program_data => |data| {
                    if (clock.slot == data.slot) {
                        try ic.tc.log("Program was deployed in this block already", .{});
                        return InstructionError.InvalidArgument;
                    }

                    const program_len: u32 = @intCast(programdata.constAccountData().len -|
                        V3State.PROGRAM_DATA_METADATA_SIZE);

                    break :blk .{ program_len, data.upgrade_authority_address };
                },
                else => break :blk .{ 0, null },
            }
        };

        break :info .{
            .len = program_len,
            .upgrade_key = upgrade_key,
            .funds = programdata.account.lamports,
        };
    };

    // Verify authority signature
    if (!migration_authority.equals(&provided_authority_key) and
        !provided_authority_key.equals(&(progdata_info.upgrade_key orelse program_key)))
    {
        try ic.tc.log("Incorrect migration authority provided", .{});
        return InstructionError.IncorrectAuthority;
    }
    if (!(try ic.ixn_info.isIndexSigner(@intFromEnum(AccountIndex.authority)))) {
        try ic.tc.log("Migration authority did not sign", .{});
        return InstructionError.MissingRequiredSignature;
    }

    // Verify Program account
    {
        var program_account = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program),
        );
        defer program_account.release();

        if (!program_account.context.is_writable) {
            try ic.tc.log("Program account not writeable", .{});
            return InstructionError.InvalidArgument;
        }
        if (!program_account.isOwnedByCurrentProgram()) {
            try ic.tc.log("Program account not owned by loader", .{});
            return InstructionError.IncorrectProgramId;
        }

        switch (try program_account.deserializeFromAccountData(
            allocator,
            V3State,
        )) {
            .program => |data| {
                if (!programdata_key.equals(&data.programdata_address)) {
                    try ic.tc.log("Program and ProgramData account mismatch", .{});
                    return InstructionError.InvalidArgument;
                }
            },
            else => {
                try ic.tc.log("Invalid Program account", .{});
                return InstructionError.InvalidAccountData;
            },
        }

        try program_account.setDataLength(allocator, &ic.tc.accounts_resize_delta, 0);
        try program_account.addLamports(progdata_info.funds);
        try program_account.setOwner(bpf_loader_program.v4.ID);
    }

    {
        var programdata = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer programdata.release();
        try programdata.setLamports(0);
    }

    if (progdata_info.len == 0) {
        // Close the program map entry.
        const old_program = try ic.tc.program_map.fetchPut(allocator, program_key, .failed);
        if (old_program) |p| p.deinit(allocator);
    } else {
        try ic.nativeInvoke(
            allocator,
            bpf_loader_program.v4.ID,
            bpf_loader_program.v4.Instruction{
                .set_program_length = .{
                    .new_size = progdata_info.len,
                },
            },
            &.{
                .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
                .{ .pubkey = provided_authority_key, .is_signer = true, .is_writable = false },
                .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
            },
            &.{},
        );

        try ic.nativeInvoke(
            allocator,
            bpf_loader_program.v4.ID,
            bpf_loader_program.v4.Instruction{
                .copy = .{
                    .destination_offset = 0,
                    .source_offset = 0,
                    .length = progdata_info.len,
                },
            },
            &.{
                .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
                .{ .pubkey = provided_authority_key, .is_signer = true, .is_writable = false },
                .{ .pubkey = programdata_key, .is_signer = false, .is_writable = false },
            },
            &.{},
        );

        try ic.nativeInvoke(
            allocator,
            bpf_loader_program.v4.ID,
            bpf_loader_program.v4.Instruction{
                .deploy = .{},
            },
            &.{
                .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
                .{ .pubkey = provided_authority_key, .is_signer = true, .is_writable = false },
            },
            &.{},
        );

        if (progdata_info.upgrade_key == null) {
            try ic.nativeInvoke(
                allocator,
                bpf_loader_program.v4.ID,
                bpf_loader_program.v4.Instruction{
                    .finalize = .{},
                },
                &.{
                    .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
                    .{ .pubkey = provided_authority_key, .is_signer = true, .is_writable = false },
                    .{ .pubkey = program_key, .is_signer = false, .is_writable = false },
                },
                &.{},
            );
        } else if (provided_authority_key.equals(&migration_authority)) {
            const upgrade_key = progdata_info.upgrade_key.?;
            try ic.nativeInvoke(
                allocator,
                bpf_loader_program.v4.ID,
                bpf_loader_program.v4.Instruction{
                    .transfer_authority = .{},
                },
                &.{
                    .{ .pubkey = program_key, .is_signer = false, .is_writable = true },
                    .{ .pubkey = provided_authority_key, .is_signer = true, .is_writable = false },
                    .{ .pubkey = upgrade_key, .is_signer = true, .is_writable = false },
                },
                &.{},
            );
        }
    }

    {
        var programdata = try ic.borrowInstructionAccount(
            @intFromEnum(AccountIndex.program_data),
        );
        defer programdata.release();
        try programdata.setDataLength(allocator, &ic.tc.accounts_resize_delta, 0);
    }

    try ic.tc.log("Migrated program {any}", .{program_key});
}

/// TODO: This function depends on syscalls and program cache implementations
/// which is are not implemented yet. It does not affect the account state resulting from
/// the execution of bpf loader instructions unless it returns an error.
/// [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/programs/bpf_loader/src/lib.rs#L115
/// [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/program/fd_bpf_loader_program.c#L238
pub fn deployProgram(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    program_id: Pubkey,
    owner_id: Pubkey,
    data: []const u8,
    deploy_slot: u64,
) (error{OutOfMemory} || InstructionError)!void {
    _ = deploy_slot;
    _ = owner_id;

    try verifyProgram(
        allocator,
        data,
        tc.slot,
        tc.feature_set,
        &tc.compute_budget,
        if (tc.log_collector) |*lc| lc else null,
    );

    try tc.log("Deploying program {f}", .{program_id});

    // Remove from the program map since it should not be accessible on this slot anymore.
    _ = try tc.program_map.fetchPut(allocator, program_id, .failed);
}

pub fn verifyProgram(
    allocator: std.mem.Allocator,
    data: []const u8,
    slot: sig.core.Slot,
    feature_set: *const sig.core.FeatureSet,
    compute_budget: *const sig.runtime.ComputeBudget,
    log_collector: ?*sig.runtime.LogCollector,
) !void {
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L124-L131
    var environment = vm.Environment.initV1(
        feature_set,
        compute_budget,
        slot,
        true,
    );

    // Deployment of programs with sol_alloc_free is disabled.
    if (environment.loader.map.get(.sol_alloc_free_) != null) {
        environment.loader.map.set(.sol_alloc_free_, null);
    }

    // Copy the program data to a new buffer
    const source = try allocator.dupe(u8, data);
    defer allocator.free(source);

    var executable = vm.elf.load(
        allocator,
        source,
        &environment.loader,
        environment.config,
    ) catch |err| {
        if (log_collector) |lc| try lc.log(allocator, "{s}", .{@errorName(err)});
        return InstructionError.InvalidAccountData;
    };
    defer executable.deinit(allocator);

    executable.verify(&environment.loader) catch |err| {
        if (log_collector) |lc| try lc.log(allocator, "{s}", .{@errorName(err)});
        return InstructionError.InvalidAccountData;
    };
}

test executeV3InitializeBuffer {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = V3State.uninitialized;
    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_state = V3State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(final_buffer_account_data);
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.initialize_buffer,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3Write {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const offset = 10;
    const source = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    const initial_buffer_account_state = V3State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State) + offset + source.len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    const start = V3State.BUFFER_METADATA_SIZE + offset;
    const end = start +| source.len;
    @memcpy(final_buffer_account_data[start..end], &source);

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .write = .{
                .offset = offset,
                .bytes = &source,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3DeployWithMaxDataLen {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");
    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const rent = sysvar.Rent.INIT;

    const additional_bytes = 1024;

    const initial_program_account_data =
        try allocator.alloc(u8, V3State.PROGRAM_SIZE);
    defer allocator.free(initial_program_account_data);
    @memset(initial_program_account_data, 0);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State.uninitialized,
        .{},
    );

    const initial_program_account_lamports = rent.minimumBalance(initial_program_account_data.len);

    const final_program_account_data =
        try allocator.alloc(u8, V3State.PROGRAM_SIZE);
    defer allocator.free(final_program_account_data);
    @memset(final_program_account_data, 0);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program = .{
                .programdata_address = program_data_account_key,
            },
        },
        .{},
    );

    const initial_buffer_account_data = try createValidProgramData(
        allocator,
        V3State{
            .buffer = .{
                .authority_address = buffer_authority_key,
            },
        },
        V3State.BUFFER_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(initial_buffer_account_data);
    const initial_buffer_account_lamports = 1_000;
    const final_buffer_account_data =
        initial_buffer_account_data[0..V3State.BUFFER_METADATA_SIZE];

    const final_program_data_account_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = 0,
                .upgrade_authority_address = buffer_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(final_program_data_account_data);

    try std.testing.expectEqualSlices(
        u8,
        initial_buffer_account_data[V3State.BUFFER_METADATA_SIZE..],
        final_program_data_account_data[V3State.PROGRAM_DATA_METADATA_SIZE..],
    );

    const max_data_len =
        final_program_data_account_data.len -|
        V3State.PROGRAM_DATA_METADATA_SIZE;

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .deploy_with_max_data_len = .{ .max_data_len = max_data_len },
        },
        &.{
            .{ .index_in_transaction = 0, .is_signer = true, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 2, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 3, .is_signer = false, .is_writable = true },
            .{ .index_in_transaction = 4, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 5, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 6, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 7, .is_signer = true, .is_writable = false },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_data.len)),
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_data_account_key,
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_account_key,
                    .lamports = initial_program_account_lamports,
                    .owner = bpf_loader_program.v3.ID,
                    .data = initial_program_account_data,
                },
                .{
                    .pubkey = buffer_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = initial_buffer_account_lamports,
                    .data = initial_buffer_account_data,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = sysvar.Clock.ID },
                .{
                    .pubkey = program.system.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .sysvar_cache = .{
                .rent = sysvar.Rent.INIT,
                .clock = sysvar.Clock.INIT,
            },
            // TODO: Should we need extra for system program cpi???
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS + 150,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = initial_buffer_account_lamports,
                    .owner = system_program.ID,
                },
                .{
                    .pubkey = program_data_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_data.len)),
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_program_data_account_data,
                },
                .{
                    .pubkey = program_account_key,
                    .lamports = initial_program_account_lamports,
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_program_account_data,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .data = final_buffer_account_data,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = sysvar.Clock.ID },
                .{
                    .pubkey = program.system.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = @intCast(
                final_buffer_account_data.len +
                    V3State.PROGRAM_DATA_METADATA_SIZE +|
                    max_data_len -|
                    initial_buffer_account_data.len,
            ),
            .sysvar_cache = .{
                .rent = sysvar.Rent.INIT,
                .clock = sysvar.Clock.INIT,
            },
        },
        .{},
    );
}

test executeV3SetAuthority {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    const initial_program_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    @memcpy(final_program_account_data, initial_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = null },
        },
        .{},
    );

    // test with no new authority
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3SetAuthorityChecked {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());
    const new_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_buffer_account_data);
    _ = try bincode.writeToSlice(
        initial_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    _ = try bincode.writeToSlice(
        final_buffer_account_data,
        V3State{
            .buffer = .{ .authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.buffer (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority_checked,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID, // id of program u wanna run
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID, // bpf_loader_program.v3.ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .feature_set = &.{
                .{
                    .feature = .enable_bpf_loader_set_authority_checked_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );

    const initial_program_account_data =
        try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_program_account_data);
    _ = try bincode.writeToSlice(
        initial_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = buffer_authority_key },
        },
        .{},
    );

    const final_program_account_data = try allocator.dupe(u8, initial_program_account_data);
    defer allocator.free(final_program_account_data);
    _ = try bincode.writeToSlice(
        final_program_account_data,
        V3State{
            .program_data = .{ .slot = 0, .upgrade_authority_address = new_authority_key },
        },
        .{},
    );

    // test with State.program_data (1 and 2 must be signers).
    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction.set_authority_checked,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .feature_set = &.{
                .{
                    .feature = .enable_bpf_loader_set_authority_checked_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_program_account_data,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = new_authority_key,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV3Close {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const close_account_key = Pubkey.initRandom(prng.random());
    const repicient_key = Pubkey.initRandom(prng.random());
    const authority_key = Pubkey.initRandom(prng.random());
    const program_key = Pubkey.initRandom(prng.random());

    const initial_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(initial_account_data);
    const final_account_data = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(final_account_data);

    const num_lamports = 42 + prng.random().uintAtMost(u64, 1337);

    // uninitialized
    {
        const uninitialized_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = true, .index_in_transaction = 1 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = uninitialized_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
            },
            .{},
        );
    }

    // buffer
    {
        const initial_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{
                .buffer = .{
                    .authority_address = authority_key,
                },
            },
            .{},
        );

        const final_data = try bincode.writeToSlice(
            final_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = -@as(i64, @intCast(initial_data.len - final_data.len)),
            },
            .{},
        );
    }

    // program_data
    {
        var clock = sysvar.Clock.INIT;
        clock.slot = 1337;

        const initial_data = try bincode.writeToSlice(
            initial_account_data,
            V3State{
                .program_data = .{
                    .slot = clock.slot - 1,
                    .upgrade_authority_address = authority_key,
                },
            },
            .{},
        );

        const final_data = try bincode.writeToSlice(
            final_account_data,
            V3State{ .uninitialized = {} },
            .{},
        );

        const program_data_buffer = try allocator.alloc(u8, @sizeOf(V3State));
        defer allocator.free(program_data_buffer);
        const program_data = try bincode.writeToSlice(
            program_data_buffer,
            V3State{
                .program = .{ .programdata_address = close_account_key },
            },
            .{},
        );

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .close = .{},
            },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 3 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = initial_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = repicient_key,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = program_key,
                        .data = program_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
                .sysvar_cache = .{
                    .clock = clock,
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = close_account_key,
                        .data = final_data,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = repicient_key,
                        .lamports = num_lamports,
                    },
                    .{
                        .pubkey = authority_key,
                    },
                    .{
                        .pubkey = program_key,
                        .data = program_data,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = -@as(i64, @intCast(initial_data.len - final_data.len)),
            },
            .{},
        );
    }
}

test executeV3Upgrade {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const spill_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());
    const buffer_account_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");

    const rent = sysvar.Rent.INIT;
    var clock = sysvar.Clock.INIT;
    clock.slot += 1337;

    // const buf_size = 512;

    const initial_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot - 1,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(initial_program_data);

    const updated_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(updated_program_data);

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(program_account_buffer);
    _ = try bincode.writeToSlice(
        program_account_buffer,
        V3State{
            .program = .{ .programdata_address = program_data_account_key },
        },
        .{},
    );

    const buffer_account_data = try createValidProgramData(
        allocator,
        V3State{
            .buffer = .{ .authority_address = upgrade_authority_key },
        },
        V3State.BUFFER_METADATA_SIZE,
        0,
    );
    defer allocator.free(buffer_account_data);

    const buffer_aid_balance = 42;
    const spill_balance = 100;
    const buffer_balance = rent.minimumBalance(buffer_account_data.len) + buffer_aid_balance;
    const program_data_balance = rent.minimumBalance(initial_program_data.len) - buffer_aid_balance;
    const expected_account_resize_delta: i64 =
        @intCast(buffer_account_data.len - V3State.BUFFER_METADATA_SIZE);

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3.ID,
        bpf_loader_program.v3.Instruction{
            .upgrade = .{},
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 2 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 3 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 6 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = initial_program_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = program_data_balance,
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .data = buffer_account_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = buffer_balance,
                },
                .{
                    .pubkey = spill_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = spill_balance,
                },
                .{
                    .pubkey = sysvar.Rent.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = sysvar.Clock.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = upgrade_authority_key,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_data_account_key,
                    .data = updated_program_data,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = rent.minimumBalance(updated_program_data.len),
                },
                .{
                    .pubkey = program_account_key,
                    .data = program_account_buffer,
                    .owner = bpf_loader_program.v3.ID,
                    .executable = true,
                },
                .{
                    .pubkey = buffer_account_key,
                    .data = buffer_account_data[0..V3State.BUFFER_METADATA_SIZE],
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = 0,
                },
                .{
                    .pubkey = spill_account_key,
                    .owner = bpf_loader_program.v3.ID,
                    .lamports = spill_balance +
                        buffer_balance +
                        program_data_balance -
                        rent.minimumBalance(initial_program_data.len),
                },
                .{
                    .pubkey = sysvar.Rent.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = sysvar.Clock.ID,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = upgrade_authority_key,
                    .owner = bpf_loader_program.v3.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = -expected_account_resize_delta,
        },
        .{},
    );
}

test executeV3ExtendProgram {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const upgrade_authority_key = Pubkey.initRandom(prng.random());

    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key, _ = pubkey_utils.findProgramAddress(
        &.{&program_account_key.data},
        bpf_loader_program.v3.ID,
    ) orelse @panic("findProgramAddress failed");

    var clock = sysvar.Clock.INIT;
    clock.slot += 1337;

    const initial_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot - 1,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        0,
    );
    defer allocator.free(initial_program_data);

    const additional_bytes = 512;
    const final_program_data = try createValidProgramData(
        allocator,
        V3State{
            .program_data = .{
                .slot = clock.slot,
                .upgrade_authority_address = upgrade_authority_key,
            },
        },
        V3State.PROGRAM_DATA_METADATA_SIZE,
        additional_bytes,
    );
    defer allocator.free(final_program_data);

    const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
    defer allocator.free(program_account_buffer);
    const program_account = try bincode.writeToSlice(
        program_account_buffer,
        V3State{
            .program = .{ .programdata_address = program_data_account_key },
        },
        .{},
    );

    // Test with and without the payer helping out to pay for extend.
    for ([_]u32{ 0, 100 }) |help_pay| {
        inline for ([_]bool{ false, true }) |check_authority| {
            std.debug.assert(help_pay < additional_bytes);

            const payer_balance = prng.random().uintAtMost(u32, 1024) + help_pay;
            const program_data_lamports =
                sysvar.Rent.INIT.minimumBalance(initial_program_data.len + additional_bytes) -
                help_pay;

            var compute_units: u64 = bpf_loader_program.v3.COMPUTE_UNITS;
            if (help_pay > 0) { // triggers native cpi transfer call
                compute_units += system_program.COMPUTE_UNITS;
            }

            try testing.expectProgramExecuteResult(
                allocator,
                bpf_loader_program.v3.ID,
                if (check_authority)
                    bpf_loader_program.v3.Instruction{
                        .extend_program_checked = .{ .additional_bytes = additional_bytes },
                    }
                else
                    bpf_loader_program.v3.Instruction{
                        .extend_program = .{ .additional_bytes = additional_bytes },
                    },
                if (check_authority)
                    &.{
                        // program_data
                        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                        // program
                        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                        // authority
                        .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
                        // system_program
                        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
                        // payer
                        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 4 },
                        // bpf program_id (for instruction)
                        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
                    }
                else
                    &.{
                        // program_data
                        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                        // program
                        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
                        // system_program
                        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
                        // payer
                        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 4 },
                        // bpf program_id (for instruction)
                        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
                    },
                .{
                    .accounts = &.{
                        .{
                            .pubkey = program_data_account_key,
                            .data = initial_program_data,
                            .owner = bpf_loader_program.v3.ID,
                            .lamports = program_data_lamports,
                        },
                        .{
                            .pubkey = program_account_key,
                            .data = program_account,
                            .owner = bpf_loader_program.v3.ID,
                        },
                        .{
                            .pubkey = upgrade_authority_key,
                            .owner = system_program.ID,
                        },
                        .{
                            .pubkey = system_program.ID,
                            .owner = ids.NATIVE_LOADER_ID,
                            .executable = true,
                        },
                        .{
                            .pubkey = payer_account_key,
                            .lamports = payer_balance,
                            .owner = system_program.ID,
                        },
                        .{
                            .pubkey = bpf_loader_program.v3.ID,
                            .owner = ids.NATIVE_LOADER_ID,
                        },
                    },
                    .compute_meter = compute_units,
                    .sysvar_cache = .{
                        .rent = sysvar.Rent.INIT,
                        .clock = clock,
                    },
                    .feature_set = if (check_authority)
                        &.{
                            .{
                                .feature = .enable_extend_program_checked,
                                .slot = 0,
                            },
                        }
                    else
                        &.{},
                },
                .{
                    .accounts = &.{
                        .{
                            .pubkey = program_data_account_key,
                            .data = final_program_data,
                            .owner = bpf_loader_program.v3.ID,
                            .lamports = program_data_lamports + help_pay,
                        },
                        .{
                            .pubkey = program_account_key,
                            .data = program_account,
                            .owner = bpf_loader_program.v3.ID,
                        },
                        .{
                            .pubkey = upgrade_authority_key,
                            .owner = system_program.ID,
                        },
                        .{
                            .pubkey = system_program.ID,
                            .owner = ids.NATIVE_LOADER_ID,
                            .executable = true,
                        },
                        .{
                            .pubkey = payer_account_key,
                            .lamports = payer_balance - help_pay,
                            .owner = system_program.ID,
                        },
                        .{
                            .pubkey = bpf_loader_program.v3.ID,
                            .owner = ids.NATIVE_LOADER_ID,
                        },
                    },
                    .accounts_resize_delta = additional_bytes,
                },
                .{},
            );
        }
    }

    // Test extend_program disabled when ENABLE_EXTEND_PROGRAM_CHECKED is enabled
    {
        var tx = try sig.runtime.testing.createTransactionContext(
            allocator,
            prng.random(),
            .{
                .accounts = &.{
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
                .sysvar_cache = .{
                    .rent = sysvar.Rent.INIT,
                    .clock = clock,
                },
                .feature_set = &.{
                    .{
                        .feature = .enable_extend_program_checked,
                        .slot = 0,
                    },
                },
            },
        );
        const tc = &tx[1];
        defer {
            sig.runtime.testing.deinitTransactionContext(allocator, tc);
            tx[0].deinit(allocator);
        }

        const instruction_info = try sig.runtime.testing.createInstructionInfo(
            tc,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .extend_program = .{ .additional_bytes = 0 },
            },
            &.{},
        );
        defer instruction_info.deinit(allocator);

        try std.testing.expectError(
            InstructionError.InvalidInstructionData,
            sig.runtime.executor.executeInstruction(allocator, tc, instruction_info),
        );
        try std.testing.expectEqual(tc.compute_meter, 0);
    }

    // Test extend_program_checked disabled when ENABLE_EXTEND_PROGRAM_CHECKED is not present.
    {
        var tx = try sig.runtime.testing.createTransactionContext(
            allocator,
            prng.random(),
            .{
                .accounts = &.{
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS,
                .sysvar_cache = .{
                    .rent = sysvar.Rent.INIT,
                    .clock = clock,
                },
            },
        );
        const tc = &tx[1];
        defer {
            sig.runtime.testing.deinitTransactionContext(allocator, tc);
            tx[0].deinit(allocator);
        }

        const instruction_info = try sig.runtime.testing.createInstructionInfo(
            tc,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .extend_program_checked = .{ .additional_bytes = 0 },
            },
            &.{},
        );
        defer instruction_info.deinit(allocator);

        try std.testing.expectError(
            InstructionError.InvalidInstructionData,
            sig.runtime.executor.executeInstruction(allocator, tc, instruction_info),
        );
        try std.testing.expectEqual(tc.compute_meter, 0);
    }
}

test executeV3Migrate {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]enum { use_auth, no_auth, migrate, migrate_zero }{
        .use_auth,
        .no_auth,
        .migrate,
        .migrate_zero,
    }) |mode| {
        const upgrade_authority_key = Pubkey.initRandom(prng.random());
        const program_account_key = Pubkey.initRandom(prng.random());
        const program_data_key, _ = pubkey_utils.findProgramAddress(
            &.{},
            program_account_key,
        ) orelse @panic("findProgramAddress failed");

        var clock = sysvar.Clock.INIT;
        clock.slot += 1337;

        const program_data_buffer = try createValidProgramData(
            allocator,
            V3State{
                .program_data = .{
                    .slot = clock.slot - 1, // must be before the current clock's slot.
                    .upgrade_authority_address = switch (mode) {
                        .use_auth => upgrade_authority_key,
                        .no_auth => null,
                        .migrate => program_account_key,
                        .migrate_zero => upgrade_authority_key,
                    },
                },
            },
            V3State.PROGRAM_DATA_METADATA_SIZE,
            0,
        );
        defer allocator.free(program_data_buffer);

        const program_data_buf = switch (mode) {
            .migrate_zero => program_data_buffer[0..V3State.PROGRAM_DATA_METADATA_SIZE],
            else => program_data_buffer,
        };

        const program_account_buffer = try allocator.alloc(u8, @sizeOf(V3State));
        defer allocator.free(program_account_buffer);
        _ = try bincode.writeToSlice(
            program_account_buffer,
            V3State{
                .program = .{
                    .programdata_address = program_data_key,
                },
            },
            .{},
        );

        const final_program_buffer = switch (mode) {
            .migrate_zero => &.{},
            else => try createValidProgramData(
                allocator,
                switch (mode) {
                    .use_auth => V4State{
                        .slot = clock.slot,
                        .authority_address_or_next_version = upgrade_authority_key,
                        .status = .deployed,
                    },
                    .no_auth => V4State{
                        .slot = clock.slot,
                        .authority_address_or_next_version = program_account_key,
                        .status = .finalized,
                    },
                    .migrate => V4State{
                        .slot = clock.slot,
                        .authority_address_or_next_version = program_account_key,
                        .status = .deployed,
                    },
                    else => unreachable,
                },
                V4State.PROGRAM_DATA_METADATA_SIZE,
                0,
            ),
        };
        defer allocator.free(final_program_buffer);

        const program_data_balance =
            sysvar.Rent.INIT.minimumBalance(program_data_buffer.len);
        const program_account_balance =
            sysvar.Rent.INIT.minimumBalance(program_account_buffer.len);

        const compute_units: u64 = bpf_loader_program.v3.COMPUTE_UNITS +
            // does 3 v4 CPI calls (+ v4.finalize or v4.transfer_authority depending on mode)
            @as(u64, switch (mode) {
                .use_auth => 3,
                .no_auth => 3 + 1,
                .migrate => 3 + 1,
                .migrate_zero => 0,
            }) * bpf_loader_program.v4.COMPUTE_UNITS;

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v3.ID,
            bpf_loader_program.v3.Instruction{
                .migrate = .{},
            },
            &.{
                // program_data_key
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                // program_account_key
                .{
                    .is_signer = mode != .use_auth,
                    .is_writable = true,
                    .index_in_transaction = 1,
                },
                .{
                    .is_signer = true,
                    .is_writable = false,
                    .index_in_transaction = switch (mode) {
                        .use_auth => 2, // upgrade_authority_key
                        .no_auth => 1, // program_account_key
                        .migrate => 3, // migration_authority
                        .migrate_zero => 2, // upgrade_authority_key
                    },
                },
                // bpf_loader_v4 for CPI
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
                // bpf_loader_v3 for v3.Instruction
                .{ .is_signer = false, .is_writable = false, .index_in_transaction = 5 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_data_key,
                        .data = program_data_buf,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = program_data_balance,
                    },
                    .{
                        .pubkey = program_account_key,
                        .data = program_account_buffer,
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = program_account_balance,
                    },
                    .{
                        .pubkey = upgrade_authority_key,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = migration_authority,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v4.ID, // needed for CPI
                        .owner = ids.NATIVE_LOADER_ID,
                        .executable = true,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = compute_units,
                .feature_set = &.{
                    .{
                        .feature = .enable_loader_v4,
                        .slot = 0,
                    },
                },
                .sysvar_cache = .{
                    .rent = sysvar.Rent.INIT,
                    .clock = clock,
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_data_key,
                        .data = &.{}, // set_length to 0
                        .owner = bpf_loader_program.v3.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = program_account_key,
                        .data = final_program_buffer,
                        .owner = bpf_loader_program.v4.ID, // v4
                        .lamports = program_account_balance + program_data_balance, // sum bal
                        .executable = mode != .migrate_zero,
                    },
                    .{
                        .pubkey = upgrade_authority_key,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = migration_authority,
                        .owner = bpf_loader_program.v3.ID,
                    },
                    .{
                        .pubkey = bpf_loader_program.v4.ID, // needed for CPI
                        .owner = ids.NATIVE_LOADER_ID,
                        .executable = true,
                    },
                    .{
                        .pubkey = bpf_loader_program.v3.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = @intCast(@as(i128, 0) -
                    program_account_buffer.len +
                    final_program_buffer.len -
                    program_data_buf.len),
            },
            .{},
        );
    }
}

fn createValidProgramData(
    allocator: std.mem.Allocator,
    state: anytype,
    state_size: usize,
    additional_bytes: usize,
) ![]u8 {
    if (!builtin.is_test)
        @compileError("createValidProgramData should only be used in tests");

    const elf_bytes = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        1024 * 1024,
    );
    defer allocator.free(elf_bytes);

    const program_data =
        try allocator.alloc(
            u8,
            state_size + elf_bytes.len + additional_bytes,
        );
    errdefer allocator.free(program_data);
    @memset(program_data, 0);

    _ = try bincode.writeToSlice(
        program_data[0..state_size],
        state,
        .{},
    );

    @memcpy(
        program_data[state_size .. program_data.len - additional_bytes],
        elf_bytes,
    );

    return program_data;
}

test executeV4Write {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_key = Pubkey.initRandom(prng.random());

    const initial_program_buffer = try allocator.alloc(u8, @sizeOf(V4State) + 100);
    defer allocator.free(initial_program_buffer);

    @memset(initial_program_buffer, 0);
    _ = try bincode.writeToSlice(
        initial_program_buffer,
        V4State{
            .slot = 0,
            .authority_address_or_next_version = program_key,
            .status = .retracted,
        },
        .{},
    );

    const final_program_buffer = try allocator.dupe(u8, initial_program_buffer);
    defer allocator.free(final_program_buffer);

    const to_write: []const u8 = "hello world";
    @memcpy(final_program_buffer[@sizeOf(V4State)..][0..to_write.len], to_write);

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v4.ID,
        bpf_loader_program.v4.Instruction{
            .write = .{ .offset = 0, .bytes = to_write },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 }, // program
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 0 }, // auth itself
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 }, // loader v4
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_key,
                    .data = initial_program_buffer,
                    .owner = bpf_loader_program.v4.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v4.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v4.COMPUTE_UNITS,
            .feature_set = &.{.{ .feature = .enable_loader_v4 }},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_key,
                    .data = final_program_buffer,
                    .owner = bpf_loader_program.v4.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v4.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV4Retract {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_key = Pubkey.initRandom(prng.random());

    const initial_program_buffer = try allocator.alloc(u8, @sizeOf(V4State));
    defer allocator.free(initial_program_buffer);
    _ = try bincode.writeToSlice(
        initial_program_buffer,
        V4State{
            .slot = 0,
            .authority_address_or_next_version = program_key,
            .status = .deployed,
        },
        .{},
    );

    const final_program_buffer = try allocator.dupe(u8, initial_program_buffer);
    defer allocator.free(final_program_buffer);
    _ = try bincode.writeToSlice(
        final_program_buffer,
        V4State{
            .slot = 0,
            .authority_address_or_next_version = program_key,
            .status = .retracted,
        },
        .{},
    );

    var clock = sysvar.Clock.INIT;
    clock.slot = DEPLOYMENT_COOLDOWN_IN_SLOTS;

    try testing.expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v4.ID,
        bpf_loader_program.v4.Instruction{ .retract = .{} },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 }, // program
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 0 }, // auth itself
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 }, // loader v4
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_key,
                    .data = initial_program_buffer,
                    .owner = bpf_loader_program.v4.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v4.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_program.v4.COMPUTE_UNITS,
            .sysvar_cache = .{ .rent = sysvar.Rent.INIT, .clock = clock },
            .feature_set = &.{.{ .feature = .enable_loader_v4 }},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = program_key,
                    .data = final_program_buffer,
                    .owner = bpf_loader_program.v4.ID,
                },
                .{
                    .pubkey = bpf_loader_program.v4.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
        .{},
    );
}

test executeV4SetProgramLength {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    for ([_]enum { open, grow, shrink, close }{ .open, .grow, .shrink, .close }) |mode| {
        const program_key = Pubkey.initRandom(prng.random());
        const recipient_key = Pubkey.initRandom(prng.random());
        const rent = sysvar.Rent.INIT;

        const bump_size: usize = 100;
        const required_lamports = rent.minimumBalance(@sizeOf(V4State) + bump_size);
        const program_lamports = required_lamports + 10;

        const buffer = try allocator.alloc(u8, @sizeOf(V4State) + bump_size);
        defer allocator.free(buffer);
        @memset(buffer, 0);

        _ = try bincode.writeToSlice(
            buffer,
            V4State{
                .slot = 0,
                .authority_address_or_next_version = program_key,
                .status = .retracted,
            },
            .{},
        );

        const args: struct {
            new_size: u32,
            init_buf: []const u8,
            final_buf: []const u8,
            moved_lamports: ?u64,
            resize_delta: i64,
        } = switch (mode) {
            .open => .{
                .new_size = bump_size,
                .init_buf = &.{},
                .final_buf = buffer,
                .moved_lamports = program_lamports - required_lamports,
                .resize_delta = @intCast(buffer.len),
            },
            .grow => .{
                .new_size = bump_size,
                .init_buf = buffer[0..@sizeOf(V4State)],
                .final_buf = buffer,
                .moved_lamports = program_lamports - required_lamports,
                .resize_delta = bump_size,
            },
            .shrink => .{
                .new_size = 1,
                .init_buf = buffer,
                .final_buf = buffer[0 .. @sizeOf(V4State) + 1],
                .moved_lamports = null,
                .resize_delta = -@as(i64, bump_size - 1),
            },
            .close => .{
                .new_size = 0,
                .init_buf = buffer,
                .final_buf = &.{},
                .moved_lamports = program_lamports,
                .resize_delta = -@as(i64, @sizeOf(V4State) + bump_size),
            },
        };

        var instr_accounts: std14.BoundedArray(testing.InstructionContextAccountMetaParams, 4) = .{};
        instr_accounts.appendSliceAssumeCapacity(&.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 }, // program
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 0 }, // auth
        });
        if (args.moved_lamports) |_| {
            instr_accounts.appendAssumeCapacity(.{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            });
        }

        try testing.expectProgramExecuteResult(
            allocator,
            bpf_loader_program.v4.ID,
            bpf_loader_program.v4.Instruction{
                .set_program_length = .{ .new_size = args.new_size },
            },
            instr_accounts.constSlice(),
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_key,
                        .data = args.init_buf,
                        .owner = bpf_loader_program.v4.ID,
                        .lamports = program_lamports,
                    },
                    .{
                        .pubkey = recipient_key,
                        .owner = system_program.ID,
                        .lamports = 0,
                    },
                    .{
                        .pubkey = bpf_loader_program.v4.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .compute_meter = bpf_loader_program.v4.COMPUTE_UNITS,
                .sysvar_cache = .{ .rent = rent },
                .feature_set = &.{.{ .feature = .enable_loader_v4 }},
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = program_key,
                        .data = args.final_buf,
                        .owner = bpf_loader_program.v4.ID,
                        .lamports = program_lamports - (args.moved_lamports orelse 0),
                        .executable = mode == .open,
                    },
                    .{
                        .pubkey = recipient_key,
                        .owner = system_program.ID,
                        .lamports = args.moved_lamports orelse 0,
                    },
                    .{
                        .pubkey = bpf_loader_program.v4.ID,
                        .owner = ids.NATIVE_LOADER_ID,
                    },
                },
                .accounts_resize_delta = args.resize_delta,
            },
            .{},
        );
    }
}

test checkProgramAccount {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_key = Pubkey.initRandom(prng.random());
    var program_data: [@sizeOf(V4State)]u8 = @splat(0);
    _ = try bincode.writeToSlice(
        &program_data,
        V4State{
            .slot = 0,
            .status = .retracted,
            .authority_address_or_next_version = program_key,
        },
        .{},
    );

    const cache, var tc = try testing.createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = program_key,
                .data = &program_data,
                .owner = bpf_loader_program.v4.ID,
            },
            .{
                .pubkey = bpf_loader_program.v4.ID,
                .owner = ids.NATIVE_LOADER_ID,
            },
        },
    });
    defer {
        testing.deinitTransactionContext(allocator, &tc);
        sig.runtime.testing.deinitAccountMap(cache, allocator);
    }

    var info = try testing.createInstructionInfo(
        &tc,
        bpf_loader_program.v4.ID,
        bpf_loader_program.v4.Instruction{ .retract = .{} },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 0 },
        },
    );
    defer info.deinit(allocator);

    try sig.runtime.executor.pushInstruction(&tc, info);
    const ic = try tc.getCurrentInstructionContext();

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    // check program owner
    {
        account.account.owner = system_program.ID;
        defer account.account.owner = bpf_loader_program.v4.ID;

        try std.testing.expectError(
            error.InvalidAccountOwner,
            checkProgramAccount(allocator, ic, &account, program_key),
        );
    }

    // check writable
    {
        account.context.is_writable = false;
        ic.ixn_info.account_metas.items[0].is_writable = false;

        defer {
            account.context.is_writable = true;
            ic.ixn_info.account_metas.items[0].is_writable = true;
        }

        try std.testing.expectError(
            error.InvalidArgument,
            checkProgramAccount(allocator, ic, &account, program_key),
        );
    }

    // check signer
    {
        ic.ixn_info.account_metas.items[1].is_signer = false;
        defer ic.ixn_info.account_metas.items[1].is_signer = true;

        try std.testing.expectError(
            error.MissingRequiredSignature,
            checkProgramAccount(allocator, ic, &account, program_key),
        );
    }

    // check auth
    {
        _ = try bincode.writeToSlice(
            tc.accounts[0].account.data,
            V4State{
                .slot = 0,
                .status = .retracted,
                .authority_address_or_next_version = Pubkey.ZEROES,
            },
            .{},
        );

        try std.testing.expectError(
            error.IncorrectAuthority,
            checkProgramAccount(allocator, ic, &account, program_key),
        );

        _ = try bincode.writeToSlice(
            tc.accounts[0].account.data,
            V4State{
                .slot = 0,
                .status = .retracted,
                .authority_address_or_next_version = program_key,
            },
            .{},
        );
    }

    // check finalized
    {
        _ = try bincode.writeToSlice(
            tc.accounts[0].account.data,
            V4State{
                .slot = 0,
                .status = .finalized,
                .authority_address_or_next_version = program_key,
            },
            .{},
        );

        try std.testing.expectError(
            error.Immutable,
            checkProgramAccount(allocator, ic, &account, program_key),
        );

        _ = try bincode.writeToSlice(
            tc.accounts[0].account.data,
            V4State{
                .slot = 0,
                .status = .retracted,
                .authority_address_or_next_version = program_key,
            },
            .{},
        );
    }

    try std.testing.expectEqual(
        try checkProgramAccount(allocator, ic, &account, program_key),
        V4State{
            .slot = 0,
            .status = .retracted,
            .authority_address_or_next_version = program_key,
        },
    );
}

test handleExecutionResult {
    var custom_error: ?u32 = null;
    var compute_meter: u64 = 1000;

    // No Error
    try std.testing.expectEqual(null, handleExecutionResult(
        .{ .ok = 0 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ));
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(1000, compute_meter);

    // Generic Error maps to Custom error with code 0
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 0x100000000 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ).?);
    try std.testing.expectEqual(0, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Custom error with specific code
    custom_error = null;
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 101 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ).?);
    try std.testing.expectEqual(101, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Deplete compute meter on non-syscall error
    custom_error = null;
    try std.testing.expectEqual(error.InvalidArgument, handleExecutionResult(
        .{ .err = error.InvalidArgument },
        &custom_error,
        &compute_meter,
        false,
        true,
    ).?);
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(0, compute_meter);

    // TODO: Handle AccessViolation
}
