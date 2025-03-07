const std = @import("std");
const sig = @import("../../../sig.zig");

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const native_cpi = sig.runtime.program.native_cpi;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const svm = sig.svm;
const system_program = sig.runtime.program.system_program;
const bpf_loader_program = sig.runtime.program.bpf_loader_program;

const Pubkey = sig.core.Pubkey;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const LogCollector = sig.runtime.LogCollector;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    var program_account = try ic.borrowProgramAccount(ic.program_meta.index_in_transaction);

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L408
    if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner)) {
        program_account.release();
        if (bpf_loader_program.v1.ID.equals(&ic.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v1.COMPUTE_UNITS);
            try ic.tc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v2.ID.equals(&ic.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v2.COMPUTE_UNITS);
            try ic.tc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_program.v3.ID.equals(&ic.program_meta.pubkey)) {
            try ic.tc.consumeCompute(bpf_loader_program.v3.COMPUTE_UNITS);
            return executeBpfLoaderV3ProgramInstruction(allocator, ic);
        } else {
            return InstructionError.IncorrectProgramId;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
    if (!program_account.account.executable) {
        try ic.tc.log("Program is not executable", .{});
        return InstructionError.IncorrectProgramId;
    }

    // TODO: The following program invocation is simplified. The final implementation will depending on our approach
    // to program caching and other features.

    //
    // Start Program Deployment
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L115
    //

    // Setup environment
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L127-L132
    var environment = svm.BuiltinProgram{};
    defer environment.deinit(allocator);
    _ = environment.functions.registerHashed(allocator, "sol_log_", svm.syscalls.log) catch {
        return InstructionError.ProgramEnvironmentSetupFailure;
    };

    // Parse ELF and create executable
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L136-L144
    var executable = svm.Executable.fromBytes(allocator, program_account.account.data, &environment, .{}) catch |err| {
        try ic.tc.log("{}", .{err});
        return InstructionError.InvalidAccountData;
    };
    defer executable.deinit(allocator);

    // Executable verification
    // This logic is implemented during ELF parsing and executable creation TODO: @Rexicon226 to confirm please
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L147-L151

    // Program caching
    // Program caching is not implemented yet.
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L153-L176

    //
    // End Program Deployment
    //

    // Load program from cache
    // Program caching is not implemented yet. (This load is subsituted by the deployment stage above)
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L461-L475

    //
    // Start Program Execution
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1557
    //

    // Serialize parameters
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588

    // Save account addresses (Low priority)
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1597

    const execution_result = blk: {
        const initial_compute_available = ic.tc.compute_meter;

        // TODO: Create VM
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1615-L1623
        const PAGE_SIZE: u64 = 32 * 1024;

        const stack_size = executable.config.stackSize();
        const heap_size = 10; // ic.tc.compute_budget.heap_size;
        const cost = std.mem.alignBackward(u64, heap_size -| 1, PAGE_SIZE) / PAGE_SIZE;
        const heap_cost = cost * 10; // ic.tc.compute_budget.heap_cost;

        // TODO: Replace with mem pool similar to agave?
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L306-L307
        const stack = allocator.alloc(u8, stack_size) catch {
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer allocator.free(stack);
        const heap = allocator.alloc(u8, heap_size) catch {
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer allocator.free(heap);

        // TODO: Create memory map
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L256-L280
        // const memory_mapping = createMemoryMapping(
        //     executable,
        //     stack,
        //     heap,
        //     regions,
        // );

        // TODO: Set syscall context
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L280-L285

        // Create VM
        // var vm = try svm.Vm.init(
        //     allocator,
        //     executable,
        //     memory_map,
        //     &environment,
        //     .noop,
        //     stack_size,
        // );

        // TODO: Execute VM
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1625-L1638

        // TODO: Log return data
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1646-L1651

        // TODO: Handle result
        // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1651-L1725

        _ = initial_compute_available;
        _ = heap_cost;

        break :blk null;
    };

    _ = execution_result;
}

pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L477
    const instruction = try ic.deserializeInstruction(allocator, bpf_loader_program.v3.Instruction);
    defer sig.bincode.free(allocator, instruction);

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
        .set_authority => executeV3SetAuthority(
            allocator,
            ic,
        ),
        .set_authority_checked => executeV3SetAuthorityChecked(
            allocator,
            ic,
        ),
        // TODO: Implement the following instructions
        // .upgrade => executeV3Upgrade(),
        // .close => executeV3Close(),
        // .extend_program => executeV3ExtendProgram(),
        else => @panic("Instruction not implemented"),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L479-L495
pub fn executeV3InitializeBuffer(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    try ic.checkNumberOfAccounts(2);

    const buffer_account_index = 0;
    const buffer_authority_index = 1;

    var buffer_account = try ic.borrowInstructionAccount(buffer_account_index);
    defer buffer_account.release();
    const buffer_account_state = try buffer_account.deserializeFromAccountData(
        allocator,
        bpf_loader_program.v3.State,
    );

    if (buffer_account_state != bpf_loader_program.v3.State.uninitialized) {
        try ic.tc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    try buffer_account.serializeIntoAccountData(bpf_loader_program.v3.State{
        .buffer = .{
            .authority_address = ic.account_metas.buffer[buffer_authority_index].pubkey,
        },
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L496-L526
pub fn executeV3Write(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    offset: u32,
    bytes: []const u8,
) InstructionError!void {
    try ic.checkNumberOfAccounts(2);

    const buffer_account_index = 0;
    const buffer_authority_index = 1;

    var buffer_account = try ic.borrowInstructionAccount(buffer_account_index);
    defer buffer_account.release();

    switch (try buffer_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .buffer => |state| {
            if (state.authority_address) |buffer_authority| {
                if (!buffer_authority.equals(&ic.account_metas.buffer[buffer_authority_index].pubkey)) {
                    try ic.tc.log("Incorrect buffer authority provided", .{});
                    return InstructionError.IncorrectAuthority;
                }

                if (!try ic.isIndexSigner(buffer_authority_index)) {
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

    if (buffer_account.checkDataIsMutable()) |err| return err;

    const start = bpf_loader_program.v3.State.BUFFER_METADATA_SIZE + @as(usize, offset);
    const end = start +| bytes.len;

    if (end > buffer_account.getData().len) {
        try ic.tc.log("Write overflow: {} < {}", .{ bytes.len, end });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(buffer_account.account.data[start..end], bytes);
}

/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565-L738
pub fn executeV3DeployWithMaxDataLen(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    max_data_len: u64,
) InstructionError!void {
    const payer_index = 0;
    const program_data_index = 1;
    const program_index = 2;
    const buffer_index = 3;
    const rent_index = 4;
    const clock_index = 5;
    // const system_program_index = 6;
    const authority_index = 7;

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L565
    try ic.checkNumberOfAccounts(4);

    // Safety: at least 4 accounts are present
    const payer_key = ic.account_metas.buffer[payer_index].pubkey;
    const program_data_key = ic.account_metas.buffer[program_data_index].pubkey;

    const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, rent_index);
    const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, clock_index);

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L575
    try ic.checkNumberOfAccounts(8);

    // Safety: at least 8 accounts are present
    const authority_key = ic.account_metas.buffer[authority_index].pubkey;

    // Verify program account and retrieve its program id
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L582-L597
    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();

        const program_state = try program_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State);

        if (program_state != bpf_loader_program.v3.State.uninitialized) {
            try ic.tc.log("Program account already initialized", .{});
            return InstructionError.AccountAlreadyInitialized;
        }

        if (program_account.getData().len < bpf_loader_program.v3.State.PROGRAM_SIZE) {
            try ic.tc.log("Program account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_account.account.lamports < rent.minimumBalance(program_account.getData().len)) {
            try ic.tc.log("Program account not rent-exempt", .{});
            return InstructionError.ExecutableAccountNotRentExempt;
        }

        break :blk program_account.pubkey;
    };

    // Verify buffer account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L601-L638
    const program_data_len = bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        switch (try buffer_account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
            .buffer => |state| {
                if (state.authority_address == null or !state.authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }

                // Safety: at least 8 accounts are present
                if (!ic.account_metas.buffer[authority_index].is_signer) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        if (buffer_account.getData().len <= bpf_loader_program.v3.State.BUFFER_METADATA_SIZE) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        const buffer_data_len = buffer_account.getData().len -| bpf_loader_program.v3.State.BUFFER_METADATA_SIZE;

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
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };

    if (!derived_key.equals(&program_data_key)) {
        try ic.tc.log("ProgramData address is not derived", .{});
        return InstructionError.InvalidArgument;
    }

    // Drain the Buffer account to payer before paying for program data account
    {
        var buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        var payer_account = try ic.borrowInstructionAccount(payer_index);
        defer payer_account.release();

        try payer_account.addLamports(buffer_account.account.lamports);
        try buffer_account.setLamports(0);
    }

    // Create the ProgramData account
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L658-L680
    const signer_derived_key = pubkey_utils.createProgramAddress(
        &.{&new_program_id.data},
        &.{bump_seed},
        ic.program_meta.pubkey,
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };

    const account_metas = &.{
        .{ .pubkey = payer_key, .is_signer = true, .is_writable = true },
        .{ .pubkey = program_data_key, .is_signer = true, .is_writable = true },
        // pass an extra account to avoid the overly strict UnbalancedInstruction error
        // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L668-L669
        .{ .pubkey = ic.account_metas.buffer[buffer_index].pubkey, .is_signer = false, .is_writable = true },
    };

    const data = bincode.writeAlloc(
        allocator,
        system_program.Instruction{
            .create_account = .{
                .lamports = @max(1, rent.minimumBalance(program_data_len)),
                .space = program_data_len,
                .owner = ic.program_meta.pubkey,
            },
        },
        .{},
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };
    defer allocator.free(data);

    try native_cpi.execute(
        allocator,
        ic,
        Instruction{
            .program_pubkey = system_program.ID,
            .account_metas = account_metas,
            .serialized = data,
        },
        &.{signer_derived_key},
    );

    // Load and verify the program bits and deploy the program
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L683-L698
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        if (buffer_account.getData().len < bpf_loader_program.v3.State.BUFFER_METADATA_SIZE)
            return InstructionError.AccountDataTooSmall;

        try deployProgram(
            allocator,
            new_program_id,
            ic.program_meta.pubkey,
            bpf_loader_program.v3.State.PROGRAM_SIZE +| program_data_len,
            buffer_account.getData()[bpf_loader_program.v3.State.BUFFER_METADATA_SIZE..],
            clock.slot,
            ic.tc.feature_set,
            if (ic.tc.log_collector != null) &ic.tc.log_collector.? else null,
        );
    }

    // Update the PorgramData account and record the program bits
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L704-L726
    {
        var program_data_account = try ic.borrowInstructionAccount(program_data_index);
        defer program_data_account.release();
        try program_data_account.serializeIntoAccountData(bpf_loader_program.v3.State{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });
        const program_data = try program_data_account.getDataMutable();

        var buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();

        @memcpy(program_data.ptr, buffer_account.getData());

        try buffer_account.setDataLength(allocator, ic.tc, bpf_loader_program.v3.State.BUFFER_METADATA_SIZE);
    }

    // Update the program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L729-735
    {
        var program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();
        try program_account.serializeIntoAccountData(bpf_loader_program.v3.State{ .program = .{
            .programdata_address = program_data_key,
        } });
        // TODO: Is it okay to pass rent here which is loaded from the sysvar_cache rather than the rent stored in the
        // transaction context in agave?
        try program_account.setExecutable(true, rent);
    }

    try ic.tc.log("Deployed program {}", .{new_program_id});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L946-L1010
pub fn executeV3SetAuthority(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.info.checkNumberOfAccounts(2);

    const account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const present_authority_key = ic.info.getAccountMetaAtIndex(1).?.pubkey;
    const new_authority = if (ic.info.getAccountMetaAtIndex(2)) |meta| meta.pubkey else null;

    switch (try account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .buffer => |buffer| {
            if (new_authority == null) {
                try ic.tc.log("Buffer authority is not optional", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!ic.info.getAccountMetaAtIndex(1).?.is_signer) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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
            if (!data.upgrade_authority_address.?.equals(present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!ic.info.getAccountMetaAtIndex(1).?.is_signer) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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

    try ic.tc.log("New authority {?}", .{new_authority});
}

/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/programs/bpf_loader/src/lib.rs#L1011-L1083
pub fn executeV3SetAuthorityChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const enable_bpf_loader_set_authority_checked_ix = 
        Pubkey.parseBase58String("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL") catch unreachable; 

    if (!ic.tc.feature_set.active.contains(enable_bpf_loader_set_authority_checked_ix)) {
        return InstructionError.InvalidInstructionData;
    }

    try ic.info.checkNumberOfAccounts(3);

    const account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const present_authority_key = ic.info.getAccountMetaAtIndex(1).?.pubkey;
    const new_authority = ic.info.getAccountMetaAtIndex(2).?.pubkey;

    switch (try account.deserializeFromAccountData(allocator, bpf_loader_program.v3.State)) {
        .buffer => |buffer| {
            if (buffer.authority_address == null) {
                try ic.tc.log("Buffer is immutable", .{});
                return InstructionError.Immutable;
            }
            if (!buffer.authority_address.?.equals(present_authority_key)) {
                try ic.tc.log("Incorrect buffer authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!ic.info.getAccountMetaAtIndex(1).?.is_signer) {
                try ic.tc.log("Buffer authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!ic.info.getAccountMetaAtIndex(2).?.is_signer) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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
            if (!data.upgrade_authority_address.?.equals(present_authority_key)) {
                try ic.tc.log("Incorrect upgrade authority provided", .{});
                return InstructionError.IncorrectAuthority;
            }
            if (!ic.info.getAccountMetaAtIndex(1).?.is_signer) {
                try ic.tc.log("Upgrade authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            if (!ic.info.getAccountMetaAtIndex(2).?.is_signer) {
                try ic.tc.log("New authority did not sign", .{});
                return InstructionError.MissingRequiredSignature;
            }
            try account.serializeIntoAccountData(bpf_loader_program.v3.State{
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

    try ic.tc.log("New authority {?}", .{new_authority});
}

/// TODO: This function depends on syscalls and program cache implementations
/// which is are not implemented yet. It does not affect the account state resulting from
/// the execution of bpf loader instructions unless it returns an error.
/// [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/programs/bpf_loader/src/lib.rs#L115
/// [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/program/fd_bpf_loader_program.c#L238
pub fn deployProgram(
    allocator: std.mem.Allocator,
    program_id: Pubkey,
    owner_id: Pubkey,
    program_len: usize,
    program_data: []const u8,
    slot: u64,
    feature_set: FeatureSet,
    maybe_log_collector: ?*LogCollector,
) InstructionError!void {
    _ = allocator;
    _ = program_id;
    _ = owner_id;
    _ = program_len;
    _ = program_data;
    _ = slot;
    _ = feature_set;
    _ = maybe_log_collector;
}

test "executeV3InitializeBuffer" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = bpf_loader_program.v3.State.uninitialized;
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_state = bpf_loader_program.v3.State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State));
    defer allocator.free(final_buffer_account_data);
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});

    try expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_program.v3,
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
    );
}

test "executeV3Write" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const offset = 10;
    const source = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };

    const initial_buffer_account_state = bpf_loader_program.v3.State{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(bpf_loader_program.v3.State) + offset + source.len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    const start = bpf_loader_program.v3.State.BUFFER_METADATA_SIZE + offset;
    const end = start +| source.len;
    @memcpy(final_buffer_account_data[start..end], &source);

    try expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_program.v3,
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
    );
}

test "executeDeployWithMaxDataLen" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const payer_account_key = Pubkey.initRandom(prng.random());
    const program_account_key = Pubkey.initRandom(prng.random());
    const program_data_account_key = try pubkey_utils.createProgramAddress(
        &.{&program_account_key.data},
        &.{255},
        bpf_loader_program.v3.ID,
    );
    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const rent = sysvar.Rent.DEFAULT;

    const max_data_len = 1024;

    const initial_program_account_data = try allocator.alloc(u8, bpf_loader_program.v3.State.PROGRAM_SIZE);
    defer allocator.free(initial_program_account_data);
    @memset(initial_program_account_data, 0);
    _ = try bincode.writeToSlice(initial_program_account_data, bpf_loader_program.v3.State.uninitialized, .{});
    const initial_program_account_lamports = rent.minimumBalance(initial_program_account_data.len);

    const final_program_account_data = try allocator.alloc(u8, bpf_loader_program.v3.State.PROGRAM_SIZE);
    defer allocator.free(final_program_account_data);
    @memset(final_program_account_data, 0);
    _ = try bincode.writeToSlice(final_program_account_data, bpf_loader_program.v3.State{ .program = .{
        .programdata_address = program_data_account_key,
    } }, .{});

    const initial_buffer_account_data = try allocator.alloc(u8, max_data_len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, bpf_loader_program.v3.State{ .buffer = .{ .authority_address = buffer_authority_key } }, .{});
    const initial_buffer_account_lamports = 1_000;
    const final_buffer_account_data = initial_buffer_account_data[0..bpf_loader_program.v3.State.BUFFER_METADATA_SIZE];

    const final_program_data_account_size = bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    const final_program_data_account_data = try allocator.alloc(u8, final_program_data_account_size);
    defer allocator.free(final_program_data_account_data);
    @memset(final_program_data_account_data, 0);
    _ = try bincode.writeToSlice(final_program_data_account_data, bpf_loader_program.v3.State{ .buffer = .{ .authority_address = buffer_authority_key } }, .{});
    // TODO: set buffer account data to random bytes and set as final program account data

    const log_collector = sig.runtime.LogCollector.default(allocator);
    defer log_collector.deinit();

    expectProgramExecuteResult(
        allocator,
        bpf_loader_program.v3,
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
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_size)),
                },
                .{
                    .pubkey = program_data_account_key,
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
                    .pubkey = program.system_program.ID,
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
                .rent = sysvar.Rent.DEFAULT,
                .clock = sysvar.Clock.DEFAULT,
            },
            .compute_meter = bpf_loader_program.v3.COMPUTE_UNITS + 150, // TODO: Should we need extra for system program cpi???
            .log_collector = log_collector,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = payer_account_key,
                    .lamports = initial_buffer_account_lamports,
                },
                .{
                    .pubkey = program_data_account_key,
                    .lamports = @max(1, rent.minimumBalance(final_program_data_account_size)),
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
                    .pubkey = program.system_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                    .executable = true,
                },
                .{ .pubkey = buffer_authority_key },
                .{
                    .pubkey = bpf_loader_program.v3.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .accounts_resize_delta = @intCast(final_buffer_account_data.len + bpf_loader_program.v3.State.PROGRAM_DATA_METADATA_SIZE +| max_data_len -| initial_buffer_account_data.len),
            .sysvar_cache = .{
                .rent = sysvar.Rent.DEFAULT,
                .clock = sysvar.Clock.DEFAULT,
            },
        },
    ) catch |err| {
        for (log_collector.collect()) |msg| {
            std.debug.print("{any}\n", .{msg});
        }
        return err;
    };
}
