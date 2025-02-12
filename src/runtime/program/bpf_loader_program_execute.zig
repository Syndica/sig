const std = @import("std");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const bincode = sig.bincode;
const native_cpi = sig.runtime.program.native_cpi;
const program = sig.runtime.program;
const pubkey_utils = sig.runtime.pubkey_utils;
const sysvar = sig.runtime.sysvar;
const system_program = sig.runtime.program.system_program;

const Pubkey = sig.core.Pubkey;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;

const bpf_loader_v1_program = sig.runtime.program.bpf_loader_v1_program;
const bpf_loader_v2_program = sig.runtime.program.bpf_loader_v2_program;
const bpf_loader_v3_program = sig.runtime.program.bpf_loader_v3_program;
const BpfLoaderV3ProgramInstruction = bpf_loader_v3_program.BpfLoaderV3ProgramInstruction;
const BpfLoaderV3ProgramState = bpf_loader_v3_program.BpfLoaderV3ProgramState;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn bpfLoaderProgramExecute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    var program_account = try ic.borrowProgramAccount();

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L408
    if (ids.NATIVE_LOADER_ID.equals(&program_account.getOwner())) {
        program_account.release();
        if (bpf_loader_v1_program.ID.equals(&ic.program_id)) {
            try ic.tc.consumeCompute(bpf_loader_v1_program.COMPUTE_UNITS);
            try ic.tc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_v2_program.ID.equals(&ic.program_id)) {
            try ic.tc.consumeCompute(bpf_loader_v2_program.COMPUTE_UNITS);
            try ic.tc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_v3_program.ID.equals(&ic.program_id)) {
            try ic.tc.consumeCompute(bpf_loader_v3_program.COMPUTE_UNITS);
            return executeBpfLoaderV3ProgramInstruction(allocator, ic);
        } else {
            return InstructionError.IncorrectProgramId;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
    if (!program_account.isExecutable()) {
        try ic.tc.log("Program is not executable", .{});
        return InstructionError.IncorrectProgramId;
    }

    // TODO: Invoke the program
    //     - Load ProgramCacheEntry from transaction program cache
    //     - Execute the program if the ProgramCacheEntry contains a loaded executable
}

pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L477
    const instruction = try ic.deserializeInstruction(allocator, BpfLoaderV3ProgramInstruction);
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
        // .upgrade => executeV3Upgrade(),
        // .set_authority => executeV3SetAuthority(),
        // .close => executeV3Close(),
        // .extend_program => executeV3ExtendProgram(),
        // .set_authority_checked => executeV3SetAuthorityChecked(),
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
    const buffer_account_state = try buffer_account.getState(
        allocator,
        BpfLoaderV3ProgramState,
    );

    if (buffer_account_state != BpfLoaderV3ProgramState.uninitialized) {
        try ic.tc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    try buffer_account.setState(BpfLoaderV3ProgramState{
        .buffer = .{
            .authority_address = ic.accounts[buffer_authority_index].pubkey,
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

    switch (try buffer_account.getState(allocator, BpfLoaderV3ProgramState)) {
        .buffer => |state| {
            if (state.authority_address) |buffer_authority| {
                if (!buffer_authority.equals(&ic.accounts[buffer_authority_index].pubkey)) {
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

    try buffer_account.checkDataIsMutable();

    const start = BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE + @as(usize, offset);
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

    const payer_key = ic.accounts[payer_index].pubkey;
    const program_data_key = ic.accounts[program_data_index].pubkey;

    const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, rent_index);
    const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, clock_index);

    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L575
    try ic.checkNumberOfAccounts(8);

    const authority_key = ic.accounts[authority_index].pubkey;

    // Verify program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L582-L597
    const new_program_id = blk: {
        const program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();
        const program_state = try program_account.getState(allocator, BpfLoaderV3ProgramState);

        if (program_state != BpfLoaderV3ProgramState.uninitialized) {
            try ic.tc.log("Program account already initialized", .{});
            return InstructionError.AccountAlreadyInitialized;
        }

        if (program_account.getData().len < BpfLoaderV3ProgramState.PROGRAM_SIZE) {
            try ic.tc.log("Program account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_account.getLamports() < rent.minimumBalance(program_account.getData().len)) {
            try ic.tc.log("Program account not rent-exempt", .{});
            return InstructionError.ExecutableAccountNotRentExempt;
        }

        break :blk program_account.pubkey;
    };

    // Verify buffer account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L601-L638
    const program_data_len = BpfLoaderV3ProgramState.PROGRAM_DATA_METADATA_SIZE +| max_data_len;
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        errdefer buffer_account.release();
        const buffer_state = try buffer_account.getState(allocator, BpfLoaderV3ProgramState);

        switch (buffer_state) {
            .buffer => |state| {
                if (state.authority_address == null or !state.authority_address.?.equals(&authority_key)) {
                    try ic.tc.log("Buffer and upgrade authority don't match", .{});
                    return InstructionError.IncorrectAuthority;
                }

                // Safe given ic.checkNumberOfAccounts(8) above
                if (!ic.accounts[authority_index].is_signer) {
                    try ic.tc.log("Upgrade authority did not sign", .{});
                    return InstructionError.MissingRequiredSignature;
                }
            },
            else => {
                try ic.tc.log("Invalid Buffer account", .{});
                return InstructionError.InvalidArgument;
            },
        }

        const buffer_data_len = buffer_account.getData().len -| BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE;

        if (buffer_account.getData().len <= BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE) {
            try ic.tc.log("Buffer account too small", .{});
            return InstructionError.AccountDataTooSmall;
        }

        buffer_account.release();

        if (max_data_len < buffer_data_len) {
            try ic.tc.log("Max data length is too small to hold Buffer data", .{});
            return InstructionError.AccountDataTooSmall;
        }

        if (program_data_len > system_program.MAX_PERMITTED_DATA_LENGTH) {
            try ic.tc.log("Max data length is too large", .{});
            return InstructionError.InvalidArgument;
        }
    }

    // Create the ProgramData account
    const derived_key, const bump_seed = pubkey_utils.findProgramAddress(
        &.{&new_program_id.data},
        bpf_loader_v3_program.ID,
    ) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };
    if (!derived_key.equals(&program_data_key)) {
        try ic.tc.log("ProgramData address is not derived", .{});
        return InstructionError.InvalidArgument;
    }

    // Drain the Buffer account to payer before paying for programdata account
    {
        var buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();
        var payer_account = try ic.borrowInstructionAccount(payer_index);
        try payer_account.addLamports(buffer_account.getLamports());
        try buffer_account.setLamports(0);
    }

    // Create the ProgramData account
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L658-L680
    const signer_derived_key = pubkey_utils.createProgramAddress(&.{&new_program_id.data}, &.{bump_seed}, ic.program_id) catch |err| {
        ic.tc.custom_error = @intFromError(err);
        return InstructionError.Custom;
    };
    try native_cpi.executeSystemProgramInstruction(
        allocator,
        ic,
        system_program.SystemProgramInstruction{ .create_account = .{
            .lamports = @max(1, rent.minimumBalance(program_data_len)),
            .space = program_data_len,
            .owner = ic.program_id,
        } },
        &.{
            .{ .pubkey = payer_key, .is_signer = true, .is_writable = true },
            .{ .pubkey = program_data_key, .is_signer = true, .is_writable = true },
            // pass an extra account to avoid the overly strict UnbalancedInstruction error
            // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L668-L669
            .{ .pubkey = ic.accounts[buffer_index].pubkey, .is_signer = false, .is_writable = true },
        },
        &.{signer_derived_key},
    );

    // Load and verify the program bits
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L683-L698
    {
        const buffer_account = try ic.borrowInstructionAccount(buffer_index);
        defer buffer_account.release();
        if (buffer_account.getData().len < BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE)
            return InstructionError.AccountDataTooSmall;
        try deployProgram(
            allocator,
            ic,
            new_program_id,
            ic.program_id,
            BpfLoaderV3ProgramState.PROGRAM_SIZE +| program_data_len,
            buffer_account.getData()[BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE..],
            clock.slot,
        );
    }

    // Update the PorgramData account and record the program bits
    // https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L704-L726
    {
        var program_data = try ic.borrowInstructionAccount(program_data_index);
        defer program_data.release();
        try program_data.setState(BpfLoaderV3ProgramState{ .program_data = .{
            .slot = clock.slot,
            .upgrade_authority_address = authority_key,
        } });
        const dst = program_data.getDataMutable();

        var buffer = try ic.borrowInstructionAccount(buffer_index);
        defer buffer.release();
        const src = buffer.getData();

        @memcpy(dst, src);

        try buffer.setDataLength(allocator, ic.tc, BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE);
    }

    // Update the program account
    // [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/programs/bpf_loader/src/lib.rs#L729-735
    {
        var program_account = try ic.borrowInstructionAccount(program_index);
        defer program_account.release();
        try program_account.setState(BpfLoaderV3ProgramState{ .program = .{
            .programdata_address = program_data_key,
        } });
        try program_account.setExecutable(true);
    }

    try ic.tc.log("Deployed program {}", .{new_program_id});
}

pub fn deployProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    program_id: Pubkey,
    owner_id: Pubkey,
    program_len: usize,
    program_data: []const u8,
    slot: u64,
) InstructionError!void {
    // TODO: Implement
    _ = allocator;
    _ = ic;
    _ = program_id;
    _ = owner_id;
    _ = program_len;
    _ = program_data;
    _ = slot;
}

test "executeV3InitializeBuffer" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = BpfLoaderV3ProgramState.uninitialized;
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(BpfLoaderV3ProgramState));
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_state = BpfLoaderV3ProgramState{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(BpfLoaderV3ProgramState));
    defer allocator.free(final_buffer_account_data);
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});

    try expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_v3_program,
        BpfLoaderV3ProgramInstruction.initialize_buffer,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = initial_buffer_account_data,
                    .owner = bpf_loader_v3_program.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_v3_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_v3_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_v3_program.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_v3_program.ID,
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

    const initial_buffer_account_state = BpfLoaderV3ProgramState{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(BpfLoaderV3ProgramState) + offset + source.len);
    defer allocator.free(initial_buffer_account_data);
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});

    const final_buffer_account_data = try allocator.dupe(u8, initial_buffer_account_data);
    defer allocator.free(final_buffer_account_data);
    const start = BpfLoaderV3ProgramState.BUFFER_METADATA_SIZE + offset;
    const end = start +| source.len;
    @memcpy(final_buffer_account_data[start..end], &source);

    try expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_v3_program,
        BpfLoaderV3ProgramInstruction{
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
                    .owner = bpf_loader_v3_program.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_v3_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = bpf_loader_v3_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = buffer_account_key,
                    .data = final_buffer_account_data,
                    .owner = bpf_loader_v3_program.ID,
                },
                .{
                    .pubkey = buffer_authority_key,
                },
                .{
                    .pubkey = bpf_loader_v3_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
        },
    );
}

// test "executeDeployWithMaxDataLen" {
//     const Pubkey = sig.core.Pubkey;

//     const expectProgramExecuteResult =
//         sig.runtime.program.test_program_execute.expectProgramExecuteResult;

//     const allocator = std.testing.allocator;

//     var prng = std.Random.DefaultPrng.init(5083);

//     const payer_account_key = Pubkey.initRandom(prng.random());
//     const program_data_account_key = Pubkey.initRandom(prng.random());
//     const program_account_key = Pubkey.initRandom(prng.random());
//     const buffer_account_key = Pubkey.initRandom(prng.random());

//     const max_data_len = 1024;

//     try expectProgramExecuteResult(
//         std.testing.allocator,
//         bpf_loader_v3_program,
//         BpfLoaderV3ProgramInstruction{
//             .deploy_with_max_data_len = max_data_len,
//         },
//         &.{
//             .{ .index_in_transaction = 0, .is_signer = true, .is_writable = true },
//             .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
//             .{ .index_in_transaction = 2, .is_signer = false, .is_writable = true },
//             .{ .index_in_transaction = 3, .is_signer = false, .is_writable = true },
//             .{ .index_in_transaction = 4, .is_signer = false, .is_writable = false },
//             .{ .index_in_transaction = 5, .is_signer = false, .is_writable = false },
//             .{ .index_in_transaction = 6, .is_signer = false, .is_writable = false },
//             .{ .index_in_transaction = 7, .is_signer = true, .is_writable = false },
//         },
//         .{
//             .accounts = &.{
//                 .{
//                     .pubkey = payer_account_key,
//                 },
//                 .{
//                     .pubkey = program_data_account_key,
//                 },
//                 .{
//                     .pubkey = program_account_key,
//                 },
//                 .{
//                     .pubkey = buffer_account_key,
//                 },
//                 .{
//                     .pubkey = sysvar.Rent.ID,
//                 },
//                 .{
//                     .pubkey = sysvar.Clock.ID,
//                 },
//                 .{
//                     .pubkey = program.system_program.ID,
//                 },
//                 .{
//                     .pubkey = buffer_authority_key,
//                 },
//                 .{
//                     .pubkey = bpf_loader_v3_program.ID,
//                 },
//             },
//             .compute_meter = bpf_loader_v3_program.COMPUTE_UNITS,
//         },
//         .{
//             .accounts = &.{
//                 .{
//                     .pubkey = program_account_key,
//                     .data = program_account_data,
//                     .owner = bpf_loader_v3_program.ID,
//                 },
//                 .{
//                     .pubkey = program_data_account_key,
//                     .data = program_data_account_data,
//                     .owner = bpf_loader_v3_program.ID,
//                 },
//             },
//         },
//     );
// }
