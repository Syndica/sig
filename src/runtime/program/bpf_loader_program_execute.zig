const std = @import("std");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const bincode = sig.bincode;

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
        .initialize_buffer => executeV3InitializeBuffer(allocator, ic),
        .write => |args| executeV3Write(allocator, ic, args.offset, args.bytes),
        // .deploy_with_max_data_len => executeV3DeployWithMaxDataLen(),
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

    const start = BpfLoaderV3ProgramState.sizeOfBufferMetadata() + @as(usize, offset);
    const end = start +| bytes.len;

    if (end > buffer_account.getData().len) {
        try ic.tc.log("Write overflow: {} < {}", .{ bytes.len, end });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(buffer_account.account.data[start..end], bytes);
}

test "executeInitializeBuffer" {
    const Pubkey = sig.core.Pubkey;

    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const buffer_account_key = Pubkey.initRandom(prng.random());
    const buffer_authority_key = Pubkey.initRandom(prng.random());

    const initial_buffer_account_state = BpfLoaderV3ProgramState.uninitialized;
    const initial_buffer_account_data = try allocator.alloc(u8, @sizeOf(BpfLoaderV3ProgramState));
    @memset(initial_buffer_account_data, 0);
    _ = try bincode.writeToSlice(initial_buffer_account_data, initial_buffer_account_state, .{});
    defer allocator.free(initial_buffer_account_data);

    const final_buffer_account_state = BpfLoaderV3ProgramState{ .buffer = .{
        .authority_address = buffer_authority_key,
    } };
    const final_buffer_account_data = try allocator.alloc(u8, @sizeOf(BpfLoaderV3ProgramState));
    @memset(final_buffer_account_data, 0);
    _ = try bincode.writeToSlice(final_buffer_account_data, final_buffer_account_state, .{});
    defer allocator.free(final_buffer_account_data);

    try expectProgramExecuteResult(
        std.testing.allocator,
        bpf_loader_v3_program,
        BpfLoaderV3ProgramInstruction.initialize_buffer,
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
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
