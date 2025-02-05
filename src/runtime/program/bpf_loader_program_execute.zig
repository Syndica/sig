const std = @import("std");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const bpf_loader_v1_program = sig.runtime.program.bpf_loader_v1_program;
const bpf_loader_v2_program = sig.runtime.program.bpf_loader_v2_program;
const bpf_loader_v3_program = sig.runtime.program.bpf_loader_v3_program;

const InstructionError = sig.core.instruction.InstructionError;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;

const BpfLoaderV3ProgramInstruction = bpf_loader_v3_program.BpfLoaderV3ProgramInstruction;
const BpfLoaderV3ProgramState = bpf_loader_v3_program.BpfLoaderV3ProgramState;

// TODO: Handle allocator errors with .Custom and return InstructionError

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn executeBpfLoaderProgramInstruction(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
) !void {
    const program_account = try eic.getBorrowedAccount(eic.program_index);

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L408
    if (ids.NATIVE_LOADER_ID.equals(program_account.getOwner())) {
        program_account.release();
        if (bpf_loader_v1_program.id().equals(eic.program_id)) {
            eic.etc.consumeCompute(bpf_loader_v1_program.compute_units());
            eic.etc.log("Deprecated loader is no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_v2_program.id().equals(eic.program_id)) {
            eic.etc.consumeCompute(bpf_loader_v2_program.compute_units());
            eic.etc.log("BPF loader management instructions are no longer supported", .{});
            return InstructionError.UnsupportedProgramId;
        } else if (bpf_loader_v3_program.id().equals(eic.program_id)) {
            eic.etc.consumeCompute(bpf_loader_v3_program.compute_units());
            executeBpfLoaderV3ProgramInstruction(allocator, eic);
        } else {
            return InstructionError.IncorrectProgramId;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
    if (!program_account.isExecutable()) {
        eic.etc.log("Program is not executable", .{});
        return InstructionError.IncorrectProgramId;
    }

    // TODO: Invoke the program
    //     - Load ProgramCacheEntry from transaction program cache
    //     - Execute the program if the ProgramCacheEntry contains a loaded executable
}

pub fn executeBpfLoaderV3ProgramInstruction(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
) !void {

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L477
    const instruction = try sig.bincode.readFromSlice(
        allocator,
        BpfLoaderV3ProgramInstruction,
        eic.instruction_data,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .initialize_buffer => executeV3InitializeBuffer(allocator, eic),
        .write => |args| executeV3Write(allocator, eic, args.offset, args.bytes),
        // .deploy_with_max_data_len => executeV3DeployWithMaxDataLen(),
        // .upgrade => executeV3Upgrade(),
        // .set_authority => executeV3SetAuthority(),
        // .close => executeV3Close(),
        // .extend_program => executeV3ExtendProgram(),
        // .set_authority_checked => executeV3SetAuthorityChecked(),
        else => @panic("Instruction not implemented"),
    };
}

pub fn executeV3InitializeBuffer(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
) !void {
    try eic.checkNumberOfAccounts(2);
    const buffer_account = try eic.getBorrowedAccount(0);
    const buffer_account_state = try buffer_account.getState(allocator, BpfLoaderV3ProgramState);

    if (buffer_account_state != BpfLoaderV3ProgramState.uninitialized) {
        eic.etc.log("Buffer account already initialized", .{});
        return InstructionError.AccountAlreadyInitialized;
    }

    const buffer_authority = try eic.getAccountPubkey(1);

    buffer_account.setState(allocator, BpfLoaderV3ProgramState.buffer{
        .authority_address = buffer_authority,
    });
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L496-L526
pub fn executeV3Write(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    offset: u32,
    bytes: []const u8,
) void {
    try eic.checkNumberOfAccounts(2);

    const buffer_account = try eic.getBorrowedAccount(0);
    defer buffer_account.release();

    const buffer_account_state = try buffer_account.getState(allocator, BpfLoaderV3ProgramState);
    const buffer_authority = switch (buffer_account_state) {
        .buffer => |state| if (state.authority_address) |addr| addr else {
            eic.etc.log("Buffer is immutable", .{});
            return InstructionError.Immutable;
        },
        else => {
            eic.etc.log("Invalid Buffer account", .{});
            return InstructionError.InvalidAccountData;
        },
    };

    if (buffer_authority.equals(try eic.getAccountPubkey(1))) {
        eic.etc.log("Incorrect buffer authority provided", .{});
        return InstructionError.IncorrectAuthority;
    }

    eic.checkIsSigner(u16, 1) catch |err| {
        eic.etc.log("Buffer authority did not sign", .{});
        return err;
    };

    const buffer_account_data = try buffer_account.getDataMutable();
    const start_offset = BpfLoaderV3ProgramState.sizeOfBufferMetadata() + @as(usize, offset);
    const end_offset = BpfLoaderV3ProgramState.sizeOfBufferMetadata() + @as(usize, offset) + bytes.len;

    if (buffer_account_data.len < end_offset) {
        eic.etc.log("Write overflow: {} < {}", .{ buffer_account_data.len, end_offset });
        return InstructionError.AccountDataTooSmall;
    }

    @memcpy(buffer_account_data[start_offset..end_offset], bytes);
}

// pub fn executeV3DeployWithMaxDataLen(allocator: std.mem.Allocator, eic: *ExecuteInstructionContext, max_data_len: usize) void {
//     @panic("Not implemented");
// }

test "executeV3InitializeBuffer" {
    const Pubkey = sig.core.Pubkey;
    const testing = sig.runtime.program.test_execute;

    const prng = std.Random.DefaultPrng.init(5083);
    const allocator = std.heap.page_allocator;

    const buffer_authority = Pubkey.initRandom(prng.random());

    const uninitialized_state_bytes = try sig.bincode.writeAlloc(
        allocator,
        BpfLoaderV3ProgramState,
        BpfLoaderV3ProgramState.uninitialized,
        .{},
    );
    defer allocator.free(uninitialized_state_bytes);

    const initialized_state_bytes = try sig.bincode.writeAlloc(
        allocator,
        BpfLoaderV3ProgramState,
        BpfLoaderV3ProgramState.buffer{
            .authority_address = buffer_authority,
        },
        .{},
    );

    try testing.expectInstructionExecutionResult(
        allocator,
        executeBpfLoaderProgramInstruction,
        BpfLoaderV3ProgramInstruction.initialize_buffer,
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = buffer_authority,
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
        },
        &.{
            .{
                .data = uninitialized_state_bytes,
            },
            .{},
        },
        &.{
            .{
                .data = initialized_state_bytes,
            },
            .{},
        },
        .{},
    );
}
