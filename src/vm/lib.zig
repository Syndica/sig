const std = @import("std");
const sig = @import("../sig.zig");

const executable = @import("executable.zig");
pub const sbpf = @import("sbpf.zig");
pub const elf = @import("elf.zig");
pub const memory = @import("memory.zig");
pub const tests = @import("tests.zig");
pub const interpreter = @import("interpreter.zig");
pub const syscalls = @import("syscalls/lib.zig");
pub const environment = @import("environment.zig");

pub const Executable = executable.Executable;
pub const Registry = executable.Registry;
pub const Assembler = executable.Assembler;
pub const Config = executable.Config;
pub const Vm = interpreter.Vm;
pub const Section = executable.Section;
pub const SyscallFn = syscalls.SyscallFn;
pub const SyscallMap = syscalls.Syscall.Registry;
pub const Environment = environment.Environment;

const InstructionError = sig.core.instruction.InstructionError;

pub const SyscallError = error{
    InvalidString,
    Abort,
    Panic,
    InvokeContextBorrowFailed,
    MalformedSignerSeed,
    BadSeeds,
    ProgramNotSupported,
    UnalignedPointer,
    TooManySigners,
    InstructionTooLarge,
    TooManyAccounts,
    CopyOverlapping,
    ReturnDataTooLarge,
    TooManySlices,
    InvalidLength,
    MaxInstructionDataLenExceeded,
    MaxInstructionAccountsExceeded,
    MaxInstructionAccountInfosExceeded,
    InvalidAttribute,
    InvalidPointer,
    ArithmeticOverflow,
    InvalidParameters,
    InvalidEndianness,
};

pub const EbpfError = error{
    ElfError,
    FunctionAlreadyRegistered,
    CallDepthExceeded,
    ExitRootCallFrame,
    DivisionByZero,
    DivideOverflow,
    ExecutionOverrun,
    CallOutsideTextSegment,
    ExceededMaxInstructions,
    JitNotCompiled,
    InvalidVirtualAddress,
    InvalidMemoryRegion,
    AccessViolation,
    StackAccessViolation,
    InvalidInstruction,
    UnsupportedInstruction,
    // ExhaustedTextSegment,
    // LibcInvocationFailed,
    VerifierError,
    // SyscallError, // Sig never returns an Ebpf syscall error
};

pub const State = struct {
    vm: Vm,
    stack: []align(16) u8,
    heap: []align(16) u8,
    regions: []memory.Region,

    pub fn deinit(self: *State, allocator: std.mem.Allocator) void {
        self.vm.deinit();
        allocator.free(self.stack);
        allocator.free(self.heap);
        allocator.free(self.regions);
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L299-L300
pub fn init(
    allocator: std.mem.Allocator,
    tc: *sig.runtime.TransactionContext,
    exe: *const Executable,
    trailing_regions: []const memory.Region,
    map: *const SyscallMap,
    instruction_data_offset: u64,
) !State {
    const PAGE_SIZE: u64 = 32 * 1024;

    const stack_size = exe.config.stackSize();
    const heap_size = tc.compute_budget.heap_size;
    const cost = std.mem.alignBackward(u64, heap_size -| 1, PAGE_SIZE) / PAGE_SIZE;
    const heap_cost = cost * tc.compute_budget.heap_cost;
    try tc.consumeCompute(heap_cost);

    const stack_gap: u64 = if (!exe.version.enableDynamicStackFrames() and
        exe.config.enable_stack_frame_gaps)
        exe.config.stack_frame_size
    else
        0;

    const heap = try allocator.alignedAlloc(u8, .fromByteUnits(16), heap_size);
    @memset(heap, 0);
    errdefer allocator.free(heap);

    const stack = try allocator.alignedAlloc(u8, .fromByteUnits(16), stack_size);
    @memset(stack, 0);
    errdefer allocator.free(stack);

    // 3 regions for the input, stack, and heap.
    const regions = try allocator.alloc(memory.Region, 3 + trailing_regions.len);
    errdefer allocator.free(regions);

    regions[0..3].* = .{
        exe.getProgramRegion(),
        .initGapped(.mutable, stack, memory.STACK_START, stack_gap),
        .init(.mutable, heap, memory.HEAP_START),
    };
    @memcpy(regions[3..], trailing_regions);

    const memory_map = try memory.MemoryMap.init(
        allocator,
        regions,
        exe.version,
        exe.config,
    );
    errdefer memory_map.deinit(allocator);

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L280-L285
    // TODO: Set syscall context

    const sbpf_vm = try Vm.init(
        allocator,
        exe,
        memory_map,
        map,
        stack.len,
        instruction_data_offset,
        tc,
    );

    return .{
        .vm = sbpf_vm,
        .stack = stack,
        .heap = heap,
        .regions = regions,
    };
}

pub const ExecutionErrorKind = enum(u8) {
    Instruction,
    Syscall,
    Ebpf,
};

pub const ExecutionError = SyscallError ||
    EbpfError ||
    InstructionError ||
    error{OutOfMemory};

pub fn getExecutionErrorKind(err: ExecutionError) ExecutionErrorKind {
    return convertExecutionError(err)[1];
}

pub fn getExecutionErrorMessage(err: ExecutionError) []const u8 {
    return convertExecutionError(err)[2];
}

pub fn convertExecutionError(err: ExecutionError) struct { i64, ExecutionErrorKind, []const u8 } {
    // zig fmt: off
    return switch (err) {
        EbpfError.ElfError =>                                       .{ 1, .Ebpf, "ELF error" },
        EbpfError.FunctionAlreadyRegistered =>                      .{ 2, .Ebpf, "function was already registered" },
        EbpfError.CallDepthExceeded =>                              .{ 3, .Ebpf, "exceeded max BPF to BPF call depth" },
        EbpfError.ExitRootCallFrame =>                              .{ 4, .Ebpf, "attempted to exit root call frame" },
        EbpfError.DivisionByZero =>                                 .{ 5, .Ebpf, "divide by zero at BPF instruction" },
        EbpfError.DivideOverflow =>                                 .{ 6, .Ebpf, "division overflow at BPF instruction" },
        EbpfError.ExecutionOverrun =>                               .{ 7, .Ebpf, "attempted to execute past the end of the text segment at BPF instruction" },
        EbpfError.CallOutsideTextSegment =>                         .{ 8, .Ebpf, "callx attempted to call outside of the text segment" },
        EbpfError.ExceededMaxInstructions =>                        .{ 9, .Ebpf, "exceeded CUs meter at BPF instruction" },
        EbpfError.JitNotCompiled =>                                 .{ 10, .Ebpf, "program has not been JIT-compiled" },
        EbpfError.InvalidVirtualAddress =>                          .{ 11, .Ebpf, "invalid virtual address" },
        EbpfError.InvalidMemoryRegion =>                            .{ 12, .Ebpf, "Invalid memory region at index" },
        EbpfError.AccessViolation =>                                .{ 13, .Ebpf, "Access violation" },
        EbpfError.StackAccessViolation =>                           .{ 14, .Ebpf, "Access violation in stack frame" },
        EbpfError.InvalidInstruction =>                             .{ 15, .Ebpf, "invalid BPF instruction" },
        EbpfError.UnsupportedInstruction =>                         .{ 16, .Ebpf, "unsupported BPF instruction" },
        // EbpfError.ExhaustedTextSegment =>                           .{ 17, .Ebpf, "Compilation exhausted text segment at BPF instruction" },
        // EbpfError.LibcInvocationFailed =>                           .{ 18, .Ebpf, "Libc calling returned error code" },
        EbpfError.VerifierError =>                                  .{ 19, .Ebpf, "Verifier error" },
        // EbpfError.SyscallError => @panic("Sig should not return an Ebpf syscall error"),

        SyscallError.InvalidString =>                               .{ 1, .Syscall, "invalid utf-8 sequence" },
        SyscallError.Abort =>                                       .{ 2, .Syscall, "SBF program panicked" },
        SyscallError.Panic =>                                       .{ 3, .Syscall, "SBF program Panicked in..." },
        SyscallError.InvokeContextBorrowFailed =>                   .{ 4, .Syscall, "Cannot borrow invoke context" },
        SyscallError.MalformedSignerSeed =>                         .{ 5, .Syscall, "Malformed signer seed" },
        SyscallError.BadSeeds =>                                    .{ 6, .Syscall, "Could not create program address with signer seeds" },
        SyscallError.ProgramNotSupported =>                         .{ 7, .Syscall, "Program not supported by inner instructions" },
        SyscallError.UnalignedPointer =>                            .{ 8, .Syscall, "Unaligned pointer" },
        SyscallError.TooManySigners =>                              .{ 9, .Syscall, "Too many signers" },
        SyscallError.InstructionTooLarge =>                         .{ 10, .Syscall, "Instruction passed to inner instruction is too large" },
        SyscallError.TooManyAccounts =>                             .{ 11, .Syscall, "Too many accounts passed to inner instruction" },
        SyscallError.CopyOverlapping =>                             .{ 12, .Syscall, "Overlapping copy" },
        SyscallError.ReturnDataTooLarge =>                          .{ 13, .Syscall, "Return data too large" },
        SyscallError.TooManySlices =>                               .{ 14, .Syscall, "Hashing too many sequences" },
        SyscallError.InvalidLength =>                               .{ 15, .Syscall, "InvalidLength" },
        SyscallError.MaxInstructionDataLenExceeded =>               .{ 16, .Syscall, "Invoked an instruction with data that is too large" },
        SyscallError.MaxInstructionAccountsExceeded =>              .{ 17, .Syscall, "Invoked an instruction with too many accounts" },
        SyscallError.MaxInstructionAccountInfosExceeded =>          .{ 18, .Syscall, "Invoked an instruction with too many account info's" },
        SyscallError.InvalidAttribute =>                            .{ 19, .Syscall, "InvalidAttribute" },
        SyscallError.InvalidPointer =>                              .{ 20, .Syscall, "Invalid pointer" },
        SyscallError.ArithmeticOverflow =>                          .{ 21, .Syscall, "Arithmetic overflow" },

        InstructionError.GenericError =>                            .{ 1, .Instruction, "generic instruction error" },
        InstructionError.InvalidArgument =>                         .{ 2, .Instruction, "invalid program argument" },
        InstructionError.InvalidInstructionData =>                  .{ 3, .Instruction, "invalid instruction data" },
        InstructionError.InvalidAccountData =>                      .{ 4, .Instruction, "invalid account data for instruction" },
        InstructionError.AccountDataTooSmall =>                     .{ 5, .Instruction, "account data too small for instruction" },
        InstructionError.InsufficientFunds =>                       .{ 6, .Instruction, "insufficient funds for instruction" },
        InstructionError.IncorrectProgramId =>                      .{ 7, .Instruction, "incorrect program id for instruction" },
        InstructionError.MissingRequiredSignature =>                .{ 8, .Instruction, "missing required signature for instruction" },
        InstructionError.AccountAlreadyInitialized =>               .{ 9, .Instruction, "instruction requires an uninitialized account" },
        InstructionError.UninitializedAccount =>                    .{ 10, .Instruction, "instruction requires an initialized account" },
        InstructionError.UnbalancedInstruction =>                   .{ 11, .Instruction, "sum of account balances before and after instruction do not match" },
        InstructionError.ModifiedProgramId =>                       .{ 12, .Instruction, "instruction illegally modified the program id of an account" },
        InstructionError.ExternalAccountLamportSpend =>             .{ 13, .Instruction, "instruction spent from the balance of an account it does not own" },
        InstructionError.ExternalAccountDataModified =>             .{ 14, .Instruction, "instruction modified data of an account it does not own" },
        InstructionError.ReadonlyLamportChange =>                   .{ 15, .Instruction, "instruction changed the balance of a read-only account" },
        InstructionError.ReadonlyDataModified =>                    .{ 16, .Instruction, "instruction modified data of a read-only account" },
        InstructionError.DuplicateAccountIndex =>                   .{ 17, .Instruction, "instruction contains duplicate accounts" },
        InstructionError.ExecutableModified =>                      .{ 18, .Instruction, "instruction changed executable bit of an account" },
        InstructionError.RentEpochModified =>                       .{ 19, .Instruction, "instruction modified rent epoch of an account" },
        InstructionError.NotEnoughAccountKeys =>                    .{ 20, .Instruction, "insufficient account keys for instruction" },
        InstructionError.AccountDataSizeChanged =>                  .{ 21, .Instruction, "program other than the account's owner changed the size of the account data" },
        InstructionError.AccountNotExecutable =>                    .{ 22, .Instruction, "instruction expected an executable account" },
        InstructionError.AccountBorrowFailed =>                     .{ 23, .Instruction, "instruction tries to borrow reference for an account which is already borrowed" },
        InstructionError.AccountBorrowOutstanding =>                .{ 24, .Instruction, "instruction left account with an outstanding borrowed reference" },
        InstructionError.DuplicateAccountOutOfSync =>               .{ 25, .Instruction, "instruction modifications of multiply-passed account differ" },
        InstructionError.Custom =>                                  .{ 26, .Instruction, "" }, // message handled in `programFailure`
        InstructionError.InvalidError =>                            .{ 27, .Instruction, "program returned invalid error code" },
        InstructionError.ExecutableDataModified =>                  .{ 28, .Instruction, "instruction changed executable accounts data" },
        InstructionError.ExecutableLamportChange =>                 .{ 29, .Instruction, "instruction changed the balance of an executable account" },
        InstructionError.ExecutableAccountNotRentExempt =>          .{ 30, .Instruction, "executable accounts must be rent exempt" },
        InstructionError.UnsupportedProgramId =>                    .{ 31, .Instruction, "Unsupported program id" },
        InstructionError.CallDepth =>                               .{ 32, .Instruction, "Cross-program invocation call depth too deep" },
        InstructionError.MissingAccount =>                          .{ 33, .Instruction, "An account required by the instruction is missing" },
        InstructionError.ReentrancyNotAllowed =>                    .{ 34, .Instruction, "Cross-program invocation reentrancy not allowed for this instruction" },
        InstructionError.MaxSeedLengthExceeded =>                   .{ 35, .Instruction, "Length of the seed is too long for address generation" },
        InstructionError.InvalidSeeds =>                            .{ 36, .Instruction, "Provided seeds do not result in a valid address" },
        InstructionError.InvalidRealloc =>                          .{ 37, .Instruction, "Failed to reallocate account data" },
        InstructionError.ComputationalBudgetExceeded =>             .{ 38, .Instruction, "Computational budget exceeded" },
        InstructionError.PrivilegeEscalation =>                     .{ 39, .Instruction, "Cross-program invocation with unauthorized signer or writable account" },
        InstructionError.ProgramEnvironmentSetupFailure =>          .{ 40, .Instruction, "Failed to create program execution environment" },
        InstructionError.ProgramFailedToComplete =>                 .{ 41, .Instruction, "Program failed to complete" },
        InstructionError.ProgramFailedToCompile =>                  .{ 42, .Instruction, "Program failed to compile" },
        InstructionError.Immutable =>                               .{ 43, .Instruction, "Account is immutable" },
        InstructionError.IncorrectAuthority =>                      .{ 44, .Instruction, "Incorrect authority provided" },
        InstructionError.BorshIoError =>                            .{ 45, .Instruction, "Failed to serialize or deserialize account data" },
        InstructionError.AccountNotRentExempt =>                    .{ 46, .Instruction, "An account does not have enough lamports to be rent-exempt" },
        InstructionError.InvalidAccountOwner =>                     .{ 47, .Instruction, "Invalid account owner" },
        InstructionError.ProgramArithmeticOverflow =>               .{ 48, .Instruction, "Program arithmetic overflowed" },
        InstructionError.UnsupportedSysvar =>                       .{ 49, .Instruction, "Unsupported sysvar" },
        InstructionError.IllegalOwner =>                            .{ 50, .Instruction, "Provided owner is not allowed" },
        InstructionError.MaxAccountsDataAllocationsExceeded =>      .{ 51, .Instruction, "Accounts data allocations exceeded the maximum allowed per transaction" },
        InstructionError.MaxAccountsExceeded =>                     .{ 52, .Instruction, "Max accounts exceeded" },
        InstructionError.MaxInstructionTraceLengthExceeded =>       .{ 53, .Instruction, "Max instruction trace length exceeded" },
        InstructionError.BuiltinProgramsMustConsumeComputeUnits =>  .{ 54, .Instruction, "Builtin programs must consume compute units" },

        // Not logged in Agave
        SyscallError.InvalidEndianness =>                           .{ -1, .Syscall, "Invalid endianness." },
        SyscallError.InvalidParameters =>                           .{ -1, .Syscall, "Invalid parameters." },

       
        else => std.debug.panic("Unexpected Sig Error: {s}\n", .{@errorName(err)}),
    };
    // zig fmt: on
}

pub fn executionErrorFromStatusCode(status_code: u64) ExecutionError {
    return switch (status_code) {
        0x100000000 => InstructionError.GenericError,
        0x200000000 => InstructionError.InvalidArgument,
        0x300000000 => InstructionError.InvalidInstructionData,
        0x400000000 => InstructionError.InvalidAccountData,
        0x500000000 => InstructionError.AccountDataTooSmall,
        0x600000000 => InstructionError.InsufficientFunds,
        0x700000000 => InstructionError.IncorrectProgramId,
        0x800000000 => InstructionError.MissingRequiredSignature,
        0x900000000 => InstructionError.AccountAlreadyInitialized,
        0xA00000000 => InstructionError.UninitializedAccount,
        0xB00000000 => InstructionError.NotEnoughAccountKeys,
        0xC00000000 => InstructionError.AccountBorrowFailed,
        0xD00000000 => InstructionError.MaxSeedLengthExceeded,
        0xE00000000 => InstructionError.InvalidSeeds,
        0xF00000000 => InstructionError.BorshIoError,
        0x1000000000 => InstructionError.AccountNotRentExempt,
        0x1100000000 => InstructionError.UnsupportedSysvar,
        0x1200000000 => InstructionError.IllegalOwner,
        0x1300000000 => InstructionError.MaxAccountsDataAllocationsExceeded,
        0x1400000000 => InstructionError.InvalidRealloc,
        0x1500000000 => InstructionError.MaxInstructionTraceLengthExceeded,
        0x1600000000 => InstructionError.BuiltinProgramsMustConsumeComputeUnits,
        0x1700000000 => InstructionError.InvalidAccountOwner,
        0x1800000000 => InstructionError.ProgramArithmeticOverflow,
        0x1900000000 => InstructionError.Immutable,
        0x1A00000000 => InstructionError.IncorrectAuthority,
        // A valid custom error has no bits set in the upper 32
        else => |value| if (value >> 32 == 0)
            InstructionError.Custom
        else
            InstructionError.InvalidError,
    };
}

/// Converts an ExecutionError to an InstructionError.
/// User must ensure that the ExecutionError is an InstructionError, otherwise it will panic.
pub fn instructionErrorFromExecutionError(err: ExecutionError) InstructionError {
    return switch (err) {
        error.GenericError => error.GenericError,
        error.InvalidArgument => error.InvalidArgument,
        error.InvalidInstructionData => error.InvalidInstructionData,
        error.InvalidAccountData => error.InvalidAccountData,
        error.AccountDataTooSmall => error.AccountDataTooSmall,
        error.InsufficientFunds => error.InsufficientFunds,
        error.IncorrectProgramId => error.IncorrectProgramId,
        error.MissingRequiredSignature => error.MissingRequiredSignature,
        error.AccountAlreadyInitialized => error.AccountAlreadyInitialized,
        error.UninitializedAccount => error.UninitializedAccount,
        error.UnbalancedInstruction => error.UnbalancedInstruction,
        error.ModifiedProgramId => error.ModifiedProgramId,
        error.ExternalAccountLamportSpend => error.ExternalAccountLamportSpend,
        error.ExternalAccountDataModified => error.ExternalAccountDataModified,
        error.ReadonlyLamportChange => error.ReadonlyLamportChange,
        error.ReadonlyDataModified => error.ReadonlyDataModified,
        error.DuplicateAccountIndex => error.DuplicateAccountIndex,
        error.ExecutableModified => error.ExecutableModified,
        error.RentEpochModified => error.RentEpochModified,
        error.NotEnoughAccountKeys => error.NotEnoughAccountKeys,
        error.AccountDataSizeChanged => error.AccountDataSizeChanged,
        error.AccountNotExecutable => error.AccountNotExecutable,
        error.AccountBorrowFailed => error.AccountBorrowFailed,
        error.AccountBorrowOutstanding => error.AccountBorrowOutstanding,
        error.DuplicateAccountOutOfSync => error.DuplicateAccountOutOfSync,
        error.Custom => error.Custom,
        error.InvalidError => error.InvalidError,
        error.ExecutableDataModified => error.ExecutableDataModified,
        error.ExecutableLamportChange => error.ExecutableLamportChange,
        error.ExecutableAccountNotRentExempt => error.ExecutableAccountNotRentExempt,
        error.UnsupportedProgramId => error.UnsupportedProgramId,
        error.CallDepth => error.CallDepth,
        error.MissingAccount => error.MissingAccount,
        error.ReentrancyNotAllowed => error.ReentrancyNotAllowed,
        error.MaxSeedLengthExceeded => error.MaxSeedLengthExceeded,
        error.InvalidSeeds => error.InvalidSeeds,
        error.InvalidRealloc => error.InvalidRealloc,
        error.ComputationalBudgetExceeded => error.ComputationalBudgetExceeded,
        error.PrivilegeEscalation => error.PrivilegeEscalation,
        error.ProgramEnvironmentSetupFailure => error.ProgramEnvironmentSetupFailure,
        error.ProgramFailedToComplete => error.ProgramFailedToComplete,
        error.ProgramFailedToCompile => error.ProgramFailedToCompile,
        error.Immutable => error.Immutable,
        error.IncorrectAuthority => error.IncorrectAuthority,
        error.BorshIoError => error.BorshIoError,
        error.AccountNotRentExempt => error.AccountNotRentExempt,
        error.InvalidAccountOwner => error.InvalidAccountOwner,
        error.ProgramArithmeticOverflow => error.ProgramArithmeticOverflow,
        error.UnsupportedSysvar => error.UnsupportedSysvar,
        error.IllegalOwner => error.IllegalOwner,
        error.MaxAccountsDataAllocationsExceeded => error.MaxAccountsDataAllocationsExceeded,
        error.MaxAccountsExceeded => error.MaxAccountsExceeded,
        error.MaxInstructionTraceLengthExceeded => error.MaxInstructionTraceLengthExceeded,
        error.BuiltinProgramsMustConsumeComputeUnits => error.BuiltinProgramsMustConsumeComputeUnits,
        else => std.debug.panic(
            "Cannot convert error to InstructionError: {s}\n",
            .{@errorName(err)},
        ),
    };
}
