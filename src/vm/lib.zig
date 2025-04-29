const std = @import("std");
const sig = @import("../sig.zig");

const executable = @import("executable.zig");
pub const sbpf = @import("sbpf.zig");
pub const elf = @import("elf.zig");
pub const memory = @import("memory.zig");
pub const tests = @import("tests.zig");
pub const interpreter = @import("interpreter.zig");
pub const syscalls = @import("syscalls/lib.zig");

pub const Executable = executable.Executable;
pub const BuiltinProgram = executable.BuiltinProgram;
pub const Registry = executable.Registry;
pub const Assembler = executable.Assembler;
pub const Config = executable.Config;
pub const Vm = interpreter.Vm;
pub const Elf = elf.Elf;
pub const Section = executable.Section;

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
    InvalidNumberOfInputs,
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
    ExhaustedTextSegment,
    LibcInvocationFailed,
    VerifierError,
    SyscallError,
};

pub const ExecutionError =
    SyscallError || EbpfError || InstructionError || std.fs.File.WriteError || error{
    OutOfMemory,
    Overflow,
};
