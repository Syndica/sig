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
    // #[error("{0}: {1:?}")]
    InvalidString, // (Utf8Error, Vec<u8>),
    // #[error("SBF program panicked")]
    Abort,
    // #[error("SBF program Panicked in {0} at {1}:{2}")]
    Panic, // (String, u64, u64),
    // #[error("Cannot borrow invoke context")]
    InvokeContextBorrowFailed,
    // #[error("Malformed signer seed: {0}: {1:?}")]
    MalformedSignerSeed, // (Utf8Error, Vec<u8>),
    // #[error("Could not create program address with signer seeds: {0}")]
    BadSeeds, // (PubkeyError),
    // #[error("Program {0} not supported by inner instructions")]
    ProgramNotSupported, // (Pubkey),
    // #[error("Unaligned pointer")]
    UnalignedPointer,
    // #[error("Too many signers")]
    TooManySigners,
    // #[error("Instruction passed to inner instruction is too large ({0} > {1})")]
    InstructionTooLarge, // (usize, usize),
    // #[error("Too many accounts passed to inner instruction")]
    TooManyAccounts,
    // #[error("Overlapping copy")]
    CopyOverlapping,
    // #[error("Return data too large ({0} > {1})")]
    ReturnDataTooLarge, // (u64, u64),
    // #[error("Hashing too many sequences")]
    TooManySlices,
    // #[error("InvalidLength")]
    InvalidLength,
    // #[error("Invoked an instruction with data that is too large ({data_len} > {max_data_len})")]
    MaxInstructionDataLenExceeded, // { data_len: u64, max_data_len: u64 },
    // #[error("Invoked an instruction with too many accounts ({num_accounts} > {max_accounts})")]
    MaxInstructionAccountsExceeded, // { num_accounts: u64, max_accounts: u64 },
    // #[error("Invoked an instruction with too many account info's ({num_account_infos} > {max_account_infos})")]
    MaxInstructionAccountInfosExceeded, // { num_account_infos: u64, max_account_infos: u64 },
    // #[error("InvalidAttribute")]
    InvalidAttribute,
    // #[error("Invalid pointer")]
    InvalidPointer,
    // #[error("Arithmetic overflow")]
    ArithmeticOverflow,
};

pub const EbpfError = error{
    // #[error("ELF error: {0}")]
    ElfError, // (#[from] ElfError),
    // #[error("function #{0} was already registered")]
    FunctionAlreadyRegistered, // (usize),
    // #[error("exceeded max BPF to BPF call depth")]
    CallDepthExceeded,
    // #[error("attempted to exit root call frame")]
    ExitRootCallFrame,
    // #[error("divide by zero at BPF instruction")]
    DivideByZero,
    // #[error("division overflow at BPF instruction")]
    DivideOverflow,
    // #[error("attempted to execute past the end of the text segment at BPF instruction")]
    ExecutionOverrun,
    // #[error("callx attempted to call outside of the text segment")]
    CallOutsideTextSegment,
    // #[error("exceeded CUs meter at BPF instruction")]
    ExceededMaxInstructions,
    // #[error("program has not been JIT-compiled")]
    JitNotCompiled,
    // #[error("invalid virtual address {0:x?}")]
    InvalidVirtualAddress, // (u64),
    // #[error("Invalid memory region at index {0}")]
    InvalidMemoryRegion, // (usize),
    // #[error("Access violation in {3} section at address {1:#x} of size {2:?}")]
    AccessViolation, // (AccessType, u64, u64, &'static str),
    // #[error("Access violation in stack frame {3} at address {1:#x} of size {2:?}")]
    StackAccessViolation, // (AccessType, u64, u64, i64),
    // #[error("invalid BPF instruction")]
    InvalidInstruction,
    // #[error("unsupported BPF instruction")]
    UnsupportedInstruction,
    // #[error("Compilation exhausted text segment at BPF instruction {0}")]
    ExhaustedTextSegment, // (usize),
    // #[error("Libc calling {0} {1:?} returned error code {2}")]
    LibcInvocationFailed, // (&'static str, Vec<String>, i32),
    // #[error("Verifier error: {0}")]
    VerifierError, // (#[from] VerifierError),
    // #[error("Syscall error: {0}")]
    SyscallError, // (Box<dyn Error>),
};

pub const ExecutionError =
    SyscallError || EbpfError || InstructionError || std.fs.File.WriteError || error{
    OutOfMemory,
    Overflow,
};
