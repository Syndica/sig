const executable = @import("executable.zig");

pub const syscalls = @import("syscalls/lib.zig");
pub const sbpf = @import("sbpf.zig");
pub const elf = @import("elf.zig");
pub const memory = @import("memory.zig");
pub const environment = @import("environment.zig");

pub const Executable = executable.Executable;
pub const Registry = executable.Registry;
pub const Assembler = executable.Assembler;
pub const Config = executable.Config;
pub const Section = executable.Section;
pub const SyscallMap = syscalls.Syscall.Registry;
pub const Environment = environment.Environment;

pub const CurveId = syscalls.CurveId;
pub const GroupOp = syscalls.GroupOp;
pub const ecc = syscalls.ecc;

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
