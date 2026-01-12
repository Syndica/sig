// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/instruction/src/account_meta.rs
// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/instruction/src/error.rs

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Instruction = struct {
    /// Program address
    program_id: Pubkey,
    /// Accounts that the command references
    accounts: []const InstructionAccount,
    /// Data is the binary encoding of the program instruction and its
    /// arguments. The lifetime of the data must outlive the instruction.
    data: []const u8,
    owned_data: bool,

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        if (self.owned_data) allocator.free(self.data);
        allocator.free(self.accounts);
    }

    // https://github.com/anza-xyz/agave/blob/3bbabb38c5800b197841eb79037a82e88e174440/sdk/instruction/src/lib.rs#L221
    pub fn initUsingBincodeAlloc(
        allocator: std.mem.Allocator,
        T: type,
        program_id: Pubkey,
        accounts: []const InstructionAccount,
        data: *const T,
    ) error{OutOfMemory}!Instruction {
        const serialized = sig.bincode.writeAlloc(allocator, data, .{}) catch
            // reviewer's note - can we trim away bincode's use of any error? I don't think we need it,
            // a bit annoying.
            return error.OutOfMemory;
        errdefer allocator.free(serialized);

        return .{
            .program_id = program_id,
            .accounts = accounts,
            .data = serialized,
            .owned_data = true,
        };
    }
};

pub const InstructionAccount = struct {
    /// An account's public key
    pubkey: Pubkey,
    /// True if account must sign the transaction
    is_signer: bool,
    /// True if the account is mutable
    is_writable: bool,
};

pub const InstructionError = error{
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError,

    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ProgramArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added
};

pub fn intFromInstructionError(err: InstructionError) i32 {
    switch (err) {
        error.GenericError => return 1,
        error.InvalidArgument => return 2,
        error.InvalidInstructionData => return 3,
        error.InvalidAccountData => return 4,
        error.AccountDataTooSmall => return 5,
        error.InsufficientFunds => return 6,
        error.IncorrectProgramId => return 7,
        error.MissingRequiredSignature => return 8,
        error.AccountAlreadyInitialized => return 9,
        error.UninitializedAccount => return 10,
        error.UnbalancedInstruction => return 11,
        error.ModifiedProgramId => return 12,
        error.ExternalAccountLamportSpend => return 13,
        error.ExternalAccountDataModified => return 14,
        error.ReadonlyLamportChange => return 15,
        error.ReadonlyDataModified => return 16,
        error.DuplicateAccountIndex => return 17,
        error.ExecutableModified => return 18,
        error.RentEpochModified => return 19,
        error.NotEnoughAccountKeys => return 20,
        error.AccountDataSizeChanged => return 21,
        error.AccountNotExecutable => return 22,
        error.AccountBorrowFailed => return 23,
        error.AccountBorrowOutstanding => return 24,
        error.DuplicateAccountOutOfSync => return 25,
        error.Custom => return 26,
        error.InvalidError => return 27,
        error.ExecutableDataModified => return 28,
        error.ExecutableLamportChange => return 29,
        error.ExecutableAccountNotRentExempt => return 30,
        error.UnsupportedProgramId => return 31,
        error.CallDepth => return 32,
        error.MissingAccount => return 33,
        error.ReentrancyNotAllowed => return 34,
        error.MaxSeedLengthExceeded => return 35,
        error.InvalidSeeds => return 36,
        error.InvalidRealloc => return 37,
        error.ComputationalBudgetExceeded => return 38,
        error.PrivilegeEscalation => return 39,
        error.ProgramEnvironmentSetupFailure => return 40,
        error.ProgramFailedToComplete => return 41,
        error.ProgramFailedToCompile => return 42,
        error.Immutable => return 43,
        error.IncorrectAuthority => return 44,
        error.BorshIoError => return 45,
        error.AccountNotRentExempt => return 46,
        error.InvalidAccountOwner => return 47,
        error.ProgramArithmeticOverflow => return 48,
        error.UnsupportedSysvar => return 49,
        error.IllegalOwner => return 50,
        error.MaxAccountsDataAllocationsExceeded => return 51,
        error.MaxAccountsExceeded => return 52,
        error.MaxInstructionTraceLengthExceeded => return 53,
        error.BuiltinProgramsMustConsumeComputeUnits => return 54,
    }
}

pub const InstructionErrorEnum = union(enum(u32)) {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom: u32,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError: []u8,
    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ProgramArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        switch (self) {
            .BorshIoError => |it| allocator.free(it),
            else => {},
        }
    }

    pub fn fromError(err: InstructionError, custom: ?u32, borsh_io: ?[]u8) !InstructionErrorEnum {
        return switch (err) {
            error.GenericError => .GenericError,
            error.InvalidArgument => .InvalidArgument,
            error.InvalidInstructionData => .InvalidInstructionData,
            error.InvalidAccountData => .InvalidAccountData,
            error.AccountDataTooSmall => .AccountDataTooSmall,
            error.InsufficientFunds => .InsufficientFunds,
            error.IncorrectProgramId => .IncorrectProgramId,
            error.MissingRequiredSignature => .MissingRequiredSignature,
            error.AccountAlreadyInitialized => .AccountAlreadyInitialized,
            error.UninitializedAccount => .UninitializedAccount,
            error.UnbalancedInstruction => .UnbalancedInstruction,
            error.ModifiedProgramId => .ModifiedProgramId,
            error.ExternalAccountLamportSpend => .ExternalAccountLamportSpend,
            error.ExternalAccountDataModified => .ExternalAccountDataModified,
            error.ReadonlyLamportChange => .ReadonlyLamportChange,
            error.ReadonlyDataModified => .ReadonlyDataModified,
            error.DuplicateAccountIndex => .DuplicateAccountIndex,
            error.ExecutableModified => .ExecutableModified,
            error.RentEpochModified => .RentEpochModified,
            error.NotEnoughAccountKeys => .NotEnoughAccountKeys,
            error.AccountDataSizeChanged => .AccountDataSizeChanged,
            error.AccountNotExecutable => .AccountNotExecutable,
            error.AccountBorrowFailed => .AccountBorrowFailed,
            error.AccountBorrowOutstanding => .AccountBorrowOutstanding,
            error.DuplicateAccountOutOfSync => .DuplicateAccountOutOfSync,
            error.Custom => .{ .Custom = custom orelse 0 },
            error.InvalidError => .InvalidError,
            error.ExecutableDataModified => .ExecutableDataModified,
            error.ExecutableLamportChange => .ExecutableLamportChange,
            error.ExecutableAccountNotRentExempt => .ExecutableAccountNotRentExempt,
            error.UnsupportedProgramId => .UnsupportedProgramId,
            error.CallDepth => .CallDepth,
            error.MissingAccount => .MissingAccount,
            error.ReentrancyNotAllowed => .ReentrancyNotAllowed,
            error.MaxSeedLengthExceeded => .MaxSeedLengthExceeded,
            error.InvalidSeeds => .InvalidSeeds,
            error.InvalidRealloc => .InvalidRealloc,
            error.ComputationalBudgetExceeded => .ComputationalBudgetExceeded,
            error.PrivilegeEscalation => .PrivilegeEscalation,
            error.ProgramEnvironmentSetupFailure => .ProgramEnvironmentSetupFailure,
            error.ProgramFailedToComplete => .ProgramFailedToComplete,
            error.ProgramFailedToCompile => .ProgramFailedToCompile,
            error.Immutable => .Immutable,
            error.IncorrectAuthority => .IncorrectAuthority,
            error.BorshIoError => .{
                .BorshIoError = borsh_io orelse return error.MissingBorshIoError,
            },
            error.AccountNotRentExempt => .AccountNotRentExempt,
            error.InvalidAccountOwner => .InvalidAccountOwner,
            error.ProgramArithmeticOverflow => .ProgramArithmeticOverflow,
            error.UnsupportedSysvar => .UnsupportedSysvar,
            error.IllegalOwner => .IllegalOwner,
            error.MaxAccountsDataAllocationsExceeded => .MaxAccountsDataAllocationsExceeded,
            error.MaxAccountsExceeded => .MaxAccountsExceeded,
            error.MaxInstructionTraceLengthExceeded => .MaxInstructionTraceLengthExceeded,
            error.BuiltinProgramsMustConsumeComputeUnits => .BuiltinProgramsMustConsumeComputeUnits,
        };
    }
};
