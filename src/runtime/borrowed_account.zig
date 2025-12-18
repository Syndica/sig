const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const TransactionContext = sig.runtime.TransactionContext;
const Rent = sig.runtime.sysvar.Rent;
const WLockGuard = sig.runtime.TransactionContextAccount.WLockGuard;

const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION =
    sig.runtime.program.system.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system.MAX_PERMITTED_DATA_LENGTH;

/// [agave] https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 100;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

/// Borrowed account context exists to provide information about the context under which an account
/// was borrowed. It replaces the reference to an `InstructionContext` used in Agave.
pub const BorrowedAccountContext = struct {
    program_id: Pubkey,
    is_signer: bool = false,
    is_writable: bool = false,
    /// TODO: remove this after upgrading to agave 2.3+ (for conformance).
    remove_accounts_executable_flag_checks: bool,
    accounts_lamport_delta: *i128,
};

/// `BorrowedAccount` represents an account which has been 'borrowed' from the `TransactionContext`
/// It provides methods for accessing and modifying account state with the required checks.
///
/// The `borrow_context` holds the context under which the account was borrowed:
///    - `program_id: Pubkey`: the program which borrowed the account
///    - `is_writable: bool`: whether the account is writable within the program instruction which borrowed the account
///
/// TODO: add remaining methods as required by the runtime
///
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L706
pub const BorrowedAccount = struct {
    /// The public key of the account
    pubkey: Pubkey,
    /// mutable reference to the account which has been borrowed
    account: *AccountSharedData,
    /// write guard for the account which has been borrowed
    account_write_guard: WLockGuard,
    /// the context under which the account was borrowed
    context: BorrowedAccountContext,

    pub fn release(self: *const BorrowedAccount) void {
        self.account_write_guard.release();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/108fcb4ff0f3cb2e7739ca163e6ead04e377e567/transaction-context/src/lib.rs#L1129
    pub fn isOwnedByCurrentProgram(self: *const BorrowedAccount) bool {
        return self.account.owner.equals(&self.context.program_id);
    }

    /// TODO: remove this after upgrading to agave 2.3+ (for conformance).
    /// [agave] https://github.com/anza-xyz/agave/blob/23e01995a3d547295dd8dfa83fafe93f07de78d9/transaction-context/src/lib.rs#L1053-L1061 (v2.2 for conformance)
    pub fn isExecutableInternal(self: *const BorrowedAccount) bool {
        return self.account.executable and !self.context.remove_accounts_executable_flag_checks;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1077
    pub fn checkDataIsMutable(self: *const BorrowedAccount) ?InstructionError {
        if (!self.context.is_writable)
            return InstructionError.ReadonlyDataModified;

        if (!self.account.owner.equals(&self.context.program_id))
            return InstructionError.ExternalAccountDataModified;

        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L1095
    pub fn checkCanSetDataLength(
        self: *const BorrowedAccount,
        resize_delta: i64,
        length: usize,
    ) ?InstructionError {
        const old_length = self.constAccountData().len;

        if (length != old_length and !self.account.owner.equals(&self.context.program_id))
            return InstructionError.AccountDataSizeChanged;

        if (length > MAX_PERMITTED_DATA_LENGTH)
            return InstructionError.InvalidRealloc;

        const length_signed: i64 = @intCast(length);
        const old_length_signed: i64 = @intCast(old_length);
        const new_accounts_resize_delta = resize_delta +| (length_signed -| old_length_signed);

        if (new_accounts_resize_delta > MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION)
            return InstructionError.MaxAccountsDataAllocationsExceeded;

        return self.checkDataIsMutable();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/transaction-context/src/lib.rs#L825
    pub fn setLamports(self: *const BorrowedAccount, lamports: u64) InstructionError!void {
        if (lamports < self.account.lamports and
            !self.account.owner.equals(&self.context.program_id))
        {
            return InstructionError.ExternalAccountLamportSpend;
        }

        if (!self.context.is_writable)
            return InstructionError.ReadonlyLamportChange;

        if (self.isExecutableInternal()) {
            return InstructionError.ExecutableLamportChange;
        }

        // Dont touch account if lamports dont change.
        if (lamports == self.account.lamports) return;

        self.context.accounts_lamport_delta.* = std.math.add(
            i128,
            self.context.accounts_lamport_delta.*,
            @as(i128, lamports) -| @as(i128, self.account.lamports),
        ) catch return InstructionError.ProgramArithmeticOverflow;

        self.account.lamports = lamports;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L800
    pub fn addLamports(self: *const BorrowedAccount, lamports: u64) InstructionError!void {
        try self.setLamports(std.math.add(
            u64,
            self.account.lamports,
            lamports,
        ) catch return InstructionError.ProgramArithmeticOverflow);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L808
    pub fn subtractLamports(self: *const BorrowedAccount, lamports: u64) InstructionError!void {
        try self.setLamports(std.math.sub(
            u64,
            self.account.lamports,
            lamports,
        ) catch return InstructionError.ProgramArithmeticOverflow);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L817
    pub fn constAccountData(self: *const BorrowedAccount) []const u8 {
        return self.account.data;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L823
    pub fn mutableAccountData(self: *const BorrowedAccount) InstructionError![]u8 {
        if (self.checkDataIsMutable()) |err| return err;
        return self.account.data;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L885
    pub fn setDataLength(
        self: *const BorrowedAccount,
        allocator: std.mem.Allocator,
        resize_delta: *i64,
        new_length: usize,
    ) (error{OutOfMemory} || InstructionError)!void {
        if (self.checkCanSetDataLength(resize_delta.*, new_length)) |err| return err;
        if (self.constAccountData().len == new_length) return;

        const old_length_signed: i64 = @intCast(self.constAccountData().len);
        const new_length_signed: i64 = @intCast(new_length);
        resize_delta.* +|= new_length_signed -| old_length_signed;

        try self.account.resize(allocator, new_length);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L916
    pub fn setDataFromSlice(
        self: *const BorrowedAccount,
        allocator: std.mem.Allocator,
        resize_delta: *i64,
        data: []const u8,
    ) (error{OutOfMemory} || InstructionError)!void {
        if (self.checkCanSetDataLength(resize_delta.*, data.len)) |err| return err;

        const old_length_signed: i64 = @intCast(self.constAccountData().len);
        const new_length_signed: i64 = @intCast(data.len);
        resize_delta.* +|= new_length_signed -| old_length_signed;

        // TODO: Implement account shared data method set data from slice
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/account/src/lib.rs#L616
        try self.account.resize(allocator, data.len);
        @memcpy(self.account.data[0..data.len], data);
    }

    /// Deserialize the account data into a type `T`
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L968
    pub fn deserializeFromAccountData(
        self: *const BorrowedAccount,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) InstructionError!T {
        return bincode.readFromSlice(
            allocator,
            T,
            self.account.data,
            .{ .allocation_limit = MAX_PERMITTED_DATA_LENGTH },
        ) catch return InstructionError.InvalidAccountData;
    }

    /// Serialize the state into the account data.
    ///
    /// `state` must support bincode serialization
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L976
    pub fn serializeIntoAccountData(
        self: *const BorrowedAccount,
        state: anytype,
    ) InstructionError!void {
        if (self.checkDataIsMutable()) |err| return err;

        const serialized_size = bincode.sizeOf(state, .{});
        if (serialized_size > self.account.data.len)
            return InstructionError.AccountDataTooSmall;

        const written = bincode.writeToSlice(self.account.data, state, .{}) catch
            return InstructionError.GenericError;

        if (written.len != serialized_size)
            return InstructionError.GenericError;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L742
    pub fn setOwner(
        self: *const BorrowedAccount,
        pubkey: Pubkey,
    ) InstructionError!void {
        var zone = tracy.Zone.init(@src(), .{ .name = "setOwner" });
        defer zone.deinit();

        if (!self.context.is_writable or
            !self.account.owner.equals(&self.context.program_id) or
            !self.account.isZeroed())
        {
            return InstructionError.ModifiedProgramId;
        }

        self.account.owner = pubkey;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L1001
    pub fn setExecutable(
        self: *BorrowedAccount,
        executable: bool,
        rent: Rent,
    ) InstructionError!void {
        if (!rent.isExempt(self.account.lamports, self.account.data.len))
            return InstructionError.ExecutableAccountNotRentExempt;

        if (!self.account.owner.equals(&self.context.program_id) or
            !self.context.is_writable)
        {
            return InstructionError.ExecutableModified;
        }

        self.account.executable = executable;
    }
};
