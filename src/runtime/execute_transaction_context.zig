const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const RwMux = sig.sync.RwMux;
const AccountSharedData = sig.runtime.AccountSharedData;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const LogCollector = sig.runtime.LogCollector;
const Transaction = sig.core.Transaction;
const SysvarCache = sig.runtime.SysvarCache;
const FeatureSet = sig.runtime.FeatureSet;

const MAX_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION =
    sig.runtime.program.system_program.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;

// https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 100;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192
pub const ExecuteTransactionContext = struct {
    accounts: std.BoundedArray(RwMux(AccountInfo), Transaction.MAX_ACCOUNTS),

    /// Total change to account data size within transaction
    accounts_resize_delta: i64,

    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: u64,

    /// If an error other than an InstructionError occurs during execution its value will
    /// be set here and InstructionError.custom will be returned
    maybe_custom_error: ?u32,

    /// Optional log collector
    maybe_log_collector: ?LogCollector,

    // TODO: the following feilds should live above the transaction level, however, they are
    // defined here temporarily for convenience.
    sysvar_cache: SysvarCache,
    lamports_per_signature: u64,
    last_blockhash: Hash,
    feature_set: FeatureSet,

    pub const AccountInfo = struct {
        touched: bool,
        account: AccountSharedData,
    };

    pub fn checkAccountsResizeDelta(
        self: *const ExecuteTransactionContext,
        delta: i64,
    ) error{MaxAccountsDataAllocationsExceeded}!void {
        if (self.accounts_resize_delta +| delta > MAX_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION)
            return error.MaxAccountsDataAllocationsExceeded;
    }

    pub fn consumeCompute(
        self: *ExecuteTransactionContext,
        compute: u64,
    ) error{ComputationalBudgetExceeded}!void {
        const exceeded = self.compute_meter < compute;
        self.compute_meter -|= compute;
        if (exceeded) return error.ComputationalBudgetExceeded;
    }

    pub fn getAccountSharedData(self: *ExecuteTransactionContext, index: usize) AccountSharedData {
        const account_info, var read_guard = self.accounts.slice()[index].readWithLock();
        defer read_guard.unlock();
        return account_info.account;
    }

    pub fn getBlockhash(self: *const ExecuteTransactionContext) Hash {
        return self.last_blockhash;
    }

    pub fn getBorrowedAccount(
        self: *ExecuteTransactionContext,
        eic: *const ExecuteInstructionContext,
        eic_info: *const ExecuteInstructionContext.AccountInfo,
    ) InstructionError!BorrowedAccount {
        if (eic_info.index_in_transaction >= self.accounts.len)
            return error.MissingAccount;

        // TODO: this lock acquire should be fallible and return
        // `InstructionError.AccountBorrowFailed`
        // writeWithLock takes an address
        const account_info = &self.accounts.slice()[eic_info.index_in_transaction];
        const etc_info, const etc_info_write_guard = account_info.writeWithLock();

        return .{
            .eic = eic,
            .eic_info = eic_info,
            .etc_info = etc_info,
            .etc_info_write_guard = etc_info_write_guard,
        };
    }

    pub fn getFeatureSet(self: *ExecuteTransactionContext) FeatureSet {
        return self.feature_set;
    }

    pub fn getSysvar(
        self: *ExecuteTransactionContext,
        comptime T: type,
    ) error{UnsupportedSysvar}!T {
        return if (self.sysvar_cache.get(T)) |value| value else error.UnsupportedSysvar;
    }

    pub fn getLamportsPerSignature(self: *ExecuteTransactionContext) u64 {
        return self.lamports_per_signature;
    }

    pub fn addAccountsResizeDelta(self: *ExecuteTransactionContext, delta: i64) void {
        self.accounts_resize_delta +|= delta;
    }

    pub fn setCustomError(self: *ExecuteTransactionContext, custom_error: u32) void {
        self.maybe_custom_error = custom_error;
    }

    pub fn log(self: *ExecuteTransactionContext, comptime fmt: []const u8, args: anytype) void {
        if (self.maybe_log_collector) |*log_collector|
            log_collector.log(fmt, args) catch @panic("TODO: handle log error");
    }
};
