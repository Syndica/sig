const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.runtime.FeatureSet;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const InstructionContext = sig.runtime.InstructionContext;

const MAX_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION =
    sig.runtime.program.system_program.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;

// https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 64;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192
pub const TransactionContext = struct {
    /// Transaction accounts
    accounts: []TransactionContextAccount,

    /// Instruction stack
    instruction_stack: std.BoundedArray(*InstructionContext, MAX_INSTRUCTION_STACK_DEPTH) = .{},
    instruction_trace: std.BoundedArray(InstructionContext, MAX_INSTRUCTION_TRACE_LENGTH) = .{},

    /// Total change to account data size within transaction
    accounts_resize_delta: i64,

    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: u64,

    /// If an error other than an InstructionError occurs during execution its value will
    /// be set here and InstructionError.custom will be returned
    custom_error: ?u32,

    /// Optional log collector
    log_collector: ?LogCollector,

    // TODO: the following feilds should live above the transaction level, however, they are
    // defined here temporarily for convenience.
    // https://github.com/orgs/Syndica/projects/2/views/14?filterQuery=+-status%3A%22%E2%9C%85+Done%22++-no%3Astatus+&pane=issue&itemId=97691745
    sysvar_cache: SysvarCache,
    lamports_per_signature: u64,
    last_blockhash: Hash,
    feature_set: FeatureSet,

    pub fn deinit(self: *TransactionContext, allocator: std.mem.Allocator) void {
        for (self.accounts) |account|
            allocator.free(account.account.data);
        allocator.free(self.accounts);
        if (self.log_collector) |lc| lc.deinit();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L233
    pub fn getAccountIndex(
        self: *TransactionContext,
        pubkey: Pubkey,
    ) ?u16 {
        for (self.accounts, 0..) |account, index|
            if (account.pubkey.equals(&pubkey)) return @intCast(index);
        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L223
    pub fn getAccountAtIndex(
        self: *const TransactionContext,
        index: u16,
    ) ?*TransactionContextAccount {
        if (index >= self.accounts.len) return null;
        return &self.accounts[index];
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L574
    pub fn consumeCompute(
        self: *TransactionContext,
        compute: u64,
    ) error{ComputationalBudgetExceeded}!void {
        const exceeded = self.compute_meter < compute;
        self.compute_meter -|= compute;
        if (exceeded) return InstructionError.ComputationalBudgetExceeded;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L94
    pub fn log(
        self: *TransactionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) error{Custom}!void {
        if (self.log_collector) |*lc|
            lc.log(fmt, args) catch |err| {
                self.custom_error = @intFromError(err);
                return InstructionError.Custom;
            };
    }
};

/// Account represents an account within a transaction and provides single threaded
/// read/write access to the account data.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L137-L139
pub const TransactionContextAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,
    read_refs: usize,
    write_ref: bool,

    pub const RLockGuard = struct {
        read_refs: *usize,

        pub fn release(self: RLockGuard) void {
            self.read_refs.* -= 1;
        }
    };

    pub const WLockGuard = struct {
        write_ref: *bool,

        pub fn release(self: WLockGuard) void {
            self.write_ref.* = false;
        }
    };

    pub fn init(
        pubkey: Pubkey,
        account: AccountSharedData,
    ) TransactionContextAccount {
        return .{
            .pubkey = pubkey,
            .account = account,
            .read_refs = 0,
            .write_ref = false,
        };
    }

    pub fn writeWithLock(
        self: *TransactionContextAccount,
    ) ?struct { *AccountSharedData, WLockGuard } {
        if (self.write_ref or self.read_refs > 0) return null;
        self.write_ref = true;
        return .{ &self.account, .{ .write_ref = &self.write_ref } };
    }

    pub fn readWithLock(
        self: *TransactionContextAccount,
    ) ?struct { *AccountSharedData, RLockGuard } {
        if (self.write_ref) return null;
        self.read_refs += 1;
        return .{ &self.account, .{ .read_refs = &self.read_refs } };
    }
};
