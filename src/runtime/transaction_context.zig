const std = @import("std");
const sig = @import("../sig.zig");

const program = sig.runtime.program;

const Hash = sig.core.Hash;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const BorrowedAccountContext = sig.runtime.BorrowedAccountContext;
const FeatureSet = sig.runtime.FeatureSet;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const ComputeBudget = sig.runtime.ComputeBudget;

// https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139
pub const MAX_INSTRUCTION_TRACE_LENGTH = 64;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH = 5;

pub const EpochContext = struct {
    /// Allocator
    allocator: std.mem.Allocator,

    /// Feature Set
    feature_set: FeatureSet,

    pub fn deinit(self: EpochContext) void {
        self.feature_set.deinit(self.allocator);
    }
};

pub const SlotContext = struct {
    /// Epoch Context
    ec: *const EpochContext,

    /// Sysvar Cache
    sysvar_cache: SysvarCache,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192
pub const TransactionContext = struct {
    /// Allocator
    allocator: std.mem.Allocator,

    /// Slot Context
    sc: *const SlotContext,

    /// Transaction accounts
    accounts: []TransactionContextAccount,

    /// Instruction stack
    instruction_stack: InstructionStack,

    /// Instruction trace
    instruction_trace: InstructionTrace,

    /// Return data
    return_data: TransactionReturnData,

    /// Total change to account data size within transaction
    accounts_resize_delta: i64,

    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: u64,

    /// Compute budget for this transaction
    compute_budget: ComputeBudget,

    /// If an error other than an InstructionError occurs during execution its value will
    /// be set here and InstructionError.custom will be returned
    custom_error: ?u32,

    /// Optional log collector
    log_collector: ?LogCollector,

    /// Previous blockhash and lamports per signature from the blockhash queue
    prev_blockhash: Hash,
    prev_lamports_per_signature: u64,

    pub const InstructionStack = std.BoundedArray(
        InstructionContext,
        MAX_INSTRUCTION_STACK_DEPTH,
    );

    pub const InstructionTrace = std.BoundedArray(struct {
        info: InstructionInfo,
        depth: u8,
    }, MAX_INSTRUCTION_TRACE_LENGTH);

    pub fn deinit(self: TransactionContext) void {
        for (self.accounts) |account| account.deinit(self.allocator);
        self.allocator.free(self.accounts);
        if (self.log_collector) |lc| lc.deinit(self.allocator);
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L646
    pub fn borrowAccountAtIndex(
        self: *TransactionContext,
        index: u16,
        context: BorrowedAccountContext,
    ) InstructionError!BorrowedAccount {
        const txn_account =
            self.getAccountAtIndex(index) orelse return InstructionError.MissingAccount;

        const account, const account_write_guard =
            txn_account.writeWithLock() orelse return InstructionError.AccountBorrowFailed;

        return .{
            .pubkey = txn_account.pubkey,
            .account = account,
            .account_write_guard = account_write_guard,
            .context = context,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L574
    pub fn consumeCompute(
        self: *TransactionContext,
        compute: u64,
    ) InstructionError!void {
        if (self.compute_meter < compute) {
            self.compute_meter = 0;
            return InstructionError.ComputationalBudgetExceeded;
        }
        self.consumeUnchecked(compute);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L100-L105
    pub fn consumeUnchecked(self: *TransactionContext, compute: u64) void {
        self.compute_meter -|= compute;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L94
    pub fn log(
        self: *TransactionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) (error{OutOfMemory} || InstructionError)!void {
        if (self.log_collector) |*lc| try lc.log(self.allocator, fmt, args);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L493
pub const TransactionReturnData = struct {
    program_id: Pubkey = Pubkey.ZEROES,
    data: std.BoundedArray(u8, MAX_RETURN_DATA) = .{},

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/95764e268fe33a19819e6f9f411ff9e732cbdf0d/cpi/src/lib.rs#L329
    pub const MAX_RETURN_DATA: usize = 1024;
};

/// Represents an account within a transaction and provides single threaded
/// read/write access to the account data to prevent invalid access during cpi.
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

    pub fn deinit(self: TransactionContextAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.account.data);
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
