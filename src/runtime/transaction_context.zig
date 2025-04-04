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

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192
pub const TransactionContext = struct {
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
    compute_budget: ComputeBudget,

    pub const InstructionStack = std.BoundedArray(
        InstructionContext,
        MAX_INSTRUCTION_STACK_DEPTH,
    );

    pub const InstructionTrace = std.BoundedArray(struct {
        info: InstructionInfo,
        depth: u8,
    }, MAX_INSTRUCTION_TRACE_LENGTH);

    pub fn deinit(self: *TransactionContext, allocator: std.mem.Allocator) void {
        for (self.accounts) |account| account.deinit(allocator);
        allocator.free(self.accounts);
        if (self.log_collector) |lc| lc.deinit();
        self.feature_set.deinit(allocator);
    }

    pub fn deinitWriteLogs(
        self: *TransactionContext,
        allocator: std.mem.Allocator,
        writer: anytype,
    ) !void {
        if (self.log_collector) |collector| {
            try writer.print("logs:\n");
            for (collector.collect()) |log_line| {
                try writer.print("    {s}\n", .{log_line});
            }
        }
        self.deinit(allocator);
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

    /// [agave] https://github.com/anza-xyz/agave/blob/43e1f62c9fa318daedec80b3f0ea1f9e7da71b11/transaction-context/src/lib.rs#L436
    pub fn getReturnData(
        self: *TransactionContext,
    ) TransactionReturnData {
        return self.return_data;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/43e1f62c9fa318daedec80b3f0ea1f9e7da71b11/transaction-context/src/lib.rs#L441
    pub fn setReturnData(
        self: *TransactionContext,
        program_id: Pubkey,
        data: []const u8,
    ) !InstructionError {
        self.return_data = TransactionReturnData{ program_id, data };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L94
    pub fn log(
        self: *TransactionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) (error{OutOfMemory} || InstructionError)!void {
        if (self.log_collector) |*lc| try lc.log(fmt, args);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L493
pub const TransactionReturnData = struct {
    program_id: Pubkey = Pubkey.ZEROES,
    data: std.ArrayListUnmanaged(u8) = .{},
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
