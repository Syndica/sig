const std = @import("std");
const tracy = @import("tracy");
const std14 = @import("std14");
const sig = @import("../sig.zig");

const program = sig.runtime.program;
const vm = sig.vm;

const Hash = sig.core.Hash;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const EpochStakeReader = sig.runtime.execution_interfaces.EpochStakeReader;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const BorrowedAccountContext = sig.runtime.BorrowedAccountContext;
const FeatureSet = sig.core.FeatureSet;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const ComputeBudget = sig.runtime.ComputeBudget;
const Rent = sig.runtime.sysvar.Rent;
const SerializedAccountMetadata = sig.runtime.program.bpf.serialize.SerializedAccountMeta;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const shared_transaction_context = @import("shared").runtime.transaction_context;

pub const MAX_ACCOUNTS_PER_INSTRUCTION = shared_transaction_context.MAX_ACCOUNTS_PER_INSTRUCTION;
pub const MAX_INSTRUCTION_TRACE_LENGTH = shared_transaction_context.MAX_INSTRUCTION_TRACE_LENGTH;
pub const MAX_INSTRUCTION_STACK_DEPTH = shared_transaction_context.MAX_INSTRUCTION_STACK_DEPTH;
pub const AccessViolationInfo = shared_transaction_context.AccessViolationInfo;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L136
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L192
pub const TransactionContext = struct {
    allocator: std.mem.Allocator,
    /// Allocator for ProgramMap entries that must outlive the transaction's arena.
    programs_allocator: std.mem.Allocator,

    /// The slot number this transaction is being executed in. Used for feature gate activations.
    slot: sig.core.Slot,

    // These data structures exist beyond the lifetime of the TransactionContext.
    // These exist per-epoch.
    feature_set: *const FeatureSet,
    epoch_stake_reader: EpochStakeReader,
    // This exists per-slot.
    sysvar_cache: *const SysvarCache,

    // The enviroment used to load and validate BPF programs.
    // Changes once per epoch, next is used when deploying bpf programs in the slot
    // prior to the next epoch. For all other slots, next is null.
    vm_environment: *const vm.Environment,
    next_vm_environment: ?*const vm.Environment,

    // Program map is used to laod and invoke valid BPF programs.
    program_map: *ProgramMap,

    /// Transaction accounts
    /// TransactionContextAccount contains a non-owning reference to an AccountSharedData
    accounts: []TransactionContextAccount,

    /// Used by CPI to access serialized account metadata.
    serialized_accounts: std14.BoundedArray(
        SerializedAccountMetadata,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ) = .{},

    /// Used by syscall.allocFree to implement sbrk bump allocation
    bpf_alloc_pos: u64 = 0,

    /// Instruction datas used when executing precompiles in the SVM
    /// Only set if a precompile is present and the move precompiles to svm feature is enabled
    instruction_datas: ?[]const []const u8 = null,

    instruction_stack: InstructionStack = .{},
    instruction_trace: InstructionTrace = .{},
    top_level_instruction_index: u16 = 0,
    return_data: TransactionReturnData = .{},

    /// Total change to account data size within transaction
    accounts_resize_delta: i64 = 0,
    /// Total change to account lamports
    accounts_lamport_delta: i128 = 0,

    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: u64,
    consumed_units: u64 = 0,
    compute_budget: ComputeBudget,

    /// If an error other than an InstructionError occurs during execution its value will
    /// be set here and InstructionError.Custom will be returned
    custom_error: ?u32 = null,

    /// SIMD-0460: when the SBPF VM raises an `AccessViolation`, the access-
    /// violation handler records the access here so the bpf_loader's
    /// post-execution error path can remap it to a more specific
    /// `InstructionError` per SIMD-0460:
    ///   - read past current account length → `AccountDataTooSmall`
    ///   - write to readonly account         → `ReadonlyDataModified`
    ///   - write to non-owned account        → `ExternalAccountDataModified`
    ///   - write past account growth budget  → `InvalidRealloc`
    /// When `handled` is true, the recorded access was repaired by the
    /// access-violation handler and must not be used for remapping.
    /// Cleared at the start of each bpf program invocation.
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0/program-runtime/src/vm.rs#L322-L385
    last_access_violation: ?AccessViolationInfo = null,

    log_collector: ?LogCollector = null,
    rent: Rent,

    /// Previous blockhash and lamports per signature from the blockhash queue
    prev_blockhash: Hash,
    prev_lamports_per_signature: u64,

    pub const InstructionStack = std14.BoundedArray(
        InstructionContext,
        MAX_INSTRUCTION_STACK_DEPTH,
    );

    pub const InstructionTrace = std14.BoundedArray(struct {
        ixn_info: InstructionInfo,
        depth: u8,
    }, MAX_INSTRUCTION_TRACE_LENGTH);

    pub fn deinit(self: TransactionContext) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "TransactionContext.deinit" });
        defer zone.deinit();

        self.allocator.free(self.accounts);
        if (self.log_collector) |*lc| lc.deinit(self.allocator);

        // Clean up CPI instruction infos stored in the trace.
        // Top-level instructions (depth == 1) are owned by ResolvedTransaction and cleaned up there.
        // CPI instructions (depth > 1) are created during execution and owned by this trace.
        for (self.instruction_trace.slice()) |entry| {
            if (entry.depth > 1) {
                entry.ixn_info.deinit(self.allocator);
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L233
    pub fn getAccountIndex(
        self: *const TransactionContext,
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

    /// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/program-runtime/src/invoke_context.rs#L688
    pub fn getCheckAligned(self: *TransactionContext) bool {
        const ic = self.getCurrentInstructionContext() catch return true;
        return ic.getCheckAligned();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/07dcd4d033f544a96a72c6c664e56871eb8a24b5/transaction-context/src/lib.rs#L340
    pub fn getCurrentInstructionContext(
        self: *TransactionContext,
    ) InstructionError!*InstructionContext {
        if (self.instruction_stack.len == 0) return InstructionError.CallDepth;
        return &self.instruction_stack.buffer[self.instruction_stack.len - 1];
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L646
    pub fn borrowAccountAtIndex(
        self: *TransactionContext,
        index: u16,
        context: BorrowedAccountContext,
    ) InstructionError!BorrowedAccount {
        const txn_account = self.getAccountAtIndex(index) orelse
            return InstructionError.MissingAccount;

        const account, const account_write_guard = txn_account.writeWithLock() orelse
            return InstructionError.AccountBorrowFailed;

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
            self.consumed_units +|= self.compute_meter;
            self.compute_meter = 0;
            return InstructionError.ComputationalBudgetExceeded;
        }
        self.consumeUnchecked(compute);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/invoke_context.rs#L100-L105
    pub fn consumeUnchecked(self: *TransactionContext, compute: u64) void {
        self.consumed_units +|= compute;
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

    pub fn takeLogCollector(
        self: *TransactionContext,
    ) ?LogCollector {
        if (self.log_collector) |lc| {
            self.log_collector = null;
            return lc;
        }
        return null;
    }

    pub fn takeReturnData(
        self: *TransactionContext,
    ) ?TransactionReturnData {
        if (self.return_data.data.len == 0) return null;
        const data = self.return_data;
        self.return_data.data.len = 0;
        return data;
    }
};

pub const TransactionReturnData = shared_transaction_context.TransactionReturnData;
pub const TransactionContextAccount = shared_transaction_context.TransactionContextAccount;
