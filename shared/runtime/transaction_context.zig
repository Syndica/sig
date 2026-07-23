const std = @import("std");
const tracy = @import("tracy");
const std14 = @import("std14");
const sig = @import("../lib.zig");

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

/// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/transaction-context/src/lib.rs#L17
pub const MAX_ACCOUNTS_PER_INSTRUCTION = 255;

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/transaction-context/src/lib.rs#L41
pub const MAX_INSTRUCTION_TRACE_LENGTH = 64;

// https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/execution_budget.rs#L8
pub const MAX_INSTRUCTION_STACK_DEPTH = 5;

/// SIMD-0460: information captured by the SBPF memory map's access-violation
/// handler so the bpf_loader post-execution path can remap a generic
/// `AccessViolation` into a specific account-related `InstructionError`.
///
/// Sig differs from Agave here: Agave resolves handled account-growth accesses
/// inside the memory-mapping layer without persisting equivalent remap
/// metadata, while Sig keeps the last attempted access for post-execution
/// classification. `handled=true` means the handler successfully repaired the
/// access by growing the region far enough for the retry to succeed, so this
/// record must be ignored by `remapAccessViolation`.
pub const AccessViolationInfo = struct {
    access_type: vm.memory.MemoryState,
    vm_addr: u64,
    len: u64,
    handled: bool = false,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f/sdk/src/transaction_context.rs#L136
/// [agave]
/// https://github.com/anza-xyz/agave/blob/faea52f/program-runtime/src/invoke_context.rs#L192
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
        // Top-level instructions (depth == 1) are owned by ResolvedTransaction and cleaned up
        // there.
        // CPI instructions (depth > 1) are created during execution and owned by this trace.
        for (self.instruction_trace.slice()) |entry| {
            if (entry.depth > 1) {
                entry.ixn_info.deinit(self.allocator);
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c/sdk/src/transaction_context.rs#L233
    pub fn getAccountIndex(
        self: *const TransactionContext,
        pubkey: Pubkey,
    ) ?u16 {
        for (self.accounts, 0..) |account, index|
            if (account.pubkey.equals(&pubkey)) return @intCast(index);
        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c/sdk/src/transaction_context.rs#L223
    pub fn getAccountAtIndex(
        self: *const TransactionContext,
        index: u16,
    ) ?*TransactionContextAccount {
        if (index >= self.accounts.len) return null;
        return &self.accounts[index];
    }

    /// [agave]
    /// https://github.com/anza-xyz/agave/blob/a11b42a/program-runtime/src/invoke_context.rs#L688
    pub fn getCheckAligned(self: *TransactionContext) bool {
        const ic = self.getCurrentInstructionContext() catch return true;
        return ic.getCheckAligned();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/07dcd4d/transaction-context/src/lib.rs#L340
    pub fn getCurrentInstructionContext(
        self: *TransactionContext,
    ) InstructionError!*InstructionContext {
        if (self.instruction_stack.len == 0) return InstructionError.CallDepth;
        return &self.instruction_stack.buffer[self.instruction_stack.len - 1];
    }

    /// [agave]
    /// https://github.com/anza-xyz/solana-sdk/blob/e1554f4/transaction-context/src/lib.rs#L646
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

    /// [agave]
    /// https://github.com/anza-xyz/agave/blob/faea52f/program-runtime/src/invoke_context.rs#L574
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

    /// [agave]
    /// https://github.com/anza-xyz/agave/blob/faea52f/program-runtime/src/invoke_context.rs#L100-L105
    pub fn consumeUnchecked(self: *TransactionContext, compute: u64) void {
        self.consumed_units +|= compute;
        self.compute_meter -|= compute;
    }

    /// [agave]
    /// https://github.com/anza-xyz/agave/blob/faea52f/program-runtime/src/log_collector.rs#L94
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

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4/transaction-context/src/lib.rs#L493
pub const TransactionReturnData = struct {
    program_id: Pubkey = Pubkey.ZEROES,
    data: std14.BoundedArray(u8, MAX_RETURN_DATA) = .{},

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/95764e2/cpi/src/lib.rs#L329
    pub const MAX_RETURN_DATA: usize = 1024;
};

/// Represents an account within a transaction and provides single threaded
/// read/write access to the account data to prevent invalid access during cpi.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f/sdk/src/transaction_context.rs#L137-L139
pub const TransactionContextAccount = struct {
    pubkey: Pubkey,
    account: *AccountSharedData,
    read_refs: usize = 0,
    write_ref: bool = false,

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

    pub fn init(pubkey: Pubkey, account: *AccountSharedData) TransactionContextAccount {
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
        return .{ self.account, .{ .write_ref = &self.write_ref } };
    }

    pub fn readWithLock(
        self: *TransactionContextAccount,
    ) ?struct { *AccountSharedData, RLockGuard } {
        if (self.write_ref) return null;
        self.read_refs += 1;
        return .{ self.account, .{ .read_refs = &self.read_refs } };
    }
};
