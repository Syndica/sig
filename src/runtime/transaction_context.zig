const std = @import("std");
const sig = @import("../sig.zig");

const ids = sig.runtime.ids;
const program = sig.runtime.program;
const stable_log = sig.runtime.stable_log;

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
    instruction_stack: std.BoundedArray(InstructionContext, MAX_INSTRUCTION_STACK_DEPTH) = .{},

    /// Instruction trace
    instruction_trace: std.BoundedArray(struct {
        instruction_info: InstructionInfo,
        stack_height: usize,
    }, MAX_INSTRUCTION_TRACE_LENGTH) = .{},

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

    pub fn deinit(self: TransactionContext, allocator: std.mem.Allocator) void {
        for (self.accounts) |account|
            allocator.free(account.account.data);
        allocator.free(self.accounts);
        if (self.log_collector) |lc| lc.deinit();
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L233
    pub fn getAccountIndex(self: *TransactionContext, pubkey: Pubkey) ?u16 {
        for (self.accounts, 0..) |account, index|
            if (account.pubkey.equals(&pubkey)) return @intCast(index);
        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L223
    pub fn getAccountAtIndex(self: *const TransactionContext, index: u16) ?*TransactionContextAccount {
        if (index >= self.accounts.len) return null;
        return &self.accounts[index];
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L646
    pub fn borrowAccountAtIndex(self: *TransactionContext, index: u16, context: BorrowedAccountContext) InstructionError!BorrowedAccount {
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
        const exceeded = self.compute_meter < compute;
        self.compute_meter -|= compute;
        if (exceeded) return InstructionError.ComputationalBudgetExceeded;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L452
    pub fn sumAccountLamports(self: *const TransactionContext, account_metas: []const InstructionInfo.AccountMeta) u128 {
        var lamports: u128 = 0;
        for (account_metas, 0..) |account_meta, index| {
            if (account_meta.index_in_callee != index) continue;

            const transaction_account = self.getAccountAtIndex(account_meta.index_in_transaction) orelse
                return 0;

            const account, const account_read_lock = transaction_account.readWithLock() orelse
                return 0;
            defer account_read_lock.release();

            lamports = std.math.add(u128, lamports, account.lamports) catch {
                return 0;
            };
        }
        return lamports;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/log_collector.rs#L94
    pub fn log(
        self: *TransactionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) InstructionError!void {
        if (self.log_collector) |*lc|
            lc.log(fmt, args) catch |err| {
                self.custom_error = @intFromError(err);
                return InstructionError.Custom;
            };
    }

    /// Check for reentrancy violations\
    /// Push an instruction onto the instruction stack\
    /// Push an associated entry onto the instruction trace\
    /// Returns a reference to the pushed instruction context\
    /// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L475
    /// [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1034-L1035
    pub fn pushInstruction(
        self: *TransactionContext,
        instruction_info: *InstructionInfo,
    ) InstructionError!*InstructionContext {
        const program_pubkey = instruction_info.program_meta.pubkey;

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L250-L253
        // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1001-L101
        if (program_pubkey.equals(&ids.NATIVE_LOADER_ID)) {
            return InstructionError.UnsupportedProgramId;
        }

        // [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/program-runtime/src/invoke_context.rs#L245-L283
        // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1048-L1070
        for (self.instruction_stack.constSlice(), 0..) |ic, level| {
            // If the program is on the stack, it must be the last entry otherwise it is a reentrancy violation
            if (program_pubkey.equals(&ic.info.program_meta.pubkey) and
                level != self.instruction_stack.len - 1)
            {
                return InstructionError.ReentrancyNotAllowed;
            }
        }

        // TODO: syscall_context.push(None)

        // Push the instruction onto the stack and trace, creating the instruction context
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L366-L403
        // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L975-L976

        instruction_info.initial_account_lamports = self.sumAccountLamports(instruction_info.account_metas.constSlice());

        const maybe_parent = if (self.instruction_stack.len > 0) blk: {
            const parent = &self.instruction_stack[self.instruction_stack.len - 1];
            if (parent.initial_account_lamports != self.sumAccountLamports(parent.account_metas.constSlice())) {
                return InstructionError.UnbalancedInstruction;
            }
            break :blk parent;
        } else null;

        if (self.instruction_trace.len >= self.instruction_trace.capacity()) {
            return InstructionError.MaxInstructionTraceLengthExceeded;
        }

        if (self.instruction_stack.len >= self.instruction_stack.capacity()) {
            return InstructionError.CallDepth;
        }

        self.instruction_stack.append(.{
            .tc = self,
            .parent = maybe_parent,
            .info = instruction_info,
        });

        self.instruction_trace.append(.{
            .info = instruction_info,
            .stack_height = self.instruction_stack.len,
        });

        return &self.instruction_stack.buffer[self.instruction_stack.len - 1];
    }

    /// Pop an instruction from the instruction stack\
    /// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L290
    pub fn popInstruction(self: *TransactionContext) ?InstructionError {
        // TODO: Syscall context
        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L291-L294

        // Pop from the instruction stack
        // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L406-L434

        if (self.instruction_stack.len == 0) {
            return InstructionError.CallDepth;
        }

        const unbalanced_instruction = blk: {
            const ic = &self.instruction_stack.buffer[self.instruction_stack.len - 1];
            const program_account = ic.borrowProgramAccount(ic.info.program_meta.index_in_transaction) catch {
                return InstructionError.AccountBorrowOutstanding;
            };
            program_account.release();
            break :blk (ic.info.initial_account_lamports != self.sumAccountLamports(ic.info.account_metas.constSlice()));
        };

        _ = self.instruction_stack.pop();

        return if (unbalanced_instruction)
            InstructionError.UnbalancedInstruction
        else
            null;
    }

    /// Execute an instruction described by the instruction info\
    /// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L462-L479
    pub fn executeInstruction(
        self: *TransactionContext,
        allocator: std.mem.Allocator,
        instruction_info: InstructionInfo,
    ) ?InstructionError {
        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L474
        var ic = try self.pushInstruction(instruction_info);

        // [agave] https://github.com/anza-xyz/agave/blob/a1ed2b1052bde05e79c31388b399dba9da10f7de/program-runtime/src/invoke_context.rs#L518-L529
        const program_pubkey = blk: {
            const program_account = ic.borrowProgramAccount() catch {
                return InstructionError.UnsupportedProgramId;
            };
            defer program_account.release();

            break :blk if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner))
                program_account.pubkey
            else
                program_account.account.owner;
        };

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/svm/src/message_processor.rs#L72-L75
        const maybe_native_program_fn = program.PRECOMPILES.get(program_pubkey.base58String().slice()) orelse blk: {
            const entrypoint = program.PROGRAM_ENTRYPOINTS.get(program_pubkey.base58String().slice());
            self.return_data.data.clearRetainingCapacity();
            break :blk entrypoint;
        };

        // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1160-L1167
        var execute_result = if (maybe_native_program_fn) |native_program_fn| blk: {
            stable_log.program_invoke(&self.log_collector, program_pubkey, self.instruction_stack.len);
            break :blk native_program_fn(allocator, &ic);
        } else InstructionError.UnsupportedProgramId;

        // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1168-L1190
        const pop_result = self.popInstruction();
        if (execute_result == null) {
            stable_log.program_success(&self.log_collector, program_pubkey);
            if (pop_result != null) execute_result = pop_result;
        } else {
            stable_log.program_failure(&self.log_collector, program_pubkey, execute_result);
        }

        return execute_result;
    }

    /// Prepare the InstructionInfo for an instruction invoked via CPI\
    /// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L325
    pub fn prepareCpiInstructionInfo(
        self: *TransactionContext,
        callee: Instruction,
        signers: []const Pubkey,
    ) InstructionError!InstructionInfo {
        if (self.instruction_stack.len == 0) {
            return InstructionError.CallDepth;
        }
        const caller = &self.instruction_stack.buffer[self.instruction_stack.len - 1];

        var deduped_instruction_accounts = InstructionInfo.AccountMetas{};
        var deduped_indexes = std.BoundedArray(usize, InstructionInfo.MAX_ACCOUNT_METAS){};

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L337-L386
        for (callee.account_metas, 0..) |account_meta, index| {
            const index_in_transaction = self.getAccountIndex(account_meta.pubkey) orelse {
                try self.log("Instruction references unkown account {}", .{account_meta.pubkey});
                return InstructionError.MissingAccount;
            };

            for (deduped_instruction_accounts.slice(), 0..) |*deduped_account, deduped_index| {
                if (deduped_account.index_in_transaction == index_in_transaction) {
                    deduped_indexes.appendAssumeCapacity(deduped_index);
                    deduped_account.is_signer = deduped_account.is_signer or account_meta.is_signer;
                    deduped_account.is_writable = deduped_account.is_writable or account_meta.is_writable;
                }
                continue;
            }

            const index_in_caller = caller.getAccountMetaIndex(account_meta.pubkey) orelse {
                try self.log("Instruction references unkown account {}", .{account_meta.pubkey});
                return InstructionError.MissingAccount;
            };

            deduped_indexes.appendAssumeCapacity(deduped_instruction_accounts.len);
            deduped_instruction_accounts.appendAssumeCapacity(.{
                .pubkey = account_meta.pubkey,
                .index_in_transaction = index_in_transaction,
                .index_in_caller = index_in_caller,
                .index_in_callee = @intCast(index),
                .is_signer = account_meta.is_signer,
                .is_writable = account_meta.is_writable,
            });
        }

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L386-L415
        for (deduped_instruction_accounts.slice()) |callee_account| {
            // Borrow the account via the caller context
            const caller_account = try caller.borrowInstructionAccount(callee_account.index_in_transaction);
            defer caller_account.release();

            // Readonly in caller cannot become writable in callee
            if (!caller_account.isWritable() and callee_account.is_writable) {
                try self.log("{}'s writable privilege escalated", .{caller_account.pubkey});
                return InstructionError.PrivilegeEscalation;
            }

            // To be signed in the callee,
            // it must be either signed in the caller or by the program
            var allow_callee_signer = caller_account.isSigner();
            for (signers) |signer| {
                if (!allow_callee_signer) {
                    if (signer.equals(&caller_account.pubkey)) allow_callee_signer = true;
                } else break;
            }
            if (!allow_callee_signer and callee_account.is_signer) {
                try self.log("{}'s signer privilege escalated", .{caller_account.pubkey});
                return InstructionError.PrivilegeEscalation;
            }
        }

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L415-L425
        var instruction_accounts = InstructionInfo.AccountMetas{};
        for (deduped_indexes.slice()) |index| {
            const deduped_account = deduped_instruction_accounts.buffer[index];
            instruction_accounts.appendAssumeCapacity(.{
                .pubkey = deduped_account.pubkey,
                .index_in_transaction = deduped_account.index_in_transaction,
                .index_in_caller = deduped_account.index_in_caller,
                .index_in_callee = deduped_account.index_in_callee,
                .is_signer = deduped_account.is_signer,
                .is_writable = deduped_account.is_writable,
            });
        }

        // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L426-L457
        const index_in_caller = caller.getAccountMetaIndex(callee.program_pubkey) orelse {
            try self.log("Unknown program {}", .{callee.program_pubkey});
            return InstructionError.MissingAccount;
        };
        const index_in_transaction = caller.account_metas.buffer[index_in_caller].index_in_transaction;

        const borrowed_program_account = try caller.borrowInstructionAccount(index_in_caller);
        defer borrowed_program_account.release();

        if (!borrowed_program_account.account.executable) {
            try self.log("Account {} is not executable", .{callee.program_pubkey});
            return InstructionError.AccountNotExecutable;
        }

        return .{
            .{
                .pubkey = callee.program_pubkey,
                .index_in_transaction = index_in_transaction,
            },
            instruction_accounts,
        };
    }

    /// Execute a native CPI instruction\
    /// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L305-L306
    pub fn executeNativeCpi(
        self: *TransactionContext,
        allocator: std.mem.Allocator,
        caller: *const InstructionContext,
        instruction: Instruction,
        signers: []const Pubkey,
    ) InstructionError!void {
        const instruction_info = try self.prepareCpiInstructionInfo(caller, instruction, signers);
        try self.executeInstruction(allocator, instruction_info);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L493
pub const TransactionReturnData = struct {
    program_pubkey: Pubkey = Pubkey.ZEROES,
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
