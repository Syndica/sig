// TODO: add comments and permalinks

const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
const InstructionError = sig.core.instruction.InstructionError;
const SystemError = sig.runtime.program.system_program.SystemProgramError;
const Pubkey = sig.core.Pubkey;

const MAX_INSTRUCTION_ACCOUNTS = sig.runtime.MAX_INSTRUCTION_ACCOUNTS;

pub const ExecuteInstructionContext = struct {
    /// The transaction context associated with this instruction execution
    etc: *ExecuteTransactionContext,

    /// The program id of the currently executing instruction
    program_id: Pubkey,

    /// The accounts used by this instruction and their required metadata
    accounts: std.BoundedArray(AccountInfo, MAX_INSTRUCTION_ACCOUNTS),

    pub const AccountInfo = struct {
        pubkey: Pubkey,
        is_signer: bool,
        is_writable: bool,
        index_in_transaction: u16,
    };

    pub fn checkAccountsResizeDelta(
        self: *const ExecuteInstructionContext,
        delta: i64,
    ) error{MaxAccountsDataAllocationsExceeded}!void {
        try self.etc.checkAccountsResizeDelta(delta);
    }

    fn checkAccountAtIndex(
        eic: *ExecuteInstructionContext,
        index: usize,
        expected: Pubkey,
    ) InstructionError!void {
        if (index >= eic.accounts.len) return error.NotEnoughAccountKeys;
        if (!expected.equals(eic.getAccountPubkey(index))) return error.InvalidArgument;
    }

    pub fn checkIsSigner(
        self: *const ExecuteInstructionContext,
        comptime T: type,
        probe: T,
    ) error{MissingRequiredSignature}!void {
        switch (T) {
            Pubkey => {
                for (self.accounts.buffer) |account| {
                    if (account.pubkey.equals(&probe))
                        if (account.is_signer) return else return error.MissingRequiredSignature;
                }
                return error.MissingRequiredSignature;
            },
            u16 => {
                if (!self.accounts.get(probe).is_signer)
                    return error.MissingRequiredSignature;
            },
            else => @compileError("Invalid type for `probe`"),
        }
    }

    pub fn checkNumberOfAccounts(
        self: *const ExecuteInstructionContext,
        required: usize,
    ) error{NotEnoughAccountKeys}!void {
        if (self.accounts.len < required) return error.NotEnoughAccountKeys;
    }

    pub fn consumeCompute(
        self: *const ExecuteInstructionContext,
        units: u64,
    ) error{ComputationalBudgetExceeded}!void {
        try self.etc.consumeCompute(units);
    }

    pub fn getAccountPubkey(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) error{NotEnoughAccountKeys}!Pubkey {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        self.accounts[index].pubkey;
    }

    pub fn getBlockhash(self: *const ExecuteInstructionContext) Hash {
        self.etc.getBlockhash();
    }

    pub fn getBorrowedAccount(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) InstructionError!BorrowedAccount {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        return self.etc.getBorrowedAccount(self, &self.accounts.get(index));
    }

    pub fn getLamportsPerSignature(self: *const ExecuteInstructionContext) u64 {
        self.etc.getLamportsPerSignature();
    }

    pub fn getSysvar(self: *const ExecuteInstructionContext, comptime T: type) error{UnsupportedSysvar}!T {
        self.etc.getSysvar(T);
    }

    pub fn isOwner(self: *const ExecuteInstructionContext, pubkey: Pubkey) bool {
        return self.program_id.equals(&pubkey);
    }

    pub fn addAccountsResizeDelta(self: *const ExecuteInstructionContext, delta: i64) void {
        self.etc.addAccountsResizeDelta(delta);
    }

    pub fn setCustomError(self: *const ExecuteInstructionContext, custom_error: u32) void {
        self.etc.setCustomError(custom_error);
    }

    pub fn log(
        self: *const ExecuteInstructionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        self.etc.log(fmt, args);
    }
};

// struct __attribute__((aligned(8UL))) fd_exec_instr_ctx {
//   ulong magic; /* ==FD_EXEC_INSTR_CTX_MAGIC */

//   fd_exec_epoch_ctx_t const * epoch_ctx;
//   fd_exec_slot_ctx_t const *  slot_ctx; /* TOJDO: needs to be made const to be thread safe. */
//   fd_exec_txn_ctx_t *         txn_ctx;  /* The transaction context for this instruction */

//   fd_exec_instr_ctx_t const * parent;

//   uint depth;      /* starts at 0 */
//   uint index;      /* number of preceding instructions with same parent */
//   uint child_cnt;  /* number of child instructions */
//   uint instr_err;  /* TOJDO: this is kind of redundant wrt instr_exec */

//   fd_funk_txn_t * funk_txn;
//   fd_acc_mgr_t *  acc_mgr;

//   /* Most instructions log the base58 program id multiple times, so it's
//      convenient to compute it once and reuse it. */
//   char program_id_base58[ FD_BASE58_ENCODED_32_SZ ];

//   fd_instr_info_t const * instr;
// };

// pub struct InvokeContext<'a> {
//     /// Information about the currently executing transaction.
//     pub transaction_context: &'a mut TransactionContext,
//     /// The local program cache for the transaction batch.
//     pub program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
//     /// Runtime configurations used to provision the invocation environment.
//     pub environment_config: EnvironmentConfig<'a>,
//     /// The compute budget for the current invocation.
//     compute_budget: ComputeBudget,
//     /// Instruction compute meter, for tracking compute units consumed against
//     /// the designated compute budget during program execution.
//     compute_meter: RefCell<u64>,
//     log_collector: Option<Rc<RefCell<LogCollector>>>,
//     /// Latest measurement not yet accumulated in [ExecuteDetailsTimings::execute_us]
//     pub execute_time: Option<Measure>,
//     pub timings: ExecuteDetailsTimings,
//     pub syscall_context: Vec<Option<SyscallContext>>,
//     traces: Vec<Vec<[u64; 12]>>,
// }

// /// Index of an account inside of the TransactionContext or an InstructionContext.
// pub type IndexOfAccount = u16;

// pub struct InstructionAccount {
//     /// Points to the account and its key in the `TransactionContext`
//     pub index_in_transaction: IndexOfAccount,
//     /// Points to the first occurrence in the parent `InstructionContext`
//     ///
//     /// This excludes the program accounts.
//     pub index_in_caller: IndexOfAccount,
//     /// Points to the first occurrence in the current `InstructionContext`
//     ///
//     /// This excludes the program accounts.
//     pub index_in_callee: IndexOfAccount,
//     /// Is this account supposed to sign
//     pub is_signer: bool,
//     /// Is this account allowed to become writable
//     pub is_writable: bool,
// }

// pub struct TransactionAccounts {
//     accounts: Vec<RefCell<AccountSharedData>>,
//     touched_flags: RefCell<Box<[bool]>>,
// }

// pub struct TransactionContext {
//     account_keys: Pin<Box<[Pubkey]>>,
//     accounts: Rc<TransactionAccounts>,
//     instruction_stack_capacity: usize,
//     instruction_trace_capacity: usize,
//     instruction_stack: Vec<usize>,
//     instruction_trace: Vec<InstructionContext>,
//     return_data: TransactionReturnData,
//     accounts_resize_delta: RefCell<i64>,
//     #[cfg(not(target_os = "solana"))]
//     remove_accounts_executable_flag_checks: bool,
//     #[cfg(not(target_os = "solana"))]
//     rent: Rent,
//     /// Useful for debugging to filter by or to look it up on the explorer
//     #[cfg(all(
//         not(target_os = "solana"),
//         feature = "debug-signature",
//         debug_assertions
//     ))]
//     signature: Signature,

// }

// pub struct TransactionReturnData {
//     pub program_id: Pubkey,
//     pub data: Vec<u8>,
// }

// pub struct InstructionContext {
//     nesting_level: usize,
//     instruction_accounts_lamport_sum: u128,
//     program_accounts: Vec<IndexOfAccount>,
//     instruction_accounts: Vec<InstructionAccount>,
//     instruction_data: Vec<u8>,
// }

// /// Shared account borrowed from the TransactionContext and an InstructionContext.
// #[derive(Debug)]
// pub struct BorrowedAccount<'a> {
//     transaction_context: &'a TransactionContext,
//     instruction_context: &'a InstructionContext,
//     index_in_transaction: IndexOfAccount,
//     index_in_instruction: IndexOfAccount,
//     account: RefMut<'a, AccountSharedData>,
// }

// /// Everything that needs to be recorded from a TransactionContext after execution
// #[cfg(not(target_os = "solana"))]
// pub struct ExecutionRecord {
//     pub accounts: Vec<TransactionAccount>,
//     pub return_data: TransactionReturnData,
//     pub touched_account_count: u64,
//     pub accounts_resize_delta: i64,
// }
