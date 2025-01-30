// TODO: add comments and permalinks

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const RwMux = sig.sync.RwMux;
const AccountSharedData = sig.runtime.AccountSharedData;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const InstructionError = sig.core.instruction.InstructionError;
const LogCollector = sig.runtime.LogCollector;
const Transaction = sig.core.Transaction;
const SysvarCache = sig.runtime.SysvarCache;

pub const MAX_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION =
    sig.runtime.MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION;

// https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/program-runtime/src/compute_budget.rs#L139
pub const MAX_INSTRUCTION_TRACE_LENGTH: usize = 100;

// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

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
        const account_info, var account_info_read_guard = self.accounts.slice()[index].readWithLock();
        defer account_info_read_guard.unlock();
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

    pub fn getSysvar(self: *ExecuteTransactionContext, comptime T: type) error{UnsupportedSysvar}!T {
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
        if (self.maybe_log_collector) |*log_collector| log_collector.log(fmt, args) catch @panic("TODO: handle log error");
    }
};

// /// Main pipeline from runtime to program execution.
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

// /// Loaded transaction shared between runtime and programs.
// ///
// /// This context is valid for the entire duration of a transaction being processed.
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

// struct __attribute__((aligned(8UL))) fd_exec_txn_ctx {
//   ulong magic; /* ==FD_EXEC_TXN_CTX_MAGIC */

//   fd_exec_epoch_ctx_t const * epoch_ctx;
//   fd_exec_slot_ctx_t const *  slot_ctx;

//   fd_funk_txn_t *       funk_txn;
//   fd_acc_mgr_t *        acc_mgr;
//   fd_spad_t *           spad;                                        /* Sized out to handle the worst case footprint of single transaction execution. */

//   ulong                 paid_fees;
//   ulong                 compute_unit_limit;                          /* Compute unit limit for this transaction. */
//   ulong                 compute_unit_price;                          /* Compute unit price for this transaction. */
//   ulong                 compute_meter;                               /* Remaining compute units */
//   ulong                 heap_size;                                   /* Heap size for VMs for this transaction. */
//   ulong                 loaded_accounts_data_size_limit;             /* Loaded accounts data size limit for this transaction. */
//   uint                  prioritization_fee_type;                     /* The type of prioritization fee to use. */
//   fd_txn_t const *      txn_descriptor;                              /* Descriptor of the transaction. */
//   fd_rawtxn_b_t         _txn_raw[1];                                 /* Raw bytes of the transaction. */
//   uint                  custom_err;                                  /* When a custom error is returned, this is where the numeric value gets stashed */
//   uchar                 instr_stack_sz;                              /* Current depth of the instruction execution stack. */
//   fd_exec_instr_ctx_t   instr_stack[FD_MAX_INSTRUCTION_STACK_DEPTH]; /* Instruction execution stack. */
//   fd_exec_instr_ctx_t * failed_instr;
//   int                   instr_err_idx;
//   /* During sanitization, v0 transactions are allowed to have up to 256 accounts:
//      https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/sdk/program/src/message/versions/v0/mod.rs#L139
//      Nonetheless, when Agave prepares a sanitized batch for execution and tries to lock accounts, a lower limit is enforced:
//      https://github.com/anza-xyz/agave/blob/838c1952595809a31520ff1603a13f2c9123aa51/accounts-db/src/account_locks.rs#L118
//      That is the limit we are going to use here. */
//   ulong                 accounts_cnt;                                /* Number of account pubkeys accessed by this transaction. */
//   fd_pubkey_t           accounts[ MAX_TX_ACCOUNT_LOCKS ];            /* Array of account pubkeys accessed by this transaction. */
//   ulong                 executable_cnt;                              /* Number of BPF upgradeable loader accounts. */
//   fd_borrowed_account_t executable_accounts[ MAX_TX_ACCOUNT_LOCKS ]; /* Array of BPF upgradeable loader program data accounts */
//   fd_borrowed_account_t borrowed_accounts[ MAX_TX_ACCOUNT_LOCKS ];   /* Array of borrowed accounts accessed by this transaction. */
//   uchar                 nonce_accounts[ MAX_TX_ACCOUNT_LOCKS ];      /* Nonce accounts in the txn to be saved */
//   uint                  num_instructions;                            /* Counter for number of instructions in txn */
//   fd_txn_return_data_t  return_data;                                 /* Data returned from `return_data` syscalls */
//   fd_vote_account_cache_t * vote_accounts_map;                       /* Cache of bank's deserialized vote accounts to support fork choice */
//   fd_vote_account_cache_entry_t * vote_accounts_pool;                /* Memory pool for deserialized vote account cache */
//   ulong                 accounts_resize_delta;                       /* Transaction level tracking for account resizing */
//   fd_hash_t             blake_txn_msg_hash;                          /* Hash of raw transaction message used by the status cache */
//   ulong                 execution_fee;                               /* Execution fee paid by the fee payer in the transaction */
//   ulong                 priority_fee;                                /* Priority fee paid by the fee payer in the transaction */
//   ulong                 collected_rent;                              /* Rent collected from accounts in this transaction */

//   uchar dirty_vote_acc  : 1;                                         /* 1 if this transaction maybe modified a vote account */
//   uchar dirty_stake_acc : 1;                                         /* 1 if this transaction maybe modified a stake account */

//   fd_capture_ctx_t * capture_ctx;

//   /* The instr_infos for the entire transaction are allocated at the start of
//      the transaction. However, this must preserve a different counter because
//      the top level instructions must get set up at once. The instruction
//      error check on a maximum instruction size can be done on the
//      instr_info_cnt instead of the instr_trace_length because it is a proxy
//      for the trace_length: the instr_info_cnt gets incremented faster than
//      the instr_trace_length because it counts all of the top level instructions
//      first. */
//   fd_instr_info_t             instr_infos[FD_MAX_INSTRUCTION_TRACE_LENGTH];
//   ulong                       instr_info_cnt;

//   fd_exec_instr_trace_entry_t instr_trace[FD_MAX_INSTRUCTION_TRACE_LENGTH]; /* Instruction trace */
//   ulong                       instr_trace_length;                           /* Number of instructions in the trace */

//   fd_log_collector_t          log_collector;             /* Log collector instance */

//   /* Execution error and type, to match Agave. */
//   int exec_err;
//   int exec_err_kind;

//   /* The has_program_id flag is used to indicate if the current transaction has valid program indices or not.
//      It will be set in fd_executor_load_transaction_accounts similar to how program_indices is used in
//      load_transaction_accounts on the agave side */
//   uchar has_program_id;
// };
