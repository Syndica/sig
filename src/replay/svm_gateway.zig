const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const vm = sig.vm;

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Ancestors = sig.core.status_cache.Ancestors;
const BlockhashQueue = sig.core.bank.BlockhashQueue;
const EpochStakes = sig.core.stake.EpochStakes;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const Slot = sig.core.Slot;
const StatusCache = sig.core.StatusCache;

const AccountsDB = sig.accounts_db.AccountsDB;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;

const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const ComputeBudget = sig.runtime.ComputeBudget;
const FeatureSet = sig.runtime.FeatureSet;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionExecutionEnvironment =
    sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

const loadPrograms = sig.runtime.program_loader.loadPrograms;
const initDurableNonceFromHash = sig.runtime.nonce.initDurableNonceFromHash;

pub fn executeTransaction(
    allocator: Allocator,
    svm_slot: *SvmSlot,
    transaction: *const RuntimeTransaction,
) !TransactionResult(ProcessedTransaction) {
    return try sig.runtime.transaction_execution.loadAndExecuteTransaction(
        allocator,
        transaction,
        &svm_slot.state.accounts,
        &try svm_slot.environment(),
        &.{ .log = true, .log_messages_byte_limit = null },
        &svm_slot.state.programs,
    );
}

/// State that needs to be initialized once per slot for the SVM
///
/// This is intended for read-only use across multiple threads simultaneously.
pub const SvmSlot = struct {
    params: Params,

    /// Data initialized and owned by this struct that will be passed by
    /// reference into the SVM
    state: struct {
        status_cache: StatusCache,
        sysvar_cache: SysvarCache,
        vm_environment: vm.Environment,
        next_vm_environment: ?vm.Environment,
        accounts: BatchAccountCache, // TODO figure out how to share this safely across threads
        programs: ProgramMap,
    },

    pub const Params = struct {
        // Simple inputs to copy into the svm
        slot: u64,
        max_age: u64,
        lamports_per_signature: u64,

        /// Owned
        blockhash_queue: BlockhashQueue,

        // Borrowed values to pass by reference into the SVM.
        ancestors: *const Ancestors,
        feature_set: FeatureSet,
        rent_collector: *const RentCollector,
        epoch_stakes: *const EpochStakes,
    };

    pub fn init(
        allocator: Allocator,
        accounts_db: *AccountsDB,
        batches: []const ResolvedBatch,
        total_transactions: usize,
        params: Params,
    ) !SvmSlot {
        // these transactions have the incorrect hash but are otherwise valid.
        // they're all being grouped together just for the account loader. the hash
        // is not actually used by the account loader, so it doesn't matter.
        //
        // TODO: minimize dependencies fo BatchAccountCache so it doesn't require
        // the transaction hash.
        var unhashed_transactions_for_account_loader =
            try std.ArrayListUnmanaged(RuntimeTransaction)
                .initCapacity(allocator, total_transactions);
        defer unhashed_transactions_for_account_loader.deinit(allocator);
        for (batches) |batch| for (batch.transactions) |tx| {
            const runtime_tx = tx.toRuntimeTransaction(.ZEROES);
            unhashed_transactions_for_account_loader.appendAssumeCapacity(runtime_tx);
        };
        const accounts = try BatchAccountCache.initFromAccountsDb(
            .AccountsDb,
            allocator,
            accounts_db,
            unhashed_transactions_for_account_loader.items,
        );

        const budget = ComputeBudget.default(1_400_000); // TODO should this be dynamic?

        const vm_environment = try vm.Environment.initV1(
            allocator,
            &params.feature_set,
            &budget,
            false,
            true, // TODO: should this be false?
        );

        const programs =
            try loadPrograms(allocator, &accounts.account_cache, &vm_environment, params.slot);
        errdefer {
            for (programs.values()) |program| program.deinit(allocator);
            programs.deinit(allocator);
        }

        return .{
            .params = params,
            .state = .{
                .status_cache = .DEFAULT, // TODO: actually use this in replay
                .sysvar_cache = .{},
                .vm_environment = vm_environment,
                .next_vm_environment = null, // TODO epoch boundary
                .accounts = accounts,
                .programs = programs,
            },
        };
    }

    pub fn deinit(self: *const SvmSlot, allocator: Allocator) void {
        self.params.blockhash_queue.deinit(allocator);
        // TODO self.state
    }

    pub fn environment(self: *const SvmSlot) !TransactionExecutionEnvironment {
        const last_blockhash = self.params.blockhash_queue.last_hash orelse
            return error.MissingLastBlockhash;

        const last_blockhash_info = self.params.blockhash_queue
            .getHashInfoIfValid(&last_blockhash, self.params.max_age) orelse
            return error.MissingLastBlockhashInfo;

        const last_lamports_per_signature =
            last_blockhash_info.fee_calculator.lamports_per_signature;

        return .{
            .ancestors = self.params.ancestors,
            .feature_set = &self.params.feature_set,
            .status_cache = &self.state.status_cache,
            .sysvar_cache = &self.state.sysvar_cache,
            .rent_collector = self.params.rent_collector,
            .blockhash_queue = &self.params.blockhash_queue,
            .epoch_stakes = self.params.epoch_stakes,
            .vm_environment = &self.state.vm_environment,
            .next_vm_environment = if (self.state.next_vm_environment) |env| &env else null,

            .slot = self.params.slot,
            .max_age = self.params.max_age,
            .last_blockhash = last_blockhash,
            .next_durable_nonce = initDurableNonceFromHash(last_blockhash),

            // this seems wrong/redundant but it's exactly how agave does it.
            // it's actually not even possible to figure out what the next
            // slot's fee rate is going to be at this point, so this field seems
            // meaningless.
            // https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank/check_transactions.rs#L94-L96
            .next_lamports_per_signature = last_lamports_per_signature,

            // https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank.rs#L2893-L2896
            .last_lamports_per_signature = last_lamports_per_signature,

            .lamports_per_signature = self.params.lamports_per_signature,
        };
    }
};
