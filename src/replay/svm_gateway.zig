const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const vm = sig.vm;

const Allocator = std.mem.Allocator;

const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const VersionedEpochStakes = sig.core.VersionedEpochStakes;
const RentCollector = sig.core.rent_collector.RentCollector;
const StatusCache = sig.core.StatusCache;

const AccountsDB = sig.accounts_db.AccountsDB;

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

// TODO: rename this struct
/// State that needs to be initialized once per batch for the SVM
///
/// This is intended for read-only use across multiple threads simultaneously.
pub const SvmSlot = struct {
    params: Params,

    /// Data initialized and owned by this struct that will be passed by
    /// reference into the SVM
    state: struct {
        sysvar_cache: SysvarCache,
        vm_environment: vm.Environment,
        next_vm_environment: ?vm.Environment,
        // TODO figure out how to share this safely across threads so this
        // struct doesn't need to be created once per batch
        accounts: BatchAccountCache,
        programs: ProgramMap,
    },

    pub const Params = struct {
        // Simple inputs to copy into the svm
        slot: u64,
        max_age: u64,
        lamports_per_signature: u64,

        /// Owned by this struct: Params
        blockhash_queue: BlockhashQueue,

        /// used to initialize the batch account cache and program map
        accounts_db: *AccountsDB,

        // Borrowed values to pass by reference into the SVM.
        ancestors: *const Ancestors,
        feature_set: FeatureSet,
        rent_collector: *const RentCollector,
        epoch_stakes: *const sig.core.EpochStakes,
        status_cache: *StatusCache,
    };

    pub fn init(
        allocator: Allocator,
        batch: []const replay.resolve_lookup.ResolvedTransaction,
        params: Params,
    ) !SvmSlot {
        // these transactions have the incorrect hash but are otherwise valid.
        // they're all being grouped together just for the account loader. the hash
        // is not actually used by the account loader, so it doesn't matter.
        //
        // TODO: minimize dependencies of BatchAccountCache so it doesn't require
        // the transaction hash.
        const unhashed_transactions_for_account_loader =
            try allocator.alloc(RuntimeTransaction, batch.len);
        defer allocator.free(unhashed_transactions_for_account_loader);
        for (batch, unhashed_transactions_for_account_loader) |tx, *unhashed| {
            unhashed.* = tx.toRuntimeTransaction(.ZEROES);
        }
        const accounts = try BatchAccountCache.initFromAccountsDb(
            .AccountsDb,
            allocator,
            params.accounts_db,
            unhashed_transactions_for_account_loader,
            params.ancestors,
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
                .sysvar_cache = .{}, // TODO: populate
                .vm_environment = vm_environment,
                .next_vm_environment = null, // TODO epoch boundary
                .accounts = accounts,
                .programs = programs,
            },
        };
    }

    pub fn deinit(self: *const SvmSlot, allocator: Allocator) void {
        _ = self; // autofix
        _ = allocator; // autofix
        // self.params.blockhash_queue.deinit(allocator); // TODO fix leak
        // TODO self.state
    }

    pub fn environment(self: *const SvmSlot) !TransactionExecutionEnvironment {
        const last_blockhash = self.params.blockhash_queue.last_hash orelse
            return error.MissingLastBlockhash;

        const last_blockhash_info = self.params.blockhash_queue
            .getHashInfoIfValid(last_blockhash, self.params.max_age) orelse
            return error.MissingLastBlockhashInfo;

        const last_lamports_per_signature = last_blockhash_info.lamports_per_signature;

        return .{
            .ancestors = self.params.ancestors,
            .feature_set = &self.params.feature_set,
            .status_cache = self.params.status_cache,
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
