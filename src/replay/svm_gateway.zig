const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const vm = sig.vm;

const Allocator = std.mem.Allocator;

const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const RentCollector = sig.core.rent_collector.RentCollector;
const StatusCache = sig.core.StatusCache;

const SlotAccountStore = sig.accounts_db.SlotAccountStore;

const ComputeBudget = sig.runtime.ComputeBudget;
const FeatureSet = sig.core.FeatureSet;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionExecutionEnvironment =
    sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

const initDurableNonceFromHash = sig.runtime.nonce.initDurableNonceFromHash;

pub fn executeTransaction(
    gpa: Allocator,
    allocator: Allocator,
    svm_gateway: *SvmGateway,
    transaction: *const RuntimeTransaction,
) !TransactionResult(ProcessedTransaction) {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();

    const environment = try svm_gateway.environment();

    return try sig.runtime.transaction_execution.loadAndExecuteTransaction(
        gpa,
        allocator,
        transaction,
        svm_gateway.params.account_store,
        &environment,
        &.{ .log = true, .log_messages_byte_limit = null },
        &svm_gateway.state.programs,
    );
}

/// State that needs to be initialized once per batch for the SVM
///
/// This is intended for read-only use across multiple threads simultaneously.
pub const SvmGateway = struct {
    params: Params,

    /// Data initialized and owned by this struct that will be passed by
    /// reference into the SVM
    state: struct {
        sysvar_cache: SysvarCache,
        vm_environment: vm.Environment,
        next_vm_environment: ?vm.Environment,
        programs: ProgramMap,

        /// This is an ugly solution, but it doesn't actually lead to any issues
        /// with contention due to how replay works. Long term, this will be
        /// resolved by moving BlockhashQueue to SlotConstants so we don't need
        /// a lock, but this requires some rework of the slot freezing logic.
        blockhash_queue: sig.sync.RwMux(BlockhashQueue).RLockGuard,
    },

    pub const Params = struct {
        // Simple inputs to copy into the svm
        slot: u64,
        max_age: u64,
        lamports_per_signature: u64,

        // Borrowed values to pass by reference into the SVM.
        account_store: SlotAccountStore,
        blockhash_queue: *sig.sync.RwMux(BlockhashQueue),
        ancestors: *const Ancestors,
        feature_set: FeatureSet,
        rent_collector: *const RentCollector,
        epoch_stakes: *const sig.core.EpochStakes,
        status_cache: *StatusCache,
    };

    pub fn init(allocator: Allocator, params: Params) !SvmGateway {
        const zone = tracy.Zone.init(@src(), .{ .name = "SvmGateway.init" });
        defer zone.deinit();

        const vm_environment = vm.Environment.initV1(
            &params.feature_set,
            // This does not actually set the compute budget. it's only used to
            // set that max call depth and stack frame size. the actual compute
            // budgets are determined per transaction.
            &ComputeBudget.DEFAULT,
            params.slot,
            false,
            false,
        );

        var sysvar_cache: SysvarCache = .{};
        try replay.update_sysvar.fillMissingSysvarCacheEntries(
            allocator,
            params.account_store.reader(),
            &sysvar_cache,
        );

        return .{
            .params = params,
            .state = .{
                .sysvar_cache = sysvar_cache,
                .vm_environment = vm_environment,
                .next_vm_environment = null, // TODO epoch boundary
                .programs = .empty,

                // blockhash queue is only written when freezing a slot,
                // which comes *after* executing all transactions, not
                // concurrently (with this struct's existence).
                // TODO: why does tryRead sometimes fail here - this seems weird?
                .blockhash_queue = params.blockhash_queue.read(),
            },
        };
    }

    pub fn deinit(self: *const SvmGateway, allocator: Allocator) void {
        var bhq = self.state.blockhash_queue;
        bhq.unlock();

        self.state.sysvar_cache.deinit(allocator);

        var programs = self.state.programs;
        programs.deinit(allocator);
    }

    pub fn environment(self: *const SvmGateway) !TransactionExecutionEnvironment {
        const last_blockhash = self.state.blockhash_queue.get().last_hash orelse
            return error.MissingLastBlockhash;

        const last_lamports_per_signature = self.state.blockhash_queue.get()
            .getLamportsPerSignature(last_blockhash) orelse
            return error.MissingLastBlockhashInfo;

        return .{
            .ancestors = self.params.ancestors,
            .feature_set = &self.params.feature_set,
            .status_cache = self.params.status_cache,
            .sysvar_cache = &self.state.sysvar_cache,
            .rent_collector = self.params.rent_collector,
            .blockhash_queue = self.state.blockhash_queue.get(),
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
