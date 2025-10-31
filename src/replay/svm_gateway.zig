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

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const ComputeBudget = sig.runtime.ComputeBudget;
const FeatureSet = sig.core.FeatureSet;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const ProgramMap = sig.runtime.program_loader.ProgramMap;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionExecutionEnvironment =
    sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

const loadPrograms = sig.runtime.program_loader.loadPrograms;
const initDurableNonceFromHash = sig.runtime.nonce.initDurableNonceFromHash;

const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;

pub fn executeTransaction(
    allocator: Allocator,
    svm_gateway: *SvmGateway,
    transaction: *const RuntimeTransaction,
) !TransactionResult(ProcessedTransaction) {
    var zone = tracy.Zone.init(@src(), .{ .name = "executeTransaction" });
    defer zone.deinit();

    const environment = try svm_gateway.environment();

    return try sig.runtime.transaction_execution.loadAndExecuteTransaction(
        allocator,
        transaction,
        &svm_gateway.state.accounts,
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
        accounts: BatchAccountCache,
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

        /// used to initialize the batch account cache and program map
        account_reader: SlotAccountReader,

        // Borrowed values to pass by reference into the SVM.
        blockhash_queue: *sig.sync.RwMux(BlockhashQueue),
        ancestors: *const Ancestors,
        feature_set: FeatureSet,
        rent_collector: *const RentCollector,
        epoch_stakes: *const sig.core.EpochStakes,
        status_cache: *StatusCache,

        sysvar_cache: *const SysvarCache,
        vm_environment: *const vm.Environment,
        next_vm_environment: ?*const vm.Environment,
    };

    pub fn init(
        allocator: Allocator,
        batch: []const ResolvedTransaction,
        params: Params,
    ) !SvmGateway {
        const zone = tracy.Zone.init(@src(), .{ .name = "SvmGateway.init" });
        defer zone.deinit();

        var accounts = try BatchAccountCache.initSufficientCapacity(allocator, batch);
        for (batch) |transaction| {
            try accounts.load(
                allocator,
                params.account_reader,
                &transaction.accounts,
                transaction.instructions,
            );
        }

        var programs = try loadPrograms(
            allocator,
            &accounts.account_cache,
            params.vm_environment,
            params.slot,
        );
        errdefer {
            for (programs.values()) |*program| program.deinit(allocator);
            programs.deinit(allocator);
        }

        return .{
            .params = params,
            .state = .{
                .accounts = accounts,
                .programs = programs,

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
        self.state.accounts.deinit(allocator);
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
            .sysvar_cache = self.params.sysvar_cache,
            .rent_collector = self.params.rent_collector,
            .blockhash_queue = self.state.blockhash_queue.get(),
            .epoch_stakes = self.params.epoch_stakes,
            .vm_environment = self.params.vm_environment,
            .next_vm_environment = if (self.params.next_vm_environment) |env| env else null,

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
