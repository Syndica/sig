const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");
const utils = @import("utils.zig");
const protobuf = @import("protobuf");

const EMIT_LOGS = false;
const TOGGLE_DIRECT_MAPPING = false;
const STACK_SIZE = 32 * 1024 * 1024;

/// [fd] https://github.com/firedancer-io/firedancer/blob/61e3d2e21419fc71002aa1c037ab637cea85416d/src/flamenco/runtime/tests/harness/fd_exec_sol_compat.c#L583
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/7d039a85e55227fdd7ae5c9d0e1c36c7cf5b01f5/src/txn_fuzzer.rs#L46
export fn sol_compat_txn_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});
    const allocator = std.heap.c_allocator;

    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    const in_slice = in_ptr[0..in_size];
    var pb_txn_ctx = pb.TxnContext.decode(
        in_slice,
        decode_arena.allocator(),
    ) catch |err| {
        std.debug.print("pb.TxnContext.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer pb_txn_ctx.deinit();

    // increase the stack limit
    var rl = try std.posix.getrlimit(.STACK);
    if (rl.cur < STACK_SIZE) {
        rl.cur = STACK_SIZE;
        try std.posix.setrlimit(.STACK, rl);
    }

    const result = executeTxnContext(allocator, pb_txn_ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        return 0;
    };

    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        std.debug.print("out_slice.len: {d} < result_bytes.len: {d}\n", .{
            out_slice.len,
            result_bytes.len,
        });
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;

    return 1;
}

const builtins = @import("builtins.zig");
const verify_transaction = @import("verify_transaction.zig");
const bank_methods = @import("bank_methods.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const features = sig.core.features;
const program = sig.runtime.program;
const sysvars = sig.runtime.sysvar;
const vm = sig.vm;
const transaction_execution = sig.runtime.transaction_execution;
const update_sysvar = sig.replay.update_sysvar;

const AccountsDb = sig.accounts_db.AccountsDB;

const Account = sig.core.Account;
const Ancestors = sig.core.Ancestors;
const BlockhashQueue = sig.core.BlockhashQueue;
const Epoch = sig.core.Epoch;
const EpochStakes = sig.core.EpochStakes;
const EpochStakesMap = sig.core.EpochStakesMap;
const FeeRateGovernor = sig.core.genesis_config.FeeRateGovernor;
const GenesisConfig = sig.core.GenesisConfig;
const Hash = sig.core.Hash;
const HardForks = sig.core.HardForks;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const Slot = sig.core.Slot;
const Signature = sig.core.Signature;
const StatusCache = sig.core.StatusCache;
const StakesCache = sig.core.StakesCache;
const Transaction = sig.core.Transaction;
const TransactionVersion = sig.core.transaction.Version;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const TransactionAddressLookup = sig.core.transaction.AddressLookup;

const AccountSharedData = sig.runtime.AccountSharedData;
const BatchAccountCache = sig.runtime.account_loader.BatchAccountCache;
const ComputeBudget = sig.runtime.ComputeBudget;
const EpochRewards = sig.runtime.sysvar.EpochRewards;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;
const FeatureSet = sig.core.features.FeatureSet;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = transaction_execution.RuntimeTransaction;
const TransactionExecutionEnvironment = transaction_execution.TransactionExecutionEnvironment;
const ProcessedTransaction = transaction_execution.ProcessedTransaction;
const TransactionResult = transaction_execution.TransactionResult(ProcessedTransaction);

const loadAndExecuteTransactions = transaction_execution.loadAndExecuteTransactions;
const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

fn executeTxnContext(
    allocator: std.mem.Allocator,
    pb_txn_ctx: pb.TxnContext,
    emit_logs: bool,
) !pb.TxnResult {
    errdefer |err| {
        std.debug.print("executeTxnContext: {s}\n", .{@errorName(err)});
        if (@errorReturnTrace()) |tr| std.debug.dumpStackTrace(tr.*);
    }

    // Load info from the protobuf transaction context
    var feature_set = try loadFeatureSet(allocator, &pb_txn_ctx);
    defer feature_set.deinit(allocator);

    const blockhashes = try loadBlockhashes(allocator, &pb_txn_ctx);
    defer allocator.free(blockhashes);

    var accounts_map = try loadAccountsMap(allocator, &pb_txn_ctx);
    defer deinitMapAndValues(allocator, accounts_map);

    // TODO: use??
    // const fee_collector = Pubkey.parseBase58String("1111111111111111111111111111111111") catch unreachable;

    // Load genesis config
    var genesis_config = GenesisConfig.default(allocator);
    defer genesis_config.deinit(allocator);
    genesis_config.epoch_schedule = getSysvarFromAccounts(
        allocator,
        EpochSchedule,
        &accounts_map,
    ) orelse EpochSchedule.DEFAULT;
    genesis_config.rent = getSysvarFromAccounts(
        allocator,
        Rent,
        &accounts_map,
    ) orelse Rent.DEFAULT;
    try genesis_config.accounts.put(program.address_lookup_table.ID, .{
        .lamports = 1,
        .data = .initEmpty(0),
        .owner = program.bpf_loader.v3.ID,
        .executable = false,
        .rent_epoch = 0,
    });
    try genesis_config.accounts.put(
        program.config.ID,
        .{
            .lamports = 1,
            .data = .initEmpty(0),
            .owner = program.bpf_loader.v3.ID,
            .executable = false,
            .rent_epoch = 0,
        },
    );

    // Bank::new_with_paths(...)
    var accounts_db, var tmp_dir_root = try sig.accounts_db.AccountsDB.initForTest(allocator);
    defer tmp_dir_root.cleanup();
    defer accounts_db.deinit();

    var slot: Slot = 0;
    var epoch: Epoch = 0;
    var parent_slot: Slot = 0;
    var parent_hash: Hash = Hash.ZEROES;
    var epoch_schedule: EpochSchedule = undefined;

    var ancestors: Ancestors = .{};
    defer ancestors.deinit(allocator);

    var compute_budget = ComputeBudget.DEFAULT;
    compute_budget.compute_unit_limit = compute_budget.compute_unit_limit;

    var fee_rate_governor = FeeRateGovernor.DEFAULT;

    var blockhash_queue = BlockhashQueue.DEFAULT;
    defer blockhash_queue.deinit(allocator);

    var epoch_stakes_map: EpochStakesMap = .{};
    defer deinitMapAndValues(allocator, epoch_stakes_map);

    var hard_forks: HardForks = .{};
    defer hard_forks.deinit(allocator);

    var stakes_cache = try StakesCache.init(allocator);
    defer stakes_cache.deinit(allocator);

    var vm_environment: vm.Environment = .{};
    defer vm_environment.deinit(allocator);

    var capitalization: Atomic(u64) = .init(0);

    // Bank::new_with_paths(...)
    // https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L1162
    {
        try ancestors.addSlot(allocator, 0);
        // bank.compute_budget = runtime_config.compute_budget;
        // bank.transaction_account_lock_limit = null;
        // bank.transaction_debug_keys = null;
        // bank.cluster_type = genesis_config.cluster_type;
        // bank.feature_set = feature_set;

        // Bank::process_genesis_config(...)
        // https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L2727
        {
            // Set the feee rate governor
            fee_rate_governor = genesis_config.fee_rate_governor;

            // Insert genesis config accounts
            var genesis_account_iterator = genesis_config.accounts.iterator();
            while (genesis_account_iterator.next()) |kv| {
                const account = try accountSharedDataFromAccount(allocator, kv.value_ptr);
                defer account.deinit(allocator);
                try accounts_db.putAccount(
                    slot,
                    kv.key_ptr.*,
                    account,
                );
            }

            // Insert genesis config rewards pool accounts
            std.debug.assert(genesis_config.rewards_pools.count() == 0);

            // Set the collector id
            // bank.collector_id = fee_collector;

            // Add genesis hash to blockhash queue, for transaction fuzzing the genesis hash
            // is the first blockhash in the blockhashes list
            blockhash_queue = BlockhashQueue.DEFAULT;
            errdefer blockhash_queue.deinit(allocator);
            try blockhash_queue.insertGenesisHash(
                allocator,
                blockhashes[0], // genesis_config.hash() for production
                fee_rate_governor.lamports_per_signature,
            );

            // Set misc bank fields
            // const hashes_per_tick = genesis_config.hashes_per_tick;
            // const ticks_per_slot = genesis_config.ticks_per_slot;
            // const ns_per_slot = genesis_config.ns_per_slot;
            // const genesis_creation_time = genesis_config.creation_time;
            // const max_tick_height = (slot + 1) * ticks_per_slot;
            // const slots_per_year = genesis_config.slots_per_year;
            epoch_schedule = genesis_config.epoch_schedule;
            // const inflation = genesis_config.inflation;
            // const rent_collector = RentCollector{
            //     .epoch = epoch,
            //     .epoch_schedule = epoch_schedule,
            //     .slots_per_year = slots_per_year,
            //     .rent = genesis_config.rent,
            // };

            // add builtin programs specefied in genesis config
            std.debug.assert(genesis_config.native_instruction_processors.items.len == 0);
        }

        // Bank::finish_init(...)
        // https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L4863
        {
            // Set reward pool pubkeys
            std.debug.assert(genesis_config.rewards_pools.count() == 0);

            try bank_methods.applyFeatureActivations(
                allocator,
                slot,
                &feature_set,
                &accounts_db,
                false,
            );

            // NOTE: This gets hit
            // Set limits for 50m block limits
            // if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_50M)) {
            //     @panic("set limits not implemented");
            // }

            // NOTE: This gets hit
            // Set limits for 60m block limits
            // if (feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_60M)) {
            //     @panic("set limits not implemented");
            // }

            // NOTE: This should not impact txn fuzzing
            // If the accounts delta hash is still in use, start the background account hasher
            // if (!feature_set.active.contains(features.REMOVE_ACCOUNTS_DELTA_HASH)) {
            //     // start background account hasher
            //     @panic("background account hasher not implemented");
            // }

            // Add builtin programs
            for (builtins.BUILTINS) |builtin_program| {
                // If the feature id is not null, and the builtin program is not migrated, add
                // to the builtin accounts map. If the builtin program has been migrated it will
                // have an entry in accounts db with owner bpf_loader.v3.ID (i.e. it is now a BPF program).
                // For fuzzing purposes, accounts db is currently empty so we do not need to check if
                // the builtin program is migrated or not.
                const builtin_is_bpf_program = if (try accounts_db.getAccountWithAncestors(
                    &builtin_program.program_id,
                    &ancestors,
                )) |account| blk: {
                    defer account.deinit(allocator);
                    break :blk account.owner.equals(&program.bpf_loader.v3.ID);
                } else false;

                if (builtin_program.enable_feature_id != null or builtin_is_bpf_program) continue;

                const data = try allocator.dupe(u8, builtin_program.data);
                defer allocator.free(data);

                try accounts_db.putAccount(
                    slot,
                    builtin_program.program_id,
                    .{
                        .lamports = 1,
                        .data = data,
                        .executable = true,
                        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                        .rent_epoch = 0,
                    },
                );
            }

            // Add precompiles
            for (program.precompiles.PRECOMPILES) |precompile| {
                if (precompile.required_feature != null) continue;
                try accounts_db.putAccount(slot, precompile.program_id, .{
                    .lamports = 1,
                    .data = &.{},
                    .executable = true,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                    .rent_epoch = 0,
                });
            }

            vm_environment = try vm.Environment.initV1(
                allocator,
                &feature_set,
                &compute_budget,
                false,
                false,
            );
        }

        // Add epoch stakes for all epochs up to the banks slot using banks stakes cache
        // The bank slot is 0 and stakes cache is empty, so we add default epoch stakes.
        for (0..epoch_schedule.getLeaderScheduleEpoch(epoch)) |e| {
            try epoch_stakes_map.put(allocator, e, try .init(allocator));
        }

        const update_sysvar_deps = update_sysvar.UpdateSysvarAccountDeps{
            .account_store = accounts_db.accountStore(),
            .capitalization = &capitalization,
            .ancestors = &ancestors,
            .rent = &genesis_config.rent,
            .slot = slot,
        };

        try update_sysvar.updateStakeHistory(
            allocator,
            .{
                .epoch = epoch,
                .parent_epoch = null, // no parent yet
                .stakes_cache = &stakes_cache,
                .update_sysvar_deps = update_sysvar_deps,
            },
        );
        try update_sysvar.updateClock(allocator, .{
            .feature_set = &feature_set,
            .epoch_schedule = &epoch_schedule,
            .epoch_stakes_map = &epoch_stakes_map,
            .stakes_cache = &stakes_cache,
            .epoch = epoch,
            .parent_epoch = null, // no parent yet
            .genesis_creation_time = genesis_config.creation_time,
            .ns_per_slot = @intCast(genesis_config.nsPerSlot()),
            .update_sysvar_deps = update_sysvar_deps,
        });
        try update_sysvar.updateRent(allocator, genesis_config.rent, update_sysvar_deps);
        try update_sysvar.updateEpochSchedule(allocator, epoch_schedule, update_sysvar_deps);
        try update_sysvar.updateRecentBlockhashes(allocator, &blockhash_queue, update_sysvar_deps);
        try update_sysvar.updateLastRestartSlot(
            allocator,
            &feature_set,
            &hard_forks,
            update_sysvar_deps,
        );

        // NOTE: Agave fills the sysvar cache here, we should not need for txn fuzzing as the sysvar cache is only used in the SVM, so we can
        // populate immediately before executing transactions. (I think....)
    }

    // Checkpoint 1 -- End of Genesis Bank Initialization
    // try writeState(allocator, .{
    //     .slot = slot,
    //     .epoch = epoch,
    //     .hash = Hash.ZEROES,
    //     .parent_slot = parent_slot,
    //     .parent_hash = parent_hash,
    //     .ancestors = ancestors,
    //     .rent = genesis_config.rent,
    //     .epoch_schedule = epoch_schedule,
    //     .accounts_db = &accounts_db,
    // });

    // NOTE: The following logic should not impact txn fuzzing
    // let bank_forks = BankForks::new_rw_arc(bank);
    //     Sets the fork graph in the banks program cache to the newly created bank_forks.
    //     bank.set_fork_graph_in_program_cache(Arc::downgrade(&bank_forks));
    // let mut bank = bank_forks.read().unwrap().root_bank();
    //     Just gets the root bank

    const parent_lt_hash: ?sig.core.LtHash = .IDENTITY;
    const lt_hash, const slot_hash = try sig.replay.freeze.hashSlot(allocator, .{
        .account_reader = accounts_db.accountReader(),
        .slot = slot,
        // At this point, Agave has not modified the signature count.
        // It's changed when the transaction is processesed and when it's committed.
        .signature_count = 0,
        .parent_lt_hash = &parent_lt_hash,
        .parent_slot_hash = &parent_hash,
        .blockhash = blockhash_queue.last_hash.?,
        .ancestors = &ancestors,
        .feature_set = &feature_set,
    });
    _ = lt_hash;

    parent_slot = slot;
    parent_hash = slot_hash;
    const parent_epoch = epoch;

    slot = loadSlot(&pb_txn_ctx);
    if (slot > 0) {
        // Bank::new_from_parent(...)
        {
            // Clone epoch schedule
            // epoch_schedule = epoch_schedule;

            // Get epoch
            epoch = epoch_schedule.getEpoch(slot);

            // Clone accounts db
            // let (rc, bank_rc_creation_time_us) = measure_us!({
            //     let accounts_db = Arc::clone(&parent.rc.accounts.accounts_db);
            //     BankRc {
            //         accounts: Arc::new(Accounts::new(accounts_db)),
            //         parent: RwLock::new(Some(Arc::clone(&parent))),
            //         bank_id_generator: Arc::clone(&parent.rc.bank_id_generator),
            //     }
            // });

            // Clone status_cache
            // const status_cache = parent.status_cache.clone();

            // Derive new fee rate governor
            fee_rate_governor = FeeRateGovernor.initDerived(
                &fee_rate_governor,
                0, // parent.signature_count()
            );

            // Get bank id
            // let bank_id = rc.bank_id_generator.fetch_add(1, Relaxed) + 1;

            // Clone blockhash queue
            // blockhash_queue = blockhash_queue;

            // Clone stakes cache
            // const stakes_cache = parent.stakes_cache.clone();

            // Clone epoch stakes
            // epoch_stakes = epoch_stakes;

            // Create new transaction processor
            // const transaction_processor = TransactionBatchProcessor::new_from(&parent.transaction_processor, slot, epoch);

            // Clone rewards pool pubkeys
            // const rewards_pools = parent.rewards_pools.clone();

            // Clone transaction debug keys
            // const transaction_debug_keys = parent.transaction_debug_keys.clone();

            // Clone transaction log collector config
            // const transaction_log_collector_config = parent.transaction_log_collector_config.clone();

            // Clone feature set
            // feature_set = feature_set;

            // Get initial accounts data size
            // const initial_accounts_data_size = parent.load_accounts_data_size();

            // Init new bank -- lots of copying of fields here
            // var new = Bank{...}

            // Create ancestors with new slot and all parent slots
            try ancestors.addSlot(allocator, slot);

            // Update epoch
            if (parent_epoch < epoch) {
                // Bank::process_new_epoch(...)

                try bank_methods.applyFeatureActivations(
                    allocator,
                    slot,
                    &feature_set,
                    &accounts_db,
                    true,
                );

                // stakes_cache.activateEpoch();
                // Since the stakes cache is empty, we don't need to actually do anything here except add
                // an entry for the parent epoch with zero stakes.
                // https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/stakes.rs#L297
                {
                    const stakes: *StakesCache.T(), //
                    var stakes_guard = stakes_cache.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.epoch = epoch;
                    std.debug.assert(stakes.stake_history.entries.len == 0);
                    stakes.stake_history.entries.appendAssumeCapacity(.{
                        .epoch = parent_epoch,
                        .stake = .{
                            .effective = 0,
                            .activating = 0,
                            .deactivating = 0,
                        },
                    });
                }

                const leader_schedule_epoch = epoch_schedule.getLeaderScheduleEpoch(slot);
                // Since stakes cache is empty, we just need to insert an empty stakes entry
                // into the epoch stakes map at the leader schedule epoch stakes map if it is not present
                // updateEpochStakes(leader_schedule_epoch);
                if (!epoch_stakes_map.contains(leader_schedule_epoch))
                    try epoch_stakes_map.put(
                        allocator,
                        leader_schedule_epoch,
                        try .init(allocator),
                    );

                // Bank::begin_partitioned_epoch_rewards(...)
                // Similar to the above, epoch rewards is set but nothing meaningful is computed
                // since there are no staked nodes or rewards to distribute.
                // See: EpochRewards Debug Log: 0a73c09ab08f77e00b0faa8cf0d70408113b0a92_265678.fix
                const epoch_rewards = EpochRewards{
                    .distribution_starting_block_height = 2,
                    .num_partitions = 1,
                    .parent_blockhash = blockhash_queue.last_hash.?,
                    .total_points = 0,
                    .total_rewards = 0,
                    .distributed_rewards = 0,
                    .active = true,
                };
                try update_sysvar.updateSysvarAccount(EpochRewards, allocator, epoch_rewards, .{
                    .account_store = accounts_db.accountStore(),
                    .ancestors = &ancestors,
                    .capitalization = &capitalization,
                    .rent = &genesis_config.rent,
                    .slot = slot,
                });
            } else {
                const leader_schedule_epoch = epoch_schedule.getLeaderScheduleEpoch(slot);
                // Since stakes cache is empty, we just need to insert an empty stakes entry
                // into the epoch stakes map at the leader schedule epoch stakes map if it is not present
                // updateEpochStakes(leader_schedule_epoch);
                if (!epoch_stakes_map.contains(leader_schedule_epoch))
                    try epoch_stakes_map.put(
                        allocator,
                        leader_schedule_epoch,
                        try .init(allocator),
                    );
            }

            // Bank::distribute_partitioned_epoch_rewards(...)
            // Effectively noop for txn fuzzing purposes since height < distribution_starting_block_height
            // See: EpochRewards Debug Log: 0a73c09ab08f77e00b0faa8cf0d70408113b0a92_265678.fix
            // try bank_methods.distributePartitionedEpochRewards();

            // Prepare program cache for upcoming feature set

            // Update sysvars
            {
                const update_sysvar_deps: update_sysvar.UpdateSysvarAccountDeps = .{
                    .account_store = accounts_db.accountStore(),
                    .capitalization = &capitalization,
                    .ancestors = &ancestors,
                    .rent = &genesis_config.rent,
                    .slot = slot,
                };

                try update_sysvar.updateSlotHashes(
                    allocator,
                    parent_slot,
                    parent_hash,
                    update_sysvar_deps,
                );
                try update_sysvar.updateStakeHistory(
                    allocator,
                    .{
                        .epoch = epoch,
                        .parent_epoch = parent_epoch,
                        .stakes_cache = &stakes_cache,
                        .update_sysvar_deps = update_sysvar_deps,
                    },
                );
                try update_sysvar.updateClock(allocator, .{
                    .feature_set = &feature_set,
                    .epoch_schedule = &epoch_schedule,
                    .epoch_stakes_map = &epoch_stakes_map,
                    .stakes_cache = &stakes_cache,
                    .epoch = epoch,
                    .parent_epoch = parent_epoch,
                    .genesis_creation_time = genesis_config.creation_time,
                    .ns_per_slot = @intCast(genesis_config.nsPerSlot()),
                    .update_sysvar_deps = update_sysvar_deps,
                });
                try update_sysvar.updateLastRestartSlot(
                    allocator,
                    &feature_set,
                    &hard_forks,
                    update_sysvar_deps,
                );
            }

            // Get num accounts modified by this slot if accounts lt hash enabled

            // A bunch of stats stuff...
        }

        // bank = bank_forks.write().unwrap().insert(bank).clone_without_scheduler();
        {
            // if (root < highest_slot_at_startup) {
            //     bank.check_program_modification_slot = true;
            // }

            // bunch of scheduler and forks stuff...
        }

        // ProgramCache::prune(slot, epoch)
        {}
    }

    // Checkpoint 2 -- End of Bank Transition to TxnContext Slot
    // try writeState(allocator, .{
    //     .slot = slot,
    //     .epoch = epoch,
    //     .hash = Hash.ZEROES,
    //     .parent_slot = parent_slot,
    //     .parent_hash = parent_hash,
    //     .ancestors = ancestors,
    //     .rent = genesis_config.rent,
    //     .epoch_schedule = epoch_schedule,
    //     .accounts_db = &accounts_db,
    // });

    // Remove address lookup table and config program accounts by inserting empty accounts (zero-lamports)
    try accounts_db.putAccount(slot, program.address_lookup_table.ID, .EMPTY);
    try accounts_db.putAccount(slot, program.config.ID, .EMPTY);

    // Load accounts into accounts db
    for (accounts_map.keys(), accounts_map.values()) |pubkey, account| {
        try accounts_db.putAccount(slot, pubkey, .{
            .lamports = account.lamports,
            .data = account.data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        });
    }

    // Update epoch schedule and rent to minimum rent exempt balance
    {
        const update_sysvar_deps = update_sysvar.UpdateSysvarAccountDeps{
            .account_store = accounts_db.accountStore(),
            .capitalization = &capitalization,
            .ancestors = &ancestors,
            .rent = &genesis_config.rent,
            .slot = slot,
        };

        try update_sysvar.updateRent(allocator, genesis_config.rent, update_sysvar_deps);
        try update_sysvar.updateEpochSchedule(allocator, epoch_schedule, update_sysvar_deps);
    }

    // Get lamports per signature from first entry in recent blockhashes
    const lamports_per_signature = blk: {
        var sysvar_cache: SysvarCache = .{};
        defer sysvar_cache.deinit(allocator);
        try update_sysvar.fillMissingSysvarCacheEntries(
            allocator,
            accounts_db.accountReader().forSlot(&ancestors),
            &sysvar_cache,
        );

        const recent_blockhashes = sysvar_cache.get(RecentBlockhashes) catch break :blk null;
        // const first_entry = recent_blockhashes.getFirst() orelse break :blk null;
        const first_entry = if (recent_blockhashes.entries.len == 0)
            break :blk null
        else
            recent_blockhashes.entries.buffer[0];

        break :blk if (first_entry.lamports_per_signature != 0)
            first_entry.lamports_per_signature
        else
            null;
    } orelse fee_rate_governor.lamports_per_signature;

    // Register blockhashes and update recent blockhashes sysvar
    for (blockhashes) |blockhash| {
        try blockhash_queue.insertHash(allocator, blockhash, lamports_per_signature);
    }
    const update_sysvar_deps = update_sysvar.UpdateSysvarAccountDeps{
        .account_store = accounts_db.accountStore(),
        .capitalization = &capitalization,
        .ancestors = &ancestors,
        .rent = &genesis_config.rent,
        .slot = slot,
    };
    try update_sysvar.updateRecentBlockhashes(allocator, &blockhash_queue, update_sysvar_deps);

    // Checkpoint 3
    // NOTE: For basic fixtures, we produce equivalent state up until this point, excluding the
    // bank hash which requires changes from dnut/replay/freeze. Once incorporated we should
    // attempt validation of all public fixtures (or at least a reasonable number) before
    // moving onto transaction debugging.
    // try writeState(allocator, .{
    //     .slot = slot,
    //     .epoch = epoch,
    //     .hash = Hash.ZEROES,
    //     .parent_slot = parent_slot,
    //     .parent_hash = parent_hash,
    //     .ancestors = ancestors,
    //     .rent = genesis_config.rent,
    //     .epoch_schedule = epoch_schedule,
    //     .accounts_db = &accounts_db,
    // });

    // Initialize and populate the sysvar cache
    var sysvar_cache = SysvarCache{};
    defer sysvar_cache.deinit(allocator);
    try update_sysvar.fillMissingSysvarCacheEntries(
        allocator,
        accounts_db.accountReader().forSlot(&ancestors),
        &sysvar_cache,
    );

    // Load transaction from protobuf context
    const transaction = try loadTransaction(allocator, &pb_txn_ctx);
    defer transaction.deinit(allocator);

    // Verify transaction
    const runtime_transaction = switch (try verify_transaction.verifyTransaction(
        allocator,
        transaction,
        &feature_set,
        accounts_db.accountReader().forSlot(&ancestors),
    )) {
        .ok => |txn| txn,
        .err => |err| return err,
    };
    defer {
        for (runtime_transaction.instructions) |info| info.deinit(allocator);
        allocator.free(runtime_transaction.instructions);
        var accs = runtime_transaction.accounts;
        accs.deinit(allocator);
    }

    // Create batch account cache from accounts db
    var accounts = try BatchAccountCache.initFromAccountsDb(
        allocator,
        accounts_db.accountReader().forSlot(&ancestors),
        &.{runtime_transaction},
    );
    defer accounts.deinit(allocator);

    const rent_collector = RentCollector{
        .epoch = epoch,
        .epoch_schedule = epoch_schedule,
        .rent = genesis_config.rent,
        .slots_per_year = genesis_config.slotsPerYear(),
    };

    const current_epoch_stakes = try EpochStakes.init(allocator);
    defer current_epoch_stakes.deinit(allocator);

    var status_cache = StatusCache.DEFAULT;

    const environment = TransactionExecutionEnvironment{
        .ancestors = &ancestors,
        .feature_set = &feature_set,
        .status_cache = &status_cache,
        .sysvar_cache = &sysvar_cache,
        .rent_collector = &rent_collector,
        .blockhash_queue = &blockhash_queue,
        .epoch_stakes = &current_epoch_stakes,
        .vm_environment = &vm_environment,
        .next_vm_environment = null,

        .slot = slot,
        .max_age = 150,
        .last_blockhash = blockhash_queue.last_hash.?,
        .next_durable_nonce = sig.runtime.nonce.initDurableNonceFromHash(
            blockhash_queue.last_hash.?,
        ),

        // TODO: these values are highly suspicious, we need to note down somewhere how exactly agave
        // juggles the many different versions of lamports_per_signature.
        .next_lamports_per_signature = lamports_per_signature,
        .last_lamports_per_signature = lamports_per_signature,
        .lamports_per_signature = 5000,
    };

    const config = sig.runtime.transaction_execution.TransactionExecutionConfig{
        .log = emit_logs,
        .log_messages_byte_limit = null,
    };

    const txn_results = try loadAndExecuteTransactions(
        allocator,
        &.{runtime_transaction},
        &accounts,
        &environment,
        &config,
    );
    defer {
        switch (txn_results[0]) {
            .ok => |*r| r.deinit(allocator),
            .err => {},
        }
        allocator.free(txn_results);
    }

    return try serializeOutput(allocator, txn_results[0], runtime_transaction);
}

fn serializeOutput(
    allocator: std.mem.Allocator,
    result: TransactionResult,
    sanitized: RuntimeTransaction,
) !pb.TxnResult {
    switch (result) {
        .ok => |txn| {
            const is_ok = switch (txn) {
                .executed => |executed| executed.executed_transaction.err == null,
                .fees_only => false,
            };

            // TODO: just hardcoding InstructionError for now, can something else happen?
            // our current design assumes that the transaction execution can only return
            // InstructionError, which seems wrong. Not to mention that we don't have a way
            // to access *which* instruction in the transaction is the one that errored.
            const status: u32, const instr_err: u32 = switch (txn) {
                .executed => |executed| .{
                    if (executed.executed_transaction.err != null) 9 else 0,
                    if (executed.executed_transaction.err) |instr_err|
                        @intFromEnum(instr_err) + 1
                    else
                        0,
                },
                .fees_only => |fees_only| fees_only: {
                    const err_codes = utils.convertTransactionError(fees_only.err);
                    break :fees_only .{
                        err_codes.err,
                        err_codes.instruction_error,
                    };
                },
            };

            const rent = switch (txn) {
                .executed => |executed_txn| executed_txn.loaded_accounts.rent_collected,
                .fees_only => 0,
            };

            const fees = switch (txn) {
                .fees_only => |fees_only| fees_only.fees,
                .executed => |executed| executed.fees,
            };

            const resulting_state: pb.ResultingState = .{
                .rent_debits = .init(allocator),
                .transaction_rent = rent,
                .acct_states = switch (txn) {
                    .executed => |executed| acct_states: {
                        var acct_states: std.ArrayList(pb.AcctState) = .init(allocator);
                        errdefer acct_states.deinit();

                        for (executed.loaded_accounts.accounts.constSlice(), 0..) |acc, i| {
                            if (!sanitized.accounts.get(i).is_writable) continue;
                            // Only keep accounts that were passed in as account_keys or as ALUT accounts
                            for (sanitized.accounts.items(.pubkey)) |key| {
                                if (key.equals(&acc.pubkey)) break;
                            } else continue;

                            try acct_states.append(.{
                                .address = try .copy(&acc.pubkey.data, allocator),
                                .lamports = acc.account.lamports,
                                .data = try .copy(acc.account.data, allocator),
                                .executable = acc.account.executable,
                                .rent_epoch = acc.account.rent_epoch,
                                .owner = try .copy(&acc.account.owner.data, allocator),
                                .seed_addr = null,
                            });
                        }

                        break :acct_states acct_states;
                    },
                    .fees_only => |fees_only| acct_states: {
                        var acct_states: std.ArrayList(pb.AcctState) = .init(allocator);
                        errdefer acct_states.deinit();
                        errdefer for (acct_states.items) |acct_state| acct_state.deinit();
                        try acct_states.ensureTotalCapacityPrecise(fees_only.rollbacks.count());

                        const fee_payer_address = sanitized.fee_payer;
                        switch (fees_only.rollbacks) {
                            .fee_payer_only => |fee_payer_account| {
                                acct_states.appendAssumeCapacity(try sharedAccountToState(
                                    allocator,
                                    fee_payer_address,
                                    fee_payer_account.account,
                                ));
                            },
                            .same_nonce_and_fee_payer => |nonce| {
                                acct_states.appendAssumeCapacity(try sharedAccountToState(
                                    allocator,
                                    nonce.pubkey,
                                    nonce.account,
                                ));
                            },
                            .separate_nonce_and_fee_payer => |pair| {
                                const nonce, const fee_payer_account = pair;
                                acct_states.appendAssumeCapacity(try sharedAccountToState(
                                    allocator,
                                    fee_payer_address,
                                    fee_payer_account.account,
                                ));
                                acct_states.appendAssumeCapacity(try sharedAccountToState(
                                    allocator,
                                    nonce.pubkey,
                                    nonce.account,
                                ));
                            },
                        }
                        break :acct_states acct_states;
                    },
                },
            };

            return .{
                .executed = true,
                .sanitization_error = false,
                .is_ok = is_ok,
                .rent = rent,

                .status = status,
                .instruction_error = instr_err,

                .resulting_state = resulting_state,
                .fee_details = .{
                    .transaction_fee = fees.transaction_fee,
                    .prioritization_fee = fees.prioritization_fee,
                },
                // TODO: obviously hard coded number. compute_meter counts how many units left instead of how many units consumed
                .executed_units = txn.executedUnits() orelse 0,
                .loaded_accounts_data_size = txn.loadedAccountsDataSize(),
            };
        },
        // TODO: 008651fd6d7efed350fa33eeba912cb6e670eb7c_265678.fix
        .err => |err| {
            const converted = utils.convertTransactionError(err);
            return .{
                .executed = false,
                .sanitization_error = true,

                .status = converted.err,
                .instruction_error = converted.instruction_error,
                .custom_error = converted.custom_error,
                .instruction_error_index = converted.instruction_index,

                .fee_details = null,
                .resulting_state = null,
                .loaded_accounts_data_size = 0,
                .rent = 0,
            };
        },
    }
}

fn sharedAccountToState(
    allocator: std.mem.Allocator,
    address: Pubkey,
    value: sig.runtime.AccountSharedData,
) !pb.AcctState {
    const address_duped: protobuf.ManagedString = try .copy(&address.data, allocator);
    errdefer address_duped.deinit();

    const data_duped: protobuf.ManagedString = try .copy(value.data, allocator);
    errdefer data_duped.deinit();

    const owner_duped: protobuf.ManagedString = try .copy(&value.owner.data, allocator);
    errdefer owner_duped.deinit();

    return .{
        .address = address_duped,
        .lamports = value.lamports,
        .data = data_duped,
        .executable = value.executable,
        .rent_epoch = value.rent_epoch,
        .owner = owner_duped,
        .seed_addr = null,
    };
}

fn parseHash(bytes: []const u8) !Hash {
    if (bytes.len != Hash.SIZE) return error.OutOfBoundsHash;
    return .{ .data = bytes[0..Hash.SIZE].* };
}

fn parsePubkey(bytes: []const u8) !Pubkey {
    if (bytes.len != Pubkey.SIZE) return error.OutOfBoundsPubkey;
    return .{ .data = bytes[0..Pubkey.SIZE].* };
}

fn loadSlot(pb_txn_ctx: *const pb.TxnContext) u64 {
    return if (pb_txn_ctx.slot_ctx) |ctx| ctx.slot else 10;
}

fn loadFeatureSet(allocator: std.mem.Allocator, pb_txn_ctx: *const pb.TxnContext) !FeatureSet {
    var feature_set = blk: {
        const maybe_pb_features = if (pb_txn_ctx.epoch_ctx) |epoch_ctx|
            if (epoch_ctx.features) |pb_features| pb_features else null
        else
            null;

        const pb_features = maybe_pb_features orelse break :blk FeatureSet.EMPTY;

        var indexed_features = std.AutoArrayHashMap(u64, Pubkey).init(allocator);
        defer indexed_features.deinit();

        for (features.FEATURES) |feature| {
            try indexed_features.put(@bitCast(feature.data[0..8].*), feature);
        }

        var feature_set = features.FeatureSet.EMPTY;

        for (pb_features.features.items) |id| {
            if (indexed_features.get(id)) |pubkey| {
                try feature_set.active.put(allocator, pubkey, 0);
            }
        }

        break :blk feature_set;
    };

    if (TOGGLE_DIRECT_MAPPING) {
        if (feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING)) {
            _ = feature_set.active.swapRemove(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING);
        } else {
            try feature_set.active.put(allocator, features.BPF_ACCOUNT_DATA_DIRECT_MAPPING, 0);
        }
    }

    return feature_set;
}

/// Load blockhashes from the protobuf transaction context.
/// If no blockhashes are provided, a default blockhash of zeroes is returned.
fn loadBlockhashes(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) ![]Hash {
    const pb_blockhashes = pb_txn_ctx.blockhash_queue.items;
    if (pb_blockhashes.len == 0)
        return try allocator.dupe(Hash, &.{Hash.ZEROES});

    const blockhashes = try allocator.alloc(Hash, pb_blockhashes.len);
    errdefer allocator.free(blockhashes);

    for (blockhashes, pb_blockhashes) |*blockhash, pb_blockhash|
        blockhash.* = try parseHash(pb_blockhash.getSlice());

    return blockhashes;
}

/// Load all accounts from the protobuf transaction context.
fn loadAccountsMap(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData) {
    const pb_accounts = pb_txn_ctx.account_shared_data.items;

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    errdefer deinitMapAndValues(allocator, accounts);

    for (pb_accounts) |pb_account| {
        try accounts.put(allocator, try parsePubkey(pb_account.address.getSlice()), .{
            .lamports = pb_account.lamports,
            .data = try allocator.dupe(u8, pb_account.data.getSlice()),
            .owner = try parsePubkey(pb_account.owner.getSlice()),
            .executable = pb_account.executable,
            .rent_epoch = pb_account.rent_epoch,
        });
    }

    return accounts;
}

/// Load the transaction from the protobuf transaction context.
/// If no transaction is provided, an error is returned.
fn loadTransaction(
    allocator: std.mem.Allocator,
    pb_txn_ctx: *const pb.TxnContext,
) !Transaction {
    const pb_txn = pb_txn_ctx.tx orelse return error.NoTransaction;

    const signatures = try allocator.alloc(
        Signature,
        @max(pb_txn.signatures.items.len, 1),
    );

    for (pb_txn.signatures.items, 0..) |pb_signature, i|
        signatures[i] = .{ .data = pb_signature.getSlice()[0..Signature.SIZE].* };

    if (pb_txn.signatures.items.len == 0)
        signatures[0] = Signature.ZEROES;

    const version, const message = try loadTransactionMesssage(
        allocator,
        pb_txn.message.?,
    );

    return .{
        .signatures = signatures,
        .version = version,
        .msg = message,
    };
}

/// Load the transaction version and message from the protobuf transaction message.
fn loadTransactionMesssage(
    allocator: std.mem.Allocator,
    message: pb.TransactionMessage,
) !struct { TransactionVersion, TransactionMessage } {
    const account_keys = try allocator.alloc(Pubkey, message.account_keys.items.len);
    for (account_keys, message.account_keys.items) |*account_key, pb_account_key|
        account_key.* = .{ .data = pb_account_key.getSlice()[0..Pubkey.SIZE].* };

    const recent_blockhash = Hash{ .data = message.recent_blockhash.getSlice()[0..Hash.SIZE].* };

    const instructions = try allocator.alloc(
        TransactionInstruction,
        message.instructions.items.len,
    );
    for (instructions, message.instructions.items) |*instruction, pb_instruction| {
        const account_indexes = try allocator.alloc(u8, pb_instruction.accounts.items.len);
        for (account_indexes, pb_instruction.accounts.items) |*account_index, pb_account_index|
            account_index.* = @truncate(pb_account_index);
        instruction.* = .{
            .program_index = @truncate(pb_instruction.program_id_index),
            .account_indexes = account_indexes,
            .data = try allocator.dupe(u8, pb_instruction.data.getSlice()),
        };
    }

    const address_lookups = try allocator.alloc(
        TransactionAddressLookup,
        message.address_table_lookups.items.len,
    );
    for (address_lookups, message.address_table_lookups.items) |*lookup, pb_lookup| {
        const writable_indexes = try allocator.alloc(u8, pb_lookup.writable_indexes.items.len);
        for (
            writable_indexes,
            pb_lookup.writable_indexes.items,
        ) |*writable_index, pb_writable_index|
            writable_index.* = @truncate(pb_writable_index);

        const readonly_indexes = try allocator.alloc(u8, pb_lookup.readonly_indexes.items.len);
        for (
            readonly_indexes,
            pb_lookup.readonly_indexes.items,
        ) |*readonly_index, pb_readonly_index|
            readonly_index.* = @truncate(pb_readonly_index);

        lookup.* = TransactionAddressLookup{
            .table_address = Pubkey{ .data = pb_lookup.account_key.getSlice()[0..Pubkey.SIZE].* },
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        };
    }

    const header = message.header orelse pb.MessageHeader{
        .num_required_signatures = 1,
        .num_readonly_signed_accounts = 0,
        .num_readonly_unsigned_accounts = 0,
    };

    return .{
        if (message.is_legacy)
            .legacy
        else
            .v0,
        .{
            .signature_count = @truncate(@max(1, header.num_required_signatures)),
            .readonly_signed_count = @truncate(header.num_readonly_signed_accounts),
            .readonly_unsigned_count = @truncate(header.num_readonly_unsigned_accounts),
            .account_keys = account_keys,
            .recent_blockhash = recent_blockhash,
            .instructions = instructions,
            .address_lookups = address_lookups,
        },
    };
}

/// Load a sysvar from the accounts map.
/// If the sysvar is not present or has zero lamports, return null.
pub fn getSysvarFromAccounts(
    allocator: std.mem.Allocator,
    comptime T: type,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
) ?T {
    const account = accounts.getPtr(T.ID) orelse return null;
    if (account.lamports == 0) return null;
    return sig.bincode.readFromSlice(
        allocator,
        T,
        account.data,
        .{},
    ) catch null;
}

// pub fn initAccountsDb(
//     allocator: std.mem.Allocator,
//     pb_txn_ctx: *const pb.TxnContext,
// ) !AccountsDb {
//     var hasher = std.crypto.hash.Blake3.init(.{});
//     const bytes: []const u8 = @as([*]const u8, @ptrCast(&pb_txn_ctx))[0..@sizeOf(pb.TxnContext)];
//     hasher.update(bytes);
//     var seed = Hash.ZEROES;
//     hasher.final(&seed.data);
//     var prng = std.Random.DefaultPrng.init(std.mem.bytesAsValue(u64, seed.data[0..8]).*);

//     const snapshot_dir_name = try std.fmt.allocPrint(
//         allocator,
//         "snapshot-dir-{}",
//         .{prng.random().int(u64)},
//     );
//     defer allocator.free(snapshot_dir_name);
//     try std.fs.cwd().makeDir(snapshot_dir_name);
//     defer std.fs.cwd().deleteTree(snapshot_dir_name) catch {};
//     const snapshot_dir = try std.fs.cwd().openDir(
//         snapshot_dir_name,
//         .{ .iterate = true },
//     );

//     return try sig.accounts_db.AccountsDB.init(.{
//         .allocator = allocator,
//         .logger = .noop,
//         .snapshot_dir = snapshot_dir,
//         .geyser_writer = null,
//         .gossip_view = null,
//         .index_allocation = .ram,
//         .number_of_index_shards = 1,
//         .buffer_pool_frames = 1024,
//     });
// }

fn accountSharedDataFromAccount(
    allocator: Allocator,
    account: *const Account,
) !AccountSharedData {
    const data = try account.data.dupeAllocatedOwned(allocator);
    defer data.deinit(allocator);

    return .{
        .lamports = account.lamports,
        .data = try allocator.dupe(u8, data.owned_allocation),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

fn accountFromAccountSharedData(
    allocator: Allocator,
    account: *const AccountSharedData,
) !Account {
    return .{
        .lamports = account.lamports,
        .data = .initAllocatedOwned(try allocator.dupe(u8, account.data)),
        .owner = account.owner,
        .executable = account.executable,
        .rent_epoch = account.rent_epoch,
    };
}

const State = struct {
    slot: Slot,
    epoch: Epoch,
    hash: Hash,
    parent_slot: Slot,
    parent_hash: Hash,
    ancestors: Ancestors,
    rent: Rent,
    epoch_schedule: EpochSchedule,
    accounts_db: *AccountsDb,
};

fn writeState(allocator: Allocator, state: State) !void {
    var file = std.fs.cwd().openFile(
        "output-state-sig.txt",
        .{ .mode = .read_write },
    ) catch |err| switch (err) {
        error.FileNotFound => try std.fs.cwd().createFile("output-state-sig.txt", .{}),
        else => return err,
    };
    defer file.close();

    try file.seekFromEnd(0);

    const writer = file.writer();

    try writer.print("Slot:  {}\n", .{state.slot});
    try writer.print("Epoch: {}\n", .{state.epoch});
    try writer.print("Hash:  {}\n", .{state.hash});
    try writer.print("Parent Slot: {}\n", .{state.parent_slot});
    try writer.print("Parent Hash: {any}\n", .{state.parent_hash});
    try writeSlice(allocator, writer, "Ancestors: ", "\n", Slot, state.ancestors.ancestors.keys());
    try writeAccounts(allocator, writer, state.accounts_db);
    try writer.print("\n", .{});
}

fn writeAccounts(
    allocator: Allocator,
    writer: anytype,
    accounts_db: *AccountsDb,
) !void {
    const accounts = try accounts_db.getAllPubkeysSorted(allocator);
    defer allocator.free(accounts);
    try writer.print("Accounts:\n", .{});
    for (accounts) |pubkey| {
        const maybe_slot_and_account = accounts_db.getSlotAndAccount(&pubkey) catch null;
        if (maybe_slot_and_account) |slot_and_account| {
            const slot, const account = slot_and_account;
            defer account.deinit(allocator);
            if (account.lamports == 0) continue;
            const data = try account.data.dupeAllocatedOwned(allocator);
            defer data.deinit(allocator);

            try writer.print(
                "  {}: slot={}, lamports={}, owner={}, executable={}, rent_epoch={}",
                .{
                    pubkey,
                    slot,
                    account.lamports,
                    account.owner,
                    account.executable,
                    account.rent_epoch,
                },
            );

            try writeSlice(allocator, writer, ", data=", "\n", u8, data.owned_allocation);
        }
    }
}

fn writeSlice(
    allocator: Allocator,
    writer: anytype,
    prefix: []const u8,
    suffix: []const u8,
    comptime T: type,
    slice: []const T,
) !void {
    const str = try std.fmt.allocPrint(allocator, "{any}", .{slice[0..@min(slice.len, 512)]});
    defer allocator.free(str);
    str[1] = '[';
    str[str.len - 2] = ']';
    try writer.print("{s}{s}{s}", .{ prefix, str[1 .. str.len - 1], suffix });
}

const ManagedString = @import("protobuf").ManagedString;

pub fn createPbManagedString(
    allocator: std.mem.Allocator,
    comptime T: type,
    string: []const u8,
) !ManagedString {
    const parsed = T.parseBase58String(string) catch unreachable;
    return try ManagedString.copy(&parsed.data, allocator);
}

pub fn createPbManagedStrings(
    allocator: std.mem.Allocator,
    comptime T: type,
    strings: []const []const u8,
) !std.ArrayList(ManagedString) {
    var result = try std.ArrayList(ManagedString).initCapacity(allocator, strings.len);
    for (strings) |string| {
        const parsed = T.parseBase58String(string) catch unreachable;
        result.appendAssumeCapacity(try ManagedString.copy(&parsed.data, allocator));
    }
    return result;
}

pub const PbInstructionsParams = struct {
    program_id: u32,
    accounts: []const u32,
    data: []const u8,
};

pub fn createPbInstructions(
    allocator: std.mem.Allocator,
    instructions: []const PbInstructionsParams,
) !std.ArrayList(pb.CompiledInstruction) {
    var result = try std.ArrayList(pb.CompiledInstruction).initCapacity(
        allocator,
        instructions.len,
    );
    for (instructions) |instruction| {
        var accounts = std.ArrayList(u32).init(allocator);
        try accounts.appendSlice(instruction.accounts);
        const data = try ManagedString.copy(instruction.data, allocator);
        try result.append(.{
            .program_id_index = instruction.program_id,
            .accounts = accounts,
            .data = data,
        });
    }
    return result;
}

pub const PbAddressLookupTablesParams = struct {
    account_key: []const u8,
    writable_indexes: []const u32,
    readonly_indexes: []const u32,
};

pub fn createPbAddressLookupTables(
    allocator: std.mem.Allocator,
    lookup_tables: []const PbAddressLookupTablesParams,
) !std.ArrayList(pb.MessageAddressTableLookup) {
    var result = try std.ArrayList(pb.MessageAddressTableLookup).initCapacity(
        allocator,
        lookup_tables.len,
    );
    for (lookup_tables) |lookup_table| {
        var writable_indexes = std.ArrayList(u32).init(allocator);
        try writable_indexes.appendSlice(lookup_table.writable_indexes);
        var readonly_indexes = std.ArrayList(u32).init(allocator);
        try readonly_indexes.appendSlice(lookup_table.readonly_indexes);
        try result.append(.{
            .account_key = try createPbManagedString(allocator, Pubkey, lookup_table.account_key),
            .writable_indexes = writable_indexes,
            .readonly_indexes = readonly_indexes,
        });
    }
    return result;
}
