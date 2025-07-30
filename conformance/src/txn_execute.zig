const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const EMIT_LOGS = false;
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

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const sysvars = sig.runtime.sysvar;
const vm = sig.vm;
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
const Clock = sig.runtime.sysvar.Clock;
const ComputeBudget = sig.runtime.ComputeBudget;
const EpochRewards = sig.runtime.sysvar.EpochRewards;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;
const FeatureSet = sig.core.features.FeatureSet;
const LastRestartSlot = sig.runtime.sysvar.LastRestartSlot;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const TransactionExecutionEnvironment = sig.runtime.transaction_execution.TransactionExecutionEnvironment;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult(sig.runtime.transaction_execution.ProcessedTransaction);

const loadAndExecuteTransactions = sig.runtime.transaction_execution.loadAndExecuteTransactions;
const loadTestAccountsDB = sig.accounts_db.db.loadTestAccountsDbEmpty;
const fillMissingSysvarCacheEntries = sig.replay.update_sysvar.fillMissingSysvarCacheEntries;
const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

fn executeTxnContext(allocator: std.mem.Allocator, pb_txn_ctx: pb.TxnContext, emit_logs: bool) !pb.TxnResult {
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
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    var accounts_db = try loadTestAccountsDB(
        allocator,
        false,
        .noop,
        tmp_dir_root.dir,
    );
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
            .accounts_db = &accounts_db,
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
        try update_sysvar.updateLastRestartSlot(allocator, &feature_set, &hard_forks, update_sysvar_deps);

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

    // TODO: use `hashSlot` to compute the slot hash after merging dnut/replay/freeze into harnew/txn-fuzzing-dbg
    // bank.rehash();
    // const slot_hash = Hash.ZEROES;
    const slot_hash = Hash.parseBase58String("6AavNxZpjzFwkHto1bfh5WcS4xLiUKecVoVCcskVY6H") catch unreachable;

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
                    const stakes: *StakesCache.T(), var stakes_guard = stakes_cache.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.epoch = epoch;
                    std.debug.assert(stakes.stake_history.entries.len == 0);
                    stakes.stake_history.entries.appendAssumeCapacity(.{ .epoch = parent_epoch, .stake = .{
                        .effective = 0,
                        .activating = 0,
                        .deactivating = 0,
                    } });
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
                try update_sysvar.updateSysvarAccount(allocator, EpochRewards, epoch_rewards, .{
                    .accounts_db = &accounts_db,
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
                const update_sysvar_deps = update_sysvar.UpdateSysvarAccountDeps{
                    .accounts_db = &accounts_db,
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
                try update_sysvar.updateLastRestartSlot(allocator, &feature_set, &hard_forks, update_sysvar_deps);
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
    try accounts_db.putAccount(slot, program.address_lookup_table.ID, AccountSharedData.EMPTY);
    try accounts_db.putAccount(slot, program.config.ID, AccountSharedData.EMPTY);

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
            .accounts_db = &accounts_db,
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
            &accounts_db,
            &ancestors,
            &sysvar_cache,
        );

        const recent_blockhashes = sysvar_cache.get(RecentBlockhashes) catch break :blk null;
        const first_entry = recent_blockhashes.getFirst() orelse break :blk null;
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
        .accounts_db = &accounts_db,
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
    try update_sysvar.fillMissingSysvarCacheEntries(allocator, &accounts_db, &ancestors, &sysvar_cache);

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
        for (runtime_transaction.instruction_infos) |info| info.deinit(allocator);
        allocator.free(runtime_transaction.instruction_infos);
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

    const environment = TransactionExecutionEnvironment{
        .ancestors = &ancestors,
        .feature_set = &feature_set,
        .status_cache = &StatusCache.default(),
        .sysvar_cache = &sysvar_cache,
        .rent_collector = &rent_collector,
        .blockhash_queue = &blockhash_queue,
        .epoch_stakes = &current_epoch_stakes,
        .vm_environment = &vm_environment,
        .next_vm_environment = null,

        .slot = slot,
        .max_age = 150,
        .last_blockhash = blockhash_queue.last_hash.?,
        .next_durable_nonce = sig.runtime.nonce.initDurableNonceFromHash(blockhash_queue.last_hash.?),

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
            .err => |e| std.debug.print("Transaction execution error: {any}\n", .{e}),
        }
        allocator.free(txn_results);
    }

    std.debug.print("result: {any}\n", .{txn_results[0]});

    return try serializeOutput(
        allocator,
        txn_results[0],
        runtime_transaction,
        pb_txn_ctx,
    );
}

fn serializeOutput(
    allocator: std.mem.Allocator,
    result: TransactionResult,
    sanitized: RuntimeTransaction,
    tx_ctx: pb.TxnContext,
) !pb.TxnResult {
    switch (result) {
        .ok => |txn| {
            if (txn == .fees_only) @panic("TODO");
            const executed_txn = txn.executed;

            return .{
                .executed = true,
                .sanitization_error = false,
                .is_ok = executed_txn.executed_transaction.err == null,
                .resulting_state = .{
                    .acct_states = a: {
                        var acc_states: std.ArrayList(pb.AcctState) = .init(allocator);
                        errdefer acc_states.deinit();

                        var loaded_account_keys: std.AutoHashMapUnmanaged(Pubkey, void) = .empty;
                        defer loaded_account_keys.deinit(allocator);

                        const tx = tx_ctx.tx.?;
                        for (tx.message.?.account_keys.items) |key| {
                            const pubkey: Pubkey = .{ .data = key.getSlice()[0..32].* };
                            try loaded_account_keys.put(allocator, pubkey, {});
                        }
                        switch (sanitized.version) {
                            .v0 => {
                                try loaded_account_keys.ensureUnusedCapacity(allocator, 2);
                                // TODO: add the readonly and writeable loaded accounts here also
                            },
                            .legacy => {},
                        }

                        for (executed_txn.loaded_accounts.accounts.constSlice(), 0..) |acc, i| {
                            if (!sanitized.accounts.get(i).is_writable) continue;
                            // Only keep accounts that were passed in as account_keys or as ALUT accounts
                            if (!loaded_account_keys.contains(acc.pubkey)) continue;

                            try acc_states.append(.{
                                .address = try .copy(&acc.pubkey.data, allocator),
                                .lamports = acc.account.lamports,
                                .data = try .copy(acc.account.data, allocator),
                                .executable = acc.account.executable,
                                .rent_epoch = acc.account.rent_epoch,
                                .owner = try .copy(&acc.account.owner.data, allocator),
                                .seed_addr = null,
                            });
                        }

                        break :a acc_states;
                    },
                    .rent_debits = .init(allocator),
                    .transaction_rent = executed_txn.loaded_accounts.rent_collected,
                },
                .fee_details = .{
                    .transaction_fee = executed_txn.fees.transaction_fee,
                    .prioritization_fee = executed_txn.fees.prioritization_fee,
                },
                // TODO: obviously hard coded number. compute_meter counts how many units left instead of how many units consumed
                .executed_units = 200000 - executed_txn.executed_transaction.compute_meter,
                .loaded_accounts_data_size = executed_txn.loaded_accounts.loaded_accounts_data_size,
            };
        },
        .err => @panic("TODO"),
    }
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

    if (try std.process.hasEnvVar(allocator, "TOGGLE_DIRECT_MAPPING")) {
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
        for (writable_indexes, pb_lookup.writable_indexes.items) |*writable_index, pb_writable_index|
            writable_index.* = @truncate(pb_writable_index);

        const readonly_indexes = try allocator.alloc(u8, pb_lookup.readonly_indexes.items.len);
        for (readonly_indexes, pb_lookup.readonly_indexes.items) |*readonly_index, pb_readonly_index|
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
    var file = std.fs.cwd().openFile("output-state-sig.txt", .{ .mode = .read_write }) catch |err| switch (err) {
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

            try writer.print("  {}: slot={}, lamports={}, owner={}, executable={}, rent_epoch={}", .{
                pubkey,
                slot,
                account.lamports,
                account.owner,
                account.executable,
                account.rent_epoch,
            });

            try writeSlice(allocator, writer, ", data=", "\n", u8, data.owned_allocation);
        }
    }
}

fn writeSlice(allocator: Allocator, writer: anytype, prefix: []const u8, suffix: []const u8, comptime T: type, slice: []const T) !void {
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
    var result = try std.ArrayList(pb.CompiledInstruction).initCapacity(allocator, instructions.len);
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
    var result = try std.ArrayList(pb.MessageAddressTableLookup).initCapacity(allocator, lookup_tables.len);
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

test "sampleTxnContext" {
    const allocator = std.testing.allocator;

    const txn_ctx = try sampleTxnContext(allocator);
    defer txn_ctx.deinit();

    const result = try executeTxnContext(allocator, txn_ctx, false);
    defer result.deinit();
}

/// 0-sample.txt
/// 0a73c09ab08f77e00b0faa8cf0d70408113b0a92_265678.fix
fn sampleTxnContext(allocator: std.mem.Allocator) !pb.TxnContext {
    @setEvalBranchQuota(1_000_000);

    const pb_slot: u64 = 963106073;

    var pb_blockhashes = std.ArrayList(ManagedString).init(allocator);
    try pb_blockhashes.appendSlice(&.{
        try createPbManagedString(allocator, Hash, "Brqgfg9qhuU6BN29JvA1U2yUwd89evLxkGrPhgQ9T7GK"),
        try createPbManagedString(allocator, Hash, "81T56cg6QzEjVM86Rroy5FCxFf6pwuXnj7DYXNeHNYP"),
        try createPbManagedString(allocator, Hash, "36nEg9eQu2k9ZbjjgUN4wbsc7n5mNj6TbzXkUznJJ22B"),
        try createPbManagedString(allocator, Hash, "GdWCqpD7scfusjv2XR5zGc72eN4WV3uJU9qqocPdz1Qb"),
        try createPbManagedString(allocator, Hash, "VA51KKvmkQNuTVMn6i9K7Q3aZPx3Zc1DzTQdbBLrLWj"),
        try createPbManagedString(allocator, Hash, "5kYLD3hcUBL119NCHvzxPLpB9AQRLCcvRdnh8LKmg1Ry"),
        try createPbManagedString(allocator, Hash, "EYVsXqunwUb3F86SoX4FF7iySFtAJSdLKG7FgMtf3jcT"),
        try createPbManagedString(allocator, Hash, "Fv2sZfGeyMMTQJ4d4qTncp3WcC38P2AoRVBJsgVp8WCf"),
        try createPbManagedString(allocator, Hash, "FPYkMwSAs6trDDL43XVm9M33KKkZ9TEvy8EarAcrPetX"),
        try createPbManagedString(allocator, Hash, "BfctqhCvJMMra4yU9bZhfk4WX6WgPHkrVxhqedrKQmJX"),
        try createPbManagedString(allocator, Hash, "ABZVpG53wJbQFy4KSdZRcaaQJXmRr7tXyo5LkDcYCEmm"),
        try createPbManagedString(allocator, Hash, "BLWf8LmnMxRAv5w3RJ5mtGBmjcHbDBhGDqj5rVQgCZGK"),
        try createPbManagedString(allocator, Hash, "Eh15BA5rcEpy1urEVy6dHn1tiZ9wfet8nkM6CMqmacWT"),
        try createPbManagedString(allocator, Hash, "EBfwhNr2qbhH2o1DRi4irs4fjhLEfMBfzYPbT2CBkjjV"),
        try createPbManagedString(allocator, Hash, "DuhSdTShpk6XvCW79xXpBHcH9cEmRyktA9HcW38ivQ3R"),
        try createPbManagedString(allocator, Hash, "CwNh2tU6oMYJkjo3VnSTyyr9sYY9mQpPr7eEuBqdDevj"),
        try createPbManagedString(allocator, Hash, "G2oUYokQXJBrALkpzjC2EnoV1cdKZnBVFYrWX1KWC1Ao"),
        try createPbManagedString(allocator, Hash, "581v5cqFQ1UL65hKQPT3DEdzRDCG17ak41JWrceo7wdH"),
        try createPbManagedString(allocator, Hash, "3LwXEdtyWt2GVYoWhPbh2rd9PcZEfYafdAXW874f5rUX"),
        try createPbManagedString(allocator, Hash, "Edo3wzDCbjhXSwXJdMm23LwACZBQxGmUtfh4j2ChYBYT"),
        try createPbManagedString(allocator, Hash, "FWPXjkD2CsfnXpRyHzFJXhPDY4MwDMaKjom5LLA9rMmq"),
        try createPbManagedString(allocator, Hash, "BGnbTWMweP3or8s681itz65bi1ocab1A8xBC9W24gUcX"),
        try createPbManagedString(allocator, Hash, "3bg4rkFGEYp6ZnmKzPBcgVZZWbxE3igFjZUZAYx2Ddwd"),
        try createPbManagedString(allocator, Hash, "FP7DFB97czLG5tEzCvFfq8ryn4NNCeJ22sArYP65Qi6b"),
        try createPbManagedString(allocator, Hash, "Bb5bNagXPrhZkNyZc4mNauxwfQtEqLZkXdVSKXzcvJEK"),
        try createPbManagedString(allocator, Hash, "5GSV45miWUYEoaHoRqsZPUBpWuHBNvX21JdaK9hhp34s"),
        try createPbManagedString(allocator, Hash, "4R812se79V9g3iSCcThn6MmPKN1udJvXRiUxof3JZbiX"),
        try createPbManagedString(allocator, Hash, "6VemdQJRFejPim7gKDU69DX45GgeBkj892RHiF1g3VL3"),
        try createPbManagedString(allocator, Hash, "8GE5FQkL1Txpzr6QoAg8BFBujBh9KYp6EDF58AMPc8XZ"),
        try createPbManagedString(allocator, Hash, "4rmm9NdRofCaUbqyMgWxpuTU5gEdC9D3dTB1NdSP8qxs"),
        try createPbManagedString(allocator, Hash, "EJkfUHsJZ8zigLy2AsEQdEWnw57oQ3ixQvFhoYeyDfBd"),
        try createPbManagedString(allocator, Hash, "AeBDhZhRN3GiiqPCudr5gcyPnc6ob1yqrfFNfMMyncA3"),
        try createPbManagedString(allocator, Hash, "HSbi9SZgihFPYnQUZnGzbvShMUwupcnevR76gb6vNQPH"),
        try createPbManagedString(allocator, Hash, "9VpyR32aG5w2r5v4c7cHmfJ3YrhxWuibLr52TP9evG4X"),
        try createPbManagedString(allocator, Hash, "HnRisD9hpCmxxWBXZzWkTXi9kFdkSNqDjD9uZ8wFHKom"),
        try createPbManagedString(allocator, Hash, "B1LaeYgZ5noLns3ScfTf6rV8MjB5PRj1iMybAGitvoAf"),
        try createPbManagedString(allocator, Hash, "7LshGoCmGZsZTZnTQd5eieiBZaEMWedbSQ9p9Bp4HmUb"),
        try createPbManagedString(allocator, Hash, "3YPTnKcKPNCC6yEfv4FnMDFCg8m7KAfP5w6sQwzLusY3"),
        try createPbManagedString(allocator, Hash, "41QJqQc9DruQ16nhUe3jSNHY84e2sfUHXvdcTrPsgZKu"),
        try createPbManagedString(allocator, Hash, "7ngFGiJfPugBrJbJGK7iYZQnVAjG1wFWgK8gWjegvKaf"),
        try createPbManagedString(allocator, Hash, "9yRBLtRJ8qgRKw9GwsCX2SAt3eiGRUWSe2zQ437BB9JP"),
        try createPbManagedString(allocator, Hash, "2bZTtX1L5xyjx8fUiNZ4r3Riz7aNgTaJ61Unw31VGB11"),
        try createPbManagedString(allocator, Hash, "3ZudUZTm9uhcnYG8rtgnecEKNAQUVxwNREKP9oFUTyYT"),
        try createPbManagedString(allocator, Hash, "2oVRwpRQKs5GC2oX6FEJH5qvxDKojABMm5BQ1rTxkswM"),
        try createPbManagedString(allocator, Hash, "6pmRPTGhKZ4WGfx39PEebgnkBwGsYRnTtfgUxzEa3ar3"),
        try createPbManagedString(allocator, Hash, "8DrZjLWMj6UfwEMsRfTKEGYzXtM3NiCYXkBvMWEDKgW3"),
        try createPbManagedString(allocator, Hash, "D5g22TZ4zeJGYRXhDREvqHWsCPascvLBuUamspjZTbUB"),
        try createPbManagedString(allocator, Hash, "J2AHpfNSJj7zbPsDQa5Xs6tosfdCq4UtDFHdb9hY5fqy"),
        try createPbManagedString(allocator, Hash, "EooYQHcHH3e8ztqqggP1KPtvwNSK56NJte2eb8sSAS3H"),
        try createPbManagedString(allocator, Hash, "3KQYijRRysiEULupdQzbe8z6VTcsA9igjmn12hh7Bocj"),
        try createPbManagedString(allocator, Hash, "ECjT1A5yqFWJBF8piU3Fg68yCQXghSxCf8bHFRzB3Uxo"),
        try createPbManagedString(allocator, Hash, "xSa7rvJwRQDFHB24QkDvyHq8oUNDGgN8KXh1RYKjjmH"),
        try createPbManagedString(allocator, Hash, "52FANf9qLdyTBRbApgqcVy29w1UHVtcddXwbGGmKdTg3"),
        try createPbManagedString(allocator, Hash, "CcTZTTgCMmZzD3p1UsF83A9wWKURqeD1KXhyLp88XFZ9"),
        try createPbManagedString(allocator, Hash, "G6kCTjN8bMZEjHMu8ZcD1QTRZiRbtDJGREBBxgEr6YQw"),
        try createPbManagedString(allocator, Hash, "wxEkJSDy4tWVnyBSN3ZhTnjDAzLqX5acMRMHpDPR3Qb"),
        try createPbManagedString(allocator, Hash, "8RBNfhJp5Wx3kbJgQVs77DXtxRGLAAyLQ94JAeqvPnAb"),
        try createPbManagedString(allocator, Hash, "HeyxuA8nG6eBQZck7nYCGjwx44ygaGXKYsgdoZFfX9A7"),
        try createPbManagedString(allocator, Hash, "5NLCrsx8TDiBXdFkMVwtkJHuEnmFxgQBLTsE8ofhfpn3"),
        try createPbManagedString(allocator, Hash, "7SfN8q1Le7TS5NnAdrbdMFYRTc9uk4zRqkNe2mZBZ7PD"),
        try createPbManagedString(allocator, Hash, "Da6BCVUApgNwmUqQvjKjDiZYseJGMpF1khPhg9JUR2ZD"),
        try createPbManagedString(allocator, Hash, "BDvj4GQPg2vRhvZo3oLBK9c2At4LfpQHZXcwTspEwcc7"),
        try createPbManagedString(allocator, Hash, "FCnPbNQredzSapocfzP27gBpGDv6LyLuB5aVDn53q32X"),
        try createPbManagedString(allocator, Hash, "DxE3FFxJgLsiMoSfkC3oGthXtpWoBix3J1zR7e2o9Zsm"),
        try createPbManagedString(allocator, Hash, "6xjFToNyoxYmqz77qwkL9FuKToCEGNEx5kYEV9jz6ArB"),
        try createPbManagedString(allocator, Hash, "AZ9roNkb7sNsBwqR4K23ThpUkxfKTiNbsgVKMQUb4EqM"),
        try createPbManagedString(allocator, Hash, "HCGY3iQG97de8nMV7Ze73hJUN61mdVj1CGRzF8WNc6jZ"),
        try createPbManagedString(allocator, Hash, "EV8xB5xRaf9v5sH5QwcDVizSyCJ37PaZk6d4u8iPWpPZ"),
        try createPbManagedString(allocator, Hash, "ZLzn5CxbJugfmgbEvPZC8CfmQihBjCxVjZgfd4yWD2o"),
        try createPbManagedString(allocator, Hash, "An7jDtCRZRt9R9dCRwoeTSiCjSgBjKG7R1MQA2rZYu35"),
        try createPbManagedString(allocator, Hash, "22STPnpwsScA24QTuAk6iYEVHDJ3cJgYgMaEjskiL8hD"),
        try createPbManagedString(allocator, Hash, "HFseWh7pnfJBy81osSULnRbUHbYRL2KFeq27VWTz9XVZ"),
        try createPbManagedString(allocator, Hash, "DuYWx9awumJrujFugTyZForYbv9k2ABXvteDSvcS98Go"),
        try createPbManagedString(allocator, Hash, "8g8CNKiVzg9jxU22AXRz2qhqDtncPWLTG3zLU3wdMMEX"),
        try createPbManagedString(allocator, Hash, "xU7LRbwMWDHubdRFfoc5Z4eNZDxpkoVFXvgChyejfQK"),
        try createPbManagedString(allocator, Hash, "CHUQaunM2KYWizY5nXij6Diz8ZyW28oHUxVkXKyy5LMm"),
        try createPbManagedString(allocator, Hash, "B2MF8FcKqEZ3WPtvd1ezKMxj6ZqqaYx93zcYoYUzeRWP"),
        try createPbManagedString(allocator, Hash, "CGikwne3JgRcj3SRLRFvaQPqpyo7i4aopbDA2SfEKg79"),
        try createPbManagedString(allocator, Hash, "44UqPLsQB5V6PeNpV2e58EJbdmbkbJ4yvoUnqYBUwaw1"),
        try createPbManagedString(allocator, Hash, "8F7qs8R2TTXwNxGZUEX29HPNV1sUnCsztdP9Ef9PYQej"),
        try createPbManagedString(allocator, Hash, "JBbMa7FvLKTKnS6pyNirBRfzqUneviw9uyjRxmmthyaw"),
        try createPbManagedString(allocator, Hash, "4piFFXTw2depcwingu1ASVEp8JzkMUNT9LaYKBJ6fmo5"),
        try createPbManagedString(allocator, Hash, "FWgP5PAx6ZgzDKtLoCmPNySXtiyuP9zVD5p93rzwS5Uj"),
        try createPbManagedString(allocator, Hash, "HRtH5B7YADRAJEfEKjYo14EH91VCQewe3yqRPPGcUJdm"),
        try createPbManagedString(allocator, Hash, "6kUT8PQEbe5JqQgr8LNW9cF2XrwENZgsnK43SYgYjSLF"),
        try createPbManagedString(allocator, Hash, "AbDt3gpQSSd4YdAnsAJcdm4hLg3qRJL9fkbqJP1jDG2j"),
        try createPbManagedString(allocator, Hash, "4zXBE8HydrfTudtrF89aL56mQcWWQ67KCG3KJUrsMcE3"),
        try createPbManagedString(allocator, Hash, "5MupSpZXygxYm9pwKFmRCfdSYKnkBrzP1qxsK97aL1Ys"),
        try createPbManagedString(allocator, Hash, "9jLCWhZk9ocdTt24pEyeuLGPdG1yevKt8KQjsy6sTJKy"),
        try createPbManagedString(allocator, Hash, "AKFgCyZQj2s38cUipfEwdUhARbGin46B5rBwW76cysyy"),
        try createPbManagedString(allocator, Hash, "5BZ16sdyyR2fJfhA3QCEV1CVj3m6XwemqTwZB67b521V"),
        try createPbManagedString(allocator, Hash, "2dYuPxZZSkv623zRD8YSFg4j8ARQCfTiy1j1EJSC4YYP"),
    });

    var pb_features = std.ArrayList(u64).init(allocator);
    try pb_features.appendSlice(&.{
        8745014806010621437,  12746719326835051004, 14880663656912538106, 16502804345974574076, 7464358868518078470,
        17393716913123127814, 13732971186947990025, 9234785398610438155,  10100493572393353740, 16296103013710192647,
        17577018535179185164, 15385144672585180686, 3448684241958864917,  17425121775286888464, 481301242188996633,
        1624608854989936671,  8981415105600321570,  3506988140780836390,  14653876980770606123, 3134844761944150069,
        2108246348442029111,  18430021276965983279, 1546541898477881404,  1668806835898317887,  3159056460576472129,
        12201061873693628997, 16173071899114884681, 9364770135828226129,  11956187351149349462, 13619680173120471639,
        9384680139578013785,  17161605067322646106, 8372877257610877025,  10333664712133278304, 5412861039235947621,
        3217121781990710377,  1903150015966124144,  5811356261681870964,  6945835685041070712,  1488222585707488897,
        6627214705358915199,  6569666574156438145,  3565309654271330957,  5878493780064894105,  13093381132344442521,
        2084081697521279647,  17477161306362325151, 4229600186559593638,  16787576091139260577, 12062129561695986340,
        2608895128084317349,  2095802506721103016,  1043332425687882412,  16343897547665426086, 9291417354790481071,
        14108717550584606385, 2835248715214383806,  12393656768987710652, 1556389209831850690,  10573955866488464067,
        15646637174429435073, 17368202427824553664, 16689784228110797507, 8919829896206010585,  10374551387690409688,
        10497943877114359008, 3080907063555444452,  8408258262441651948,  5430309645140455150,  4916053440333993713,
        18217605389258098417, 13670794101765931764, 8874445338316567292,  3409744574215488768,  10063831043806321919,
        18374874237651057918, 9179305531911086342,  9366572022445289733,  15380324738982398213, 9097679053262300425,
        10495550516822450953, 7864064290362191627,  18144481263832097545, 5578517568662789904,  11624213139604368141,
        16848847066493635853, 12225317994633210130, 14619788719167645459, 10385816867675816217, 3512547638711095073,
        9113171681910074659,  15971986844778064160, 13831771339838013222, 17303821259868640037, 18441458011090382631,
        11999326408594957611, 15535597526625688877, 5767610882599127859,  14215830687796369199, 16289631300196563759,
        17399141370576840507, 7214857342143386434,  5384249827800624464,  520740239964572501,   6311061834237835095,
        3166764948442193245,  5303753339766582627,  4370055567390280552,  4735839496477279080,  16496703778821928294,
        18162940069776114027, 1198485897243202931,  7862845774565664116,  8819118190285818754,  9953734627229811591,
        10698831373887447946, 2327033929746074006,  3881292352862657435,  18133352788893609373, 18293821216929072545,
        9119622038963368358,  15609181264665189287, 5414484214763729842,  7329498988891357619,  975688835218675129,
        6511130474743735231,  18438685373618101179, 9162963928319863751,  4754971307110775241,  12131964148810607046,
        14333591601570674120, 9339287304698073547,  7100026270969684438,  10857131225954620888, 17801294591820438486,
        5516281661825108445,  16152940683682092504, 6184463475151954912,  16785213942406793693, 12022621848025119714,
        11476252442372581349, 6210313007554900458,  15094721454033211366, 14076166885815648232, 15425406085474705386,
    });

    var pb_accounts = std.ArrayList(pb.AcctState).init(allocator);
    try pb_accounts.appendSlice(&.{
        .{
            .address = try createPbManagedString(allocator, Pubkey, "2mURtedre68vMJzQnDrb6f4XAuyRm7Tje8pujzDfvD9M"),
            .lamports = 9365460398065587802,
            .executable = true,
            .rent_epoch = 5155847230196380021,
            .owner = try createPbManagedString(allocator, Pubkey, "11111111111111111111111111111111"),
        },
        .{
            .address = try createPbManagedString(allocator, Pubkey, "6CdPUpVZW1aXCK9gfNSjxnrySvH5mGgDdiuerUYeSRxq"),
            .lamports = 2149935733931552121,
            .data = try .copy(&.{
                1,   0,   0,   0,   1,   0,  0,   0,  125, 67,  221, 3,   128, 80, 136, 101, 229, 47,  139, 240, 175, 86,  36,  122, 119, 139, 50,  32, 105, 222, 10, 14,
                185, 55,  222, 237, 15,  97, 223, 57, 1,   38,  95,  238, 182, 36, 65,  96,  132, 232, 80,  181, 76,  191, 123, 13,  128, 239, 136, 1,  244, 161, 58, 100,
                178, 155, 207, 80,  187, 65, 68,  62, 189, 178, 67,  182, 236, 17, 33,  109,
            }, allocator),
            .rent_epoch = 15322425405372815508,
            .owner = try createPbManagedString(allocator, Pubkey, "11111111111111111111111111111111"),
        },
        .{
            .address = try createPbManagedString(allocator, Pubkey, "SysvarRecentB1ockHashes11111111111111111111"),
            .lamports = 2314125629479449457,
            .data = try .copy(&.{
                70,  0,   0,   0,   0,   0,   0,   0,   95,  71,  247, 4,   156, 158, 207, 15,  159, 76,  27,  54,  168, 84,  167, 91,  103, 92,  73,  194, 130, 26,  57,  82,
                15,  168, 143, 112, 234, 192, 168, 163, 19,  59,  101, 248, 208, 119, 192, 120, 17,  55,  208, 3,   172, 127, 74,  0,   161, 154, 68,  20,  54,  173, 37,  168,
                232, 232, 203, 10,  100, 159, 39,  245, 80,  187, 211, 190, 161, 192, 192, 59,  154, 250, 93,  219, 248, 74,  155, 70,  88,  125, 62,  76,  27,  105, 222, 241,
                171, 87,  46,  129, 2,   228, 170, 170, 1,   176, 219, 170, 234, 104, 204, 201, 10,  165, 170, 26,  243, 20,  90,  64,  189, 155, 187, 87,  216, 104, 110, 225,
                100, 118, 58,  36,  245, 85,  125, 38,  166, 57,  190, 175, 197, 203, 192, 187, 197, 228, 9,   129, 189, 211, 157, 161, 250, 226, 127, 47,  206, 34,  77,  22,
                149, 132, 106, 133, 171, 205, 135, 176, 206, 16,  187, 248, 119, 160, 47,  59,  244, 50,  241, 133, 195, 86,  149, 109, 128, 27,  27,  192, 84,  42,  43,  31,
                10,  40,  242, 177, 170, 78,  140, 40,  178, 148, 64,  2,   160, 237, 155, 255, 60,  236, 160, 108, 1,   110, 109, 56,  160, 120, 55,  88,  102, 109, 41,  244,
                100, 68,  220, 109, 73,  187, 202, 195, 96,  167, 129, 23,  76,  240, 225, 99,  172, 141, 178, 155, 170, 213, 180, 182, 168, 180, 70,  72,  30,  10,  61,  105,
                36,  98,  14,  196, 62,  30,  58,  140, 255, 98,  191, 21,  38,  102, 19,  194, 70,  183, 1,   221, 58,  127, 17,  94,  86,  58,  152, 52,  212, 164, 225, 156,
                160, 175, 225, 211, 75,  123, 14,  48,  251, 58,  240, 109, 203, 230, 204, 203, 179, 224, 173, 128, 153, 140, 192, 66,  183, 118, 126, 3,   101, 217, 112, 59,
                14,  59,  76,  46,  200, 247, 213, 61,  251, 4,   23,  133, 42,  20,  169, 134, 155, 20,  111, 252, 146, 223, 181, 28,  125, 220, 99,  248, 126, 251, 165, 166,
                114, 8,   199, 94,  244, 228, 64,  21,  242, 66,  220, 167, 208, 12,  251, 47,  93,  217, 146, 10,  96,  175, 160, 39,  201, 17,  13,  236, 210, 149, 18,  157,
                116, 63,  177, 37,  12,  209, 201, 94,  204, 159, 120, 1,   61,  44,  84,  7,   201, 103, 60,  79,  238, 197, 216, 253, 194, 52,  170, 245, 88,  207, 14,  64,
                2,   229, 0,   114, 247, 219, 134, 71,  26,  162, 167, 212, 181, 154, 242, 151, 239, 122, 241, 197, 20,  229, 97,  71,  81,  17,  197, 19,  35,  173, 211, 33,
                126, 222, 136, 27,  7,   7,   111, 53,  249, 75,  146, 73,  241, 225, 232, 210, 252, 124, 26,  156, 164, 182, 193, 36,  183, 186, 197, 249, 77,  131, 15,  75,
                67,  147, 124, 127, 164, 46,  7,   212, 23,  123, 8,   4,   10,  86,  116, 131, 63,  124, 121, 210, 46,  88,  193, 236, 51,  211, 166, 43,  9,   10,  90,  47,
                115, 82,  28,  194, 0,   126, 50,  140, 226, 208, 61,  217, 184, 1,   55,  35,  17,  203, 51,  36,  225, 35,  198, 246, 119, 11,  45,  241, 156, 101, 254, 237,
                109, 203, 126, 147, 158, 148, 245, 35,  254, 31,  171, 197, 178, 42,  158, 238, 178, 75,  69,  227, 102, 129, 181, 239, 239, 104, 78,  78,  72,  209, 251, 247,
                119, 151, 2,   30,  130, 182, 223, 134, 115, 204, 215, 3,   231, 233, 11,  135, 194, 216, 160, 84,  193, 57,  22,  214, 225, 159, 195, 236, 60,  74,  81,  99,
                102, 150, 74,  127, 238, 126, 44,  154, 56,  194, 165, 17,  47,  227, 87,  143, 191, 167, 107, 65,  196, 189, 30,  50,  16,  146, 42,  213, 236, 146, 93,  55,
                140, 90,  248, 171, 36,  7,   41,  68,  179, 175, 250, 176, 22,  110, 181, 158, 217, 67,  123, 57,  93,  99,  236, 231, 46,  28,  66,  17,  169, 46,  0,   147,
                176, 231, 141, 108, 42,  126, 210, 228, 6,   46,  99,  205, 57,  199, 86,  127, 247, 117, 21,  189, 130, 169, 5,   242, 127, 132, 46,  180, 57,  87,  144, 92,
                236, 224, 16,  223, 130, 16,  133, 74,  39,  233, 146, 12,  248, 55,  73,  40,  129, 72,  105, 179, 11,  2,   84,  142, 115, 31,  176, 203, 95,  120, 19,  12,
                117, 162, 247, 208, 66,  212, 251, 242, 192, 200, 156, 18,  96,  13,  61,  234, 149, 230, 66,  231, 232, 62,  79,  57,  12,  8,   111, 181, 206, 95,  6,   85,
                23,  245, 155, 7,   82,  90,  220, 175, 187, 151, 249, 92,  149, 245, 134, 140, 78,  215, 61,  217, 119, 63,  4,   53,  204, 178, 24,  153, 106, 54,  229, 56,
                30,  231, 44,  78,  178, 250, 78,  79,  50,  210, 65,  235, 212, 64,  195, 44,  66,  187, 180, 134, 51,  26,  253, 91,  85,  159, 141, 247, 8,   121, 31,  194,
                251, 136, 197, 151, 178, 43,  236, 20,  126, 25,  247, 97,  79,  60,  18,  10,  114, 252, 21,  144, 0,   236, 64,  217, 233, 121, 98,  50,  136, 40,  226, 191,
                203, 111, 75,  225, 188, 242, 195, 48,  255, 230, 122, 79,  125, 92,  147, 199, 208, 169, 241, 176, 179, 172, 153, 214, 73,  39,  196, 132, 41,  61,  197, 34,
                160, 89,  251, 87,  134, 114, 97,  79,  229, 110, 118, 147, 218, 117, 252, 173, 61,  111, 178, 164, 229, 246, 130, 73,  113, 238, 56,  163, 29,  249, 246, 97,
                102, 208, 219, 93,  235, 251, 229, 102, 169, 107, 177, 155, 97,  5,   40,  80,  208, 40,  198, 214, 115, 94,  192, 130, 150, 94,  105, 190, 233, 240, 153, 124,
                200, 201, 178, 239, 205, 33,  192, 127, 212, 60,  102, 169, 7,   81,  191, 170, 39,  62,  128, 204, 32,  159, 138, 28,  31,  140, 123, 248, 177, 167, 34,  119,
                232, 187, 235, 30,  247, 239, 24,  193, 104, 107, 201, 204, 22,  191, 178, 154, 84,  200, 149, 83,  137, 86,  151, 171, 83,  100, 96,  123, 56,  242, 23,  37,
                117, 50,  21,  191, 57,  16,  153, 233, 11,  217, 253, 245, 228, 187, 128, 99,  43,  108, 99,  162, 162, 249, 47,  214, 164, 129, 35,  228, 217, 202, 19,  17,
                123, 60,  24,  176, 172, 50,  18,  248, 200, 3,   211, 161, 82,  244, 70,  234, 91,  18,  132, 232, 132, 76,  164, 162, 110, 199, 116, 131, 137, 11,  134, 55,
                55,  225, 213, 110, 62,  110, 243, 175, 192, 63,  55,  219, 57,  142, 122, 231, 58,  15,  41,  183, 57,  70,  218, 194, 236, 135, 40,  107, 15,  76,  128, 85,
                46,  18,  106, 228, 42,  192, 208, 136, 150, 82,  14,  190, 221, 96,  137, 214, 22,  183, 178, 209, 49,  254, 136, 0,   26,  13,  32,  60,  137, 60,  247, 244,
                0,   200, 91,  157, 212, 137, 131, 240, 160, 171, 30,  148, 208, 188, 120, 44,  114, 185, 194, 143, 225, 182, 241, 89,  172, 122, 75,  104, 208, 112, 246, 153,
                232, 158, 47,  207, 30,  19,  109, 59,  145, 20,  155, 207, 211, 230, 82,  80,  173, 87,  71,  85,  221, 144, 226, 61,  137, 186, 107, 219, 50,  201, 45,  116,
                94,  238, 216, 226, 10,  11,  73,  6,   11,  25,  111, 52,  141, 107, 159, 61,  184, 134, 243, 247, 55,  69,  246, 122, 207, 198, 98,  219, 193, 93,  128, 166,
                53,  26,  5,   128, 244, 50,  229, 130, 221, 168, 100, 31,  167, 182, 132, 43,  85,  231, 5,   60,  130, 4,   30,  199, 26,  169, 144, 119, 63,  129, 123, 189,
                141, 82,  85,  62,  31,  181, 80,  16,  35,  153, 183, 214, 179, 199, 152, 143, 36,  230, 37,  148, 110, 4,   37,  89,  88,  239, 160, 107, 79,  73,  134, 244,
                117, 110, 109, 181, 211, 66,  227, 161, 191, 12,  69,  32,  193, 237, 167, 94,  117, 12,  239, 243, 142, 44,  63,  179, 170, 86,  154, 151, 38,  131, 15,  164,
                26,  245, 195, 217, 102, 235, 199, 175, 165, 210, 247, 230, 245, 151, 207, 69,  67,  193, 144, 58,  168, 0,   114, 111, 213, 14,  212, 40,  36,  91,  88,  55,
                177, 229, 137, 20,  87,  76,  141, 124, 9,   88,  52,  143, 212, 162, 183, 172, 108, 159, 211, 11,  135, 170, 98,  80,  52,  171, 24,  252, 96,  103, 64,  239,
                167, 96,  217, 221, 209, 21,  9,   217, 148, 109, 10,  131, 157, 83,  79,  192, 132, 144, 7,   179, 237, 222, 170, 89,  125, 75,  209, 234, 33,  187, 67,  12,
                125, 76,  125, 9,   50,  235, 35,  247, 25,  79,  168, 134, 147, 208, 67,  107, 74,  78,  87,  160, 190, 36,  95,  175, 63,  96,  29,  235, 155, 240, 31,  79,
                145, 118, 100, 176, 66,  29,  176, 61,  3,   68,  37,  131, 108, 214, 17,  106, 139, 24,  186, 68,  59,  106, 217, 193, 36,  81,  62,  65,  41,  186, 100, 56,
                147, 121, 62,  36,  23,  175, 116, 164, 75,  152, 162, 32,  191, 225, 166, 78,  99,  31,  15,  94,  147, 162, 13,  148, 66,  101, 251, 194, 205, 58,  89,  205,
                249, 170, 49,  246, 182, 86,  201, 68,  71,  23,  21,  146, 254, 190, 61,  166, 6,   194, 76,  244, 37,  87,  144, 75,  59,  107, 168, 215, 0,   68,  56,  139,
                82,  37,  59,  2,   236, 230, 214, 9,   122, 193, 32,  82,  102, 60,  39,  235, 205, 111, 28,  156, 199, 255, 96,  81,  244, 84,  124, 228, 194, 90,  124, 123,
                207, 106, 130, 145, 34,  98,  213, 49,  196, 244, 19,  168, 2,   128, 122, 23,  214, 228, 14,  112, 46,  126, 185, 253, 177, 181, 115, 233, 62,  176, 173, 66,
                164, 84,  6,   128, 232, 157, 89,  230, 133, 14,  213, 250, 213, 146, 227, 49,  34,  156, 19,  219, 199, 135, 95,  63,  241, 77,  172, 162, 216, 75,  188, 18,
                143, 6,   180, 48,  255, 240, 49,  151, 117, 118, 43,  253, 78,  128, 157, 54,  27,  94,  197, 22,  169, 56,  89,  90,  19,  187, 148, 242, 33,  177, 165, 184,
                61,  1,   173, 63,  234, 151, 176, 227, 144, 16,  176, 220, 51,  169, 128, 201, 87,  130, 23,  191, 174, 229, 250, 212, 180, 250, 222, 3,   104, 98,  107, 253,
                8,   74,  33,  51,  60,  195, 177, 156, 82,  225, 83,  124, 63,  105, 193, 205, 97,  69,  134, 228, 15,  239, 124, 223, 11,  172, 65,  140, 47,  193, 129, 58,
                101, 222, 42,  214, 6,   60,  174, 251, 142, 76,  229, 169, 30,  153, 241, 122, 77,  124, 121, 33,  32,  212, 197, 241, 76,  36,  145, 69,  62,  166, 194, 0,
                47,  128, 141, 243, 104, 132, 7,   76,  8,   21,  126, 167, 136, 69,  51,  162, 10,  7,   74,  114, 13,  248, 66,  250, 149, 206, 57,  180, 21,  18,  238, 218,
                126, 241, 57,  144, 63,  219, 159, 182, 144, 117, 80,  208, 243, 245, 173, 191, 113, 117, 228, 64,  205, 75,  190, 250, 133, 49,  158, 152, 3,   75,  233, 31,
                60,  52,  235, 138, 6,   27,  14,  250, 83,  207, 110, 196, 105, 32,  112, 175, 121, 41,  39,  42,  66,  158, 239, 212, 74,  213, 34,  48,  216, 156, 240, 138,
                20,  122, 131, 53,  6,   152, 150, 35,  38,  168, 250, 114, 105, 93,  152, 184, 251, 75,  140, 216, 205, 182, 63,  209, 42,  122, 205, 59,  16,  60,  179, 177,
                52,  71,  170, 88,  28,  209, 110, 55,  30,  2,   212, 204, 254, 163, 223, 108, 221, 187, 112, 157, 122, 7,   63,  133, 74,  171, 128, 240, 141, 132, 137, 51,
                18,  113, 187, 195, 83,  156, 209, 49,  244, 84,  223, 193, 159, 24,  217, 116, 185, 214, 206, 115, 148, 41,  30,  51,  68,  59,  112, 45,  71,  217, 99,  83,
                128, 114, 164, 104, 161, 194, 23,  121, 255, 217, 84,  150, 62,  165, 140, 72,  87,  165, 7,   100, 203, 106, 117, 76,  152, 96,  206, 69,  128, 182, 212, 230,
                173, 15,  133, 192, 101, 142, 252, 246, 28,  133, 255, 230, 205, 181, 51,  32,  168, 197, 73,  230, 29,  219, 238, 32,  214, 25,  66,  204, 177, 115, 197, 197,
                250, 115, 204, 143, 245, 227, 44,  129, 38,  80,  125, 244, 194, 56,  41,  250, 121, 192, 208, 181, 114, 90,  170, 20,  54,  69,  119, 96,  235, 44,  74,  186,
                137, 8,   235, 154, 250, 120, 101, 122, 83,  45,  211, 145, 236, 248, 77,  45,  14,  5,   201, 33,  44,  54,  73,  184, 171, 34,  13,  25,  111, 194, 120, 166,
                159, 65,  220, 16,  20,  16,  186, 164, 141, 137, 21,  76,  10,  242, 161, 160, 151, 121, 98,  142, 238, 139, 174, 237, 122, 209, 213, 148, 12,  161, 226, 90,
                130, 253, 118, 49,  195, 226, 103, 169, 66,  159, 122, 91,  119, 224, 217, 216, 58,  186, 23,  114, 0,   196, 141, 110, 44,  255, 221, 21,  240, 89,  226, 214,
                113, 228, 151, 1,   209, 73,  219, 176, 198, 58,  251, 64,  157, 125, 111, 193, 208, 100, 217, 45,  43,  94,  243, 22,  125, 247, 215, 77,  209, 32,  90,  121,
                187, 19,  186, 196, 126, 147, 229, 30,  131, 71,  179, 118, 19,  42,  113, 193, 158, 72,  108, 104, 194, 89,  213, 99,  6,   136, 160, 165, 2,   104, 175, 47,
                34,  36,  142, 242, 152, 135, 228, 101, 93,  220, 147, 114, 240, 170, 4,   77,  35,  241, 206, 34,  164, 207, 80,  187, 164, 86,  42,  46,  1,   207, 167, 11,
                161, 37,  224, 227, 101, 239, 3,   79,  154, 164, 163, 88,  87,  67,  27,  61,  134, 51,  239, 162, 240, 248, 63,  174, 193, 77,  158, 49,  188, 181, 64,  241,
                154, 113, 44,  154, 211, 153, 227, 144, 148, 101, 213, 243, 161, 121, 57,  69,  207, 163, 65,  162, 214, 71,  16,  64,  226, 76,  95,  109, 176, 39,  31,  191,
                48,  16,  146, 62,  41,  15,  112, 16,  18,  152, 66,  230, 183, 7,   38,  123, 61,  138, 136, 133, 90,  169, 93,  216, 123, 211, 84,  128, 189, 17,  22,  236,
                153, 86,  86,  26,  234, 201, 185, 133, 8,   237, 117, 2,   76,  88,  115, 166, 170, 247, 198, 235, 52,  80,  9,   172, 250, 22,  152, 219, 131, 240, 212, 91,
                223, 180, 231, 201, 71,  193, 10,  173, 163, 32,  181, 213, 184, 193, 125, 153, 24,  99,  172, 1,   135, 94,  89,  35,  150, 22,  212, 234, 208, 97,  124, 177,
                107, 36,  54,  207, 7,   234, 107, 53,  158, 152, 144, 217, 71,  95,  34,  124, 10,  36,  243, 203, 83,  240, 240, 195, 110, 159, 217, 39,  46,  225, 208, 139,
                4,   120, 185, 91,  153, 84,  173, 225, 105, 173, 46,  216, 33,  54,  241, 247, 154, 195, 131, 73,  201, 250, 255, 61,  207, 59,  3,   132, 213, 21,  8,   236,
                31,  196, 65,  223, 218, 132, 85,  114, 224, 85,  168, 197, 49,  25,  104, 135, 105, 38,  247, 124, 225, 33,  29,  231, 172, 222, 131, 20,  255, 23,  198, 204,
                117, 74,  187, 160, 215, 167, 47,  214, 65,  134, 214, 192, 252, 145, 132, 100, 116, 189, 171, 176, 150, 89,  132, 176, 143, 244, 157, 80,  247, 194, 31,  216,
                253, 169, 72,  124, 43,  123, 192, 110, 16,  218, 204, 234, 132, 223, 32,  94,  192, 12,  244, 86,  100, 63,  45,  42,  90,  50,  129, 39,  196, 62,  101, 248,
                166, 150, 108, 186, 226, 143, 155, 5,   131, 255, 212, 45,  251, 211, 228, 110, 220, 86,  171, 255, 240, 88,  198, 141, 136, 11,  129, 110, 68,  114, 119, 14,
                102, 185, 113, 167, 211, 130, 26,  7,   101, 104, 172, 0,   218, 193, 243, 120, 72,  228, 70,  252, 83,  68,  55,  36,  45,  16,  64,  72,  227, 123, 63,  130,
                208, 85,  2,   77,  36,  5,   234, 5,   125, 238, 188, 159, 192, 63,  6,   114, 166, 229, 187, 0,   123, 189, 122, 117, 120, 91,  75,  227, 216, 16,  129, 155,
                106, 116, 108, 47,  86,  102, 117, 166, 12,  14,  147, 166, 97,  84,  230, 234, 240, 66,  121, 205, 148, 225, 178, 211, 111, 209, 93,  207, 215, 152, 165, 204,
                230, 195, 199, 218, 69,  251, 216, 109, 189, 191, 239, 164, 237, 135, 197, 160, 167, 217, 21,  115, 219, 236, 176, 187, 153, 235, 179, 169, 124, 166, 143, 206,
                232, 84,  213, 122, 87,  18,  211, 178, 245, 116, 54,  229, 155, 93,  233, 46,  183, 28,  191, 75,  221, 56,  52,  32,  13,  175, 22,  190, 36,  25,  130, 219,
                179, 19,  118, 246, 166, 188, 28,  126, 97,  99,  115, 166, 112, 225, 5,   129, 46,  60,  245, 31,  249, 185, 128, 82,
            }, allocator),
            .rent_epoch = 4691045773770054888,
            .owner = try createPbManagedString(allocator, Pubkey, "Sysvar1111111111111111111111111111111111111"),
        },
        .{
            .address = try createPbManagedString(allocator, Pubkey, "9Ryytjr8fozTZEy6bUqXC5eU86rtVmPUEmmj7iLUj9Wg"),
            .lamports = 7686924270384124087,
            .executable = true,
            .rent_epoch = 7216444550539344568,
            .owner = try createPbManagedString(allocator, Pubkey, "HfJBAKKCsfwScEwZLKUZau41WVNufhxzmZMnL1B3xNHX"),
        },
        .{
            .address = try createPbManagedString(allocator, Pubkey, "2sndiBU5xRWBk2dGhWU1bZWJopxrmEMitjHAKNvXsyjm"),
            .lamports = 5191045593681845111,
            .data = try .copy(&.{
                1,   0,   0,   0,   255, 255, 255, 255, 255, 255, 255, 255, 44, 173, 247, 40,  0,  0,   0,  0,   0,   1,   62,  216, 11, 154, 130, 247, 42, 92, 187, 16,
                114, 140, 8,   151, 91,  75,  61,  250, 204, 70,  74,  201, 60, 141, 114, 153, 9,  40,  59, 105, 27,  145, 177, 232, 6,  167, 213, 23,  25, 44, 86,  142,
                224, 138, 132, 95,  115, 210, 151, 136, 207, 3,   92,  49,  69, 178, 26,  179, 68, 216, 6,  46,  169, 64,  0,   0,
            }, allocator),
            .rent_epoch = 3739901766483084015,
            .owner = try createPbManagedString(allocator, Pubkey, "AddressLookupTab1e1111111111111111111111111"),
        },
    });

    const pb_tx = pb.SanitizedTransaction{
        .message = .{
            .header = .{
                .num_required_signatures = 3,
                .num_readonly_unsigned_accounts = 1,
            },
            .account_keys = try createPbManagedStrings(allocator, Pubkey, &.{
                "2mURtedre68vMJzQnDrb6f4XAuyRm7Tje8pujzDfvD9M",
                "9Ryytjr8fozTZEy6bUqXC5eU86rtVmPUEmmj7iLUj9Wg",
                "6CdPUpVZW1aXCK9gfNSjxnrySvH5mGgDdiuerUYeSRxq",
                "11111111111111111111111111111111",
            }),
            .recent_blockhash = try createPbManagedString(allocator, Hash, "5VM6f4cVttMPcqEovhp9fg2ipKqAsQ2U23mrcUfJWgm"),
            .instructions = try createPbInstructions(allocator, &.{.{
                .program_id = 3,
                .accounts = &.{ 2, 4, 1, 3 },
                .data = &.{ 4, 0, 0, 0 },
            }}),
            .address_table_lookups = try createPbAddressLookupTables(allocator, &.{.{
                .account_key = "2sndiBU5xRWBk2dGhWU1bZWJopxrmEMitjHAKNvXsyjm",
                .writable_indexes = &.{},
                .readonly_indexes = &.{0},
            }}),
        },
        .message_hash = try createPbManagedString(allocator, Hash, "11111111111111111111111111111111"),
        .signatures = try createPbManagedStrings(allocator, Signature, &.{
            "5J6RCYMNCZq2kqTHLS1XCHqtSTBEn6uVbyqa6wbrXAdXGQreHdjRvKufeWVbqhWHG6ATno74rEyzuvLbidVq1Pq9",
            "ePsUp71bQrtnkePWJZDsV67LUFc9k35RtPEP8bvK3U1YemiHaNxz9UJZq39dd1GZXx9GRNxSU2QEH18EHMRiAHu",
            "4Hdo6guPkSQ31Y1KHMKtKG69Uu7asCZuccqQUWeFnFGaAwSZdgG98Hsx7hrQ6BjTMjXFdYZim3qsNQ93JcKXUSNb",
        }),
    };

    return pb.TxnContext{
        .slot_ctx = .{ .slot = pb_slot },
        .epoch_ctx = .{
            .features = .{ .features = pb_features },
            .new_stake_accounts = .init(allocator),
            .stake_accounts = .init(allocator),
            .new_vote_accounts = .init(allocator),
            .vote_accounts_t = .init(allocator),
            .vote_accounts_t_1 = .init(allocator),
            .vote_accounts_t_2 = .init(allocator),
        },
        .blockhash_queue = pb_blockhashes,
        .account_shared_data = pb_accounts,
        .tx = pb_tx,
    };
}

// EpochRewards Debug Log: 0a73c09ab08f77e00b0faa8cf0d70408113b0a92_265678.fix
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs:60:9] &distributed_rewards = 0
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs:61:9] &point_value = PointValue {
//     rewards: 0,
//     points: 0,
// }
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs:62:9] &stake_rewards_by_partition = [
//     [],
// ]
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs:68:9] self.block_height() = 1
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/calculation.rs:69:9] distribution_starting_block_height = 2
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/sysvar.rs:47:9] &epoch_rewards = EpochRewards {
//     distribution_starting_block_height: 2,
//     num_partitions: 1,
//     parent_blockhash: Brqgfg9qhuU6BN29JvA1U2yUwd89evLxkGrPhgQ9T7GK,
//     total_points: 0,
//     total_rewards: 0,
//     distributed_rewards: 0,
//     active: true,
// }
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/distribution.rs:43:9] &self.epoch_reward_status = Active(
//     StartBlockHeightAndRewards {
//         distribution_starting_block_height: 2,
//         stake_rewards_by_partition: [
//             [],
//         ],
//     },
// )
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/distribution.rs:57:9] height = 1
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/distribution.rs:57:9] distribution_starting_block_height = 2
// [/home/ubuntu/jump/agave/runtime/src/bank/partitioned_epoch_rewards/distribution.rs:57:9] distribution_end_exclusive = 3

// [ 1, 0, 0, 0, 1, 0, 0, 0, 125, 67, 221, 3, 128, 80, 136, 101, 229, 47, 139, 240, 175, 86, 36, 122, 119, 139, 50, 32, 105, 222, 10, 14, 185, 55, 222, 237, 15, 97, 223, 57, 1, 38, 95, 238, 182, 36, 65, 96, 132, 232, 80, 181, 76, 191, 123, 13, 128, 239, 136, 1, 244, 161, 58, 100, 178, 155, 207, 80, 187, 65, 68, 62, 189, 178, 67, 182, 236, 17, 33, 109 ]
// [ 1, 0, 0, 0, 1, 0, 0, 0, 125, 67, 221, 3, 128, 80, 136, 101, 229, 47, 139, 240, 175, 86, 36, 122, 119, 139, 50, 32, 105, 222, 10, 14, 185, 55, 222, 237, 15, 97, 223, 57, 129, 214, 61, 31, 179, 208, 218, 154, 77, 207, 109, 78, 94, 55, 210, 239, 219, 49, 49, 142, 241, 230, 44, 155, 83, 177, 21, 15, 38, 163, 10, 243, 136, 19, 0, 0, 0, 0, 0, 0 ]
