const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountStore = sig.accounts_db.AccountStore;
const AccountSharedData = sig.runtime.AccountSharedData;

const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Epoch = sig.core.Epoch;
const EpochStakes = sig.core.EpochStakes;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const StakesCache = sig.core.StakesCache;
const EpochConstants = sig.core.EpochConstants;
const FeatureSet = sig.core.FeatureSet;

const EpochTracker = sig.replay.trackers.EpochTracker;
const SlotAccountStore = sig.replay.slot_account_store.SlotAccountStore;

const beginPartitionedRewards = sig.replay.rewards.calculation.beginPartitionedRewards;
const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// Process a new epoch. This includes:
/// 1. Apply feature activations.
/// 2. Activate stakes cache for the new epoch.
/// 3. Update epoch stakes
/// 4. Begin partitioned rewards
pub fn processNewEpoch(
    allocator: Allocator,
    slot: Slot,
    slot_state: *SlotState,
    /// These are not constant until we process the new epoch
    slot_constants: *SlotConstants,
    epoch_tracker: *EpochTracker,
    slot_store: SlotAccountStore,
) !void {
    try applyFeatureActivations(
        allocator,
        slot_store,
        epoch_tracker,
        slot_constants,
        true, // allow_new_activations
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1623-L1631
    const epoch = epoch_tracker.schedule.getEpoch(slot);
    try slot_state.stakes_cache.activateEpoch(
        allocator,
        epoch,
        slot_constants.feature_set.newWarmupCooldownRateEpoch(&epoch_tracker.schedule),
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1632-L1636
    const parent_epoch = epoch_tracker.schedule.getEpoch(slot_constants.parent_slot);
    try updateEpochStakes(
        allocator,
        slot,
        parent_epoch,
        &slot_state.stakes_cache,
        epoch_tracker,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1637-L1647
    try beginPartitionedRewards(
        allocator,
        slot,
        slot_state,
        slot_constants,
        epoch_tracker,
        slot_store,
    );
}

pub fn updateEpochStakes(
    allocator: Allocator,
    slot: Slot,
    parent_epoch: Epoch,
    stakes_cache: *StakesCache,
    epoch_tracker: *EpochTracker,
) !void {
    const leader_schedule_epoch = epoch_tracker.schedule.getLeaderScheduleEpoch(slot);
    if (!epoch_tracker.epochs.contains(leader_schedule_epoch)) {
        // TODO: This is mixing the wrong epoch constants with the wrong stakes.
        // We are setting epoch constants for the leader schedule epoch with the epoch constants from the parent epoch.
        const parent_epoch_constants = epoch_tracker.get(parent_epoch) orelse {
            return error.ParentEpochConstantsNotFound;
        };

        const epoch_stakes = try getEpochStakes(
            allocator,
            leader_schedule_epoch,
            stakes_cache,
        );
        errdefer epoch_stakes.deinit(allocator);

        const epoch_constants = EpochConstants{
            .hashes_per_tick = parent_epoch_constants.hashes_per_tick,
            .ticks_per_slot = parent_epoch_constants.ticks_per_slot,
            .ns_per_slot = parent_epoch_constants.ns_per_slot,
            .genesis_creation_time = parent_epoch_constants.genesis_creation_time,
            .slots_per_year = parent_epoch_constants.slots_per_year,
            .stakes = epoch_stakes,
            .rent_collector = parent_epoch_constants.rent_collector,
        };

        try epoch_tracker.put(allocator, leader_schedule_epoch, epoch_constants);
    }
}

pub fn getEpochStakes(
    allocator: Allocator,
    leader_schedule_epoch: Epoch,
    stakes_cache: *StakesCache,
) !EpochStakes {
    const stakes = blk: {
        const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
        defer stakes_lg.unlock();
        break :blk try stakes.clone(allocator);
    };
    const epoch_vote_accounts = stakes.vote_accounts.vote_accounts;

    var node_id_to_vote_accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        sig.core.epoch_stakes.NodeVoteAccounts,
    ){};
    errdefer sig.utils.collections.deinitMapAndValues(allocator, node_id_to_vote_accounts);

    var epoch_authorized_voters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey){};
    errdefer epoch_authorized_voters.deinit(allocator);

    var total_stake: u64 = 0;
    for (epoch_vote_accounts.keys(), epoch_vote_accounts.values()) |key, stake_and_vote_account| {
        if (stake_and_vote_account.stake > 0) {
            total_stake += stake_and_vote_account.stake;

            var vote_state = stake_and_vote_account.account.state;
            if (vote_state.voters.getAuthorizedVoter(leader_schedule_epoch)) |authorized_voter| {
                const node_vote_accounts = try node_id_to_vote_accounts.getOrPut(
                    allocator,
                    authorized_voter,
                );

                if (!node_vote_accounts.found_existing) {
                    node_vote_accounts.value_ptr.* = .EMPTY;
                }

                node_vote_accounts.value_ptr.total_stake += stake_and_vote_account.stake;
                try node_vote_accounts.value_ptr.vote_accounts.append(allocator, key);

                try epoch_authorized_voters.put(allocator, key, authorized_voter);
            }
        }
    }

    const new_stakes = try stakes.convert(allocator, .delegation);

    return .{
        .stakes = new_stakes,
        .total_stake = total_stake,
        .node_id_to_vote_accounts = node_id_to_vote_accounts,
        .epoch_authorized_voters = epoch_authorized_voters,
    };
}

/// https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L5332
pub fn applyFeatureActivations(
    allocator: Allocator,
    slot_store: SlotAccountStore,
    epoch_tracker: *EpochTracker,
    slot_constants: *SlotConstants,
    allow_new_activations: bool,
) !void {
    // Iterate through the inactive features and:
    // 1. Try and load the feature account from the accounts db.
    // 2. If the account exists, check if it has been activated already.
    // 3. If it has been activated, add it to the active set.
    // 4. If it has not been activated, and new activations are allowed,
    //    add it to the active set and activate it by setting the slot
    //    and writing it back to the accounts db.
    const feature_set = &slot_constants.feature_set;
    var new_feature_activations = FeatureSet.ALL_DISABLED;
    var inactive_iterator = feature_set.iterator(slot_store.slot, .inactive);
    while (inactive_iterator.next()) |feature| {
        const feature_id: Pubkey = features.map.get(feature).key;
        if (try slot_store.get(allocator, feature_id)) |feature_account| {
            defer feature_account.deinit(allocator);
            if (try featureActivationSlotFromAccount(feature_account)) |activation_slot| {
                feature_set.setSlot(feature, activation_slot);
            } else if (allow_new_activations) {
                feature_set.setSlot(feature, slot_store.slot);
                new_feature_activations.setSlot(feature, slot_store.slot);
                const account = try AccountSharedData.fromAccount(allocator, &feature_account);
                defer allocator.free(account.data);
                try slot_store.put(feature_id, account);
            }
        }
    }

    // Update active set of reserved account keys which are not allowed to be write locked
    slot_constants.reserved_accounts.update(feature_set, slot_store.slot);

    const epoch_constants = epoch_tracker.getMutablePtrForSlot(slot_store.slot).?;

    // Activate pico inflation if it is in the newly activated set
    if (new_feature_activations.active(.pico_inflation, slot_store.slot)) {
        slot_constants.inflation = .PICO;
        slot_constants.fee_rate_governor.burn_percent = 50; // DEFAULT_BURN_PERCENT: 50% fee burn.
        epoch_constants.rent_collector.rent.burn_percent = 50; // 50% rent bur.
    }

    if (feature_set
        .fullInflationFeatures(slot_store.slot)
        .enabled(new_feature_activations, slot_store.slot))
    {
        slot_constants.inflation = .FULL;
        slot_constants.fee_rate_governor.burn_percent = 50; // DEFAULT_BURN_PERCENT: 50% fee burn.
        epoch_constants.rent_collector.rent.burn_percent = 50; // 50% rent bur.
    }

    // Apply built-in program feature transitions
    // Agave provides an option to not apply builtin program transitions, we can add this later if needed.
    // TODO: migrateBuiltinProgramToCoreBpf
    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot_store,
        epoch_constants,
        feature_set,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.active(.raise_block_limits_to_100m, slot_store.slot)) {
        // TODO: Implement
        return error.RaiseBlockLimitsTo100MActivationNotImplemented;
    }

    if (new_feature_activations.active(.raise_account_cu_limit, slot_store.slot)) {
        // TODO: Implement
        return error.RaiseAccountCuLimitActivationNotImplemented;
    }
}

/// Apply built-in program feature transitions
/// [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5451
fn applyBuiltinProgramFeatureTransitions(
    allocator: Allocator,
    slot_store: SlotAccountStore,
    epoch_constants: *const EpochConstants,
    feature_set: *const FeatureSet,
    new_feature_activations: *const FeatureSet,
    allow_new_activations: bool,
) !void {
    for (builtin_programs.BUILTINS) |builtin_program| {
        // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5473-L5498
        var is_core_bpf = false;
        if (builtin_program.core_bpf_migration_config) |core_bpf_config| {
            if (new_feature_activations.active(core_bpf_config.enable_feature_id, slot_store.slot)) {
                is_core_bpf = true;
                migrateBuiltinProgramToCoreBpf(
                    allocator,
                    slot_store,
                    epoch_constants,
                    feature_set,
                    builtin_program.program_id,
                    core_bpf_config,
                    .builtin,
                ) catch {
                    // Failed to migrate
                    is_core_bpf = false;
                };
            } else {
                if (try slot_store.get(allocator, builtin_program.program_id)) |account| {
                    defer account.deinit(allocator);
                    is_core_bpf = account.owner.equals(&program.bpf_loader.v3.ID);
                } else is_core_bpf = false;
            }
        }

        // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5500-L5520
        if (builtin_program.enable_feature_id) |feature_id| {
            const should_enable_on_transition = !is_core_bpf and if (allow_new_activations)
                new_feature_activations.active(feature_id, slot_store.slot)
            else
                feature_set.active(feature_id, slot_store.slot);

            if (should_enable_on_transition) {
                try slot_store.putBuiltinProgramAccount(
                    allocator,
                    builtin_program,
                );
            }
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5526-L5540
    for (builtin_programs.STATELESS_BUILTINS) |builtin_program| {
        const core_bpf_config = builtin_program.core_bpf_migration_config orelse continue;
        if (new_feature_activations.active(core_bpf_config.enable_feature_id, 0)) {
            migrateBuiltinProgramToCoreBpf(
                allocator,
                slot_store,
                epoch_constants,
                feature_set,
                builtin_program.program_id,
                core_bpf_config,
                .stateless_builtin,
            ) catch {
                // Failed to migrate
                return;
            };
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5542-L5551
    for (program.precompiles.PRECOMPILES) |precompile| {
        const feature_id = precompile.required_feature orelse continue;
        if (!feature_set.active(feature_id, slot_store.slot)) continue;
        try slot_store.putPrecompile(allocator, precompile);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.0.3/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L221
fn migrateBuiltinProgramToCoreBpf(
    allocator: Allocator,
    slot_store: SlotAccountStore,
    epoch_constants: *const EpochConstants,
    feature_set: *const FeatureSet,
    builtin_program_id: Pubkey,
    migration_config: builtin_programs.CoreBpfMigrationConfig,
    migration_type: enum { builtin, stateless_builtin },
) !void {
    const loader_v3 = program.bpf_loader.v3;

    const target = .{
        .program_account = switch (migration_type) {
            .builtin => blk: {
                const account = (slot_store.get(allocator, builtin_program_id) catch null) orelse
                    return error.AccountNotFound;
                if (!account.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID))
                    return error.IncorrectOwner;
                break :blk account;
            },
            .stateless_builtin => blk: {
                if ((slot_store.get(allocator, builtin_program_id) catch null) != null)
                    return error.AccountExists;
                break :blk null;
            },
        },
        .program_data_address = blk: {
            const program_data_address, _ = sig.runtime.pubkey_utils.findProgramAddress(
                &.{&builtin_program_id.data},
                program.bpf_loader.v3.ID,
            ) orelse unreachable; // agave/solana-address-1.0.0 panics on this case.

            if ((slot_store.get(allocator, program_data_address) catch null) != null) {
                return error.ProgramHasDataAccount;
            }
            break :blk program_data_address;
        },
    };

    const source = blk: {
        const buffer_account = (slot_store.get(
            allocator,
            migration_config.source_buffer_address,
        ) catch null) orelse return error.AccountNotFound;

        if (!buffer_account.owner.equals(&loader_v3.ID))
            return error.IncorrectOwner;

        const buffer_size = loader_v3.State.BUFFER_METADATA_SIZE;
        if (buffer_account.data.len() < buffer_size)
            return error.InvalidBufferAccount;

        const buffer_data = try buffer_account.data.readAllAllocate(allocator);
        errdefer allocator.free(buffer_data);

        const state = bincode.readFromSlice(
            std.testing.failing_allocator,
            loader_v3.State,
            buffer_data[0..buffer_size],
            .{},
        ) catch return error.InvalidBufferAccount;

        break :blk switch (state) {
            .buffer => |args| .{
                .account = buffer_account,
                .authority = args.authority_address,
                .data = buffer_data,
            },
            else => return error.InvalidBufferAccount,
        };
    };
    defer allocator.free(source.data);

    if (migration_config.verified_build_hash) |expected_hash| {
        const offset = loader_v3.State.BUFFER_METADATA_SIZE;
        const end_offset = @max(offset, for (0..source.data.len) |i| {
            const backwards_idx = source.data.len - i - 1;
            if (source.data[backwards_idx] != 0) break backwards_idx + 1;
        } else 0);

        const hash = sig.core.Hash.init(source.data[offset..end_offset]);
        if (!hash.eql(expected_hash)) {
            return error.BuildHashMismatch;
        }
    }

    // Attempt serialization first.
    var new_target_buffer: [loader_v3.State.BUFFER_METADATA_SIZE]u8 = undefined;
    const new_target_account: AccountSharedData = .{
        .data = try bincode.writeToSlice(
            &new_target_buffer,
            loader_v3.State{ .buffer = .{ .authority_address = target.program_data_address } },
            .{},
        ),
        .lamports = @max(1, epoch_constants.rent_collector.rent.minimumBalance(
            loader_v3.State.PROGRAM_SIZE,
        )),
        .rent_epoch = 0,
        .owner = loader_v3.ID,
        .executable = true,
    };

    const new_target_pda: AccountSharedData = blk: {
        if (migration_config.upgrade_authority_address) |provided_authority| {
            if (source.authority == null or !provided_authority.equals(&source.authority.?)) {
                return error.UpgradeAuthorityMismatch;
            }
        }

        const elf = source.data[loader_v3.State.BUFFER_METADATA_SIZE..];
        const space = loader_v3.State.sizeOfProgramData(elf.len);
        const data = try allocator.alloc(u8, space);
        errdefer allocator.free(data);

        _ = try bincode.writeToSlice(
            data,
            loader_v3.State{ .program_data = .{
                .slot = slot_store.slot,
                .upgrade_authority_address = migration_config.upgrade_authority_address,
            } },
            .{},
        );
        @memcpy(data[loader_v3.State.PROGRAM_DATA_METADATA_SIZE..][0..elf.len], elf);

        break :blk .{
            .data = data,
            .lamports = @max(1, epoch_constants.rent_collector.rent.minimumBalance(space)),
            .rent_epoch = 0,
            .owner = loader_v3.ID,
            .executable = false,
        };
    };
    defer allocator.free(new_target_pda.data);

    const old_data_size = std.math.add(
        u64,
        if (target.program_account) |account| account.data.len() else 0,
        source.account.data.len(),
    ) catch return error.ArithmeticOverflow;
    const new_data_size = std.math.add(
        u64,
        new_target_account.data.len,
        new_target_pda.data.len,
    ) catch return error.ArithmeticOverflow;

    // Do the verification part of bpf_loader.v3.deployProgram
    {
        const compute_budget: sig.runtime.ComputeBudget = .DEFAULT;
        try program.bpf_loader.verifyProgram(
            allocator,
            new_target_pda.data[loader_v3.State.PROGRAM_DATA_METADATA_SIZE..],
            slot_store.slot,
            feature_set,
            &compute_budget,
            null, // no LogCollector
        );
    }

    // update capitalization
    {
        const lamports_to_burn = std.math.add(
            u64,
            if (target.program_account) |account| account.lamports else 0,
            source.account.lamports,
        ) catch return error.ArithmeticOverflow;
        const lamports_to_fund = std.math.add(
            u64,
            new_target_account.lamports,
            new_target_pda.lamports,
        ) catch return error.ArithmeticOverflow;

        switch (std.math.order(lamports_to_burn, lamports_to_fund)) {
            .gt => {
                const delta = std.math.sub(
                    u64,
                    lamports_to_burn,
                    lamports_to_fund,
                ) catch return error.ArithmeticOverflow;
                _ = slot_store.state.capitalization.fetchSub(delta, .monotonic);
            },
            .lt => {
                const delta = std.math.sub(
                    u64,
                    lamports_to_fund,
                    lamports_to_burn,
                ) catch return error.ArithmeticOverflow;
                _ = slot_store.state.capitalization.fetchAdd(delta, .monotonic);
            },
            .eq => {},
        }
    }

    {
        // TODO: remove program_id from list of bank's built-ins
        try slot_store.put(builtin_program_id, new_target_account);
        try slot_store.put(target.program_data_address, new_target_pda);
        try slot_store.put(migration_config.source_buffer_address, AccountSharedData.EMPTY);
    }

    // calculate_and_update_accounts_data_size_delta_off_chain
    {
        // These are assert()!s
        const old_size = std.math.cast(i64, old_data_size).?;
        const new_size = std.math.cast(i64, new_data_size).?;
        const delta_size = new_size -| old_size;
        if (delta_size > 0) {
            // TODO: update accounts_data_size_delta_off_chain atomically with saturading add delta.
        }
    }
}

fn featureActivationSlotFromAccount(account: Account) !?u64 {
    if (!account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return null;
    var feature_bytes = [_]u8{0} ** 9;
    account.data.readAll(&feature_bytes);
    return bincode.readFromSlice(failing_allocator, ?u64, &feature_bytes, .{});
}

const ThreadSafeAccountMap = sig.accounts_db.account_store.ThreadSafeAccountMap;

const TestEnvironment = struct {
    genesis_config: sig.core.GenesisConfig,
    account_map: ThreadSafeAccountMap,
    ancestors: Ancestors,
    epoch_tracker: EpochTracker,
    slot_constants: SlotConstants,
    slot_state: SlotState,

    pub fn init(allocator: Allocator) !TestEnvironment {
        var genesis_config = sig.core.GenesisConfig.default(allocator);
        errdefer genesis_config.deinit(allocator);

        var account_map = ThreadSafeAccountMap.init(allocator);
        errdefer account_map.deinit();

        var ancestors = Ancestors.EMPTY;
        errdefer ancestors.deinit(allocator);

        var epoch_tracker: EpochTracker = .{ .schedule = .INIT };
        errdefer epoch_tracker.deinit(allocator);

        var epoch_constants = EpochConstants.genesis(genesis_config);
        errdefer epoch_constants.deinit(allocator);
        try epoch_tracker.put(allocator, 0, epoch_constants);

        var slot_constants = try SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);

        var slot_state = SlotState.GENESIS;
        errdefer slot_state.deinit(allocator);

        return TestEnvironment{
            .genesis_config = genesis_config,
            .account_map = account_map,
            .ancestors = ancestors,
            .epoch_tracker = epoch_tracker,
            .slot_constants = slot_constants,
            .slot_state = slot_state,
        };
    }

    pub fn deinit(self: *TestEnvironment, allocator: Allocator) void {
        self.genesis_config.deinit(allocator);
        self.account_map.deinit();
        self.ancestors.deinit(allocator);
        self.epoch_tracker.deinit(allocator);
        self.slot_constants.deinit(allocator);
        self.slot_state.deinit(allocator);
    }

    pub fn insertFeatureAccount(
        self: *TestEnvironment,
        allocator: Allocator,
        slot: Slot,
        lamports: u64,
        feature: features.Feature,
        activation_slot: ?Slot,
    ) !void {
        const feature_id = features.map.get(feature).key;
        const data = try allocator.alloc(u8, 9);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try bincode.writeToSlice(
            data,
            activation_slot,
            .{},
        );
        const feature_account = AccountSharedData{
            .lamports = lamports,
            .owner = sig.runtime.ids.FEATURE_PROGRAM_ID,
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
            .data = data,
        };
        try self.accountStore().put(slot, feature_id, feature_account);
    }

    pub fn slotAccountStore(
        self: *TestEnvironment,
        slot: Slot,
    ) SlotAccountStore {
        return SlotAccountStore.init(
            slot,
            &self.slot_state,
            self.accountStore(),
            &self.ancestors,
        );
    }

    pub fn accountStore(
        self: *TestEnvironment,
    ) AccountStore {
        return .{ .thread_safe_map = &self.account_map };
    }
};

test "applyFeatureActivations: activate pico inflation" {
    const allocator = std.testing.allocator;

    {
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        const initial_rent_collector = env.epoch_tracker.getPtrForSlot(slot).?.rent_collector;
        const initial_fee_rate_governor = env.slot_constants.fee_rate_governor;

        try applyFeatureActivations(
            allocator,
            env.slotAccountStore(slot),
            &env.epoch_tracker,
            &env.slot_constants,
            false,
        );
        try std.testing.expectEqual(
            sig.core.genesis_config.Inflation.DEFAULT,
            env.slot_constants.inflation,
        );
        try std.testing.expectEqual(
            initial_fee_rate_governor.burn_percent,
            env.slot_constants.fee_rate_governor.burn_percent,
        );
        try std.testing.expectEqual(
            initial_rent_collector.rent.burn_percent,
            env.epoch_tracker.getPtrForSlot(slot).?.rent_collector.rent.burn_percent,
        );

        // Test PICO inflation activation - null in feature
        try env.insertFeatureAccount(allocator, slot, 1, .pico_inflation, null);

        // Don't allow new activations
        try applyFeatureActivations(
            allocator,
            env.slotAccountStore(slot),
            &env.epoch_tracker,
            &env.slot_constants,
            false,
        );

        try std.testing.expectEqual(
            sig.core.genesis_config.Inflation.DEFAULT,
            env.slot_constants.inflation,
        );
        try std.testing.expectEqual(
            initial_fee_rate_governor.burn_percent,
            env.slot_constants.fee_rate_governor.burn_percent,
        );
        try std.testing.expectEqual(
            initial_rent_collector.rent.burn_percent,
            env.epoch_tracker.getPtrForSlot(slot).?.rent_collector.rent.burn_percent,
        );

        // Allow new activations
        try applyFeatureActivations(
            allocator,
            env.slotAccountStore(slot),
            &env.epoch_tracker,
            &env.slot_constants,
            true,
        );
        try std.testing.expectEqual(0, env.slot_constants.feature_set.get(.pico_inflation));
        try std.testing.expectEqual(
            sig.core.genesis_config.Inflation.PICO,
            env.slot_constants.inflation,
        );
        try std.testing.expectEqual(50, env.slot_constants.fee_rate_governor.burn_percent);
        try std.testing.expectEqual(
            50,
            env.epoch_tracker.getPtrForSlot(slot).?.rent_collector.rent.burn_percent,
        );
    }

    {
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        const initial_inflation = env.slot_constants.inflation;
        const initial_rent_collector = env.epoch_tracker.getPtrForSlot(slot).?.rent_collector;
        const initial_fee_rate_governor = env.slot_constants.fee_rate_governor;

        // Test PICO inflation activation - feature slot 1
        try env.insertFeatureAccount(allocator, slot, 1, .pico_inflation, 1);

        // Allow new activations
        try applyFeatureActivations(
            allocator,
            env.slotAccountStore(slot),
            &env.epoch_tracker,
            &env.slot_constants,
            true,
        );
        try std.testing.expectEqual(1, env.slot_constants.feature_set.get(.pico_inflation));
        try std.testing.expectEqual(
            initial_inflation,
            env.slot_constants.inflation,
        );
        try std.testing.expectEqual(
            initial_fee_rate_governor.burn_percent,
            env.slot_constants.fee_rate_governor.burn_percent,
        );
        try std.testing.expectEqual(
            initial_rent_collector.rent.burn_percent,
            env.epoch_tracker.getPtrForSlot(slot).?.rent_collector.rent.burn_percent,
        );
    }
}
