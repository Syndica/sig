const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountStore = sig.accounts_db.SlotAccountStore;
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
const FeatureSet = sig.core.FeatureSet;
const Rent = sig.runtime.sysvar.Rent;

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
    slot_constants: *SlotConstants,
    slot_state: *SlotState,
    slot_store: SlotAccountStore,
    epoch_tracker: *sig.core.EpochTracker,
) !void {
    try applyFeatureActivations(
        allocator,
        slot,
        slot_constants,
        slot_state,
        slot_store,
        true, // allow_new_activations
    );

    try slot_state.stakes_cache.activateEpoch(
        allocator,
        epoch_tracker.epoch_schedule.getEpoch(slot),
        slot_constants.feature_set.newWarmupCooldownRateEpoch(&epoch_tracker.epoch_schedule),
    );

    try updateEpochStakes(
        allocator,
        slot,
        &slot_constants.ancestors,
        &slot_constants.feature_set,
        &slot_state.stakes_cache,
        epoch_tracker,
    );

    try beginPartitionedRewards(
        allocator,
        slot,
        slot_constants,
        slot_state,
        slot_store,
        epoch_tracker,
    );
}

pub fn updateEpochStakes(
    allocator: Allocator,
    slot: Slot,
    ancestors: *const Ancestors,
    feature_set: *const FeatureSet,
    stakes_cache: *StakesCache,
    epoch_tracker: *sig.core.EpochTracker,
) !void {
    const epoch_info = epoch_tracker.getEpochInfoNoOffset(slot, ancestors) catch null;
    if (epoch_info == null) {
        const epoch_stakes = try getEpochStakes(
            allocator,
            epoch_tracker.epoch_schedule.getLeaderScheduleEpoch(slot),
            stakes_cache,
        );
        errdefer epoch_stakes.deinit(allocator);

        _ = try epoch_tracker.insertUnrootedEpochInfo(
            allocator,
            slot,
            ancestors,
            epoch_stakes,
            feature_set,
        );
    }
}

/// Compute the epoch stakes for the given leader schedule epoch.
/// Contains
///  - snapshot of the current stakes, converted to Stakes(.delegation).
///  - total stake delegated to current vote accounts.
///  - mapping of authorized voters (node IDs) to their vote accounts active in this epoch.
///  - mapping of vote accounts to their authorized voters.
/// The authorized voters are determined based on the vote state and leader schedule epoch.
pub fn getEpochStakes(
    allocator: Allocator,
    leader_schedule_epoch: Epoch,
    stakes_cache: *StakesCache,
) !EpochStakes {
    const new_stakes = blk: {
        const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
        defer stakes_lg.unlock();
        break :blk try stakes.convert(allocator, .delegation);
    };
    errdefer new_stakes.deinit(allocator);
    const epoch_vote_accounts = new_stakes.vote_accounts.vote_accounts;

    var node_id_to_vote_accounts = sig.utils.collections.PubkeyMap(
        sig.core.epoch_stakes.NodeVoteAccounts,
    ){};
    errdefer sig.utils.collections.deinitMapAndValues(allocator, node_id_to_vote_accounts);

    var epoch_authorized_voters = sig.utils.collections.PubkeyMap(Pubkey){};
    errdefer epoch_authorized_voters.deinit(allocator);

    var total_stake: u64 = 0;
    for (epoch_vote_accounts.keys(), epoch_vote_accounts.values()) |key, stake_and_vote_account| {
        if (stake_and_vote_account.stake > 0) {
            total_stake += stake_and_vote_account.stake;

            var vote_state = stake_and_vote_account.account.state;
            if (vote_state.authorized_voters.getAuthorizedVoter(leader_schedule_epoch)) |authorized_voter| {
                const node_vote_accounts = try node_id_to_vote_accounts.getOrPut(
                    allocator,
                    vote_state.node_pubkey,
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

    return .{
        .stakes = new_stakes,
        .total_stake = total_stake,
        .node_id_to_vote_accounts = node_id_to_vote_accounts,
        .epoch_authorized_voters = epoch_authorized_voters,
    };
}

/// Apply feature activations at the given slot.
/// Activated features are stored in feature accounts with a non-null activation slot.
/// Pending feature activations are stored in feature accounts with a null activation slot.
/// If new activations are allowed, pending features will be activated at the current slot, have
/// their feature account updated, and the corresponding effects applied.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L5332
pub fn applyFeatureActivations(
    allocator: Allocator,
    slot: Slot,
    slot_constants: *SlotConstants,
    slot_state: *SlotState,
    slot_store: SlotAccountStore,
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
    var inactive_iterator = feature_set.iterator(slot, .inactive);
    while (inactive_iterator.next()) |feature| {
        const feature_id: Pubkey = features.map.get(feature).key;
        if (try slot_store.reader().get(allocator, feature_id)) |feature_account| {
            defer feature_account.deinit(allocator);
            if (try featureActivationSlotFromAccount(feature_account)) |activation_slot| {
                feature_set.setSlot(feature, activation_slot);
            } else if (allow_new_activations) {
                feature_set.setSlot(feature, slot);
                new_feature_activations.setSlot(feature, slot);
                const account = try AccountSharedData.fromAccount(allocator, &feature_account);
                defer allocator.free(account.data);
                try slot_store.put(feature_id, account);
            }
        }
    }

    slot_constants.reserved_accounts.update(feature_set, slot);

    if (new_feature_activations.active(.pico_inflation, slot)) {
        slot_constants.inflation = .PICO;
        slot_constants.fee_rate_governor.burn_percent = 50; // DEFAULT_BURN_PERCENT: 50% fee burn.
        slot_constants.rent_collector.rent.burn_percent = 50; // 50% rent bur.
    }
    if (feature_set.fullInflationFeaturesEnabled(slot, &new_feature_activations)) {
        slot_constants.inflation = .FULL;
        slot_constants.fee_rate_governor.burn_percent = 50; // DEFAULT_BURN_PERCENT: 50% fee burn.
        slot_constants.rent_collector.rent.burn_percent = 50; // 50% rent bur.
    }

    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot,
        slot_state,
        slot_store,
        &slot_constants.rent_collector.rent,
        feature_set,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.active(.raise_block_limits_to_100m, slot)) {
        // TODO: Implement once cost tracker is added
        // https://github.com/orgs/Syndica/projects/2/views/10?pane=issue&itemId=149549898
        return error.RaiseBlockLimitsTo100MActivationNotImplemented;
    }
    if (new_feature_activations.active(.raise_account_cu_limit, slot)) {
        // TODO: Implement once cost tracker is added
        // https://github.com/orgs/Syndica/projects/2/views/10?pane=issue&itemId=149549898
        return error.RaiseAccountCuLimitActivationNotImplemented;
    }
}

/// Apply built-in program feature transitions
/// [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5451
fn applyBuiltinProgramFeatureTransitions(
    allocator: Allocator,
    slot: Slot,
    slot_state: *SlotState,
    slot_store: SlotAccountStore,
    rent: *const Rent,
    feature_set: *const FeatureSet,
    new_feature_activations: *const FeatureSet,
    allow_new_activations: bool,
) !void {
    for (builtin_programs.BUILTINS) |builtin_program| {
        // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5473-L5498
        var is_core_bpf = false;
        if (builtin_program.core_bpf_migration_config) |core_bpf_config| {
            if (new_feature_activations.active(core_bpf_config.enable_feature_id, slot)) {
                is_core_bpf = true;
                migrateBuiltinProgramToCoreBpf(
                    allocator,
                    slot,
                    slot_store,
                    &slot_state.capitalization,
                    rent,
                    feature_set,
                    builtin_program.program_id,
                    core_bpf_config,
                    .builtin,
                ) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => {
                        // Failed to migrate
                        is_core_bpf = false;
                    },
                };
            } else {
                if (try slot_store.reader().get(allocator, builtin_program.program_id)) |account| {
                    defer account.deinit(allocator);
                    is_core_bpf = account.owner.equals(&program.bpf_loader.v3.ID);
                } else is_core_bpf = false;
            }
        }

        // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5500-L5520
        if (builtin_program.enable_feature_id) |feature_id| {
            const should_enable_on_transition = !is_core_bpf and if (allow_new_activations)
                new_feature_activations.active(feature_id, slot)
            else
                feature_set.active(feature_id, slot);

            if (should_enable_on_transition) {
                try putBuiltinProgramAccount(
                    allocator,
                    slot_store,
                    builtin_program,
                    &slot_state.capitalization,
                );
            }
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5526-L5540
    for (builtin_programs.STATELESS_BUILTINS) |builtin_program| {
        const core_bpf_config = builtin_program.core_bpf_migration_config orelse continue;
        if (new_feature_activations.active(core_bpf_config.enable_feature_id, slot)) {
            migrateBuiltinProgramToCoreBpf(
                allocator,
                slot,
                slot_store,
                &slot_state.capitalization,
                rent,
                feature_set,
                builtin_program.program_id,
                core_bpf_config,
                .stateless_builtin,
            ) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return, // Failed to migrate
            };
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L5542-L5551
    for (program.precompiles.PRECOMPILES) |precompile| {
        const feature_id = precompile.required_feature orelse continue;
        if (!feature_set.active(feature_id, slot)) continue;
        try putPrecompile(allocator, slot_store, precompile, &slot_state.capitalization);
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.0.3/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L221
fn migrateBuiltinProgramToCoreBpf(
    allocator: Allocator,
    slot: Slot,
    slot_store: SlotAccountStore,
    capitalization: *Atomic(u64),
    rent: *const Rent,
    feature_set: *const FeatureSet,
    builtin_program_id: Pubkey,
    migration_config: builtin_programs.CoreBpfMigrationConfig,
    migration_type: enum { builtin, stateless_builtin },
) !void {
    const loader_v3 = program.bpf_loader.v3;

    const target = .{
        .program_account = switch (migration_type) {
            .builtin => blk: {
                const account = (try slot_store.reader()
                    .get(allocator, builtin_program_id)) orelse
                    return error.AccountNotFound;
                if (!account.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID))
                    return error.IncorrectOwner;
                break :blk account;
            },
            .stateless_builtin => blk: {
                if ((try slot_store.reader().get(allocator, builtin_program_id))) |account| {
                    defer account.deinit(allocator);
                    return error.AccountExists;
                }
                break :blk null;
            },
        },
        .program_data_address = blk: {
            const program_data_address, _ = sig.runtime.pubkey_utils.findProgramAddress(
                &.{&builtin_program_id.data},
                program.bpf_loader.v3.ID,
            ) orelse unreachable; // agave/solana-address-1.0.0 panics on this case.

            if ((try slot_store.reader().get(allocator, program_data_address))) |account| {
                defer account.deinit(allocator);
                return error.ProgramHasDataAccount;
            }
            break :blk program_data_address;
        },
    };

    const source = blk: {
        const buffer_account = (try slot_store.reader().get(
            allocator,
            migration_config.source_buffer_address,
        )) orelse return error.AccountNotFound;
        defer buffer_account.deinit(allocator);

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
                .authority = args.authority_address,
                .lamports = buffer_account.lamports,
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
        .lamports = @max(1, rent.minimumBalance(
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
                .slot = slot,
                .upgrade_authority_address = migration_config.upgrade_authority_address,
            } },
            .{},
        );
        @memcpy(data[loader_v3.State.PROGRAM_DATA_METADATA_SIZE..][0..elf.len], elf);

        break :blk .{
            .data = data,
            .lamports = @max(1, rent.minimumBalance(space)),
            .rent_epoch = 0,
            .owner = loader_v3.ID,
            .executable = false,
        };
    };
    defer allocator.free(new_target_pda.data);

    const old_data_size = std.math.add(
        u64,
        if (target.program_account) |account| account.data.len() else 0,
        source.data.len,
    ) catch return error.ArithmeticOverflow;
    const new_data_size = std.math.add(
        u64,
        new_target_account.data.len,
        new_target_pda.data.len,
    ) catch return error.ArithmeticOverflow;

    // Do the verification part of bpf_loader.v3.deployProgram
    const compute_budget: sig.runtime.ComputeBudget = .DEFAULT;
    try program.bpf_loader.verifyProgram(
        allocator,
        new_target_pda.data[loader_v3.State.PROGRAM_DATA_METADATA_SIZE..],
        slot,
        feature_set,
        &compute_budget,
        null, // no LogCollector
    );

    // update capitalization
    const lamports_to_burn = std.math.add(
        u64,
        if (target.program_account) |account| account.lamports else 0,
        source.lamports,
    ) catch return error.ArithmeticOverflow;
    const lamports_to_fund = std.math.add(
        u64,
        new_target_account.lamports,
        new_target_pda.lamports,
    ) catch return error.ArithmeticOverflow;

    switch (std.math.order(lamports_to_burn, lamports_to_fund)) {
        .gt => _ = capitalization.fetchSub(lamports_to_burn - lamports_to_fund, .monotonic),
        .lt => _ = capitalization.fetchAdd(lamports_to_fund - lamports_to_burn, .monotonic),
        .eq => {},
    }

    try slot_store.put(builtin_program_id, new_target_account);
    try slot_store.put(target.program_data_address, new_target_pda);
    try slot_store.put(migration_config.source_buffer_address, AccountSharedData.EMPTY);

    // Agave asserts that 'old/new_data_size' is less than i64 max.
    // [agave] https://github.com/anza-xyz/agave/blob/8fdea4cea8ad35a2b00211050ac29b46fccc1188/runtime/src/bank.rs#L6141
    const old_size = std.math.cast(i64, old_data_size).?;
    const new_size = std.math.cast(i64, new_data_size).?;
    const delta_size = new_size -| old_size;
    _ = delta_size;

    // Update accounts_data_size_delta_off_chain
    // TODO: We do not track accounts_data_size_delta_off_chain anywhere. If it is required we should
    // add it to SlotState and updated everywhere.
    // Issue: https://github.com/orgs/Syndica/projects/2?pane=issue&itemId=149662657&issue=Syndica%7Csig%7C1176
    // if (delta_size > 0) { accounts_data_size_delta_off_chain += delta_size }
}

fn featureActivationSlotFromAccount(account: Account) !?u64 {
    if (!account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return null;
    var feature_bytes = [_]u8{0} ** 9;
    account.data.readAll(&feature_bytes);
    return bincode.readFromSlice(failing_allocator, ?u64, &feature_bytes, .{});
}

fn putAndUpdateCapitalization(
    allocator: Allocator,
    store: SlotAccountStore,
    address: Pubkey,
    account: AccountSharedData,
    capitalization: *Atomic(u64),
) !void {
    const maybe_old_account = try store.reader().get(allocator, address);
    const old_account_data_len = if (maybe_old_account) |old_account| blk: {
        defer old_account.deinit(allocator);

        if (account.lamports > old_account.lamports)
            _ = capitalization.fetchAdd(account.lamports - old_account.lamports, .monotonic)
        else
            _ = capitalization.fetchSub(old_account.lamports - account.lamports, .monotonic);

        break :blk old_account.data.len();
    } else blk: {
        _ = capitalization.fetchAdd(account.lamports, .monotonic);
        break :blk 0;
    };

    try store.put(address, account);

    // NOTE: update account size delta in slot state?
    _ = old_account_data_len;
}

fn burnAndPurgeAccount(
    store: SlotAccountStore,
    address: Pubkey,
    account: *const Account,
    capitalization: *Atomic(u64),
) !void {
    try store.put(address, .{
        .lamports = 0,
        .data = &.{},
        .executable = false,
        .owner = .ZEROES,
        .rent_epoch = 0,
    });
    _ = capitalization.fetchSub(account.lamports, .monotonic);
    // NOTE: update account size delta in slot state?
}

fn putPrecompile(
    allocator: Allocator,
    store: SlotAccountStore,
    precompile: program.precompiles.Precompile,
    capitalization: *Atomic(u64),
) !void {
    const maybe_account = try store.reader().get(allocator, precompile.program_id);
    defer if (maybe_account) |account| account.deinit(allocator);

    if (maybe_account) |account| if (!account.executable) {
        try burnAndPurgeAccount(
            store,
            precompile.program_id,
            &account,
            capitalization,
        );
    } else return;

    // NOTE: Do we need this?
    // assert!(!self.freeze_started());

    const lamports, const rent_epoch = inheritLamportsAndRentEpoch(maybe_account);

    try putAndUpdateCapitalization(
        allocator,
        store,
        precompile.program_id,
        .{
            .lamports = lamports,
            .data = &.{},
            .executable = true,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .rent_epoch = rent_epoch,
        },
        capitalization,
    );
}

fn putBuiltinProgramAccount(
    allocator: Allocator,
    store: SlotAccountStore,
    builtin_program: builtin_programs.BuiltinProgram,
    capitalization: *Atomic(u64),
) !void {
    if (try store.reader().get(allocator, builtin_program.program_id)) |account| {
        defer account.deinit(allocator);
        if (sig.runtime.ids.NATIVE_LOADER_ID.equals(&account.owner)) return;
        try burnAndPurgeAccount(
            store,
            builtin_program.program_id,
            &account,
            capitalization,
        );
    }

    const lamports, const rent_epoch = inheritLamportsAndRentEpoch(null);
    const account: AccountSharedData = .{
        .lamports = lamports,
        .data = try allocator.dupe(u8, builtin_program.data),
        .executable = true,
        .owner = sig.runtime.ids.NATIVE_LOADER_ID,
        .rent_epoch = rent_epoch,
    };
    defer allocator.free(account.data);

    try putAndUpdateCapitalization(
        allocator,
        store,
        builtin_program.program_id,
        account,
        capitalization,
    );
}

fn inheritLamportsAndRentEpoch(
    maybe_account: ?Account,
) struct { u64, u64 } {
    return if (maybe_account) |account|
        .{ account.lamports, account.rent_epoch }
    else
        .{ 1, 0 };
}

const TestEnvironment = struct {
    genesis_config: sig.core.GenesisConfig,
    db_context: sig.accounts_db.Two.TestContext,
    ancestors: Ancestors,
    slot_constants: SlotConstants,
    slot_state: SlotState,

    pub fn init(allocator: Allocator) !TestEnvironment {
        var genesis_config = sig.core.GenesisConfig.default(allocator);
        errdefer genesis_config.deinit(allocator);

        var db_context = try sig.accounts_db.Two.initTest(allocator);
        errdefer db_context.deinit();

        var ancestors = Ancestors.EMPTY;
        errdefer ancestors.deinit(allocator);

        var slot_constants = try SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);

        var slot_state = SlotState.GENESIS;
        errdefer slot_state.deinit(allocator);

        return TestEnvironment{
            .genesis_config = genesis_config,
            .db_context = db_context,
            .ancestors = ancestors,
            .slot_constants = slot_constants,
            .slot_state = slot_state,
        };
    }

    pub fn deinit(self: *TestEnvironment, allocator: Allocator) void {
        self.genesis_config.deinit(allocator);
        self.db_context.deinit();
        self.ancestors.deinit(allocator);
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
        return .{ .accounts_db_two = .{
            &self.db_context.db,
            slot,
            &self.ancestors,
        } };
    }

    pub fn accountStore(
        self: *TestEnvironment,
    ) AccountStore {
        return .{ .accounts_db_two = &self.db_context.db };
    }
};

test updateEpochStakes {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var epoch_tracker = sig.core.EpochTracker.init(.default, 0, .INIT);
    defer epoch_tracker.deinit(allocator);

    var stakes_cache = StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);
    stakes_cache.stakes.private.v = try sig.core.stakes.randomStakes(allocator, random, .{});

    const ancestors = try Ancestors.initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    { // Non-Empty stakes
        try updateEpochStakes(
            allocator,
            0,
            &ancestors,
            &.ALL_DISABLED,
            &stakes_cache,
            &epoch_tracker,
        );
        const epoch_info = try epoch_tracker.unrooted_epochs.get(&ancestors);
        try std.testing.expectEqual(
            stakes_cache.stakes.private.v.epoch,
            epoch_info.stakes.stakes.epoch,
        );
    }
}

test getEpochStakes {
    const allocator = std.testing.allocator;
    const VoteAccount = sig.core.stakes.VoteAccount;
    const createTestVoteAccount = sig.runtime.program.vote.state.createTestVoteAccount;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const leader_schedule_epoch: Epoch = 1;
    var stakes_cache = StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    { // Empty stakes
        const epoch_stakes = try getEpochStakes(
            allocator,
            leader_schedule_epoch,
            &stakes_cache,
        );
        defer epoch_stakes.deinit(allocator);

        try std.testing.expectEqual(0, epoch_stakes.total_stake);
    }

    // Insert some stakes
    var expected_total_stake: u64 = 0;
    {
        const stakes, var stakes_lg = stakes_cache.stakes.writeWithLock();
        defer stakes_lg.unlock();

        for (0..5) |_| {
            const raw_vote_account = try createTestVoteAccount(
                allocator,
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
                10,
                1,
                leader_schedule_epoch,
            );
            defer raw_vote_account.deinit(allocator);

            const stake = random.intRangeAtMost(u64, 1, 1_000_000_000_000);
            const vote_account = try VoteAccount.fromAccountSharedData(
                allocator,
                raw_vote_account,
                null,
            );

            expected_total_stake += stake;
            try stakes.vote_accounts.vote_accounts.put(
                allocator,
                Pubkey.initRandom(random),
                .{
                    .stake = stake,
                    .account = vote_account,
                },
            );
        }
    }

    { // Non-Empty stakes
        const epoch_stakes = try getEpochStakes(
            allocator,
            leader_schedule_epoch,
            &stakes_cache,
        );
        defer epoch_stakes.deinit(allocator);

        try std.testing.expectEqual(expected_total_stake, epoch_stakes.total_stake);
    }
}

test "applyFeatureActivations: basic activations" {
    const allocator = std.testing.allocator;

    { // Test PICO inflation activation - new activation
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        const initial_rent_collector = env.slot_constants.rent_collector;
        const initial_fee_rate_governor = env.slot_constants.fee_rate_governor;

        try applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
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
            env.slot_constants.rent_collector.rent.burn_percent,
        );

        try env.insertFeatureAccount(allocator, slot, 1, .pico_inflation, null);

        // Don't allow new activations
        try applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
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
            env.slot_constants.rent_collector.rent.burn_percent,
        );

        // Allow new activations
        try applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
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
            env.slot_constants.rent_collector.rent.burn_percent,
        );
    }

    { // Test PICO inflation activation - already activated
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        const initial_inflation = env.slot_constants.inflation;
        const initial_rent_collector = env.slot_constants.rent_collector;
        const initial_fee_rate_governor = env.slot_constants.fee_rate_governor;

        try env.insertFeatureAccount(allocator, slot, 1, .pico_inflation, 1);

        // Allow new activations
        try applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
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
            env.slot_constants.rent_collector.rent.burn_percent,
        );
    }

    { // Full inflation activation - new activation
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        // Test full inflation activation - feature slot 1
        try env.insertFeatureAccount(allocator, slot, 1, .full_inflation_mainnet_enable, null);
        try env.insertFeatureAccount(allocator, slot, 1, .full_inflation_mainnet_vote, null);

        // Allow new activations
        try applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
            true,
        );
        try std.testing.expectEqual(
            0,
            env.slot_constants.feature_set.get(.full_inflation_mainnet_enable),
        );
        try std.testing.expectEqual(
            0,
            env.slot_constants.feature_set.get(.full_inflation_mainnet_vote),
        );
        try std.testing.expectEqual(
            sig.core.genesis_config.Inflation.FULL,
            env.slot_constants.inflation,
        );
        try std.testing.expectEqual(50, env.slot_constants.fee_rate_governor.burn_percent);
        try std.testing.expectEqual(
            50,
            env.slot_constants.rent_collector.rent.burn_percent,
        );
    }

    { // Error on raize block limits
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        // Test full inflation activation - feature slot 1
        try env.insertFeatureAccount(allocator, slot, 1, .raise_block_limits_to_100m, null);

        // Allow new activations
        const err = applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
            true,
        );
        try std.testing.expectError(
            error.RaiseBlockLimitsTo100MActivationNotImplemented,
            err,
        );
    }

    { // Error on raise account CU limit
        const slot: Slot = 0;

        var env = try TestEnvironment.init(allocator);
        defer env.deinit(allocator);
        try env.ancestors.addSlot(allocator, slot);

        // Test full inflation activation - feature slot 1
        try env.insertFeatureAccount(allocator, slot, 1, .raise_account_cu_limit, null);

        // Allow new activations
        const err = applyFeatureActivations(
            allocator,
            slot,
            &env.slot_constants,
            &env.slot_state,
            env.slotAccountStore(slot),
            true,
        );
        try std.testing.expectError(
            error.RaiseAccountCuLimitActivationNotImplemented,
            err,
        );
    }
}

test "applyFeatureActivations: Builtin Transitions" {
    const allocator = std.testing.allocator;

    const slot: Slot = 0;

    var env = try TestEnvironment.init(allocator);
    defer env.deinit(allocator);
    try env.ancestors.addSlot(allocator, slot);

    // Set address lookup table migration feature
    try env.insertFeatureAccount(
        allocator,
        slot,
        1,
        .migrate_address_lookup_table_program_to_core_bpf,
        null,
    );

    // Should be noop since the account doesn't exist yet
    try applyFeatureActivations(
        allocator,
        slot,
        &env.slot_constants,
        &env.slot_state,
        env.slotAccountStore(slot),
        true,
    );

    // Get the builtin program info
    const builtin_program = for (builtin_programs.BUILTINS) |bp| {
        if (bp.program_id.equals(&sig.runtime.program.address_lookup_table.ID)) break bp;
    } else unreachable;

    // Attempt migration - should fail since account doesn't exist
    try std.testing.expectError(error.AccountNotFound, migrateBuiltinProgramToCoreBpf(
        allocator,
        slot,
        env.slotAccountStore(slot),
        &env.slot_state.capitalization,
        &env.slot_constants.rent_collector.rent,
        &env.slot_constants.feature_set,
        builtin_program.program_id,
        builtin_program.core_bpf_migration_config.?,
        .builtin,
    ));

    // Store invalid account - Incorrect Owner
    try env.slotAccountStore(0).put(
        builtin_program.program_id,
        AccountSharedData{
            .lamports = 1,
            .data = &.{},
            .executable = false,
            .owner = .ZEROES,
            .rent_epoch = 0,
        },
    );
    try std.testing.expectError(error.IncorrectOwner, migrateBuiltinProgramToCoreBpf(
        allocator,
        slot,
        env.slotAccountStore(slot),
        &env.slot_state.capitalization,
        &env.slot_constants.rent_collector.rent,
        &env.slot_constants.feature_set,
        builtin_program.program_id,
        builtin_program.core_bpf_migration_config.?,
        .builtin,
    ));

    // TODO: Full migration tests
    // Store program data account, store buffer account, perform migration, verify results.
}
