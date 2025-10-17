const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountStore = sig.accounts_db.AccountStore;

const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const ReservedAccounts = sig.core.ReservedAccounts;

const SlotState = sig.core.SlotState;
const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;

const SlotAccountStore = sig.replay.slot_account_store.SlotAccountStore;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// https://github.com/anza-xyz/agave/blob/v3.0.0/runtime/src/bank.rs#L5332
pub fn applyFeatureActivations(
    allocator: Allocator,
    slot_store: SlotAccountStore,
    feature_set: *FeatureSet,
    reserved_accounts: *ReservedAccounts,
    allow_new_activations: bool,
) !void {
    // Iterate through the inactive features and:
    // 1. Try and load the feature account from the accounts db.
    // 2. If the account exists, check if it has been activated already.
    // 3. If it has been activated, add it to the active set.
    // 4. If it has not been activated, and new activations are allowed,
    //    add it to the active set and activate it by setting the slot
    //    and writing it back to the accounts db.
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
    reserved_accounts.update(feature_set, slot_store.slot);

    // Activate pico inflation if it is in the newly activated set
    if (new_feature_activations.active(.pico_inflation, slot_store.slot)) {
        // *self.inflation.write().unwrap() = Inflation::pico();
        // self.fee_rate_governor.burn_percent = solana_fee_calculator::DEFAULT_BURN_PERCENT; // 50% fee burn
        // self.rent_collector.rent.burn_percent = 50; // 50% rent burn
        return error.PicoInflationActivationNotImplemented;
    }

    if (feature_set.fullInflationFeatures(slot_store.slot).enabled(new_feature_activations, slot_store.slot)) {
        // *self.inflation.write().unwrap() = Inflation::full();
        // self.fee_rate_governor.burn_percent = solana_fee_calculator::DEFAULT_BURN_PERCENT; // 50% fee burn
        // self.rent_collector.rent.burn_percent = 50; // 50% rent burn
        return error.FullInflationActivationNotImplemented;
    }

    // Apply built-in program feature transitions
    // Agave provides an option to not apply builtin program transitions, we can add this later if needed.
    // TODO: migrateBuiltinProgramToCoreBpf
    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot_store,
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
                    builtin_program.program_id,
                    core_bpf_config,
                ) catch |err| {
                    // Failed to migrate
                    _ = err;
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
                builtin_program.program_id,
                core_bpf_config,
            ) catch |err| {
                // Failed to migrate
                _ = err;
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

fn migrateBuiltinProgramToCoreBpf(
    program_id: Pubkey,
    migration_config: builtin_programs.CoreBpfMigrationConfig,
) !void {
    // TODO: Implement core BPF migration logic
    _ = program_id;
    _ = migration_config;
}

fn featureActivationSlotFromAccount(account: Account) !?u64 {
    if (!account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return null;
    var feature_bytes = [_]u8{0} ** 9;
    account.data.readAll(&feature_bytes);
    return bincode.readFromSlice(failing_allocator, ?u64, &feature_bytes, .{});
}

test "applyBuiltinProgramFeatureTransitions" {
    const ThreadSafeAccountMap = sig.accounts_db.account_store.ThreadSafeAccountMap;
    const allocator = std.testing.allocator;

    var slot_state = SlotState.genesis;
    defer slot_state.deinit(allocator);

    var account_map = ThreadSafeAccountMap.init(allocator);
    defer account_map.deinit();

    const ancestors = Ancestors.EMPTY;
    defer ancestors.deinit(allocator);

    const slot_store = SlotAccountStore.init(
        0,
        &slot_state,
        AccountStore{ .thread_safe_map = &account_map },
        &ancestors,
    );

    const feature_set = FeatureSet.ALL_DISABLED;
    const feature_activations = FeatureSet.ALL_DISABLED;

    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot_store,
        &feature_set,
        &feature_activations,
        false,
    );
}
