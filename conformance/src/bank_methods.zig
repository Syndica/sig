const sig = @import("sig");
const std = @import("std");

const builtins = @import("builtins.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;

const AccountsDb = sig.accounts_db.AccountsDB;

const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// A minimal implementation of `Bank::apply_feature_activations` for fuzzing purposes.
/// If a fixture hits an error, we may need to implement the missing feature activation logic.
/// https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/runtime/src/bank.rs#L6453
pub fn applyFeatureActivations(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    accounts_db: *AccountsDb,
    allow_new_activations: bool,
) !void {
    const new_feature_activations = try computeActiveFeatureSet(
        allocator,
        slot,
        feature_set,
        accounts_db,
        allow_new_activations,
    );

    var iterator = new_feature_activations.iterator(slot);
    while (iterator.next()) |feature| {
        const feature_id: Pubkey = features.map.get(feature);
        const db_account = try tryGetAccount(accounts_db, feature_id) orelse continue;
        defer db_account.deinit(allocator);

        const account = try accountSharedDataFromAccount(allocator, &db_account);
        defer account.deinit(allocator);

        _ = try bincode.writeToSlice(account.data, slot, .{});

        try accounts_db.putAccount(slot, feature_id, account);
    }

    // Update active set of reserved account keys which are not allowed to be write locked
    // self.reserved_account_keys = {
    //     let mut reserved_accounts = ReservedAccountKeys::clone(&self.reserved_account_keys);
    //     reserved_accounts.update_active_set(&self.feature_set);
    //     Arc::new(reserved_accounts)
    // };

    if (new_feature_activations.active(.pico_inflation, slot))
        return error.PicoInflationActivationNotImplemented;

    if (feature_set.fullInflationFeatures(slot).enabled(new_feature_activations, slot)) {
        return error.FullInflationActivationNotImplemented;
    }

    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot,
        feature_set,
        accounts_db,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.active(.update_hashes_per_tick, slot))
        return error.UpdateHashesPerTickActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick2, slot))
        return error.UpdateHashesPerTick2ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick3, slot))
        return error.UpdateHashesPerTick3ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick4, slot))
        return error.UpdateHashesPerTick4ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick5, slot))
        return error.UpdateHashesPerTick5ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick6, slot))
        return error.UpdateHashesPerTick6ActivationNotImplemented;

    if (new_feature_activations.active(.accounts_lt_hash, slot))
        return error.AccountsLtHashActivationNotImplemented;

    if (new_feature_activations.active(.raise_block_limits_to_50m, slot) and
        !feature_set.active(.raise_block_limits_to_60m, slot))
        return error.RaiseBlockLimitsTo50MActivationNotImplemented;

    if (new_feature_activations.active(.raise_block_limits_to_60m, slot))
        return error.RaiseBlockLimitsTo60MActivationNotImplemented;

    if (new_feature_activations.active(.remove_accounts_delta_hash, slot))
        return error.RemoveAccountsDeltaHashActivationNotImplemented;
}

fn applyBuiltinProgramFeatureTransitions(
    allocator: Allocator,
    slot: Slot,
    feature_set: *const FeatureSet,
    accounts_db: *AccountsDb,
    new_feature_activations: *const FeatureSet,
    allow_new_activations: bool,
) !void {
    for (builtins.BUILTINS) |builtin_program| {
        var is_core_bpf = false;
        if (builtin_program.core_bpf_migration_config) |core_bpf_config| {
            if (new_feature_activations.active(core_bpf_config.enable_feature_id, slot)) {
                try migrateBuiltinProgramToCoreBpf();
                is_core_bpf = true;
            } else {
                const maybe_account = try tryGetAccount(accounts_db, builtin_program.program_id);
                defer if (maybe_account) |account| account.deinit(allocator);
                is_core_bpf = if (maybe_account) |account|
                    account.owner.equals(&program.bpf_loader.v3.ID)
                else
                    false;
            }
        }

        if (builtin_program.enable_feature_id) |enable_feature_id| {
            const should_enable_on_transition = !is_core_bpf and if (allow_new_activations)
                new_feature_activations.active(enable_feature_id, slot)
            else
                feature_set.active(enable_feature_id, slot);

            if (should_enable_on_transition) {
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
        }
    }

    for (builtins.STATELESS_BUILTINS) |builtin_program| {
        const core_bpf_config = builtin_program.core_bpf_migration_config orelse continue;
        if (new_feature_activations.active(core_bpf_config.enable_feature_id, 0)) {
            try migrateBuiltinProgramToCoreBpf();
        }
    }

    for (program.precompiles.PRECOMPILES) |precompile| {
        const feature_id = precompile.required_feature orelse continue;
        if (!feature_set.active(feature_id, 0)) continue;

        const maybe_account = accounts_db.getAccountLatest(
            &precompile.program_id,
        ) catch |err| switch (err) {
            error.PubkeyNotInIndex => null,
            else => return err,
        };
        defer if (maybe_account) |account| account.deinit(allocator);

        // If account is present and executable, do nothing. Otherwise burn and purge, then create a new account.
        if (maybe_account) |account| if (account.executable) return;

        // TODO: burn_and_purge_account

        try accounts_db.putAccount(
            slot,
            precompile.program_id,
            .{
                .lamports = 1,
                .data = &.{},
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = 0,
            },
        );
    }
}

fn migrateBuiltinProgramToCoreBpf() !void {
    // TODO
    return error.MigrateBuiltinProgramToCoreBpfNotImplemented;
}

fn computeActiveFeatureSet(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    accounts_db: *AccountsDb,
    allow_new_activations: bool,
) !FeatureSet {
    // TODO: requires reimplementation of feature_set.inactive or some other solution
    // var inactive = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    var pending: FeatureSet = .ALL_DISABLED;

    var iterator = feature_set.iterator(slot);
    while (iterator.next()) |feature| {
        const feature_id: Pubkey = features.map.get(feature);
        var maybe_activation_slot: ?u64 = null;

        if (try tryGetAccount(accounts_db, feature_id)) |account| {
            if (try featureActivationSlotFromAccount(allocator, account)) |activation_slot| {
                maybe_activation_slot = activation_slot;
            } else if (allow_new_activations) {
                pending.setSlot(feature, 0);
                maybe_activation_slot = slot;
            }
        }

        if (maybe_activation_slot) |activation_slot| {
            feature_set.setSlot(feature, activation_slot);
        } else {
            // try inactive.put(allocator, feature_id, {});
        }
    }

    return pending;
}

fn featureActivationSlotFromAccount(allocator: Allocator, account: Account) !?u64 {
    if (!account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return null;
    const data_len = account.data.len();
    const data = try allocator.alloc(u8, data_len);
    errdefer allocator.free(data);
    account.data.readAll(data);
    return bincode.readFromSlice(failing_allocator, ?u64, data, .{});
}

fn tryGetAccount(
    accounts_db: *AccountsDb,
    pubkey: Pubkey,
) !?Account {
    return accounts_db.getAccountLatest(&pubkey) catch |err| switch (err) {
        error.PubkeyNotInIndex => null,
        else => error.AccountsDbInternal,
    };
}

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
