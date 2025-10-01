const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountsDb = sig.accounts_db.AccountsDB;
const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const ReservedAccounts = sig.core.ReservedAccounts;

const SlotState = sig.core.SlotState;
const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const SlotAccountStore = struct {
    slot: Slot,
    state: *SlotState,
    writer: AccountStore,
    reader: SlotAccountReader,

    pub fn init(
        slot: Slot,
        state: *SlotState,
        writer: AccountStore,
        ancestors: *const Ancestors,
    ) SlotAccountStore {
        return .{
            .slot = slot,
            .state = state,
            .writer = writer,
            .reader = writer.reader().forSlot(ancestors),
        };
    }

    pub fn get(self: *const SlotAccountStore, key: Pubkey) !?Account {
        return self.reader.get(key);
    }

    pub fn put(
        self: SlotAccountStore,
        key: Pubkey,
        account: AccountSharedData,
    ) !void {
        try self.writer.put(self.slot, key, account);
    }

    pub fn putAndUpdateCapitalization(
        self: SlotAccountStore,
        key: Pubkey,
        new_account: AccountSharedData,
    ) !void {
        const old_account_data_len = if (try self.get(key)) |old_account| blk: {
            const diff = if (new_account.lamports > old_account.lamports)
                new_account.lamports - old_account.lamports
            else
                old_account.lamports - new_account.lamports;
            _ = self.state.capitalization.fetchSub(diff, .monotonic);
            break :blk old_account.data.len();
        } else blk: {
            _ = self.state.capitalization.fetchAdd(new_account.lamports, .monotonic);
            break :blk 0;
        };

        try self.put(key, new_account);

        // NOTE: update account size delta in slot state?
        _ = old_account_data_len;
    }

    pub fn burnAndPurgeAccount(self: SlotAccountStore, key: Pubkey, account: AccountSharedData) !void {
        const account_data_len = account.data.len;

        _ = self.state.capitalization.fetchSub(account.lamports, .monotonic);
        var acc = account;
        acc.lamports = 0;
        @memset(acc.data, 0);
        try self.put(key, acc);

        // NOTE: update account size delta in slot state?
        _ = account_data_len;
    }

    pub fn putPrecompile(
        self: SlotAccountStore,
        allocator: Allocator,
        precompile: program.precompiles.Precompile,
    ) !void {
        const maybe_account = try self.get(precompile.program_id);
        defer if (maybe_account) |account| account.deinit(allocator);

        if (maybe_account) |account| if (!account.executable) {
            try self.burnAndPurgeAccount(
                precompile.program_id,
                try accountSharedDataFromAccount(allocator, &account),
            );
        } else return;

        // assert!(!self.freeze_started()); NOTE: Do we need this?

        const lamports, const rent_epoch = inheritLamportsAndRentEpoch(maybe_account);

        try self.putAndUpdateCapitalization(
            precompile.program_id,
            .{
                .lamports = lamports,
                .data = &.{},
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = rent_epoch,
            },
        );
    }

    pub fn putBuiltinProgramAccount(
        self: SlotAccountStore,
        allocator: Allocator,
        builtin_program: builtin_programs.BuiltinProgram,
    ) !void {
        if (try self.reader.get(builtin_program.program_id)) |account| {
            if (sig.runtime.ids.NATIVE_LOADER_ID.equals(&account.owner)) return;
            const account_shared_data = try accountSharedDataFromAccount(allocator, &account);
            defer allocator.free(account_shared_data.data);
            try self.burnAndPurgeAccount(builtin_program.program_id, account_shared_data);
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

        try self.putAndUpdateCapitalization(builtin_program.program_id, account);
    }

    fn inheritLamportsAndRentEpoch(
        maybe_account: ?Account,
    ) struct { u64, u64 } {
        return if (maybe_account) |account|
            .{ account.lamports, account.rent_epoch }
        else
            .{ 1, 0 };
    }
};

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
        if (try slot_store.get(feature_id)) |feature_account| {
            if (try featureActivationSlotFromAccount(feature_account)) |activation_slot| {
                feature_set.setSlot(feature, activation_slot);
            } else if (allow_new_activations) {
                feature_set.setSlot(feature, slot_store.slot);
                new_feature_activations.setSlot(feature, slot_store.slot);
                const account = try accountSharedDataFromAccount(allocator, &feature_account);
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
    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot_store,
        feature_set,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.active(.update_hashes_per_tick, slot_store.slot))
        return error.UpdateHashesPerTickActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick2, slot_store.slot))
        return error.UpdateHashesPerTick2ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick3, slot_store.slot))
        return error.UpdateHashesPerTick3ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick4, slot_store.slot))
        return error.UpdateHashesPerTick4ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick5, slot_store.slot))
        return error.UpdateHashesPerTick5ActivationNotImplemented;

    if (new_feature_activations.active(.update_hashes_per_tick6, slot_store.slot))
        return error.UpdateHashesPerTick6ActivationNotImplemented;

    if (new_feature_activations.active(.accounts_lt_hash, slot_store.slot))
        return error.AccountsLtHashActivationNotImplemented;

    if (new_feature_activations.active(.raise_block_limits_to_50m, slot_store.slot) and
        !feature_set.active(.raise_block_limits_to_60m, slot_store.slot))
        return error.RaiseBlockLimitsTo50MActivationNotImplemented;

    if (new_feature_activations.active(.raise_block_limits_to_60m, slot_store.slot))
        return error.RaiseBlockLimitsTo60MActivationNotImplemented;

    if (new_feature_activations.active(.remove_accounts_delta_hash, slot_store.slot))
        return error.RemoveAccountsDeltaHashActivationNotImplemented;
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
                const maybe_account = try slot_store.get(builtin_program.program_id);
                defer if (maybe_account) |account| account.deinit(allocator);
                is_core_bpf = if (maybe_account) |account|
                    account.owner.equals(&program.bpf_loader.v3.ID)
                else
                    false;
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
    const feature_bytes = []u8{0} ** 9;
    account.data.readAll(feature_bytes);
    return bincode.readFromSlice(failing_allocator, ?u64, feature_bytes, .{});
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

test "applyBuiltinProgramFeatureTransitions" {
    const ThreadSafeAccountMap = sig.accounts_db.account_store.ThreadSafeAccountMap;
    const allocator = std.testing.allocator;

    var slot_state = try SlotState.genesis(allocator);
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
