const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const std = @import("std");

const builtins = @import("builtins.zig");
const verify_transaction = @import("verify_transaction.zig");

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
const FeeRateGovernor = sig.core.FeeRateGovernor;
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
const Clock = sig.runtime.sysvar.Clock;
const ComputeBudget = sig.runtime.ComputeBudget;
const EpochSchedule = sig.runtime.sysvar.EpochSchedule;
const FeatureSet = sig.core.features.FeatureSet;
const LastRestartSlot = sig.runtime.sysvar.LastRestartSlot;
const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const SysvarCache = sig.runtime.SysvarCache;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;

const loadTestAccountsDB = sig.accounts_db.db.loadTestAccountsDbEmpty;
const fillMissingSysvarCacheEntries = sig.replay.update_sysvar.fillMissingSysvarCacheEntries;
const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

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

    for (new_feature_activations.keys()) |feature_id| {
        const db_account = try tryGetAccount(accounts_db, feature_id) orelse continue;
        defer db_account.deinit(allocator);

        const activation_slot = try featureActivationSlotFromAccount(allocator, db_account) orelse continue;

        const account = try accountSharedDataFromAccount(allocator, &db_account);
        defer account.deinit(allocator);

        _ = try bincode.writeToSlice(account.data, activation_slot, .{});

        try accounts_db.putAccount(slot, feature_id, account);
    }

    // Update active set of reserved account keys which are not allowed to be write locked
    // self.reserved_account_keys = {
    //     let mut reserved_keys = ReservedAccountKeys::clone(&self.reserved_account_keys);
    //     reserved_keys.update_active_set(&self.feature_set);
    //     Arc::new(reserved_keys)
    // };

    if (new_feature_activations.contains(features.PICO_INFLATION))
        return error.PicoInflationActivationNotImplemented;

    const is_disjoint = blk: {
        const full_inflation_features = try feature_set.fullInflationFeaturesEnabled(allocator);
        const smaller, const larger = if (new_feature_activations.count() <= full_inflation_features.count())
            .{ new_feature_activations, full_inflation_features }
        else
            .{ full_inflation_features, new_feature_activations };
        for (smaller.keys()) |key| if (larger.contains(key)) break :blk false;
        break :blk true;
    };
    if (!is_disjoint) return error.FullInflationActivationNotImplemented;

    try applyBuiltinProgramFeatureTransitions(
        allocator,
        slot,
        feature_set,
        accounts_db,
        &new_feature_activations,
        allow_new_activations,
    );

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK))
        return error.UpdateHashesPerTickActivationNotImplemented;

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK2))
        return error.UpdateHashesPerTick2ActivationNotImplemented;

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK3))
        return error.UpdateHashesPerTick3ActivationNotImplemented;

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK4))
        return error.UpdateHashesPerTick4ActivationNotImplemented;

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK5))
        return error.UpdateHashesPerTick5ActivationNotImplemented;

    if (new_feature_activations.contains(features.UPDATE_HASHES_PER_TICK6))
        return error.UpdateHashesPerTick6ActivationNotImplemented;

    if (new_feature_activations.contains(features.ACCOUNTS_LT_HASH))
        return error.AccountsLtHashActivationNotImplemented;

    if (new_feature_activations.contains(features.RAISE_BLOCK_LIMITS_TO_50M) and
        !feature_set.active.contains(features.RAISE_BLOCK_LIMITS_TO_60M))
        return error.RaiseBlockLimitsTo50MActivationNotImplemented;

    if (new_feature_activations.contains(features.RAISE_BLOCK_LIMITS_TO_60M))
        return error.RaiseBlockLimitsTo60MActivationNotImplemented;

    if (new_feature_activations.contains(features.REMOVE_ACCOUNTS_DELTA_HASH))
        return error.RemoveAccountsDeltaHashActivationNotImplemented;
}

fn applyBuiltinProgramFeatureTransitions(
    allocator: Allocator,
    slot: Slot,
    feature_set: *const FeatureSet,
    accounts_db: *AccountsDb,
    new_feature_activations: *const std.AutoArrayHashMapUnmanaged(Pubkey, void),
    allow_new_activations: bool,
) !void {
    for (builtins.BUILTINS) |builtin_program| {
        var is_core_bpf = false;
        if (builtin_program.core_bpf_migration_config) |core_bpf_config| {
            if (new_feature_activations.contains(core_bpf_config.enable_feature_id)) {
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
                new_feature_activations.contains(enable_feature_id)
            else
                feature_set.active.contains(enable_feature_id);

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
        if (new_feature_activations.contains(core_bpf_config.enable_feature_id)) {
            try migrateBuiltinProgramToCoreBpf();
        }
    }

    for (program.precompiles.PRECOMPILES) |precompile| {
        const feature_id = precompile.required_feature orelse continue;
        if (!feature_set.active.contains(feature_id)) continue;

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
) !std.AutoArrayHashMapUnmanaged(Pubkey, void) {
    // TODO: requires reimplementation of feature_set.inactive or some other solution
    // var inactive = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    var pending = std.AutoArrayHashMapUnmanaged(Pubkey, void){};
    errdefer pending.deinit(allocator);

    const keys = try allocator.dupe(Pubkey, feature_set.active.keys());
    defer allocator.free(keys);

    for (feature_set.active.keys()) |feature_id| {
        var maybe_activation_slot: ?u64 = null;

        if (try tryGetAccount(accounts_db, feature_id)) |account| {
            if (try featureActivationSlotFromAccount(
                allocator,
                account,
            )) |activation_slot| {
                maybe_activation_slot = activation_slot;
            } else if (allow_new_activations) {
                try pending.put(allocator, feature_id, {});
                maybe_activation_slot = slot;
            }
        }

        if (maybe_activation_slot) |activation_slot| {
            try feature_set.active.put(allocator, feature_id, activation_slot);
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
    return accounts_db.getAccount(&pubkey) catch |err| switch (err) {
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
