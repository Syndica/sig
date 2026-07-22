const sig = @import("sig");
const std = @import("std");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const features = sig.core.features;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;

const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// A minimal implementation of `Bank::apply_activated_features` for fuzzing purposes.
/// Mirrors the fork-only `Bank::new_for_txn_tests` path used by solfuzz-agave
/// (agave PR #11880): it flips feature gates and refreshes feature accounts but
/// does NOT seed builtin or precompile program accounts into accounts-db.
///
/// Upstream agave deliberately split this into two paths:
///   - `compute_and_apply_genesis_features` seeds builtin accounts via
///     `add_builtin_program_accounts` (genesis only).
///   - `apply_activated_features` is program-cache only and is what the
///     snapshot-restore and txn-test paths call.
/// See agave PRs #7830 (epoch-boundary split) and #7914 (genesis-vs-snapshot
/// split) for the design.
///
/// Each fixture must therefore carry any program account it invokes; missing
/// ones surface as `TransactionError::ProgramAccountNotFound` during account
/// loading, matching the contract documented in `txn_execute.zig`.
/// https://github.com/firedancer-io/agave/blob/c333aca/runtime/src/bank.rs#L4665
pub fn applyFeatureActivations(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    account_store: AccountStore,
    allow_new_activations: bool,
) !void {
    const new_feature_activations = try computeActiveFeatureSet(
        allocator,
        slot,
        feature_set,
        account_store.reader(),
        allow_new_activations,
    );

    var iterator = new_feature_activations.iterator(slot, .active);
    while (iterator.next()) |feature| {
        const feature_id: Pubkey = features.pubkey_map.get(feature);
        const db_account =
            try tryGetAccount(allocator, account_store.reader(), feature_id) orelse continue;
        defer db_account.deinit(allocator);

        const account = try accountSharedDataFromAccount(allocator, &db_account);
        defer account.deinit(allocator);

        _ = try bincode.writeToSlice(account.data, slot, .{});

        try account_store.put(slot, feature_id, account);
    }

    // Update active set of reserved account keys which are not allowed to be write locked
    // self.reserved_account_keys = {
    //     let mut reserved_accounts = ReservedAccountKeys::clone(&self.reserved_account_keys);
    //     reserved_accounts.update_active_set(&self.feature_set);
    //     Arc::new(reserved_accounts)
    // };

    if (new_feature_activations.active(.pico_inflation, slot))
        return error.PicoInflationActivationNotImplemented;

    if (feature_set.fullInflationFeaturesEnabled(slot, &new_feature_activations)) {
        return error.FullInflationActivationNotImplemented;
    }
}

fn computeActiveFeatureSet(
    allocator: Allocator,
    slot: u64,
    feature_set: *FeatureSet,
    account_reader: AccountReader,
    allow_new_activations: bool,
) !FeatureSet {
    // TODO: requires reimplementation of feature_set.inactive or some other solution
    // var inactive = sig.utils.collections.PubkeyMap(void){};
    var pending: FeatureSet = .ALL_DISABLED;

    var iterator = feature_set.iterator(slot, .inactive);
    while (iterator.next()) |feature| {
        const feature_id: Pubkey = features.pubkey_map.get(feature);
        var maybe_activation_slot: ?u64 = null;

        if (try tryGetAccount(allocator, account_reader, feature_id)) |account| {
            defer account.deinit(allocator);
            if (try featureActivationSlotFromAccount(allocator, account)) |activation_slot| {
                maybe_activation_slot = activation_slot;
            } else if (allow_new_activations) {
                pending.setSlot(feature, slot);
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
    allocator: std.mem.Allocator,
    account_reader: AccountReader,
    pubkey: Pubkey,
) !?Account {
    return account_reader.getLatest(allocator, pubkey) catch error.AccountsDbInternal;
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
