const std = @import("std");
const sig = @import("../sig.zig");

const features = sig.runtime.features;

const Pubkey = sig.core.Pubkey;
const Account = sig.core.Account;
const SlotState = sig.core.SlotState;
const EpochSchedule = sig.core.EpochSchedule;

const AccountsDb = sig.accounts_db.AccountsDB;

const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.runtime.FeatureSet;

// pub fn storeAndUpdateCapitalisation(
//     state: *SlotState,
//     accounts_db: *AccountsDb,
//     new_warmup_and_cooldown_rate_epoch: ?u64,
//     slot: u64,
//     pubkey: Pubkey,
//     new_account: AccountSharedData,
// ) !void {
//     const old_account = try accounts_db.getAccount(&pubkey);
//     try storeAndUpdateCapitalisationWithOldAccount(
//         state,
//         accounts_db,
//         new_warmup_and_cooldown_rate_epoch,
//         slot,
//         pubkey,
//         new_account,
//         &old_account,
//     );
// }

pub fn storeAndUpdateCapitalisationWithOldAccount(
    state: *SlotState,
    accounts_db: *AccountsDb,
    new_warmup_and_cooldown_rate_epoch: ?u64,
    slot: u64,
    pubkey: Pubkey,
    new_account: AccountSharedData,
    old_account: *const AccountSharedData,
) !void {
    // Update the slot capitalization
    if (new_account.lamports > old_account.lamports)
        state.capitalization.fetchAdd(new_account.lamports - old_account.lamports, .monotonic)
    else if (new_account.lamports < old_account.lamports)
        state.capitalization.fetchSub(old_account.lamports - new_account.lamports, .monotonic);

    // Update the off-chain slot account resize delta
    const old_data_len: i64 = if (old_account) |acc| @as(i64, @intCast(acc.data.len)) else 0;
    const new_data_len: i64 = @as(i64, @intCast(new_account.data.len));
    if (new_data_len != old_data_len) state.accounts_data_size_delta_off_chain.fetchAdd(
        old_data_len - new_data_len,
        .monotonic,
    );

    // Write new account to accounts_db
    storeAccount(
        state,
        accounts_db,
        new_warmup_and_cooldown_rate_epoch,
        slot,
        pubkey,
        new_account,
    );
}

pub fn storeAccount(
    state: *SlotState,
    accounts_db: *AccountsDb,
    new_warmup_and_cooldown_rate_epoch: ?u64,
    slot: u64,
    pubkey: Pubkey,
    account: AccountSharedData,
) !void {
    try storeAccounts(
        state,
        accounts_db,
        new_warmup_and_cooldown_rate_epoch,
        slot,
        &.{pubkey},
        &.{account},
    );
}

pub fn storeAccounts(
    state: *SlotState,
    accounts_db: *AccountsDb,
    new_warmup_and_cooldown_rate_epoch: ?u64,
    slot: u64,
    pubkeys: []const Pubkey,
    accounts: []const AccountSharedData,
) !void {
    // Assert !self.freeze_started?

    for (pubkeys, accounts) |pubkey, account| {
        _ = pubkey;
        _ = account;
        _ = state;
        _ = new_warmup_and_cooldown_rate_epoch;
        // state.stakes.checkAndStore(
        //     pubkey,
        //     &account,
        //     new_warmup_and_cooldown_rate_epoch,
        // );
    }

    // TODO: bank.update_bank_hash_stats?

    _ = slot;
    _ = accounts_db;
    // TODO: accounts_db.storeAccountsCached(slot, accounts);
}

pub fn newWarmupAndCooldownRateEpoch(
    feature_set: *const FeatureSet,
    epoch_schedule: *const EpochSchedule,
) u64 {
    return if (feature_set.active.get(features.REDUCE_STAKE_WARMUP_COOLDOWN)) |slot|
        epoch_schedule.getEpoch(slot)
    else
        null;
}
