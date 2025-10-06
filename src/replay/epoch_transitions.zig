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

const Epoch = sig.core.Epoch;
const StakesCache = sig.core.StakesCache;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const ReservedAccounts = sig.core.ReservedAccounts;
const EpochStakes = sig.core.EpochStakes;
const EpochStakesMap = sig.core.EpochStakesMap;

const EpochTracker = sig.replay.trackers.EpochTracker;
const EpochConstants = sig.core.EpochConstants;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;

const applyFeatureActivations = @import("apply_feature_activations.zig").applyFeatureActivations;

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
                try AccountSharedData.fromAccount(allocator, &account),
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
            const account_shared_data = try AccountSharedData.fromAccount(allocator, &account);
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

/// Process a new epoch. This includes:
/// 1. Apply feature activations.
/// 2. Activate stakes cache for the new epoch.
/// 3. Update epoch stakes
/// 4. Begin partitioned rewards
pub fn process_new_epoch(
    allocator: Allocator,
    slot: Slot,
    slot_state: *SlotState,
    /// These are not constant until we process the new epoch
    slot_constants: *SlotConstants,
    epoch_tracker: *EpochTracker,
    account_store: AccountStore,
) !void {
    const slot_store = SlotAccountStore.init(
        slot,
        slot_state,
        account_store,
        &Ancestors.EMPTY,
    );

    try applyFeatureActivations(
        allocator,
        slot_store,
        &slot_constants.feature_set,
        &slot_constants.reserved_accounts,
        true, // allow_new_activations
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1623-L1631
    const current_epoch = epoch_tracker.schedule.getEpoch(slot);
    try activateEpoch(
        allocator,
        current_epoch,
        &slot_state.stakes_cache,
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
    // beginPartitionedRewards()
}

pub fn updateEpochStakes(
    allocator: Allocator,
    slot: Slot,
    parent_epoch: Epoch,
    stakes_cache: *const StakesCache,
    epoch_tracker: *EpochTracker,
) !void {
    const leader_schedule_epoch = epoch_tracker.schedule.getLeaderScheduleEpoch(slot);
    if (!epoch_tracker.epochs.contains(leader_schedule_epoch)) {
        const parent_epoch_constants = epoch_tracker.getForSlot(parent_epoch) orelse {
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
    stakes_cache: *const StakesCache,
) !EpochStakes {
    _ = leader_schedule_epoch;
    _ = stakes_cache;
    // TODO: Currently does nothing
    return try EpochStakes.init(allocator);
}

pub fn activateEpoch(
    allocator: Allocator,
    epoch: Epoch,
    stakes_cache: *StakesCache,
) !void {
    _ = allocator;
    _ = epoch;
    _ = stakes_cache;
}

pub fn refreshVoteAccounts(
    allocator: Allocator,
    epoch: Epoch,
    stakes_cache: *StakesCache,
) !void {
    _ = allocator;
    _ = epoch;
    _ = stakes_cache;
}
