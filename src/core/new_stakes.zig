const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Random = std.Random;

const vote_program = sig.runtime.program.vote;
const stake_program = sig.runtime.program.stake;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;

const AccountSharedData = sig.runtime.AccountSharedData;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const VoteState = sig.runtime.program.vote.state.VoteState;

const RwMux = sig.sync.RwMux;
const ReferenceCounter = sig.sync.ReferenceCounter;

const createTestVoteAccountWithAuthorized =
    sig.runtime.program.vote.state.createTestVoteAccountWithAuthorized;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const VersionedEpochStakes = union(enum(u32)) {
    current: EpochStakes,
};

pub const EpochStakes = struct {
    /// Full stakes information.
    stakes: Stakes,
    /// The total stake delegated to all vote accounts.
    total_delegated: u64,
    /// Map of node address to the vote accounts which are allowed to vote on its
    /// behalf and the total stake delegated to the node via those vote accounts.
    node_voters: std.AutoArrayHashMapUnmanaged(Pubkey, struct {
        voters: std.ArrayListUnmanaged(Pubkey),
        total_delegated: u64,
    }),
    /// Map of vote accounts to the pubkey authorized to sign vote transactions.
    vote_authorities: std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey),

    pub fn deinit(self: *EpochStakes, allocator: Allocator) void {
        self.stakes.deinit(allocator);
        for (self.node_voters.values()) |*value| value.voters.deinit(allocator);
        self.node_voters.deinit(allocator);
        self.vote_authorities.deinit(allocator);
    }

    /// Initialize EpochStakes from Stakes data and leader schedule epoch.
    /// Computes total delegated stake, node voters and voter authorities.
    /// Takes ownership of `stakes` and will deinitialize it on error
    pub fn init(allocator: Allocator, stakes: Stakes, leader_schedule_epoch: Epoch) !EpochStakes {
        var self = EpochStakes{
            .total_delegated = 0,
            .stakes = stakes,
            .node_voters = .empty,
            .vote_authorities = .empty,
        };
        errdefer self.deinit(allocator);
        try self.node_voters.ensureUnusedCapacity(allocator, stakes.staked_nodes.count());
        try self.vote_authorities.ensureUnusedCapacity(allocator, stakes.voters.count());

        for (stakes.voters.keys(), stakes.voters.values()) |address, *voter| {
            if (voter.delegated == 0) continue;
            self.total_delegated += voter.delegated;

            if (voter.state.voters.getAuthorizedVoter(leader_schedule_epoch)) |authority| {
                try self.vote_authorities.put(allocator, address, authority);

                const voters = try self.node_voters.getOrPut(
                    allocator,
                    voter.state.node_pubkey,
                );

                if (!voters.found_existing) {
                    voters.value_ptr.* = .{
                        .total_delegated = 0,
                        .voters = .empty,
                    };
                }

                voters.value_ptr.total_delegated += voter.delegated;
                try voters.value_ptr.voters.append(allocator, address);
            }
        }

        return self;
    }
};

pub const StakesCache = struct {
    stakes: RwMux(Stakes),

    pub fn checkAndStore(
        self: *StakesCache,
        allocator: Allocator,
        address: Pubkey,
        account: AccountSharedData,
        new_rate_activation_epoch: ?Epoch,
    ) !void {
        if (vote_program.ID.equals(&account.owner)) {
            if (voteStateFromAccount(
                allocator,
                account.data,
            )) |vote_state| {
                errdefer vote_state.deinit(allocator);
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.updateVoter(
                    allocator,
                    address,
                    account.lamports,
                    vote_state,
                    new_rate_activation_epoch,
                );
            } else {
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.removeVoter(allocator, address);
            }
        } else if (stake_program.ID.equals(&account.owner)) {
            if (delegationFromAccount(
                allocator,
                account.data,
            )) |delegation| {
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.updateDelegation(
                    allocator,
                    address,
                    delegation,
                    new_rate_activation_epoch,
                );
            } else {
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.removeDelegation(
                    allocator,
                    address,
                    new_rate_activation_epoch,
                );
            }
        }
    }

    pub fn activateEpoch(
        self: *StakesCache,
        allocator: Allocator,
        next_epoch: Epoch,
        new_rate_activation_epoch: ?Epoch,
    ) !void {
        var stakes, var stakes_guard = self.stakes.writeWithLock();
        defer stakes_guard.unlock();

        // Add a new stakes history entry for the epoch just passed.
        var cluster_stake: StakeHistory.StakeState = .{};
        for (stakes.delegations.values()) |delegation| {
            cluster_stake.add(delegation.getStakeState(
                stakes.epoch,
                stakes.stake_history,
                new_rate_activation_epoch,
            ));
        }
        try stakes.stake_history.insertEntry(stakes.epoch, cluster_stake);

        // Set the new stakes epoch
        stakes.epoch = next_epoch;

        // Compute the stake delegated to each node
        var voter_delegations = std.AutoArrayHashMapUnmanaged(Pubkey, u64).empty;
        defer voter_delegations.deinit(allocator);
        try voter_delegations.ensureUnusedCapacity(allocator, stakes.voters.count());
        for (stakes.delegations.values()) |delegation| {
            const voter_delegation = try voter_delegations.getOrPut(
                allocator,
                delegation.voter,
            );
            if (!voter_delegation.found_existing) voter_delegation.value_ptr.* = 0;
            voter_delegation.value_ptr.* += delegation.getStakeState(
                next_epoch,
                stakes.stake_history,
                new_rate_activation_epoch,
            );
        }

        // Update the stake delegated to each node, and compute the
        stakes.staked_nodes.clearRetainingCapacity();
        for (stakes.voters.keys(), stakes.voters.values()) |address, *voter| {
            voter.delegated = voter_delegations.get(address) orelse 0;
            if (voter.delegated > 0) {
                const entry = try stakes.staked_nodes.getOrPut(allocator, voter.state.node_pubkey);
                if (!entry.found_existing)
                    entry.value_ptr.* = voter.delegated
                else
                    entry.value_ptr.* += voter.delegated;
            }
        }
    }

    fn voteStateFromAccount(allocator: Allocator, account: AccountSharedData) ?VoteState {
        if (account.lamports == 0) return null;
        _ = allocator;
    }

    fn delegationFromAccount(allocator: Allocator, account: AccountSharedData) ?Delegation {
        if (account.lamports == 0) return null;
        _ = allocator;
    }
};

pub const Stakes = struct {
    epoch: Epoch,
    voters: std.AutoArrayHashMapUnmanaged(Pubkey, Voter),
    delegations: std.AutoArrayHashMapUnmanaged(Pubkey, Delegation),
    staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    stake_history: StakeHistory,

    pub fn deinit(self: *Stakes, allocator: Allocator) void {
        for (self.voters.values()) |*voter| voter.deinit(allocator);
        self.voters.deinit(allocator);
        self.delegations.deinit(allocator);
        self.staked_nodes.deinit(allocator);
    }

    pub fn updateVoter(
        self: *Stakes,
        allocator: Allocator,
        address: Pubkey,
        lamports: u64,
        vote_state: VoteState,
        new_rate_activation_epoch: ?Epoch,
    ) !void {
        const entry = try self.voters.getOrPut(allocator, address);

        if (!entry.found_existing) {
            var delegated: u64 = 0;
            for (self.delegations.values()) |*delegation| {
                if (delegation.voter.equals(&address)) continue;
                delegated += delegation.getStakeState(
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                ).effective;
            }
            entry.value_ptr.* = try Voter.init(
                allocator,
                delegated,
                lamports,
                vote_state,
            );
            try self.addNodeStake(allocator, vote_state.node_pubkey, delegated);
        } else {
            if (vote_state.node_pubkey.equals(&entry.value_ptr.state.node_pubkey)) {
                try self.subtractNodeStake(
                    entry.value_ptr.state.node_pubkey,
                    entry.value_ptr.delegated,
                );
                try self.addNodeStake(
                    allocator,
                    vote_state.node_pubkey,
                    entry.value_ptr.delegated,
                );
            }
            entry.value_ptr.deinit(allocator);
            entry.value_ptr.* = try Voter.init(
                allocator,
                entry.value_ptr.delegated,
                lamports,
                vote_state,
            );
        }
    }

    pub fn removeVoter(
        self: *Stakes,
        allocator: Allocator,
        address: Pubkey,
    ) !void {
        if (self.voters.fetchSwapRemove(address)) |entry| {
            defer entry.value.deinit(allocator);
            try self.subtractNodeStake(entry.value.state.node_pubkey, entry.value.delegated);
        }
    }

    pub fn updateDelegation(
        self: *Stakes,
        allocator: Allocator,
        address: Pubkey,
        delegation: Delegation,
        new_rate_activation_epoch: ?Epoch,
    ) !void {
        const delegated = delegation.getStakeState(
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
        ).effective;

        if (try self.delegations.fetchPut(
            allocator,
            address,
            delegation,
        )) |old_delegation| {
            const old_delegated = old_delegation.value.getStakeState(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            ).effective;

            if (!delegation.voter.equals(&old_delegation.value.voter)) {
                try self.subtractVoterStake(old_delegation.value.voter, old_delegated);
                try self.addVoterStake(allocator, delegation.voter, delegated);
            }
        } else {
            try self.addVoterStake(allocator, delegation.voter, delegated);
        }
    }

    pub fn removeDelegation(
        self: *Stakes,
        address: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) !void {
        const delegation = self.delegations.fetchSwapRemove(address) orelse return;
        const delegated = delegation.value.getStakeState(
            self.epoch,
            self.stake_history,
            new_rate_activation_epoch,
        ).effective;
        self.subtractVoterStake(delegation.value.voter, delegated);
    }

    pub fn calculateVoterDelegatedStake(
        self: *const Stakes,
        address: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) u64 {
        var stake: u64 = 0;
        for (self.delegations.values()) |*delegation| {
            if (delegation.voter.equals(&address)) continue;
            stake += delegation.getEffectiveStake(
                self.epoch,
                self.stake_history,
                new_rate_activation_epoch,
            );
        }
        return stake;
    }

    pub fn addVoterStake(self: *Stakes, allocator: Allocator, address: Pubkey, amount: u64) !void {
        if (amount == 0) return;
        const voter = self.voters.getPtr(address) orelse return;
        voter.delegated += amount;
        try self.addNodeStake(allocator, voter.state.node_pubkey, amount);
    }

    pub fn addNodeStake(self: *Stakes, allocator: Allocator, address: Pubkey, amount: u64) !void {
        if (amount == 0) return;
        const current = try self.staked_nodes.getOrPut(allocator, address);
        if (!current.found_existing)
            current.value_ptr.* = amount
        else
            current.value_ptr.* += amount;
    }

    pub fn subtractVoterStake(self: *Stakes, address: Pubkey, amount: u64) !void {
        if (amount == 0) return;
        const voter = self.voters.getPtr(address) orelse return;
        voter.delegated = try std.math.sub(u64, voter.delegated, amount);
        try self.subtractNodeStake(voter.state.node_pubkey, amount);
    }

    pub fn subtractNodeStake(self: *Stakes, address: Pubkey, amount: u64) !void {
        if (amount == 0) return;
        const current = self.staked_nodes.getPtr(address) orelse
            return error.StakedNodeNotFound;
        if (current.* == amount)
            _ = self.staked_nodes.swapRemove(address)
        else
            current.* = try std.math.sub(u64, current.*, amount);
    }
};

pub const Voter = struct {
    /// The stake currently delegated to this node.
    delegated: u64,

    /// The current lamports of the node.
    lamports: u64,

    /// The current vote state of the node
    state: VoteState,

    /// Reference count for VoteState
    rc: *ReferenceCounter,

    pub fn deinit(self: *Voter, allocator: Allocator) void {
        if (self.rc.release()) {
            self.state.deinit(allocator);
            allocator.destroy(self.rc);
        }
    }

    pub fn init(
        allocator: Allocator,
        delegated: u64,
        lamports: u64,
        state: VoteState,
    ) !Voter {
        const rc = try allocator.create(ReferenceCounter);
        errdefer allocator.destroy(rc);
        rc.* = .init;
        return .{ .delegated = delegated, .lamports = lamports, .state = state, .rc = rc };
    }

    pub fn acquireWithNewDelegation(self: *const Voter, delegated: u64) void {
        std.debug.assert(self.rc.acquire());
        var new = self.*;
        new.delegated = delegated;
        return new;
    }
};

pub const Delegation = struct {
    /// The address of the node to which the stake is delegated.
    voter: Pubkey,

    /// The amount of stake delegated to the node.
    delegated: u64,

    /// The epoch at which the stake is activated
    activation_epoch: Epoch,

    /// The epoch at which the stake is deactivated
    deactivation_epoch: Epoch,

    /// The current credits observed in the stake account
    credits_observed: u64,

    pub fn getStakeState(
        self: *const Delegation,
        epoch: Epoch,
        stake_history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) StakeHistory.StakeState {
        // Compute the stake which has been activated up until the specified epoch.
        var effective, const activating = if (self.activation_epoch == std.math.maxInt(u64))
            // Bootstrapped, all stake effective
            .{ self.delegated, 0 }
        else if (self.activation_epoch == self.deactivation_epoch)
            // Activated but instantly deactivated
            .{ 0, 0 }
        else if (epoch == self.activation_epoch)
            // Activation just started, all stake is activating
            .{ 0, self.delegated }
        else if (epoch < self.activation_epoch)
            // Activation has not started
            .{ 0, 0 }
        else if (!stake_history.containsEpoch(self.activation_epoch))
            // Activation epoch dropped out of history, assume fully activated
            .{ self.delegated, 0 }
        else blk: {
            var effective: u64 = 0;

            for (self.activation_epoch + 1..epoch + 1) |e| {
                const prev_cluster_stake = (stake_history.getEntry(e - 1) orelse break).stake;

                if (prev_cluster_stake.activating == 0) break;

                const remaining_activated_stake = self.delegated - effective;
                const weight = @as(f64, @floatFromInt(remaining_activated_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.activating));

                const warmup_cooldown_rate =
                    warmupCooldownRate(e, new_rate_activation_epoch);
                const newly_effective_cluster_stake =
                    @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;

                const weighted_effective_state: u64 =
                    @intFromFloat(weight * newly_effective_cluster_stake);
                const newly_effective_stake = @max(weighted_effective_state, 1);

                effective += newly_effective_stake;

                if (effective >= self.delegated) {
                    effective = self.delegated;
                    break;
                }

                if (e >= self.deactivation_epoch) {
                    break;
                }
            }

            break :blk .{ effective, self.delegated - effective };
        };

        return if (epoch < self.deactivation_epoch)
            // Deactivation has not started yet, effective and activatig are correct
            .{ .effective = effective, .activating = activating }
        else if (epoch == self.deactivation_epoch)
            // Deactivation just started, all effective stake is now deactivating
            .{ .effective = effective, .deactivating = effective }
        else if (!stake_history.containsEpoch(self.deactivation_epoch))
            // Deactivation epoch dropped out of history, assume fully deactivated
            .{}
        else blk: {
            // Deactivate stake up to current epoch
            for (self.deactivation_epoch + 1..epoch + 1) |e| {
                const prev_cluster_stake = (stake_history.getEntry(e - 1) orelse break).stake;

                if (prev_cluster_stake.deactivating == 0) break;

                const weight = @as(f64, @floatFromInt(effective)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.deactivating));

                const warmup_cooldown_rate =
                    warmupCooldownRate(e, new_rate_activation_epoch);
                const newly_not_effective_cluster_stake =
                    @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;

                const newly_not_effected_stake: u64 =
                    @max(1, @as(u64, @intFromFloat(weight * newly_not_effective_cluster_stake)));

                effective -|= newly_not_effected_stake;

                if (effective == 0) {
                    break;
                }
            }
            break :blk .{ .effective = effective, .deactivating = effective };
        };
    }

    fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
        return if (current_epoch < new_rate_activation_epoch orelse std.math.maxInt(u64))
            0.25
        else
            0.09;
    }
};

/// Initialize random `valid` EpochStakes for testing
pub fn randomStakes(
    allocator: Allocator,
    random: Random,
    options: struct {
        epoch: Epoch = 5,
        max_nodes: usize = 5,
        num_voters: usize = 10,
        num_delegations: usize = 50,
        commission_min: u8 = 0,
        commission_max: u8 = 100,
        new_rate_activation_epoch: ?Epoch = null,
        delegation_min: u64 = 100_000_000, // 0.1 SOL
        delegation_max: u64 = 10_000_000_000, // 10 SOL
        activation_epoch_min: Epoch = 0,
        activation_epoch_max: Epoch = 10,
        effective_epochs_min: Epoch = 0,
        effective_epochs_max: Epoch = std.math.maxInt(Epoch),
    },
) !Stakes {
    if (!builtin.is_test) @compileError("only for tests");

    var self = Stakes{
        .epoch = options.epoch,
        .voters = .empty,
        .delegations = .empty,
        .staked_nodes = .empty,
        .stake_history = .INIT,
    };

    for (0..options.epoch) |e| {
        try self.stake_history.insertEntry(e, .{
            .effective = 1_000_000_000 * 1_000_000, // 1 million SOL
            .activating = 250_000_000 * 1_000_000, // 250k SOL
            .deactivating = 250_000_000 * 1_000_000, // 250k SOL
        });
    }

    const nodes = try allocator.alloc(Pubkey, options.max_nodes);
    defer allocator.free(nodes);
    for (nodes) |*node| node.* = Pubkey.initRandom(random);

    const voters = try allocator.alloc(Pubkey, options.num_voters);
    defer allocator.free(voters);
    for (voters) |*voter| voter.* = Pubkey.initRandom(random);

    for (0..options.num_voters) |i| {
        var vote_state = try VoteState.init(
            allocator,
            nodes[random.uintLessThan(usize, options.max_nodes)],
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            random.intRangeAtMost(
                u8,
                options.commission_min,
                options.commission_max,
            ),
            options.epoch + 1,
        );
        errdefer vote_state.deinit(allocator);
        try self.updateVoter(
            allocator,
            voters[i],
            1_000_000_000,
            vote_state,
            options.new_rate_activation_epoch,
        );
    }

    for (0..options.num_delegations) |_| {
        const activation_epoch = random.intRangeAtMost(
            Epoch,
            options.activation_epoch_min,
            options.activation_epoch_max,
        );
        const deactivation_epoch = activation_epoch +|
            random.intRangeAtMost(
                Epoch,
                options.effective_epochs_min,
                options.effective_epochs_max,
            );
        const staker_delegation = Delegation{
            .voter = voters[random.uintLessThan(usize, options.num_voters)],
            .delegated = random.intRangeAtMost(
                u64,
                options.delegation_min,
                options.delegation_max,
            ),
            .activation_epoch = activation_epoch,
            .deactivation_epoch = deactivation_epoch,
            .credits_observed = 0,
        };
        try self.updateDelegation(
            allocator,
            Pubkey.initRandom(random),
            staker_delegation,
            options.new_rate_activation_epoch,
        );
    }

    return self;
}

test "randomStakes creates valid stakes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var stakes = try randomStakes(allocator, random, .{
        .epoch = 10,
        .max_nodes = 10,
        .num_voters = 20,
        .num_delegations = 100,
        .activation_epoch_max = 10,
    });
    defer stakes.deinit(allocator);

    try std.testing.expectEqual(10, stakes.epoch);
    try std.testing.expect(10 > stakes.staked_nodes.count());
    try std.testing.expectEqual(20, stakes.voters.count());
    try std.testing.expectEqual(100, stakes.delegations.count());
}

// test "calculateStakePoints" {
//     const allocator = std.testing.allocator;
//     var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
//     const random = prng.random();

//     var stakes = try randomStakes(allocator, random, .{
//         .epoch = 10,
//         .max_nodes = 2,
//         .num_voters = 5,
//         .num_delegations = 10,
//         .activation_epoch_max = 9,
//         .effective_epochs_min = 5,
//     });
//     defer stakes.deinit(allocator);

//     for (stakes.delegations.values()) |*delegation| {
//         const delegate = stakes.voters.getPtr(delegation.voter) orelse continue;
//         const result = calculateStakePointsAndCredits(
//             delegation,
//             &delegate.state,
//             &stakes.stake_history,
//             null,
//         );
//         std.debug.print("Delegation: {any}\n", .{delegation});
//         std.debug.print("Delegate: {any}\n", .{delegate});
//         std.debug.print("Points: {}, New Credits Observed: {}, Force Update: {}\n", .{
//             result.points_earned,
//             result.new_credits_observed,
//             result.force_credits_update_with_skipped_rewards,
//         });

//         // Delegate: {}\ points={}, new_credits_observed={}, force_update={s}\n", .{
//         //     delegation.voter,
//         //     result.points,
//         //     result.new_credits_observed,
//         //     result.force_credits_update_with_skipped_rewards,
//         // });
//     }
// }

// const builtin = @import("builtin");
// const std = @import("std");
// const sig = @import("../../sig.zig");

// const Allocator = std.mem.Allocator;
// const Random = std.Random;

// const vote_program = sig.runtime.program.vote;
// const stake_program = sig.runtime.program.stake;

// const Pubkey = sig.core.Pubkey;
// const Epoch = sig.core.Epoch;
// const Slot = sig.core.Slot;

// const AccountSharedData = sig.runtime.AccountSharedData;
// const StakeHistory = sig.runtime.sysvar.StakeHistory;
// const VoteState = sig.runtime.program.vote.state.VoteState;

// const RwMux = sig.sync.RwMux;
// const ReferenceCounter = sig.sync.ReferenceCounter;

// const FeatureSet = sig.core.FeatureSet;
// const EpochSchedule = sig.core.EpochSchedule;
// const Inflation = sig.core.Inflation;

// const Delegation = sig.core.new_stakes.Delegation;
// const Voter = sig.core.new_stakes.Voter;
// const StakesCache = sig.core.new_stakes.StakesCache;

// pub const RewardType = union(enum) {
//     fee,
//     rent,
//     staking,
//     voting,
// };

// pub const VoterReward = struct {
//     address: Pubkey,
//     reward_type: RewardType,
//     lamports: u64,
//     post_balance: u64,
//     commission: u8,
// };

// pub const StakerReward = struct {
//     address: Pubkey,
//     delegation: Delegation,
//     reward: u64,
//     commission: u8,
// };

// pub fn getInflationStartSlot(slot: Slot, feature_set: *const FeatureSet) Slot {
//     const full_inflation_features = feature_set.fullInflationFeatures(slot);

//     const mainnet_slot = full_inflation_features.mainnetSlot(feature_set);
//     const devnet_and_testnet_slot = full_inflation_features.devnetAndTestnetSlot(feature_set);

//     if (mainnet_slot != null or devnet_and_testnet_slot != null) {
//         return @min(
//             mainnet_slot orelse std.math.maxInt(Slot),
//             devnet_and_testnet_slot orelse std.math.maxInt(Slot),
//         );
//     }

//     return if (feature_set.active(.pico_inflation, slot))
//         feature_set.get(.pico_inflation).?
//     else
//         0;
// }

// pub fn getInflationNumSlots(
//     slot: Slot,
//     epoch: Epoch,
//     feature_set: *const FeatureSet,
//     epoch_schedule: *const EpochSchedule,
// ) u64 {
//     const inflation_activation_slot = getInflationStartSlot(slot, feature_set);
//     const inflation_start_slot = epoch_schedule.getFirstSlotInEpoch(
//         epoch_schedule.getEpoch(inflation_activation_slot) -| 1,
//     );
//     return epoch_schedule.getFirstSlotInEpoch(epoch) - inflation_start_slot;
// }

// pub fn getSlotInYearsForInflation(
//     slot: Slot,
//     epoch: Epoch,
//     slots_per_year: f64,
//     feature_set: *const FeatureSet,
//     epoch_schedule: *const EpochSchedule,
// ) f64 {
//     std.debug.assert(slots_per_year > 0.0);
//     const num_slots = getInflationNumSlots(
//         slot,
//         epoch,
//         feature_set,
//         epoch_schedule,
//     );
//     return @as(f64, @floatFromInt(num_slots)) / slots_per_year;
// }

// pub fn getEpochDurationInYears(
//     epoch: Epoch,
//     slots_per_year: f64,
//     epoch_schedule: *const EpochSchedule,
// ) f64 {
//     std.debug.assert(slots_per_year > 0.0);
//     return @as(f64, @floatFromInt(epoch_schedule.getSlotsInEpoch(epoch))) / slots_per_year;
// }

// const SlotConstants = sig.core.SlotConstants;
// const SlotState = sig.core.SlotState;
// const SlotAccountStore = sig.accounts_db.SlotAccountStore;

// pub fn beginPartitionedRewards(
//     allocator: Allocator,
//     slot: Slot,
//     /// These are not constant until we process the new epoch
//     slot_constants: *SlotConstants,
//     slot_state: *SlotState,
//     slot_store: SlotAccountStore,
// ) !void {}

// fn calculateRewardsAndDistributeVoteRewards(
//     allocator: Allocator,
//     slot: Slot,
//     epoch: Epoch,
//     slots_per_year: f64,
//     previous_epoch: Epoch,
//     capitalization: *AtomicU64,
//     epoch_schedule: *const EpochSchedule,
//     feature_set: *const FeatureSet,
//     inflation: *const Inflation,
//     stakes_cache: *StakesCache,
//     epoch_vote_accounts: *const VoteAccounts,
//     new_warmup_and_cooldown_rate_epoch: ?Epoch,
//     slot_store: SlotAccountStore,
// ) !struct {
//     rewards_distributed: u64,
//     rewards: u64,
//     points_earned: u128,
//     PartitionedStakeRewards,
// } {
//     const slot_in_years = getSlotInYearsForInflation(
//         slot,
//         epoch,
//         slots_per_year,
//         feature_set,
//         epoch_schedule,
//     );

//     const validator_rate = inflation.validatorRate(slot_in_years);
//     const foundation_rate = inflation.foundationRate(slot_in_years);

//     const previous_epoch_duration_in_years = getEpochDurationInYears(
//         previous_epoch,
//         slots_per_year,
//         epoch_schedule,
//     );

//     const validator_rewards: u64 = @intFromFloat(validator_rate *
//         @as(f64, @floatFromInt(previous_epoch_capitalization)) *
//         previous_epoch_duration_in_years);

//     const minumum_delegation = @max(1_000_000_000, sig.runtime.program.stake.getMinimumDelegation(
//         slot,
//         feature_set,
//     ));

//     {
//         const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
//         defer stakes_lg.unlock();

//         const point_value = try calculatePointsEarned(
//             stakes.delegations.values(),
//             next_epoch_delegates,
//             &stakes.stake_history,
//             minimum_delegation,
//             new_warmup_and_cooldown_rate_epoch,
//         ) orelse return null;
//     }

//     // // TODO: Lookup in rewards calculation cache
//     // var rewards_for_partitioning = try calculateRewardsForPartitioning(
//     //     allocator,
//     //     slot,
//     //     epoch,
//     //     slots_per_year,
//     //     previous_epoch,
//     //     capitalization.load(.monotonic),
//     //     epoch_schedule,
//     //     feature_set,
//     //     inflation,
//     //     stakes_cache,
//     //     epoch_vote_accounts,
//     //     new_warmup_and_cooldown_rate_epoch,
//     // );
//     // defer rewards_for_partitioning.deinit(allocator);

//     try storeVoteAccountsPartitioned(
//         allocator,
//         slot_store,
//         stakes_cache,
//         rewards_for_partitioning.vote_rewards.vote_rewards.entries,
//         new_warmup_and_cooldown_rate_epoch,
//     );

//     // TODO: Update vote rewards
//     // Looks like this is for metadata, and not protocol defining

//     std.debug.assert(rewards_for_partitioning.point_value.rewards >=
//         rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports +
//             rewards_for_partitioning.stake_rewards.total_stake_rewards_lamports);

//     _ = capitalization.fetchAdd(
//         rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports,
//         .monotonic,
//     );

//     rewards_for_partitioning.stake_rewards.stake_rewards.acquire();
//     return .{
//         rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports,
//         rewards_for_partitioning.point_value,
//         rewards_for_partitioning.stake_rewards.stake_rewards,
//     };
// }

// fn calculateRewardsForPartitioning(
//     allocator: Allocator,
//     slot: Slot,
//     epoch: Epoch,
//     slots_per_year: f64,
//     previous_epoch: Epoch,
//     previous_epoch_capitalization: u64,
//     epoch_schedule: *const EpochSchedule,
//     feature_set: *const FeatureSet,
//     inflation: *const Inflation,
//     stakes_cache: *StakesCache,
//     epoch_vote_accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, Voter),
//     new_warmup_and_cooldown_rate_epoch: ?Epoch,
// ) !RewardsForPartitioning {
//     const slot_in_years = getSlotInYearsForInflation(
//         slot,
//         epoch,
//         slots_per_year,
//         feature_set,
//         epoch_schedule,
//     );

//     const validator_rate = inflation.validatorRate(slot_in_years);
//     const foundation_rate = inflation.foundationRate(slot_in_years);

//     const previous_epoch_duration_in_years = getEpochDurationInYears(
//         previous_epoch,
//         slots_per_year,
//         epoch_schedule,
//     );

//     const validator_rewards: u64 = @intFromFloat(validator_rate *
//         @as(f64, @floatFromInt(previous_epoch_capitalization)) *
//         previous_epoch_duration_in_years);

//     const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
//     defer stakes_lg.unlock();

//     // const minumum_delegation = @max(1_000_000_000, sig.runtime.program.stake.getMinimumDelegation(
//     //     slot,
//     //     feature_set,
//     // ));

//     const point_value = try calculatePointsEarned(
//         stakes.delegations.values(),
//         next_epoch_delegates,
//         &stakes.stake_history,
//         minimum_delegation,
//         new_warmup_and_cooldown_rate_epoch,
//     ) orelse return null;

//     return try calculateStakeVoteRewards(
//         allocator,
//         stake_history,
//         filtered_stake_delegations,
//         epoch_vote_accounts,
//         rewarded_epoch,
//         point_value,
//         new_warmup_and_cooldown_rate_epoch,
//     );

//     // return .{
//     //     .vote_rewards = validator_rewards.vote_rewards,
//     //     .stake_rewards = validator_rewards.stake_rewards,
//     //     .point_value = validator_rewards.point_value,
//     //     .validator_rate = prev_inflation_rewards.validator_rate,
//     //     .foundation_rate = prev_inflation_rewards.foundation_rate,
//     //     .previous_epoch_duration_in_years = prev_inflation_rewards.previous_epoch_duration_in_years,
//     //     .capitalization = previous_epoch_capitalization,
//     // };
// }

// fn calculateValidatorRewards(
//     allocator: Allocator,
//     rewards: u64,
//     rewarded_epoch: Epoch,
//     stakes_cache: *StakesCache,
//     delegates: *const std.AutoArrayHashMapUnmanaged(Pubkey, Voter),
//     minimum_delegation: u64,
//     new_warmup_and_cooldown_rate_epoch: ?Epoch,
// ) !?struct {
//     voter_rewards: ReferenceCounter.Wrapped(VoterReward),
//     staker_rewards: ReferenceCounter.Wrapped(StakerReward),
//     points_earned: u128,
// } {
//     const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
//     defer stakes_lg.unlock();

//     // const minumum_delegation = @max(1_000_000_000, sig.runtime.program.stake.getMinimumDelegation(
//     //     slot,
//     //     feature_set,
//     // ));

//     const point_value = try calculatePointsEarned(
//         stakes.delegations.values(),
//         next_epoch_delegates,
//         &stakes.stake_history,
//         minimum_delegation,
//         new_warmup_and_cooldown_rate_epoch,
//     ) orelse return null;

//     return try calculateStakeVoteRewards(
//         allocator,
//         stake_history,
//         filtered_stake_delegations,
//         epoch_vote_accounts,
//         rewarded_epoch,
//         point_value,
//         new_warmup_and_cooldown_rate_epoch,
//     );
// }

// pub fn calculatePointsEarned(
//     delegations: []const Delegation,
//     delegates: *const std.AutoArrayHashMapUnmanaged(Pubkey, Voter),
//     stake_history: *const StakeHistory,
//     minimum_delegation: u64,
//     new_warmup_and_cooldown_rate_epoch: ?Epoch,
// ) !?u128 {
//     var points_earned: u128 = 0;
//     for (delegations) |*delegation| {
//         if (delegation.delegated < minimum_delegation) continue;
//         const delegate = delegates.getPtr(delegation.voter) orelse continue;
//         points_earned += calculateStakePointsAndCredits(
//             delegation,
//             &delegate.state,
//             stake_history,
//             new_warmup_and_cooldown_rate_epoch,
//         ).points_earned;
//     }
//     return if (points_earned > 0) points_earned else null;
// }

// pub fn calculateStakePointsAndCredits(
//     delegation: *const Delegation,
//     vote_state: *const VoteState,
//     stake_history: *const StakeHistory,
//     new_rate_activation_epoch: ?Epoch,
// ) struct {
//     points_earned: u128,
//     new_credits_observed: u64,
//     force_credits_update_with_skipped_rewards: bool,
// } {
//     const credits_in_vote = vote_state.epochCredits();

//     return if (credits_in_vote < delegation.credits_observed)
//         // NOTE: Interesting case where. Need to think about it more.
//         .{
//             .points_earned = 0,
//             .new_credits_observed = credits_in_vote,
//             .force_credits_update_with_skipped_rewards = true,
//         }
//     else if (credits_in_vote == delegation.credits_observed)
//         // No new credits earned since last observation
//         .{
//             .points_earned = 0,
//             .new_credits_observed = delegation.credits_observed,
//             .force_credits_update_with_skipped_rewards = false,
//         }
//     else blk: {
//         var new_credits_observed: u64 = delegation.credits_observed;
//         var points_earned: u128 = 0;

//         for (vote_state.epoch_credits.items) |epoch_credits| {
//             const earned_credits: u128 = if (delegation.credits_observed < epoch_credits.prev_credits)
//                 // The staker observed the entire previous epoch, so they earn all credits
//                 epoch_credits.credits - epoch_credits.prev_credits
//             else if (delegation.credits_observed < epoch_credits.credits)
//                 // The staker observerd part of the previous epoch, so they earn partial credits
//                 epoch_credits.credits - new_credits_observed
//             else
//                 // The staker observed none of the previous epoch, so they earn no credits
//                 0;

//             // Get the stakers effective stake for the epoch and calculate earned points
//             const effective: u128 = (delegation.getStakeState(
//                 epoch_credits.epoch,
//                 stake_history,
//                 new_rate_activation_epoch,
//             )).effective;
//             points_earned += effective * earned_credits;

//             // The staker has now earned points up to the current epoch's credits
//             new_credits_observed = @max(new_credits_observed, epoch_credits.credits);
//         }

//         break :blk .{
//             .points_earned = points_earned,
//             .new_credits_observed = new_credits_observed,
//             .force_credits_update_with_skipped_rewards = false,
//         };
//     };
// }
