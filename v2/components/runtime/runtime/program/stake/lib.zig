const std = @import("std");
const sig = @import("../../../component.zig");

const bincode = sig.bincode;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const FeatureSet = sig.core.FeatureSet;
const sysvar = sig.runtime.sysvar;

/// Self-referencing namespace for backward-compatible `stake.state.*` paths.
pub const state = @This();

pub const ID: Pubkey = .parse("Stake11111111111111111111111111111111111111");

pub fn getMinimumDelegation(slot: Slot, feature_set: *const FeatureSet) u64 {
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    return if (feature_set.active(.upgrade_bpf_stake_program_to_v5, slot))
        1 * LAMPORTS_PER_SOL
    else
        1;
}

// --- state types ---

pub const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

pub fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
    return if (current_epoch < new_rate_activation_epoch orelse std.math.maxInt(u64))
        DEFAULT_WARMUP_COOLDOWN_RATE
    else
        NEW_WARMUP_COOLDOWN_RATE;
}

pub const StakeStateV2 = union(enum) {
    uninitialized,
    initialized: Meta,
    stake: struct { meta: Meta, stake: Stake, flags: StakeFlags },
    rewards_pool,

    /// [agave] https://github.com/solana-program/stake/blob/69620421bf76ecddb62357e1e1cd5c0961f7794d/interface/src/state.rs#L214
    pub const SIZE = 200;

    pub const Meta = struct {
        rent_exempt_reserve: u64,
        authorized: Authorized,
        lockup: Lockup,
    };

    pub const Stake = struct {
        delegation: Delegation,
        credits_observed: u64,

        pub fn getDelegation(self: *const Stake) Delegation {
            return self.delegation;
        }

        pub fn initRandom(random: std.Random) Stake {
            return .{
                .delegation = Delegation.initRandom(random),
                .credits_observed = random.int(u64),
            };
        }
    };

    pub const StakeFlags = packed struct {
        bits: u8,

        pub const EMPTY: StakeFlags = .{ .bits = 0 };
    };

    pub const Authorized = struct {
        staker: Pubkey,
        withdrawer: Pubkey,

        pub const DEFAULT: Authorized = .{ .staker = Pubkey.ZEROES, .withdrawer = Pubkey.ZEROES };
    };

    pub const Lockup = struct {
        unix_timestamp: i64,
        epoch: Epoch,
        custodian: Pubkey,

        pub const DEFAULT: Lockup = .{
            .unix_timestamp = 0,
            .epoch = 0,
            .custodian = Pubkey.ZEROES,
        };

        pub fn isInForce(
            self: *const Lockup,
            clock: *const sysvar.Clock,
            maybe_custodian: ?*const Pubkey,
        ) bool {
            if (maybe_custodian) |custodian| {
                if (custodian.equals(&self.custodian)) return false;
            }
            return self.unix_timestamp > clock.unix_timestamp or self.epoch > clock.epoch;
        }
    };

    pub const Delegation = struct {
        voter_pubkey: Pubkey,
        stake: u64,
        activation_epoch: Epoch,
        deactivation_epoch: Epoch = std.math.maxInt(u64),
        /// deprecated
        deprecated_warmup_cooldown_rate: f64 = DEFAULT_WARMUP_COOLDOWN_RATE,

        pub fn isBootstrap(self: *const Delegation) bool {
            return self.activation_epoch == std.math.maxInt(u64);
        }

        pub fn getDelegation(self: *const Delegation) Delegation {
            return self.*;
        }

        pub fn getEffectiveStake(
            self: *const Delegation,
            epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) u64 {
            return self.getStakeState(
                epoch,
                history,
                new_rate_activation_epoch,
            ).effective;
        }

        pub fn getStakeState(
            self: *const Delegation,
            epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) sysvar.StakeHistory.StakeState {
            const effective_stake, const activating_stake = self.getEffectiveAndActivatingStake(
                epoch,
                history,
                new_rate_activation_epoch,
            );

            if (epoch < self.deactivation_epoch) {
                return .{
                    .effective = effective_stake,
                    .activating = activating_stake,
                };
            }

            if (epoch == self.deactivation_epoch) {
                return .{
                    .effective = effective_stake,
                    .deactivating = effective_stake,
                };
            }

            const entry = history.getEntry(self.deactivation_epoch) orelse return .{};

            var prev_epoch = self.deactivation_epoch;
            var prev_cluster_stake = entry.stake;

            var current_epoch: Epoch = undefined;
            var current_effective_stake = effective_stake;

            while (true) {
                current_epoch = prev_epoch + 1;

                if (prev_cluster_stake.deactivating == 0) break;

                const weight = @as(f64, @floatFromInt(current_effective_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.deactivating));

                const warmup_cooldown_rate = warmupCooldownRate(
                    current_epoch,
                    new_rate_activation_epoch,
                );

                const newly_not_effective_cluster_stake = @as(
                    f64,
                    @floatFromInt(prev_cluster_stake.effective),
                ) * warmup_cooldown_rate;

                const newly_not_effective_stake: u64 = @max(1, std.math.lossyCast(
                    u64,
                    weight * newly_not_effective_cluster_stake,
                ));

                current_effective_stake = current_effective_stake -| newly_not_effective_stake;
                if (current_effective_stake == 0) break;
                if (current_epoch >= epoch) break;

                if (history.getEntry(current_epoch)) |current_entry| {
                    prev_epoch = current_entry.epoch;
                    prev_cluster_stake = current_entry.stake;
                } else break;
            }

            return .{
                .effective = current_effective_stake,
                .deactivating = current_effective_stake,
            };
        }

        pub fn getEffectiveAndActivatingStake(
            self: *const Delegation,
            epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) struct { u64, u64 } {
            if (self.isBootstrap()) return .{ self.stake, 0 };
            if (self.activation_epoch == self.deactivation_epoch) return .{ 0, 0 };
            if (epoch == self.activation_epoch) return .{ 0, self.stake };
            if (epoch < self.activation_epoch) return .{ 0, 0 };

            const entry = history.getEntry(self.activation_epoch) orelse return .{ self.stake, 0 };

            var prev_epoch = self.activation_epoch;
            var prev_cluster_stake = entry.stake;

            var current_epoch: Epoch = undefined;
            var current_effective_stake: u64 = 0;

            while (true) {
                current_epoch = prev_epoch + 1;

                if (prev_cluster_stake.activating == 0) break;

                const remaining_activated_stake = self.stake - current_effective_stake;
                const weight = @as(f64, @floatFromInt(remaining_activated_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.activating));
                const warmup_cooldown_rate_val =
                    warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_effective_cluster_stake =
                    @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate_val;
                const weighted_effective_state: u64 =
                    @intFromFloat(weight * newly_effective_cluster_stake);
                const newly_effective_stake = @max(weighted_effective_state, 1);

                current_effective_stake += newly_effective_stake;
                if (current_effective_stake >= self.stake) {
                    current_effective_stake = self.stake;
                    break;
                }

                if (current_epoch >= epoch or current_epoch >= self.deactivation_epoch) break;

                if (history.getEntry(current_epoch)) |next_entry| {
                    prev_epoch = next_entry.epoch;
                    prev_cluster_stake = next_entry.stake;
                } else break;
            }

            return .{
                current_effective_stake,
                self.stake - current_effective_stake,
            };
        }

        pub fn initRandom(random: std.Random) Delegation {
            return .{
                .voter_pubkey = Pubkey.initRandom(random),
                .stake = random.int(u64),
                .activation_epoch = random.int(Epoch),
                .deactivation_epoch = random.int(Epoch),
                .deprecated_warmup_cooldown_rate = random.float(f64),
            };
        }

        pub fn eql(self: *const Delegation, other: *const Delegation) bool {
            return self.voter_pubkey.equals(&other.voter_pubkey) and
                self.stake == other.stake and
                self.activation_epoch == other.activation_epoch and
                self.deactivation_epoch == other.deactivation_epoch and
                self.deprecated_warmup_cooldown_rate == other.deprecated_warmup_cooldown_rate;
        }
    };

    pub const StakeAuthorize = enum { staker, withdrawer };

    pub fn getStake(self: *const StakeStateV2) ?Stake {
        return switch (self.*) {
            .uninitialized => null,
            .initialized => null,
            .stake => |s| s.stake,
            .rewards_pool => null,
        };
    }

    pub fn getStakePtr(self: *StakeStateV2) ?*Stake {
        return switch (self.*) {
            .uninitialized => null,
            .initialized => null,
            .stake => |*s| &s.stake,
            .rewards_pool => null,
        };
    }

    pub fn getDelegation(self: *const StakeStateV2) ?Delegation {
        return switch (self.*) {
            .uninitialized => null,
            .initialized => null,
            .stake => |s| s.stake.delegation,
            .rewards_pool => null,
        };
    }

    pub fn fromAccountData(data: []const u8) !StakeStateV2 {
        return sig.bincode.readFromSlice(
            sig.utils.allocators.failing.allocator(.{}),
            StakeStateV2,
            data,
            .{},
        );
    }
};

// --- instruction types ---

/// [agave] https://github.com/solana-program/stake/blob/bb6932ed816eb39205102eee2e0cbc0cd511dcaa/interface/src/instruction.rs#L37
pub const Instruction = union(enum) {
    /// Initialize a stake with lockup and authorization information
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized stake account
    ///   1. `[]` Rent sysvar
    ///
    /// [`Authorized`] carries pubkeys that must sign staker transactions
    /// and withdrawer transactions; [`Lockup`] carries information about
    /// withdrawal restrictions.
    initialize: struct { StakeStateV2.Authorized, StakeStateV2.Lockup },

    /// Authorize a key to manage stake or withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` The stake or withdraw authority
    ///   3. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
    ///      lockup expiration
    authorize: struct { Pubkey, StakeStateV2.StakeAuthorize },

    /// Delegate a stake to a particular vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account to be delegated
    ///   1. `[]` Vote account to which this stake will be delegated
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[]` Unused account, formerly the stake config
    ///   5. `[SIGNER]` Stake authority
    ///
    /// The entire balance of the staking account is staked. `DelegateStake`
    /// can be called multiple times, but re-delegation is delayed by one epoch.
    delegate_stake,

    /// Split `u64` tokens and stake off a stake account into another stake account.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be split; must be in the Initialized or Stake state
    ///   1. `[WRITE]` Uninitialized stake account that will take the split-off amount
    ///   2. `[SIGNER]` Stake authority
    split: u64,

    /// Withdraw unstaked lamports from the stake account
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account from which to withdraw
    ///   1. `[WRITE]` Recipient account
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[SIGNER]` Withdraw authority
    ///   5. Optional: `[SIGNER]` Lockup authority, if before lockup expiration
    ///
    /// The `u64` is the portion of the stake account balance to be withdrawn,
    /// must be `<= StakeAccount.lamports - staked_lamports`.
    withdraw: u64,

    /// Deactivates the stake in the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Stake authority
    deactivate,

    /// Set stake lockup
    ///
    /// If a lockup is not active, the withdraw authority may set a new lockup
    /// If a lockup is active, the lockup custodian may update the lockup parameters
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account
    ///   1. `[SIGNER]` Lockup authority or withdraw authority
    set_lockup: LockupArgs,

    /// Merge two stake accounts.
    ///
    /// Both accounts must have identical lockup and authority keys. A merge
    /// is possible between two stakes in the following states with no additional
    /// conditions:
    ///
    /// * two deactivated stakes
    /// * an inactive stake into an activating stake during its activation epoch
    ///
    /// For the following cases, the voter pubkey and vote credits observed must match:
    ///
    /// * two activated stakes
    /// * two activating accounts that share an activation epoch, during the activation epoch
    ///
    /// All other combinations of stake states will fail to merge, including all
    /// "transient" states, where a stake is activating or deactivating with a
    /// non-zero effective stake.
    ///
    /// # Account references
    ///   0. `[WRITE]` Destination stake account for the merge
    ///   1. `[WRITE]` Source stake account for to merge.  This account will be drained
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[SIGNER]` Stake authority
    merge,

    /// Authorize a key to manage stake or withdrawal with a derived key
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[SIGNER]` Base key of stake or withdraw authority
    ///   2. `[]` Clock sysvar
    ///   3. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_with_seed: AuthorizeWithSeedArgs,

    /// Initialize a stake with authorization information
    ///
    /// This instruction is similar to `Initialize` except that the withdraw authority
    /// must be a signer, and no lockup is applied to the account.
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized stake account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` The stake authority
    ///   3. `[SIGNER]` The withdraw authority
    initialize_checked,

    /// Authorize a key to manage stake or withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new
    /// stake or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` The stake or withdraw authority
    ///   3. `[SIGNER]` The new stake or withdraw authority
    ///   4. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_checked: StakeStateV2.StakeAuthorize,

    /// Authorize a key to manage stake or withdrawal with a derived key
    ///
    /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement that
    /// the new stake or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[SIGNER]` Base key of stake or withdraw authority
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` The new stake or withdraw authority
    ///   4. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_checked_with_seed: AuthorizeCheckedWithSeedArgs,

    /// Set stake lockup
    ///
    /// This instruction behaves like `SetLockup` with the additional requirement that
    /// the new lockup authority also be a signer.
    ///
    /// If a lockup is not active, the withdraw authority may set a new lockup
    /// If a lockup is active, the lockup custodian may update the lockup parameters
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account
    ///   1. `[SIGNER]` Lockup authority or withdraw authority
    ///   2. Optional: `[SIGNER]` New lockup authority
    set_lockup_checked: LockupCheckedArgs,

    /// Get the minimum stake delegation, in lamports
    ///
    /// # Account references
    ///   None
    ///
    /// Returns the minimum delegation as a little-endian encoded u64 value.
    /// Programs can use the [`get_minimum_delegation()`] helper function to invoke and
    /// retrieve the return value for this instruction.
    ///
    /// [`get_minimum_delegation()`]: crate::tools::get_minimum_delegation
    get_minimum_delegation,

    /// Deactivate stake delegated to a vote account that has been delinquent for at least
    /// [`crate::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION`] epochs.
    ///
    /// No signer is required for this instruction as it is a common good to deactivate abandoned
    /// stake.
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account
    ///   1. `[]` Delinquent vote account for the delegated stake account
    ///   2. `[]` Reference vote account that has voted at least once in the last
    ///      [`crate::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION`] epochs
    deactivate_delinquent,

    /// Redelegate activated stake to another vote account.
    ///
    /// Upon success:
    ///   * the balance of the delegated stake account will be reduced to the undelegated amount in
    ///     the account (rent exempt minimum and any additional lamports not part of the delegation),
    ///     and scheduled for deactivation.
    ///   * the provided uninitialized stake account will receive the original balance of the
    ///     delegated stake account, minus the rent exempt minimum, and scheduled for activation to
    ///     the provided vote account. Any existing lamports in the uninitialized stake account
    ///     will also be included in the re-delegation.
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account to be redelegated. The account must be fully
    ///      activated and carry a balance greater than or equal to the minimum delegation amount
    ///      plus rent exempt minimum
    ///   1. `[WRITE]` Uninitialized stake account that will hold the redelegated stake
    ///   2. `[]` Vote account to which this stake will be re-delegated
    ///   3. `[]` Unused account, formerly the stake config
    ///   4. `[SIGNER]` Stake authority
    ///
    /// deprecated since 2.1.0
    _redelegate,

    /// Move stake between accounts with the same authorities and lockups, using Staker authority.
    ///
    /// The source account must be fully active. If its entire delegation is moved, it immediately
    /// becomes inactive. Otherwise, at least the minimum delegation of active stake must remain.
    ///
    /// The destination account must be fully active or fully inactive. If it is active, it must
    /// be delegated to the same vote account as the source. If it is inactive, it
    /// immediately becomes active, and must contain at least the minimum delegation. The
    /// destination must be pre-funded with the rent-exempt reserve.
    ///
    /// This instruction only affects or moves active stake. Additional unstaked lamports are never
    /// moved, activated, or deactivated, and accounts are never deallocated.
    ///
    /// # Account references
    ///   0. `[WRITE]` Active source stake account
    ///   1. `[WRITE]` Active or inactive destination stake account
    ///   2. `[SIGNER]` Stake authority
    ///
    /// The `u64` is the portion of the stake to move, which may be the entire delegation
    move_stake: u64,

    /// Move unstaked lamports between accounts with the same authorities and lockups, using Staker
    /// authority.
    ///
    /// The source account must be fully active or fully inactive. The destination may be in any
    /// mergeable state (active, inactive, or activating, but not in warmup cooldown). Only lamports that
    /// are neither backing a delegation nor required for rent-exemption may be moved.
    ///
    /// # Account references
    ///   0. `[WRITE]` Active or inactive source stake account
    ///   1. `[WRITE]` Mergeable destination stake account
    ///   2. `[SIGNER]` Stake authority
    ///
    /// The `u64` is the portion of available lamports to move
    move_lamports: u64,
};

pub const LockupArgs = struct {
    unix_timestamp: ?i64 = null,
    epoch: ?Epoch = null,
    custodian: ?Pubkey = null,
};

pub const AuthorizeCheckedWithSeedArgs = struct {
    stake_authorize: StakeStateV2.StakeAuthorize,
    authority_seed: []const u8, // is there a fixed upper bound here?
    authority_owner: Pubkey,

    pub const @"!bincode-config:authority_seed" = sig.runtime.program.SEED_FIELD_CONFIG;
};

pub const AuthorizeWithSeedArgs = struct {
    new_authorized_pubkey: Pubkey,
    stake_authorize: StakeStateV2.StakeAuthorize,
    authority_seed: []const u8, // is there a fixed upper bound here?
    authority_owner: Pubkey,

    pub const @"!bincode-config:authority_seed" = sig.runtime.program.SEED_FIELD_CONFIG;
};

pub const LockupCheckedArgs = struct {
    unix_timestamp: ?i64 = null,
    epoch: ?Epoch = null,
};

// --- tests ---

test StakeStateV2 {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const stake_state = StakeStateV2{ .stake = .{
        .meta = .{
            .authorized = .{
                .staker = Pubkey.initRandom(random),
                .withdrawer = Pubkey.initRandom(random),
            },
            .lockup = .{
                .unix_timestamp = 1234567890,
                .epoch = 42,
                .custodian = Pubkey.initRandom(random),
            },
            .rent_exempt_reserve = 1_000_000,
        },
        .stake = .initRandom(random),
        .flags = .EMPTY,
    } };

    // Test serialization/deserialization via account data
    const serialized = try sig.bincode.writeAlloc(allocator, stake_state, .{});
    defer allocator.free(serialized);

    const from_account = try StakeStateV2.fromAccountData(serialized);

    try std.testing.expect(from_account.getDelegation().?.eql(&stake_state.getDelegation().?));

    // Test delegation mutation
    var state_mut = stake_state;
    const stake_ptr = state_mut.getStakePtr().?;
    stake_ptr.delegation.stake += 500_000;
    try std.testing.expectEqual(
        stake_state.getDelegation().?.stake + 500_000,
        state_mut.getDelegation().?.stake,
    );
}
