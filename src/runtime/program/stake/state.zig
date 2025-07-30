const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const sysvar = sig.runtime.sysvar;
const InstructionError = sig.core.instruction.InstructionError;

const program = @import("lib.zig");
const instruction = @import("instruction.zig");

const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
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

        pub fn setLockup(
            self: *Meta,
            lockup: *const instruction.LockupArgs,
            signers: []const Pubkey,
            clock: *const sysvar.Clock,
        ) InstructionError!void {
            if (self.lockup.isInForce(clock, null)) {
                const custodian_signed = for (signers) |signer| {
                    if (signer.equals(&self.lockup.custodian)) break true;
                } else false;

                if (!custodian_signed) return error.MissingRequiredSignature;
            } else {
                const withdrawer_signed = for (signers) |signer| {
                    if (signer.equals(&self.authorized.withdrawer)) break true;
                } else false;

                if (!withdrawer_signed) return error.MissingRequiredSignature;
            }

            if (lockup.unix_timestamp) |unix_timestamp| self.lockup.unix_timestamp = unix_timestamp;
            if (lockup.epoch) |epoch| self.lockup.epoch = epoch;
            if (lockup.custodian) |custodian| self.lockup.custodian = custodian;
        }
    };

    pub const Stake = struct {
        delegation: Delegation,
        credits_observed: u64,

        fn stake(
            self: *const Stake,
            epoch: Epoch,
            history: *const sig.runtime.sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) void {
            return self.delegation.effectiveStake(epoch, history, new_rate_activation_epoch);
        }

        pub fn split(
            self: *Stake,
            ic: *sig.runtime.InstructionContext,
            remaining_stake_delta: u64,
            split_stake_amount: u64,
        ) InstructionError!Stake {
            if (remaining_stake_delta > self.delegation.stake) return {
                ic.tc.custom_error = @intFromEnum(program.StakeError.insufficient_stake);
                return error.Custom;
            };

            self.delegation.stake -= remaining_stake_delta;

            var new: Stake = self.*;
            new.delegation.stake = split_stake_amount;

            return new;
        }

        pub fn deactivate(self: *Stake, epoch: Epoch) ?program.StakeError {
            if (self.delegation.deactivation_epoch != std.math.maxInt(u64))
                return .already_deactivated;
            self.delegation.deactivation_epoch = epoch;
            return null;
        }
    };

    pub const StakeFlags = struct {
        bits: u8,
        pub const EMPTY: StakeFlags = .{ .bits = 0 };

        // I couldn't call it "union"
        pub fn combine(self: StakeFlags, other: StakeFlags) StakeFlags {
            return .{ .bits = self.bits | other.bits };
        }
    };

    pub const Authorized = struct {
        staker: Pubkey,
        withdrawer: Pubkey,

        pub const DEFAULT: Authorized = .{ .staker = Pubkey.ZEROES, .withdrawer = Pubkey.ZEROES };

        pub fn check(
            self: *const Authorized,
            signers: []const Pubkey,
            stake_authorize: StakeAuthorize,
        ) error{MissingRequiredSignature}!void {
            const authorized_signer = switch (stake_authorize) {
                .staker => &self.staker,
                .withdrawer => &self.withdrawer,
            };

            const has_signature = for (signers) |signer| {
                if (signer.equals(authorized_signer)) break true;
            } else false;

            if (!has_signature) return error.MissingRequiredSignature;
        }

        // [agave] https://github.com/solana-program/stake/blob/69620421bf76ecddb62357e1e1cd5c0961f7794d/interface/src/state.rs#L410
        pub fn authorize(
            self: *Authorized,
            signers: []const Pubkey,
            new_authorized: *const Pubkey,
            stake_authorize: StakeAuthorize,
            lockup_custodian_args: ?struct { *const Lockup, *const sysvar.Clock, ?*const Pubkey },
        ) ?struct { ?program.StakeError, InstructionError } {
            switch (stake_authorize) {
                .staker => {
                    const has_required_signer = for (signers) |signer| {
                        if (signer.equals(&self.staker) or signer.equals(&self.withdrawer))
                            break true;
                    } else false;

                    if (!has_required_signer) return .{ null, error.MissingRequiredSignature };
                    self.staker = new_authorized.*;
                },
                .withdrawer => {
                    if (lockup_custodian_args) |args| {
                        const lockup, const clock, const maybe_custodian = args;

                        if (lockup.isInForce(clock, null)) {
                            const custodian = maybe_custodian orelse
                                return .{ .custodian_missing, error.Custom };

                            const has_custodian_signer = for (signers) |signer| {
                                if (signer.equals(custodian)) break true;
                            } else false;

                            if (!has_custodian_signer)
                                return .{ .custodian_signature_missing, error.Custom };
                            if (lockup.isInForce(clock, custodian))
                                return .{ .lockup_in_force, error.Custom };
                        }
                    }
                    self.check(signers, stake_authorize) catch |err| return .{ null, err };
                    self.withdrawer = new_authorized.*;
                },
            }
            return null;
        }

        pub fn equals(self: *const Authorized, other: *const Authorized) bool {
            if (!self.staker.equals(&other.staker)) return false;
            return self.withdrawer.equals(&other.withdrawer);
        }
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

        pub fn equals(self: *const Lockup, other: *const Lockup) bool {
            if (self.unix_timestamp != other.unix_timestamp) return false;
            if (self.epoch != other.epoch) return false;
            return self.custodian.equals(&other.custodian);
        }
    };

    pub const Delegation = struct {
        voter_pubkey: Pubkey,
        stake: u64,
        activation_epoch: Epoch,
        deactivation_epoch: Epoch = std.math.maxInt(u64),
        /// deprecated
        _warmup_cooldown_rate: f64 = DEFAULT_WARMUP_COOLDOWN_RATE,

        /// [agave] https://github.com/solana-program/stake/blob/69620421bf76ecddb62357e1e1cd5c0961f7794d/interface/src/state.rs#L677
        pub fn effectiveStake(
            self: *const Delegation,
            epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) u64 {
            return self.stakeActivatingAndDeactivating(
                epoch,
                history,
                new_rate_activation_epoch,
            ).effective;
        }

        pub fn stakeActivatingAndDeactivating(
            self: *const Delegation,
            target_epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) sysvar.StakeHistory.StakeState {
            const effective_stake, const activating_stake = self.stakeAndActivating(
                target_epoch,
                history,
                new_rate_activation_epoch,
            );

            // de-activate some portion if necessary
            if (target_epoch < self.deactivation_epoch) {
                if (activating_stake == 0) {
                    return .{ .effective = effective_stake };
                }
                return .{
                    .effective = effective_stake,
                    .activating = activating_stake,
                };
            }

            if (target_epoch == self.deactivation_epoch) {
                // yes.. with_deactivating sets both
                return .{
                    .effective = effective_stake,
                    .deactivating = effective_stake,
                };
            }

            const entry = history.getEntry(self.deactivation_epoch) orelse
                return .{};
            var prev_epoch = self.deactivation_epoch;
            var prev_cluster_stake = entry.stake;

            var current_epoch = prev_epoch;
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
                if (current_epoch >= target_epoch) break;

                const current_cluster = history.getEntry(current_epoch) orelse break;
                prev_epoch = current_epoch;
                prev_cluster_stake = current_cluster.stake;
            }

            return .{
                .effective = current_effective_stake,
                .deactivating = current_effective_stake,
            };
        }

        /// returned tuple is (effective, activating) stake
        fn stakeAndActivating(
            self: *const Delegation,
            target_epoch: Epoch,
            history: *const sysvar.StakeHistory,
            new_rate_activation_epoch: ?Epoch,
        ) struct { u64, u64 } {
            const delegated_stake = self.stake;

            if (self.isBootstrap()) return .{ delegated_stake, 0 };
            if (self.activation_epoch == self.deactivation_epoch) return .{ 0, 0 };
            if (self.activation_epoch == target_epoch) return .{ 0, delegated_stake };
            if (self.activation_epoch > target_epoch) return .{ 0, 0 };

            const entry = history.getEntry(self.activation_epoch) orelse
                return .{ delegated_stake, 0 };

            var prev_epoch = self.activation_epoch;
            var prev_cluster_stake = entry.stake;

            var current_epoch: Epoch = prev_epoch + 1;
            var current_effective_stake: u64 = 0;
            while (true) {
                current_epoch = prev_epoch + 1;
                if (prev_cluster_stake.activating == 0) break;

                const remaining_activating_stake = delegated_stake - current_effective_stake;
                const weight = @as(f64, @floatFromInt(remaining_activating_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.activating));

                const warmup_cooldown_rate = warmupCooldownRate(
                    current_epoch,
                    new_rate_activation_epoch,
                );

                const newly_effective_cluster_take = @as(
                    f64,
                    @floatFromInt(prev_cluster_stake.effective),
                ) * warmup_cooldown_rate;

                const newly_effective_stake: u64 = std.math.lossyCast(
                    u64,
                    @max(1, weight * newly_effective_cluster_take),
                );

                current_effective_stake += newly_effective_stake;
                if (current_effective_stake >= delegated_stake) {
                    current_effective_stake = delegated_stake;
                    break;
                }

                if (current_epoch >= target_epoch or current_epoch >= self.deactivation_epoch) {
                    break;
                }

                const current_cluster = history.getEntry(current_epoch) orelse break;
                prev_epoch = current_epoch;
                prev_cluster_stake = current_cluster.stake;
            }

            return .{ current_effective_stake, delegated_stake - current_effective_stake };
        }

        fn isBootstrap(self: *const Delegation) bool {
            return self.activation_epoch == std.math.maxInt(u64);
        }
    };

    pub const StakeAuthorize = enum { staker, withdrawer };
};
