const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

pub const StakeStateV2 = union(enum) {
    uninitialized,
    initialized: Meta,
    stake: struct { meta: Meta, stake: Stake, flags: StakeFlags },
    rewards_pool,

    pub const Meta = struct {
        rent_exempt_reserve: u64,
        authorized: Authorized,
        lockup: Lockup,
    };

    pub const Stake = struct {
        delegation: Delegation,
        credits_observed: u64,
    };

    pub const StakeFlags = struct {
        bits: u8,
    };

    pub const Authorized = struct {
        staker: Pubkey,
        withdrawer: Pubkey,
    };

    pub const Lockup = struct {
        unix_timestamp: i64,
        epoch: Epoch,
        custodian: Pubkey,
    };

    pub const Delegation = struct {
        voter_pubkey: Pubkey,
        stake: u64,
        activation_epoch: Epoch,
        deactivation_epoch: Epoch,
        /// deprecated
        _warmup_cooldown_rate: f64,
    };

    pub const StakeAuthorize = enum { Staker, Withdrawer };
};
