const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const PubkeyMap = sig.utils.collections.PubkeyMap;

map: PubkeyMap(StakeDelegation),

pub const StakeDelegation = struct {
    stake_account: Pubkey,
    vote_account: Pubkey,
    stake: u64,
    activation_epoch: u64,
    deactivation_epoch: u64,
    warmup_cooldown_rate: f64,
    credits_observed: u64,
    is_tombstone: bool,
};
