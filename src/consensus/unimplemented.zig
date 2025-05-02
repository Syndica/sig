// Houses all unimplemented structure external to the tower
// but needed by it.

const std = @import("std");
const sig = @import("../sig.zig");
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
// TODO DUPLICATE_THRESHOLD is defined in replay stage in Agave
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const LatestValidatorVotesForFrozenBanks = struct {
    max_gossip_frozen_votes: std.AutoHashMap(Pubkey, struct { slot: Slot, hashes: []Hash }),
    pub fn checkAddVote(
        self: *LatestValidatorVotesForFrozenBanks,
        vote_pubkey: Pubkey,
        frozend_hash: ?Hash,
        is_replay_vote: bool,
    ) struct { bool, ?Slot } {
        _ = self;
        _ = vote_pubkey;
        _ = frozend_hash;
        _ = is_replay_vote;
        @panic("Unimplemented");
    }
};
pub const VoteAccount = struct {};
pub const StakedAccount = struct { stake: u64, account: VoteAccount };
const VotedSlotAndPubkey = struct { slot: Slot, pubkey: Pubkey };
pub const ExpirationSlot = Slot;
const HashThatShouldBeMadeBTreeMap = std.AutoArrayHashMapUnmanaged(
    ExpirationSlot,
    std.ArrayList(VotedSlotAndPubkey),
);
pub const LockoutIntervals = HashThatShouldBeMadeBTreeMap;
