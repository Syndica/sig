// Houses all unimplemented structure external to the tower
// but needed by it.

const std = @import("std");
const sig = @import("../sig.zig");
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

pub const FrozenVotes = struct { slot: Slot, hashes: []Hash };
pub const LatestValidatorVotesForFrozenBanks = struct {
    max_gossip_frozen_votes: std.AutoArrayHashMapUnmanaged(Pubkey, FrozenVotes) = .{},
    pub fn checkAddVote(
        self: *LatestValidatorVotesForFrozenBanks,
        vote_pubkey: Pubkey,
        vote_slot: Slot,
        frozen_hash: ?Hash,
        is_replay_vote: bool,
    ) struct { bool, ?Slot } {
        _ = self;
        _ = vote_pubkey;
        _ = vote_slot;
        _ = frozen_hash;
        _ = is_replay_vote;
        // TODO Implement
        return .{ false, null };
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
