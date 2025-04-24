// Houses all unimplemented structure external to the tower
// but needed by it.

const std = @import("std");
const sig = @import("../sig.zig");
const Bank = sig.accounts_db.Bank;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SortedMap = sig.utils.collections.SortedMap;

const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
// TODO DUPLICATE_THRESHOLD is defined in replay stage in Agave
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const BankForks = struct {
    pub fn rootBank(self: *const BankForks) Bank {
        _ = self;
        @panic("Unimplemented");
    }
    pub fn frozenBanks(self: *const BankForks) SortedMap(Slot, Bank) {
        _ = self;
        @panic("Unimplemented");
    }
    pub fn getWithCheckedHash(
        self: *const BankForks,
        heaviest: SlotAndHash,
    ) ?Bank {
        _ = self;
        _ = heaviest;
        @panic("Unimplemented");
    }
};

// TODO Implemented as part of ProgressMap
pub const ForkStats = struct {
    computed: bool,
    lockout_intervals: LockoutIntervals,
};

// TODO Implemented as part of ProgressMap
pub const ForkProgress = struct {
    fork_stats: ForkStats,
};

pub const ProgressMap = struct {
    progress_map: std.AutoHashMap(Slot, ForkProgress),
    pub fn getHash(_: ProgressMap, _: Slot) ?Hash {
        @panic("Unimplemented");
    }
    pub fn getForkStats(_: ProgressMap, _: Slot) ?ForkStats {
        @panic("Unimplemented");
    }
};

pub const ReplayStage = struct {
    pub fn initializeProgressAndForkChoice(
        root_bank: *const Bank,
        frozen_banks: *const []Bank,
        my_pubkey: *const Pubkey,
        vote_account: *const Pubkey,
        duplicate_slot_hashes: std.ArrayList(SlotAndHash),
    ) struct {
        ProgressMap,
        HeaviestSubtreeForkChoice,
    } {
        _ = root_bank;
        _ = frozen_banks;
        _ = my_pubkey;
        _ = vote_account;
        _ = duplicate_slot_hashes;
        @panic("Unimplemented");
    }
};

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
