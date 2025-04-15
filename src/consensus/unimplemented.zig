// Houses all unimplemented structure external to the tower
// but needed by it.
//
const std = @import("std");
const sig = @import("../sig.zig");
const Bank = sig.accounts_db.Bank;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SortedMap = sig.utils.collections.SortedMap;

const LockoutIntervals = sig.consensus.tower.LockoutIntervals;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;

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

pub const ForkStats = struct {
    computed: bool,
    lockout_intervals: LockoutIntervals,
};

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
        frozen_banks: std.ArrayList(Bank),
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
