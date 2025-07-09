const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;

const Account = sig.core.Account;
const AccountsDB = sig.accounts_db.AccountsDB;
const Hash = sig.core.Hash;
const LatestValidatorVotesForFrozenBanks = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const LockoutIntervals = sig.consensus.replay_tower.LockoutIntervals;
const Lockout = sig.runtime.program.vote.state.Lockout;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SortedSet = sig.utils.collections.SortedSet;
const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const TowerVoteState = sig.consensus.tower_state.TowerVoteState;
const VoteState = sig.runtime.program.vote.state.VoteState;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;
const VotedSlotAndPubkey = sig.consensus.unimplemented.VotedSlotAndPubkey;
const StakeAndVoteAccountsMap = sig.core.vote_accounts.StakeAndVoteAccountsMap;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;

const DUPLICATE_THRESHOLD = sig.replay.service.DUPLICATE_THRESHOLD;

pub const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote.state.MAX_LOCKOUT_HISTORY;

pub const Stake = u64;

pub const VotedSlot = Slot;

pub const ThresholdDecision = union(enum) {
    passed_threshold,
    failed_threshold: struct {
        // vote depth
        u64,
        // Observed stake
        u64,
    },
};

pub const TowerError = error{
    IoError,
    SerializeError,
    InvalidSignature,
    WrongTower,
    TooOldTower,
    FatallyInconsistent,
    FatallyInconsistentTimeWarp,
    FatallyInconsistentDivergedAncestors,
    FatallyInconsistentReplayOutOfOrder,
    HardFork,
    // Converted into erros from panics (debugs) in Agave
    /// Slots in tower are not older than last_checked_slot
    FatallyInconsistentTowerSlotOrder,
};

pub const Tower = struct {
    logger: ScopedLogger(@typeName(Tower)),
    vote_state: TowerVoteState,

    pub fn init(logger: Logger) Tower {
        var tower = Tower{
            .logger = logger.withScope(@typeName(Tower)),
            .vote_state = .{},
        };
        // VoteState::root_slot is ensured to be Some in Tower
        tower.vote_state.root_slot = 0;
        return tower;
    }

    pub fn initializeLockoutsFromBank(
        self: *Tower,
        allocator: std.mem.Allocator,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        accounts_db: *AccountsDB,
    ) !void {
        const vote_account = accounts_db.getAccount(vote_account_pubkey) catch {
            self.initializeRoot(fork_root);
            return;
        };

        const vote_state = try stateFromAccount(
            allocator,
            &vote_account,
            vote_account_pubkey,
        );

        var lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(
            allocator,
            vote_state.votes.items.len,
        );
        for (vote_state.votes.items) |landed| {
            try lockouts.append(
                allocator,
                Lockout{
                    .slot = landed.lockout.slot,
                    .confirmation_count = landed.lockout.confirmation_count,
                },
            );
        }
        self.vote_state = TowerVoteState{
            .votes = try std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY)
                .fromSlice(try lockouts.toOwnedSlice(allocator)),
            .root_slot = vote_state.root_slot,
        };
        self.initializeRoot(fork_root);

        var flags = try std.DynamicBitSetUnmanaged.initEmpty(
            allocator,
            self.vote_state.votes.len,
        );
        defer flags.deinit(allocator);

        for (self.vote_state.votes.constSlice(), 0..) |vote, i| {
            flags.setValue(i, vote.slot > fork_root);
        }

        try self.initializeLockouts(flags);
    }

    pub fn initializeLockouts(
        self: *Tower,
        should_retain: std.DynamicBitSetUnmanaged,
    ) !void {
        std.debug.assert(should_retain.capacity() >= self.vote_state.votes.len);
        var retained = try std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY).init(0);
        for (self.vote_state.votes.constSlice(), 0..) |item, i| {
            if (should_retain.isSet(i)) {
                _ = try retained.append(item);
            }
        }
        self.vote_state.votes = retained;
    }

    /// Updating root is needed to correctly restore from newly-saved tower for the next
    /// boot.
    pub fn initializeRoot(self: *Tower, root_slot: Slot) void {
        self.vote_state.root_slot = root_slot;
    }

    /// Record a vote in the tower.
    /// Returns a new root slot when the oldest vote reaches maximum lockout.
    pub fn recordBankVoteAndUpdateLockouts(
        self: *Tower,
        vote_slot: Slot,
    ) !?Slot {
        if (self.vote_state.lastVotedSlot()) |last_voted_sot| {
            if (vote_slot <= last_voted_sot) {
                return error.VoteTooOld;
            }
        }

        const old_root = try self.getRoot();

        try self.vote_state.processNextVoteSlot(vote_slot);

        const new_root = try self.getRoot();

        if (old_root != new_root) {
            return new_root;
        } else {
            return null;
        }
    }

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.vote_state.votes.len);
        for (self.vote_state.votes.constSlice(), 0..) |vote, i| {
            slots[i] = vote.slot;
        }
        return slots;
    }

    // root may be forcibly set by arbitrary replay root slot, for example from a root
    // after replaying a snapshot.
    // Also, tower.getRoot() couldn't be null; initializeLockouts() ensures that.
    // Conceptually, every tower must have been constructed from a concrete starting point,
    // which establishes the origin of trust (i.e. root) whether booting from genesis (slot 0) or
    // snapshot (slot N). In other words, there should be no possibility a Tower doesn't have
    // root, unlike young vote accounts.
    pub fn getRoot(self: *const Tower) !Slot {
        if (self.vote_state.root_slot == null) return error.RootSlotMissing;
        return self.vote_state.root_slot.?;
    }

    // a slot is recent if it's newer than the last vote we have. If we haven't voted yet
    // but have a root (hard forks situation) then compare it to the root
    pub fn isRecent(self: *const Tower, slot: Slot) bool {
        if (self.vote_state.lastVotedSlot()) |last_voted_slot| {
            if (slot <= last_voted_slot) {
                return false;
            } else if (self.vote_state.root_slot) |root_slot| {
                if (slot <= root_slot) {
                    return false;
                }
            }
        }
        return true;
    }

    pub fn hasVoted(self: *const Tower, slot: Slot) bool {
        for (self.vote_state.votes.constSlice()) |vote| {
            if (slot == vote.slot) {
                return true;
            }
        }
        return false;
    }

    /// Use to check if a vote can be casted for this slot without violating previous lockouts
    pub fn isLockedOut(
        self: *const Tower,
        slot: Slot,
        ancestors: *const SortedSet(Slot),
    ) !bool {
        if (!self.isRecent(slot)) {
            return true;
        }

        // Check if a slot is locked out by simulating adding a vote for that
        // slot to the current lockouts to pop any expired votes. If any of the
        // remaining voted slots are on a different fork from the checked slot,
        // it's still locked out.
        var vote_state = self.vote_state;

        try vote_state.processNextVoteSlot(slot);

        for (vote_state.votes.constSlice()) |vote| {
            if (slot != vote.slot and
                // This means the validator is trying to vote on a fork incompatible with previous votes.
                !ancestors.contains(vote.slot))
            {
                return true;
            }
        }

        if (vote_state.root_slot) |root_slot| {
            if (slot != root_slot
                // This case should never happen because bank forks purges all
                // non-descendants of the root every time root is set
            and !ancestors.contains(root_slot)) {
                return error.InvalidRootSlot;
            }
        }

        // Not locked out, vote safe to be casted.
        return false;
    }

    pub fn votedSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.vote_state.votes.len);
        for (self.vote_state.votes.slice(), 0..) |lockout, i| {
            slots[i] = lockout.slot;
        }
        return slots;
    }

    pub fn restore(
        tower_storage: *const TowerStorage,
        node_pubkey: *const Pubkey,
    ) !Tower {
        return try tower_storage.load(node_pubkey);
    }
};

pub fn stateFromAccount(
    allocator: std.mem.Allocator,
    vote_account: *const Account,
    vote_account_pubkey: *const Pubkey,
) !VoteState {
    const buf = try allocator.alloc(u8, vote_account.data.len());
    // TODO Not sure if this is the way to get the data from the vote account. Review.
    _ = vote_account.writeToBuf(vote_account_pubkey, buf);
    const versioned_state = try sig.bincode.readFromSlice(
        allocator,
        VoteStateVersions,
        buf,
        .{},
    );
    return try versioned_state.convertToCurrent(allocator);
}

pub fn populateAncestorVotedStakes(
    voted_stakes: *SortedSet(Slot),
    vote_slots: []const Slot,
    ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
) !void {
    // If there's no ancestors, that means this slot must be from before the current root,
    // in which case the lockouts won't be calculated in bank_weight anyways, so ignore
    // this slot
    for (vote_slots) |vote_slot| {
        if (ancestors.getPtr(vote_slot)) |maybe_slot_ancestors| {
            try voted_stakes.put(vote_slot);
            for (maybe_slot_ancestors.items()) |slot| {
                _ = try voted_stakes.put(slot);
            }
        }
    }
}

fn updateAncestorVotedStakes(
    voted_stakes: *VotedStakes,
    voted_slot: Slot,
    voted_stake: u64,
    ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
) void {
    // If there's no ancestors, that means this slot must be from
    // before the current root, so ignore this slot
    if (ancestors.getPtr(voted_slot)) |vote_slot_ancestors| {
        var entry_vote_stake = try voted_stakes.getOrPutValue(voted_slot, 0);
        entry_vote_stake.value_ptr += voted_stake;
        var iter = vote_slot_ancestors.*.iterator();
        for (iter.next()) |ancestor_slot| {
            var entry_voted_stake = try voted_stakes.getOrPutValue(ancestor_slot, 0);
            entry_voted_stake.value_ptr += voted_stake;
        }
    }
}

pub fn isSlotDuplicateConfirmed(
    slot: Slot,
    voted_stakes: *const VotedStakes,
    total_stake: Stake,
) bool {
    if (voted_stakes.get(slot)) |stake| {
        return (@as(f64, @floatFromInt(stake)) / @as(f64, @floatFromInt(total_stake))) >
            DUPLICATE_THRESHOLD;
    } else {
        return false;
    }
}

test "is slot duplicate confirmed not enough stake failure" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 52);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "is slot duplicate confirmed unknown slot" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "is slot duplicate confirmed pass" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 53);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(result);
}
