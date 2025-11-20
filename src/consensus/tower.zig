const std = @import("std");
const sig = @import("../sig.zig");

const Account = sig.core.Account;
const AccountsDB = sig.accounts_db.AccountsDB;
const LockoutIntervals = sig.consensus.replay_tower.LockoutIntervals;
const Lockout = sig.runtime.program.vote.state.Lockout;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const TowerVoteState = sig.consensus.tower_state.TowerVoteState;
const VoteState = sig.runtime.program.vote.state.VoteState;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;
const vote_program = sig.runtime.program.vote;

pub const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote.state.MAX_LOCKOUT_HISTORY;

pub const Stake = u64;

pub const VotedSlot = Slot;

const ComputedBankState = struct {
    /// Maps each validator (by their Pubkey) to the amount of stake they have voted
    /// with on this fork. Helps determine who has already committed to this
    /// fork and how much total stake that represents.
    voted_stakes: VotedStakes,
    /// Represents the total active stake in the network.
    total_stake: Stake,
    /// The sum of stake from all validators who have voted on the
    /// fork leading up to the current bank (slot).
    fork_stake: Stake,
    // Tree of intervals of lockouts of the form [slot, slot + slot.lockout],
    // keyed by end of the range
    lockout_intervals: LockoutIntervals,
    my_latest_landed_vote: ?Slot,
};

pub const ThresholdDecision = union(enum) {
    passed_threshold,
    failed_threshold: FailedThreshold,

    pub const FailedThreshold = struct {
        vote_depth: u64,
        observed_stake: u64,
    };

    pub fn eql(self: ThresholdDecision, other: ThresholdDecision) bool {
        return std.meta.eql(self, other);
    }
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
    /// Vote account is not owned by the vote program
    InvalidVoteAccountOwner,
};

pub const Tower = struct {
    logger: Logger,
    vote_state: TowerVoteState,

    const Logger = sig.trace.Logger(@typeName(Tower));

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
        slot_account_reader: sig.accounts_db.SlotAccountReader,
    ) !void {
        self.logger.info().logf(
            "initializeLockoutsFromBank: fork_root={}, vote_pubkey={}",
            .{ fork_root, vote_account_pubkey },
        );
        const vote_account = blk: {
            const maybe_vote_account = try slot_account_reader.get(
                allocator,
                vote_account_pubkey.*,
            );
            break :blk maybe_vote_account orelse {
                self.logger.info().logf(
                    "Vote account not found, initializing root to {}",
                    .{fork_root},
                );
                self.initializeRoot(fork_root);
                return;
            };
        };
        defer vote_account.deinit(allocator);

        // Validate that the account is owned by the vote program
        if (!vote_account.owner.equals(&vote_program.ID)) {
            self.logger.err().logf(
                "Invalid vote account owner. Expected: {}, Got: {}",
                .{ vote_program.ID, vote_account.owner },
            );
            return error.InvalidVoteAccountOwner;
        }

        self.logger.debug().logf(
            "Vote account loaded: Pubkey={}, Lamports={}, Owner={}, Data length={}",
            .{
                vote_account_pubkey,
                vote_account.lamports,
                vote_account.owner,
                vote_account.data.len(),
            },
        );

        const vote_state = try stateFromAccount(
            allocator,
            &vote_account,
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
            }
        } else if (self.vote_state.root_slot) |root_slot| {
            if (slot <= root_slot) {
                return false;
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
        ancestors: *const Ancestors,
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
                !ancestors.containsSlot(vote.slot))
            {
                return true;
            }
        }

        if (vote_state.root_slot) |root_slot| {
            if (slot != root_slot
                // This case should never happen because bank forks purges all
                // non-descendants of the root every time root is set
            and !ancestors.containsSlot(root_slot)) {
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

pub fn lastVotedSlotInBank(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDB,
    vote_account_pubkey: *const Pubkey,
) !?Slot {
    const vote_account = try accounts_db.getAccountLatest(allocator, vote_account_pubkey) orelse
        return null;
    defer vote_account.deinit(allocator);

    const vote_state = stateFromAccount(
        allocator,
        &vote_account,
    ) catch return null;
    return vote_state.lastVotedSlot();
}

pub fn stateFromAccount(
    allocator: std.mem.Allocator,
    vote_account: *const Account,
) (error{BincodeError} || std.mem.Allocator.Error)!VoteState {
    var iter = vote_account.data.iterator();
    const versioned_state = sig.bincode.read(
        allocator,
        VoteStateVersions,
        iter.reader(),
        .{},
    ) catch return error.BincodeError;
    return try versioned_state.convertToCurrent(allocator);
}

const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;

test "initializeLockoutsFromBank handles missing vote account" {
    const allocator = std.testing.allocator;

    var tower: Tower = .init(.noop);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());

    // Create an empty account map (vote account not found)
    var account_map: std.AutoArrayHashMapUnmanaged(Pubkey, Account) = .empty;
    defer account_map.deinit(allocator);

    const slot_account_reader: sig.accounts_db.SlotAccountReader = .{
        .account_map = &account_map,
    };

    const fork_root: Slot = 100;

    try tower.initializeLockoutsFromBank(
        allocator,
        &vote_pubkey,
        fork_root,
        slot_account_reader,
    );

    // Verify tower was initialized with the root
    try std.testing.expectEqual(fork_root, tower.vote_state.root_slot);
    try std.testing.expectEqual(0, tower.vote_state.votes.len);
}

test "initializeLockoutsFromBank handles invalid vote account owner" {
    const allocator = std.testing.allocator;

    var tower: Tower = .init(.noop);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());
    const wrong_owner: Pubkey = Pubkey.initRandom(prng.random());

    // Create an account with wrong owner
    const account_with_wrong_owner = Account{
        .data = AccountDataHandle.initAllocated(&[_]u8{}),
        .executable = false,
        .lamports = 1000,
        .owner = wrong_owner,
        .rent_epoch = 0,
    };

    var account_map: std.AutoArrayHashMapUnmanaged(Pubkey, Account) = .empty;
    defer {
        var iter = account_map.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        account_map.deinit(allocator);
    }
    try account_map.put(allocator, vote_pubkey, account_with_wrong_owner);

    const slot_account_reader: sig.accounts_db.SlotAccountReader = .{
        .account_map = &account_map,
    };

    // Should return InvalidVoteAccountOwner error
    const result = tower.initializeLockoutsFromBank(
        allocator,
        &vote_pubkey,
        100,
        slot_account_reader,
    );

    try std.testing.expectError(error.InvalidVoteAccountOwner, result);
}

test "initializeLockoutsFromBank handles invalid vote state" {
    const allocator = std.testing.allocator;

    var tower: Tower = .init(.noop);

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());

    // Create an account with invalid vote state data (garbage bytes)
    const invalid_data_bytes = try allocator.alloc(u8, 4);
    defer allocator.free(invalid_data_bytes);
    @memcpy(invalid_data_bytes, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });

    const invalid_account = Account{
        .data = AccountDataHandle.initAllocated(invalid_data_bytes),
        .executable = false,
        .lamports = 1000,
        .owner = vote_program.ID,
        .rent_epoch = 0,
    };

    var account_map: std.AutoArrayHashMapUnmanaged(Pubkey, Account) = .empty;
    defer {
        var iter = account_map.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        account_map.deinit(allocator);
    }
    try account_map.put(allocator, vote_pubkey, invalid_account);

    const slot_account_reader: sig.accounts_db.SlotAccountReader = .{
        .account_map = &account_map,
    };

    // Should return BincodeError when trying to deserialize invalid vote state
    const result = tower.initializeLockoutsFromBank(
        allocator,
        &vote_pubkey,
        100,
        slot_account_reader,
    );

    try std.testing.expectError(error.BincodeError, result);
}

test "isRecent with no votes checks root_slot" {
    var tower: Tower = .init(.noop);

    // Set up tower with no votes but with a root
    tower.vote_state.root_slot = 100;
    tower.vote_state.votes = .{};

    // Slots at or before root should NOT be recent
    try std.testing.expect(!tower.isRecent(99));
    try std.testing.expect(!tower.isRecent(100));

    // Slots after root should be recent
    try std.testing.expect(tower.isRecent(101));
    try std.testing.expect(tower.isRecent(200));
}

test "isLockedOut with no votes and root" {
    const allocator = std.testing.allocator;

    var tower: Tower = .init(.noop);
    tower.vote_state.root_slot = 100;
    tower.vote_state.votes = .{};

    // Create ancestors for a slot after root
    var ancestors_map: std.AutoArrayHashMapUnmanaged(Slot, void) = .empty;
    defer ancestors_map.deinit(allocator);

    // Slot 101 should have ancestors including the root (100)
    try ancestors_map.put(allocator, 100, {});
    try ancestors_map.put(allocator, 99, {});
    try ancestors_map.put(allocator, 98, {});

    const ancestors: Ancestors = .{ .ancestors = ancestors_map };

    // Slot 101 (after root, has root as ancestor) should NOT be locked out
    try std.testing.expect(!try tower.isLockedOut(101, &ancestors));

    // Slot 100 (the root itself) SHOULD be locked out (not recent, already finalized)
    try std.testing.expect(try tower.isLockedOut(100, &ancestors));

    // Slot 99 (before root) SHOULD be locked out (not recent)
    try std.testing.expect(try tower.isLockedOut(99, &ancestors));
}
