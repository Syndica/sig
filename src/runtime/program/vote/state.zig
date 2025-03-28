/// [agave] Analogous to https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L1
const std = @import("std");
const sig = @import("../../../sig.zig");
const builtin = @import("builtin");

const InstructionError = sig.core.instruction.InstructionError;
const VoteError = sig.runtime.program.vote_program.VoteError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.hash.Hash;
const SortedMap = sig.utils.collections.SortedMap;
const RingBuffer = sig.utils.collections.RingBuffer;

const Clock = sig.runtime.sysvar.Clock;
const SlotHashes = sig.runtime.sysvar.SlotHashes;

pub const MAX_PRIOR_VOTERS: usize = 32;
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const INITIAL_LOCKOUT: usize = 2;

// Maximum number of credits history to keep around
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// Number of slots of grace period for which maximum vote credits are awarded - votes landing within this number of slots of the slot that is being voted on are awarded full credits.
pub const VOTE_CREDITS_GRACE_SLOTS: u8 = 2;

// Maximum number of credits to award for a vote; this number of credits is awarded to votes on slots that land within the grace period. After that grace period, vote credits are reduced.
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u8 = 16;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L357
pub const BlockTimestamp = struct {
    slot: Slot,
    timestamp: i64,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L85
pub const Lockout = struct {
    slot: Slot,
    /// The count inclusive of this slot plus the number of
    /// slots voted on top of this slot.
    confirmation_count: u32,

    pub fn isLockedOutAtSlot(self: *const Lockout, slot: Slot) !bool {
        return try self.lastLockedOutSlot() >= slot;
    }

    // The last slot at which a vote is still locked out. Validators should not
    // vote on a slot in another fork which is less than or equal to this slot
    // to avoid having their stake slashed.
    pub fn lastLockedOutSlot(self: *const Lockout) !Slot {
        return (self.slot +| (try self.lockout()));
    }

    // The number of slots for which this vote is locked
    pub fn lockout(self: *const Lockout) !u64 {
        return std.math.powi(u64, INITIAL_LOCKOUT, self.confirmation_count);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L135
pub const LandedVote = struct {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    latency: u8,
    lockout: Lockout,
};

/// [agave] Analogous tuple [(Pubkey, Epoch, Epoch)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L444.
pub const PriorVote = struct {
    /// authorized voter at the time of the vote.
    key: Pubkey,
    /// the start epoch of the vote (inlcusive).
    start: Epoch,
    /// the end epoch of the vote (exclusive).
    end: Epoch,
};

/// [agave] Analogous tuple [(Epoch, u64, u64)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L448
pub const EpochCredit = struct {
    epoch: Epoch,
    credits: u64,
    prev_credits: u64,
};

pub const Vote = struct {
    /// A stack of votes starting with the oldest vote
    slots: std.ArrayList(Slot),
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
};

pub const AuthorizedVoters = struct {
    authorized_voters: SortedMap(Epoch, Pubkey),

    pub fn init(allocator: std.mem.Allocator, epoch: Epoch, pubkey: Pubkey) !AuthorizedVoters {
        var authorized_voters = SortedMap(Epoch, Pubkey).init(allocator);
        try authorized_voters.put(epoch, pubkey);
        return AuthorizedVoters{ .authorized_voters = authorized_voters };
    }

    pub fn deinit(self: AuthorizedVoters) void {
        self.authorized_voters.deinit();
    }

    pub fn count(self: *const AuthorizedVoters) usize {
        return self.authorized_voters.count();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L22
    pub fn getAuthorizedVoter(
        self: *AuthorizedVoters,
        epoch: Epoch,
    ) ?Pubkey {
        if (self.getOrCalculateAuthorizedVoterForEpoch(epoch)) |entry| {
            return entry[0];
        } else {
            return null;
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L27
    pub fn getAndCacheAuthorizedVoterForEpoch(self: *AuthorizedVoters, epoch: Epoch) !?Pubkey {
        if (self.getOrCalculateAuthorizedVoterForEpoch(epoch)) |entry| {
            const pubkey, const existed = entry;
            if (!existed) {
                try self.authorized_voters.put(epoch, pubkey);
            }
            return pubkey;
        } else {
            return null;
        }
    }

    pub fn insert(self: *AuthorizedVoters, epoch: Epoch, authorized_voter: Pubkey) !void {
        try self.authorized_voters.put(epoch, authorized_voter);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L42
    pub fn purgeAuthorizedVoters(
        self: *AuthorizedVoters,
        allocator: std.mem.Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!bool {
        var expired_keys = std.ArrayList(Epoch).init(allocator);
        defer expired_keys.deinit();

        var voter_iter = self.authorized_voters.iterator();
        while (voter_iter.next()) |entry| {
            if (entry.key_ptr.* < current_epoch) {
                try expired_keys.append(entry.key_ptr.*);
            }
        }

        for (expired_keys.items) |key| {
            _ = self.authorized_voters.swapRemoveNoSort(key);
        }
        self.authorized_voters.sort();

        // Have to uphold this invariant b/c this is
        // 1) The check for whether the vote state is initialized
        // 2) How future authorized voters for uninitialized epochs are set
        //    by this function
        std.debug.assert(self.authorized_voters.count() != 0);
        return true;
    }

    pub fn isEmpty(self: *const AuthorizedVoters) bool {
        return self.authorized_voters.count() == 0;
    }

    pub fn first(self: *AuthorizedVoters) ?struct { Epoch, Pubkey } {
        var voter_iter = self.authorized_voters.iterator();
        if (voter_iter.next()) |entry| {
            return .{ entry.key_ptr.*, entry.value_ptr.* };
        } else {
            return null;
        }
    }

    pub fn last(self: *const AuthorizedVoters) ?struct { Epoch, Pubkey } {
        const last_epoch = self.authorized_voters.max orelse return null;
        if (self.authorized_voters.get(last_epoch)) |last_pubkey| {
            return .{ last_epoch, last_pubkey };
        } else {
            return null;
        }
    }

    pub fn len(self: *const AuthorizedVoters) usize {
        return self.authorized_voters.count();
    }

    pub fn contains(self: *const AuthorizedVoters, epoch: Epoch) bool {
        return self.authorized_voters.contains(epoch);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L90
    ///
    /// Returns the authorized voter at the given epoch if the epoch is >= the
    /// current epoch, and a bool indicating whether the entry for this epoch
    /// exists in the self.authorized_voter map
    fn getOrCalculateAuthorizedVoterForEpoch(
        self: *AuthorizedVoters,
        epoch: Epoch,
    ) ?struct { Pubkey, bool } {
        if (self.authorized_voters.get(epoch)) |pubkey| {
            return .{ pubkey, true };
        } else {
            _, const values = self.authorized_voters.range(0, epoch);
            if (values.len == 0) {
                return null;
            }
            const last_voter = values[values.len - 1];
            return .{ last_voter, false };
        }
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L20
pub const VoteStateVersions = union(enum) {
    v0_23_5: VoteState0_23_5,
    v1_14_11: VoteState1_14_11,
    current: VoteState,

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L80
    fn landedVotesFromLockouts(
        allocator: std.mem.Allocator,
        lockouts: std.ArrayList(Lockout),
    ) !std.ArrayList(LandedVote) {
        var landed_votes = std.ArrayList(LandedVote).init(allocator);
        errdefer landed_votes.deinit();

        for (lockouts.items) |lockout| {
            try landed_votes.append(LandedVote{
                .latency = 0,
                .lockout = lockout,
            });
        }

        return landed_votes;
    }

    pub fn deinit(self: VoteStateVersions) void {
        switch (self) {
            .v0_23_5 => |vote_state| vote_state.deinit(),
            .v1_14_11 => |vote_state| vote_state.deinit(),
            .current => |vote_state| vote_state.deinit(),
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L31
    pub fn convertToCurrent(self: VoteStateVersions, allocator: std.mem.Allocator) !VoteState {
        switch (self) {
            .v0_23_5 => |state| {
                const authorized_voters = try AuthorizedVoters.init(
                    allocator,
                    state.authorized_voter_epoch,
                    state.authorized_voter,
                );
                return VoteState{
                    .node_pubkey = state.node_pubkey,
                    .authorized_withdrawer = state.authorized_withdrawer,
                    .commission = state.commission,
                    .votes = try VoteStateVersions.landedVotesFromLockouts(allocator, state.votes),
                    .root_slot = state.root_slot,
                    .authorized_voters = authorized_voters,
                    .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
                    .epoch_credits = state.epoch_credits,
                    .last_timestamp = state.last_timestamp,
                };
            },
            .v1_14_11 => |state| return VoteState{
                .node_pubkey = state.node_pubkey,
                .authorized_withdrawer = state.authorized_withdrawer,
                .commission = state.commission,
                .votes = try VoteStateVersions.landedVotesFromLockouts(allocator, state.votes),
                .root_slot = state.root_slot,
                .authorized_voters = state.authorized_voters,
                .prior_voters = state.prior_voters,
                .epoch_credits = state.epoch_credits,
                .last_timestamp = state.last_timestamp,
            },
            .current => |state| return state,
        }
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteStateVersions) bool {
        switch (self) {
            .v0_23_5 => |state| return state.authorized_voter.equals(&Pubkey.ZEROES),
            .v1_14_11 => |state| return state.authorized_voters.count() == 0,
            .current => |state| return state.authorized_voters.count() == 0,
        }
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_0_23_5.rs#L11
pub const VoteState0_23_5 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for vote transactions
    authorized_voter: Pubkey,
    /// when the authorized voter was set/initialized
    authorized_voter_epoch: Epoch,

    /// history of prior authorized voters and the epoch ranges for which
    ///  they were set
    prior_voters: RingBuffer(PriorVote, MAX_PRIOR_VOTERS),

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(Lockout),

    root_slot: ?Slot,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    pub fn init(
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState0_23_5 {
        return .{
            .node_pubkey = node_pubkey,
            .authorized_voter = authorized_voter,
            .authorized_voter_epoch = clock.epoch,
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
            .votes = std.ArrayList(Lockout).init(allocator),
            .root_slot = null,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: VoteState0_23_5) void {
        self.votes.deinit();
        self.epoch_credits.deinit();
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_1_14_11.rs#L16
pub const VoteState1_14_11 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(Lockout),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: RingBuffer(PriorVote, MAX_PRIOR_VOTERS),

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const MAX_VOTE_STATE_SIZE: usize = 3731;

    pub fn init(
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState1_14_11 {
        const authorized_voters = try AuthorizedVoters.init(
            allocator,
            clock.epoch,
            authorized_voter,
        );

        return .{
            .node_pubkey = node_pubkey,
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
            .votes = std.ArrayList(Lockout).init(allocator),
            .root_slot = null,
            .authorized_voters = authorized_voters,
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: VoteState1_14_11) void {
        self.votes.deinit();
        self.authorized_voters.deinit();
        self.epoch_credits.deinit();
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L422
pub const VoteState = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    // TODO rename to withdrawer
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(LandedVote),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    // TODO rename to voters
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: RingBuffer(PriorVote, MAX_PRIOR_VOTERS),

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const MAX_VOTE_STATE_SIZE: usize = 3762;

    pub fn default(allocator: std.mem.Allocator) VoteState {
        return .{
            .node_pubkey = Pubkey.ZEROES,
            .authorized_withdrawer = Pubkey.ZEROES,
            .commission = 0,
            .votes = std.ArrayList(LandedVote).init(allocator),
            .root_slot = null,
            .authorized_voters = AuthorizedVoters{
                .authorized_voters = SortedMap(Epoch, Pubkey).init(allocator),
            },
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState {
        const authorized_voters = AuthorizedVoters.init(
            allocator,
            clock.epoch,
            authorized_voter,
        ) catch {
            return InstructionError.Custom;
        };

        return .{
            .node_pubkey = node_pubkey,
            .authorized_voters = authorized_voters,
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
            .votes = std.ArrayList(LandedVote).init(allocator),
            .root_slot = null,
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: VoteState) void {
        self.votes.deinit();
        self.authorized_voters.deinit();
        self.epoch_credits.deinit();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteState) bool {
        return self.authorized_voters.count() == 0;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L862
    pub fn setNewAuthorizedVoter(
        self: *VoteState,
        new_authorized_voter: Pubkey,
        target_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if (self.authorized_voters.contains(target_epoch)) {
            // Failure, return VoteError.
            return VoteError.too_soon_to_reauthorize;
        }

        const latest_epoch, const latest_pubkey = self.authorized_voters.last() orelse
            return InstructionError.InvalidAccountData;

        if (!latest_pubkey.equals(&new_authorized_voter)) {
            const epoch_of_last_authorized_switch = if (self.prior_voters.last()) |prior_voter|
                prior_voter.end
            else
                0;

            if (target_epoch <= latest_epoch) {
                return InstructionError.InvalidAccountData;
            }

            self.prior_voters.append(PriorVote{
                .key = latest_pubkey,
                .start = epoch_of_last_authorized_switch,
                .end = target_epoch,
            });
        }

        try self.authorized_voters.insert(target_epoch, new_authorized_voter);
        // Success, return null.
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L922
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteState,
        allocator: std.mem.Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!Pubkey {
        const pubkey = self.authorized_voters
            .getAndCacheAuthorizedVoterForEpoch(current_epoch) catch |err| {
            return switch (err) {
                error.OutOfMemory => err,
            };
        } orelse return InstructionError.InvalidAccountData;
        _ = try self.authorized_voters.purgeAuthorizedVoters(allocator, current_epoch);
        return pubkey;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/9806724b6d49dec06a9d50396adf26565d6b7745/programs/vote/src/vote_state/mod.rs#L792
    ///
    /// Given a proposed new commission, returns true if this would be a commission increase, false otherwise
    pub fn isCommissionIncrease(self: *const VoteState, commission: u8) bool {
        return commission > self.commission;
    }

    pub fn lastLockout(self: *const VoteState) ?Lockout {
        if (self.votes.getLastOrNull()) |vote| {
            return vote.lockout;
        }
        return null;
    }

    pub fn lastVotedSlot(self: *const VoteState) ?Slot {
        if (self.lastLockout()) |lock_out| {
            return lock_out.slot;
        }
        return null;
    }

    /// Returns the credits to award for a vote at the given lockout slot index
    pub fn creditsForVoteAtIndex(self: *const VoteState, index: usize) u64 {
        const latency = if (index < self.votes.items.len)
            self.votes.items[index].latency
        else
            0;

        // If latency is 0, this means that the Lockout was created from a software version
        // that didn't store vote latencies; in this case, 1 credit is awarded
        if (latency == 0) {
            return 1;
        }

        if (latency <= VOTE_CREDITS_GRACE_SLOTS) {
            // latency was <= VOTE_CREDITS_GRACE_SLOTS, so maximum credits are awarded
            return VOTE_CREDITS_MAXIMUM_PER_SLOT;
        }

        // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
        const diff = latency - VOTE_CREDITS_GRACE_SLOTS;

        if (diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT) {
            // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
            return 1;
        }

        // Subtract diff from VOTE_CREDITS_MAXIMUM_PER_SLOT which is the number of credits to award
        return VOTE_CREDITS_MAXIMUM_PER_SLOT - diff;
    }

    /// increment credits, record credits for last epoch if new epoch
    pub fn incrementCredits(
        self: *VoteState,
        epoch: Epoch,
        credits: u64,
    ) error{OutOfMemory}!void {
        // increment credits, record by epoch

        // never seen a credit
        if (self.epoch_credits.items.len == 0) {
            try self.epoch_credits.append(
                .{ .epoch = epoch, .credits = 0, .prev_credits = 0 },
            );
            // TODO Revisit and compare panic with Agave
        } else if (epoch != self.epoch_credits.getLast().epoch) {
            const last = self.epoch_credits.getLast();
            const last_credits = last.credits;
            const last_prev_credits = last.prev_credits;

            if (last_credits != last_prev_credits) {
                // if credits were earned previous epoch
                // append entry at end of list for the new epoch
                try self.epoch_credits.append(
                    EpochCredit{
                        .epoch = epoch,
                        .credits = last_credits,
                        .prev_credits = last_credits,
                    },
                );
            } else {
                // else just move the current epoch
                const last_epoch_credit =
                    &self.epoch_credits.items[self.epoch_credits.items.len - 1];
                last_epoch_credit.epoch = epoch;
            }

            // Remove too old epoch_credits
            if (self.epoch_credits.items.len > MAX_EPOCH_CREDITS_HISTORY) {
                _ = self.epoch_credits.orderedRemove(0);
            }
        }

        // Saturating add for the credits
        {
            const last_epoch_credit = &self.epoch_credits.items[self.epoch_credits.items.len - 1];
            last_epoch_credit.credits = last_epoch_credit.credits +| credits;
        }
    }

    // TODO add logging
    // The goal is to check if each slot in vote_slots appears in slot_hashes with the correct hash.
    pub fn checkSlotsAreValid(
        self: *const VoteState,
        vote: *const Vote,
        recent_vote_slots: []const Slot,
        slot_hashes: *const SlotHashes,
    ) (error{Overflow} || InstructionError)!?VoteError {
        const vote_hash = vote.hash;

        // index into the vote's slots, starting at the oldest slot
        var i: usize = 0;

        // index into the slot_hashes, starting at the oldest known slot hash
        var j: usize = slot_hashes.entries.len;

        // Note:
        //
        // 1) `vote_slots` is sorted from oldest/smallest vote to newest/largest
        // vote, due to the way votes are applied to the vote state (newest votes
        // pushed to the back).
        //
        // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
        // the oldest/smallest vote
        //
        // So:
        // for vote_states we are iterating from 0 up to the (size - 1) index
        // for slot_hashes we are iterating from (size - 1) index down to 0
        while (i < recent_vote_slots.len and j > 0) {
            // 1) increment `i` to find the smallest slot `s` in `vote_slots`
            // where `s` >= `last_voted_slot`
            // vote slot `s` to be processed must be newer than last voted slot
            const less_than_last_voted_slot =
                if (self.lastVotedSlot()) |last_voted_slot|
                recent_vote_slots[i] <= last_voted_slot
            else
                false;

            if (less_than_last_voted_slot) {
                i = try std.math.add(usize, i, 1);
                continue;
            }

            // 2) Find the hash for this slot `s`.
            if (recent_vote_slots[i] !=
                slot_hashes.entries[try std.math.sub(usize, j, 1)].@"0")
            {
                // Decrement `j` to find newer slots
                j = try std.math.sub(usize, j, 1);
                continue;
            }

            // 3) Once the hash for `s` is found, bump `s` to the next slot
            // in `vote_slots` and continue.
            i = try std.math.add(usize, i, 1);
            j = try std.math.sub(usize, j, 1);
        }

        if (j == slot_hashes.entries.len) {
            // This means we never made it to steps 2) or 3) above, otherwise
            // `j` would have been decremented at least once. This means
            // there are not slots in `vote_slots` greater than `last_voted_slot`
            return VoteError.vote_too_old;
        }

        if (i != recent_vote_slots.len) {
            // This means there existed some slot for which we couldn't find
            // a matching slot hash in step 2)
            return VoteError.slots_mismatch;
        }
        if (!vote_hash.eql(slot_hashes.entries[j].@"1")) {
            // This means the newest slot in the `vote_slots` has a match that
            // doesn't match the expected hash for that slot on this
            // fork
            return VoteError.slot_hash_mismatch;
        }
        return null;
    }

    pub fn processNextVoteSlot(
        self: *VoteState,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{Underflow} || error{Overflow} || error{OutOfMemory})!void {
        // Ignore votes for slots earlier than we already have votes for
        if (self.lastVotedSlot()) |last_voted_slot| {
            if (next_vote_slot <= last_voted_slot) {
                return;
            }
        }

        try self.popExpiredVotes(next_vote_slot);

        const landed_vote: LandedVote = .{
            .latency = VoteState.computeVoteLatency(next_vote_slot, current_slot),
            .lockout = Lockout{ .confirmation_count = 1, .slot = next_vote_slot },
        };

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if (self.votes.items.len == MAX_LOCKOUT_HISTORY) {
            const credits = self.creditsForVoteAtIndex(0);
            const popped_vote = self.votes.orderedRemove(0);
            self.root_slot = popped_vote.lockout.slot;
            try self.incrementCredits(epoch, credits);
        }

        try self.votes.append(landed_vote);
        try self.doubleLockouts();
    }

    /// Pop all recent votes that are not locked out at the next vote slot.
    /// This allows validators to switch forks once their votes for another fork have
    /// expired. This also allows validators to continue voting on recent blocks in
    /// the same fork without increasing lockouts.
    pub fn popExpiredVotes(
        self: *VoteState,
        next_vote_slot: Slot,
    ) !void {
        while (self.lastLockout()) |vote| {
            if (!try vote.isLockedOutAtSlot(next_vote_slot)) {
                _ = self.votes.popOrNull();
            } else {
                break;
            }
        }
    }

    pub fn doubleLockouts(self: *VoteState) error{Overflow}!void {
        const stack_depth = self.votes.items.len;

        for (self.votes.items, 0..) |*vote, i| {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            const confirmation_count = vote.lockout.confirmation_count;
            if (stack_depth > try std.math.add(usize, i, confirmation_count)) {
                vote.lockout.confirmation_count +|= 1;
            }
        }
    }

    pub fn processTimestamp(
        self: *VoteState,
        slot: Slot,
        timestamp: i64,
    ) ?VoteError {
        const new_timestamp = BlockTimestamp{ .slot = slot, .timestamp = timestamp };

        if (slot < self.last_timestamp.slot or timestamp < self.last_timestamp.timestamp or
            (slot == self.last_timestamp.slot and
            !std.meta.eql(new_timestamp, self.last_timestamp) and
            self.last_timestamp.slot != 0))
        {
            return VoteError.timestamp_too_old;
        }

        self.last_timestamp = new_timestamp;
        return null;
    }

    pub fn processVote(
        self: *VoteState,
        allocator: std.mem.Allocator,
        vote: *const Vote,
        slot_hashes: SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{Overflow} || error{Underflow} || error{OutOfMemory} || InstructionError)!?VoteError {
        if (vote.slots.items.len == 0) {
            return VoteError.empty_slots;
        }

        const earliest_slot_in_history = blk: {
            if (slot_hashes.entries.len > 0) {
                const slot, _ = slot_hashes.entries[slot_hashes.entries.len - 1];
                break :blk slot;
            } else {
                break :blk 0;
            }
        };
        var recent_vote_slots = std.ArrayList(Slot).init(allocator);
        defer recent_vote_slots.deinit();

        for (vote.slots.items) |slot| {
            if (slot >= earliest_slot_in_history) {
                try recent_vote_slots.append(slot);
            }
        }

        if (recent_vote_slots.items.len == 0) {
            return VoteError.votes_too_old_all_filtered;
        }

        return self.processVoteUnfiltered(
            recent_vote_slots.items,
            vote,
            &slot_hashes,
            epoch,
            current_slot,
        );
    }

    pub fn processVoteUnfiltered(
        self: *VoteState,
        recent_vote_slots: []const Slot,
        vote: *const Vote,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{Underflow} || error{Overflow} || error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkSlotsAreValid(
            vote,
            recent_vote_slots,
            slot_hashes,
        )) |err| {
            return err;
        }

        for (recent_vote_slots) |recent_vote_slot| {
            try self.processNextVoteSlot(recent_vote_slot, epoch, current_slot);
        }

        return null;
    }

    /// Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
    pub fn computeVoteLatency(voted_for_slot: Slot, current_slot: Slot) u8 {
        return @intCast(@min(current_slot -| voted_for_slot, std.math.maxInt(u8)));
    }
};

pub const VoteAuthorize = enum {
    withdrawer,
    voter,
};

pub fn createTestVoteState(
    allocator: std.mem.Allocator,
    node_pubkey: Pubkey,
    authorized_voter: ?Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
) !VoteState {
    if (!builtin.is_test) {
        @panic("createTestVoteState should only be called in test mode");
    }

    return .{
        .node_pubkey = node_pubkey,
        .authorized_voters = if (authorized_voter) |authorized_voter_|
            try AuthorizedVoters.init(allocator, 0, authorized_voter_)
        else
            AuthorizedVoters{
                .authorized_voters = SortedMap(Epoch, Pubkey).init(allocator),
            },
        .authorized_withdrawer = authorized_withdrawer,
        .commission = commission,
        .votes = std.ArrayList(LandedVote).init(allocator),
        .root_slot = null,
        .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
        .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
        .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
    };
}

// TODO how can InstructionContext be easily passed/mocked for testing?
pub fn verifyAndGetVoteState(
    allocator: std.mem.Allocator,
    ic: *sig.runtime.InstructionContext,
    vote_account: *sig.runtime.BorrowedAccount,
    clock: *const Clock,
) (error{OutOfMemory} || InstructionError)!VoteState {
    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );

    if (!versioned_state.isUninitialized()) {
        return (InstructionError.UninitializedAccount);
    }
    var vote_state = try versioned_state.convertToCurrent(allocator);

    const authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(allocator, clock.epoch);
    if (!ic.info.isPubkeySigner(authorized_voter)) {
        return InstructionError.MissingRequiredSignature;
    }

    return vote_state;
}

test "Lockout.lockout" {
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 1,
        };
        try std.testing.expectEqual(2, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 2,
        };
        try std.testing.expectEqual(4, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 3,
        };
        try std.testing.expectEqual(8, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 4,
        };
        try std.testing.expectEqual(16, lockout.lockout());
    }
}

test "Lockout.lastLockedOutSlot" {
    // | vote | vote slot | lockout | lock expiration slot |
    // |------|-----------|---------|----------------------|
    // | 4    | 4         | 2       | 6                    |
    // | 3    | 3         | 4       | 7                    |
    // | 2    | 2         | 8       | 10                   |
    // | 1    | 1         | 16      | 17                   |
    {
        const lockout = Lockout{
            .slot = 1,
            .confirmation_count = 4,
        };
        try std.testing.expectEqual(17, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 2,
            .confirmation_count = 3,
        };
        try std.testing.expectEqual(10, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 3,
            .confirmation_count = 2,
        };
        try std.testing.expectEqual(7, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 4,
            .confirmation_count = 1,
        };
        try std.testing.expectEqual(6, lockout.lastLockedOutSlot());
    }
}

test "VoteState.convertToCurrent" {
    const allocator = std.testing.allocator;
    // VoteState0_23_5 -> Current
    {
        const vote_state_0_23_5 = VoteStateVersions{ .v0_23_5 = try VoteState0_23_5.init(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            Clock{
                .slot = 0,
                .epoch_start_timestamp = 0,
                .epoch = 0,
                .leader_schedule_epoch = 0,
                .unix_timestamp = 0,
            },
        ) };
        const vote_state = try VoteStateVersions.convertToCurrent(vote_state_0_23_5, allocator);
        defer vote_state.deinit();
        try std.testing.expectEqual(1, vote_state.authorized_voters.count());
        var authorized_voter = vote_state.authorized_voters;
        try std.testing.expect(authorized_voter.getAuthorizedVoter(0).?.equals(&Pubkey.ZEROES));
        try std.testing.expect(vote_state.authorized_withdrawer.equals(&Pubkey.ZEROES));
        try std.testing.expectEqual(10, vote_state.commission);
        try std.testing.expectEqual(0, vote_state.votes.items.len);
        try std.testing.expectEqual(null, vote_state.root_slot);
        try std.testing.expect(vote_state.prior_voters.is_empty);
        try std.testing.expectEqual(0, vote_state.epoch_credits.items.len);
        try std.testing.expectEqual(0, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(0, vote_state.last_timestamp.timestamp);
    }
    // VoteStatev1_14_11 -> Current
    {
        const vote_state_1_14_1 = VoteStateVersions{ .v1_14_11 = try VoteState1_14_11.init(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            Clock{
                .slot = 0,
                .epoch_start_timestamp = 0,
                .epoch = 0,
                .leader_schedule_epoch = 0,
                .unix_timestamp = 0,
            },
        ) };
        const vote_state = try VoteStateVersions.convertToCurrent(vote_state_1_14_1, allocator);
        defer vote_state.deinit();
        try std.testing.expectEqual(1, vote_state.authorized_voters.count());
        var authorized_voter = vote_state.authorized_voters;
        try std.testing.expect(authorized_voter.getAuthorizedVoter(0).?.equals(&Pubkey.ZEROES));
        try std.testing.expect(vote_state.authorized_withdrawer.equals(&Pubkey.ZEROES));
        try std.testing.expectEqual(10, vote_state.commission);
        try std.testing.expectEqual(0, vote_state.votes.items.len);
        try std.testing.expectEqual(null, vote_state.root_slot);
        try std.testing.expect(vote_state.prior_voters.is_empty);
        try std.testing.expectEqual(0, vote_state.epoch_credits.items.len);
        try std.testing.expectEqual(0, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(0, vote_state.last_timestamp.timestamp);
    }

    // Current -> Current
    {
        const expected = try VoteState.init(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            Clock{
                .slot = 0,
                .epoch_start_timestamp = 0,
                .epoch = 0,
                .leader_schedule_epoch = 0,
                .unix_timestamp = 0,
            },
        );

        const vote_state_1_14_1 = VoteStateVersions{ .current = expected };
        const vote_state = try VoteStateVersions.convertToCurrent(vote_state_1_14_1, allocator);
        defer vote_state.deinit();
        try std.testing.expectEqual(
            expected.authorized_voters.count(),
            vote_state.authorized_voters.count(),
        );
        var authorized_voter = vote_state.authorized_voters;
        var expected_authorized_voter = expected.authorized_voters;
        try std.testing.expectEqual(
            expected_authorized_voter.getAuthorizedVoter(0).?,
            authorized_voter.getAuthorizedVoter(0).?,
        );
        try std.testing.expectEqual(
            expected.authorized_withdrawer,
            vote_state.authorized_withdrawer,
        );
        try std.testing.expectEqual(expected.commission, vote_state.commission);
        try std.testing.expectEqual(expected.votes.items.len, vote_state.votes.items.len);
        try std.testing.expectEqual(expected.root_slot, vote_state.root_slot);
        try std.testing.expectEqual(
            expected.prior_voters.is_empty,
            vote_state.prior_voters.is_empty,
        );
        try std.testing.expectEqual(
            expected.epoch_credits.items.len,
            vote_state.epoch_credits.items.len,
        );
        try std.testing.expectEqual(expected.last_timestamp.slot, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(
            expected.last_timestamp.timestamp,
            vote_state.last_timestamp.timestamp,
        );
    }
}

test "VoteState.setNewAuthorizedVoter: success" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

    const target_epoch: Epoch = 5;
    _ = try vote_state.setNewAuthorizedVoter(new_voter, target_epoch);

    const retrived_voter = vote_state.authorized_voters.getAuthorizedVoter(target_epoch).?;
    try std.testing.expectEqual(new_voter, retrived_voter);
}

test "VoteState.setNewAuthorizedVoter: too soon to reauthorize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

    // Same as initial epoch
    const target_epoch: Epoch = 0;
    const err = try vote_state.setNewAuthorizedVoter(new_voter, target_epoch);
    try std.testing.expectEqual(
        VoteError.too_soon_to_reauthorize,
        err.?,
    );
}

test "VoteState.setNewAuthorizedVoter: invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2, // epoch of current authorized voter
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

    const target_epoch: Epoch = 1;
    try std.testing.expectError(
        InstructionError.InvalidAccountData,
        vote_state.setNewAuthorizedVoter(new_voter, target_epoch),
    );
}

test "VoteState.isUninitialized: invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2, // epoch of current authorized voter
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    try std.testing.expect(!vote_state.isUninitialized());

    const uninitialized_state = VoteStateVersions{
        .current = try createTestVoteState(
            allocator,
            node_publey,
            null, // Authorized voters not set
            authorized_withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "AuthorizedVoters.init" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 10, voter_pubkey);
    defer authorized_voters.deinit();
    try std.testing.expectEqual(authorized_voters.count(), 1);
}

test "AuthorizedVoters.getAuthorizedVoter" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    const new_pubkey = Pubkey.initRandom(prng.random());

    var authorized_voters = try AuthorizedVoters.init(allocator, 10, voter_pubkey);
    defer authorized_voters.deinit();

    const epoch: Epoch = 15;
    try authorized_voters.insert(epoch, new_pubkey);
    try std.testing.expectEqual(new_pubkey, authorized_voters.getAuthorizedVoter(epoch).?);
}

test "AuthorizedVoters.purgeAuthorizedVoters" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit();

    try authorized_voters.insert(10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(15, Pubkey.initRandom(prng.random()));

    try std.testing.expectEqual(authorized_voters.count(), 3);
    _ = try authorized_voters.purgeAuthorizedVoters(allocator, 12);
    // Only epoch 15 should remain
    try std.testing.expectEqual(authorized_voters.count(), 1);
}

test "AuthorizedVoters.first" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit();

    try authorized_voters.insert(10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(15, Pubkey.initRandom(prng.random()));

    const epoch, const pubkey = authorized_voters.first().?;
    try std.testing.expectEqual(5, epoch);
    try std.testing.expectEqual(voter_pubkey, pubkey);
}

test "AuthorizedVoters.last" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(
        allocator,
        5,
        Pubkey.initRandom(prng.random()),
    );
    defer authorized_voters.deinit();

    try authorized_voters.insert(10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(15, voter_pubkey);

    const epoch, const pubkey = authorized_voters.last().?;
    try std.testing.expectEqual(15, epoch);
    try std.testing.expectEqual(voter_pubkey, pubkey);
}

test "AuthorizedVoters.isEmpty" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    var authorized_voters = try AuthorizedVoters.init(
        allocator,
        5,
        Pubkey.initRandom(prng.random()),
    );
    defer authorized_voters.deinit();
    try std.testing.expect(!authorized_voters.isEmpty());
}

test "AuthorizedVoters.len" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit();

    try std.testing.expectEqual(authorized_voters.count(), 1);

    try authorized_voters.insert(10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(15, Pubkey.initRandom(prng.random()));

    try std.testing.expectEqual(authorized_voters.count(), 3);
}

test "AuthorizedVoters.contains" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit();

    try std.testing.expect(authorized_voters.contains(5));
    try std.testing.expect(!authorized_voters.contains(15));
}
