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
        return std.math.powi(u64, INITIAL_LOCKOUT, self.confirmation_count) catch
            return error.ArithmeticOverflow;
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

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L58
pub const Vote = struct {
    /// A stack of votes starting with the oldest vote
    slots: []const Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
};

pub const VoteStateUpdate = struct {
    /// The proposed tower
    lockouts: []Lockout,
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
};

pub const TowerSync = struct {
    /// The proposed tower
    lockouts: []Lockout,
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
    /// the unique identifier for the chain up to and
    /// including this block. Does not require replaying
    /// in order to compute.
    block_id: Hash,
};

pub const AuthorizedVoters = struct {
    voters: SortedMap(Epoch, Pubkey),

    pub fn init(allocator: std.mem.Allocator, epoch: Epoch, pubkey: Pubkey) !AuthorizedVoters {
        var authorized_voters = SortedMap(Epoch, Pubkey).init(allocator);
        try authorized_voters.put(epoch, pubkey);
        return AuthorizedVoters{ .voters = authorized_voters };
    }

    pub fn deinit(self: AuthorizedVoters) void {
        self.voters.deinit();
    }

    pub fn count(self: *const AuthorizedVoters) usize {
        return self.voters.count();
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
                try self.voters.put(epoch, pubkey);
            }
            return pubkey;
        } else {
            return null;
        }
    }

    pub fn insert(self: *AuthorizedVoters, epoch: Epoch, authorized_voter: Pubkey) !void {
        try self.voters.put(epoch, authorized_voter);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L42
    pub fn purgeAuthorizedVoters(
        self: *AuthorizedVoters,
        allocator: std.mem.Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!bool {
        var expired_keys = std.ArrayList(Epoch).init(allocator);
        defer expired_keys.deinit();

        var voter_iter = self.voters.iterator();
        while (voter_iter.next()) |entry| {
            if (entry.key_ptr.* < current_epoch) {
                try expired_keys.append(entry.key_ptr.*);
            }
        }

        for (expired_keys.items) |key| {
            _ = self.voters.swapRemoveNoSort(key);
        }
        self.voters.sort();

        // Have to uphold this invariant b/c this is
        // 1) The check for whether the vote state is initialized
        // 2) How future authorized voters for uninitialized epochs are set
        //    by this function
        std.debug.assert(self.voters.count() != 0);
        return true;
    }

    pub fn isEmpty(self: *const AuthorizedVoters) bool {
        return self.voters.count() == 0;
    }

    pub fn first(self: *AuthorizedVoters) ?struct { Epoch, Pubkey } {
        var voter_iter = self.voters.iterator();
        if (voter_iter.next()) |entry| {
            return .{ entry.key_ptr.*, entry.value_ptr.* };
        } else {
            return null;
        }
    }

    pub fn last(self: *const AuthorizedVoters) ?struct { Epoch, Pubkey } {
        const last_epoch = self.voters.max orelse return null;
        if (self.voters.get(last_epoch)) |last_pubkey| {
            return .{ last_epoch, last_pubkey };
        } else {
            return null;
        }
    }

    pub fn len(self: *const AuthorizedVoters) usize {
        return self.voters.count();
    }

    pub fn contains(self: *const AuthorizedVoters, epoch: Epoch) bool {
        return self.voters.contains(epoch);
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
        if (self.voters.get(epoch)) |pubkey| {
            return .{ pubkey, true };
        } else {
            _, const values = self.voters.range(0, epoch);
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
                    state.voter_epoch,
                    state.voter,
                );
                return VoteState{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .commission = state.commission,
                    .votes = try VoteStateVersions.landedVotesFromLockouts(allocator, state.votes),
                    .root_slot = state.root_slot,
                    .voters = authorized_voters,
                    .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
                    .epoch_credits = state.epoch_credits,
                    .last_timestamp = state.last_timestamp,
                };
            },
            .v1_14_11 => |state| return VoteState{
                .node_pubkey = state.node_pubkey,
                .withdrawer = state.withdrawer,
                .commission = state.commission,
                .votes = try VoteStateVersions.landedVotesFromLockouts(allocator, state.votes),
                .root_slot = state.root_slot,
                .voters = state.voters,
                .prior_voters = state.prior_voters,
                .epoch_credits = state.epoch_credits,
                .last_timestamp = state.last_timestamp,
            },
            .current => |state| return state,
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteStateVersions) bool {
        switch (self) {
            .v0_23_5 => |state| return state.voter.equals(&Pubkey.ZEROES),
            .v1_14_11 => |state| return state.voters.count() == 0,
            .current => |state| return state.voters.count() == 0,
        }
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_0_23_5.rs#L11
pub const VoteState0_23_5 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for vote transactions
    voter: Pubkey,
    /// when the authorized voter was set/initialized
    voter_epoch: Epoch,

    /// history of prior authorized voters and the epoch ranges for which
    ///  they were set
    prior_voters: RingBuffer(PriorVote, MAX_PRIOR_VOTERS),

    /// the signer for withdrawals
    withdrawer: Pubkey,
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
        withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState0_23_5 {
        return .{
            .node_pubkey = node_pubkey,
            .voter = authorized_voter,
            .voter_epoch = clock.epoch,
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .withdrawer = withdrawer,
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
    withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(Lockout),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    voters: AuthorizedVoters,

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
        withdrawer: Pubkey,
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
            .withdrawer = withdrawer,
            .commission = commission,
            .votes = std.ArrayList(Lockout).init(allocator),
            .root_slot = null,
            .voters = authorized_voters,
            .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: VoteState1_14_11) void {
        self.votes.deinit();
        self.voters.deinit();
        self.epoch_credits.deinit();
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L422
pub const VoteState = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    votes: std.ArrayList(LandedVote),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    voters: AuthorizedVoters,

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
            .withdrawer = Pubkey.ZEROES,
            .commission = 0,
            .votes = std.ArrayList(LandedVote).init(allocator),
            .root_slot = null,
            .voters = AuthorizedVoters{
                .voters = SortedMap(Epoch, Pubkey).init(allocator),
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
        withdrawer: Pubkey,
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
            .voters = authorized_voters,
            .withdrawer = withdrawer,
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
        self.voters.deinit();
        self.epoch_credits.deinit();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteState) bool {
        return self.voters.count() == 0;
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
        if (self.voters.contains(target_epoch)) {
            // Failure, return VoteError.
            return VoteError.too_soon_to_reauthorize;
        }

        const latest_epoch, const latest_pubkey = self.voters.last() orelse
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

        try self.voters.insert(target_epoch, new_authorized_voter);
        // Success, return null.
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L922
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteState,
        allocator: std.mem.Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!Pubkey {
        const pubkey = self.voters
            .getAndCacheAuthorizedVoterForEpoch(current_epoch) catch |err| {
            return switch (err) {
                error.OutOfMemory => err,
            };
        } orelse return InstructionError.InvalidAccountData;
        _ = try self.voters.purgeAuthorizedVoters(allocator, current_epoch);
        return pubkey;
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L777
    ///
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L845
    ///
    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteState to the Rewards program to trade credits for lamports.
    pub fn getCredits(self: *const VoteState) u64 {
        return if (self.epoch_credits.items.len == 0)
            0
        else
            self.epoch_credits.getLast().credits;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L743
    ///
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
                last_epoch_credit.*.epoch = epoch;
            }

            // Remove too old epoch_credits
            if (self.epoch_credits.items.len > MAX_EPOCH_CREDITS_HISTORY) {
                _ = self.epoch_credits.orderedRemove(0);
            }
        }

        // Saturating add for the credits
        {
            const last_epoch_credit = &self.epoch_credits.items[self.epoch_credits.items.len - 1];
            last_epoch_credit.*.credits = last_epoch_credit.credits +| credits;
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/e17340519f792d97cf4af7b9eb81056d475c70f9/programs/vote/src/vote_state/mod.rs#L303
    ///
    // The goal is to check if each slot in vote_slots appears in slot_hashes with the correct hash.
    pub fn checkSlotsAreValid(
        self: *const VoteState,
        vote: *const Vote,
        recent_vote_slots: []const Slot,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
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
                i = std.math.add(usize, i, 1) catch return error.ArithmeticOverflow;
                continue;
            }

            // 2) Find the hash for this slot `s`.
            if (recent_vote_slots[i] !=
                slot_hashes.entries[
                std.math.sub(usize, j, 1) catch
                    return error.ArithmeticOverflow
            ].@"0") {
                // Decrement `j` to find newer slots
                j = std.math.sub(usize, j, 1) catch return error.ArithmeticOverflow;
                continue;
            }

            // 3) Once the hash for `s` is found, bump `s` to the next slot
            // in `vote_slots` and continue.
            i = std.math.add(usize, i, 1) catch return error.ArithmeticOverflow;
            j = std.math.sub(usize, j, 1) catch return error.ArithmeticOverflow;
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L709
    pub fn processNextVoteSlot(
        self: *VoteState,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) !void {
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L939
    ///
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L949
    pub fn doubleLockouts(self: *VoteState) !void {
        const stack_depth = self.votes.items.len;

        for (self.votes.items, 0..) |*vote, i| {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            const confirmation_count = vote.lockout.confirmation_count;
            if (stack_depth > std.math.add(usize, i, confirmation_count) catch
                return error.ArithmeticOverflow)
            {
                vote.lockout.confirmation_count +|= 1;
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L963
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

    /// [agave] https://github.com/anza-xyz/agave/blob/a0717a15d349dc5e0c30384bee6d039377b92167/programs/vote/src/vote_state/mod.rs#L618
    pub fn processVote(
        self: *VoteState,
        allocator: std.mem.Allocator,
        vote: *const Vote,
        slot_hashes: SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (vote.slots.len == 0) {
            return VoteError.empty_slots;
        }

        const earliest_slot_in_history = if (slot_hashes.entries.len != 0)
            slot_hashes.entries[slot_hashes.entries.len - 1].@"0"
        else
            0;

        var recent_vote_slots = std.ArrayList(Slot).init(allocator);
        defer recent_vote_slots.deinit();

        for (vote.slots) |slot| {
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

    /// [agave] https://github.com/anza-xyz/agave/blob/a0717a15d349dc5e0c30384bee6d039377b92167/programs/vote/src/vote_state/mod.rs#L603
    pub fn processVoteUnfiltered(
        self: *VoteState,
        recent_vote_slots: []const Slot,
        vote: *const Vote,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
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

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L772
    ///
    /// Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
    pub fn computeVoteLatency(voted_for_slot: Slot, current_slot: Slot) u8 {
        return @min(current_slot -| voted_for_slot, std.math.maxInt(u8));
    }

    fn compareFn(context: void, key: Slot, mid_item: LandedVote) std.math.Order {
        _ = context;
        return std.math.order(key, mid_item.lockout.slot);
    }

    pub fn contains_slot(self: *const VoteState, candidate_slot: Slot) bool {
        return std.sort.binarySearch(
            LandedVote,
            candidate_slot,
            self.votes.items,
            {},
            compareFn,
        ) != null;
    }

    pub fn checkBeforeProcessVoteStateUpdate(
        self: *VoteState,
        allocator: std.mem.Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        vote_state_update: *VoteStateUpdate,
    ) !?VoteError {
        try self.checkAndFilterProposedVoteState(
            allocator,
            slot_hashes,
            vote_state_update,
        );

        _ = epoch;
        _ = slot;
    }

    pub fn checkAndFilterProposedVoteState(
        self: *VoteState,
        allocator: std.mem.Allocator,
        slot_hashes: *const SlotHashes,
        vote_state_update: *VoteStateUpdate,
    ) !?VoteError {
        if (vote_state_update.lockouts.len == 0) {
            return VoteError.empty_slots;
        }

        const last_proposed_slot = vote_state_update
        // must be nonempty, checked above
            .lockouts[vote_state_update.lockouts.len - 1].slot;

        // If the proposed state is not new enough, return
        if (self.votes.getLastOrNull()) |last_vote| {
            if (last_proposed_slot <= last_vote.lockout.slot) {
                return VoteError.vote_too_old;
            }
        }

        if (slot_hashes.entries.len == 0) {
            return VoteError.vote_too_old;
        }

        const earliest_slot_hash_in_history = slot_hashes
            .entries[slot_hashes.entries.len - 1].@"0";

        // Check if the proposed vote state is too old to be in the SlotHash history
        if (last_proposed_slot < earliest_slot_hash_in_history) {
            // If this is the last slot in the vote update, it must be in SlotHashes,
            // otherwise we have no way of confirming if the hash matches
            return VoteError.vote_too_old;
        }

        if (vote_state_update.*.root) |root| {
            // If the new proposed root `R` is less than the earliest slot hash in the history
            // such that we cannot verify whether the slot was actually was on this fork, set
            // the root to the latest vote in the vote state that's less than R. If no
            // votes from the vote state are less than R, use its root instead.
            if (root < earliest_slot_hash_in_history) {
                // First overwrite the proposed root with the vote state's root
                vote_state_update.*.root = self.root_slot;
                // Then try to find the latest vote in vote state that's less than R
                var iter = std.mem.reverseIterator(self.votes);
                while (iter.next()) |vote| {
                    if (vote.lockout.slot <= root) {
                        vote_state_update.*.root = vote.lockout.slot;
                        break;
                    }
                }
            }
        }

        // Index into the new proposed vote state's slots, starting with the root if it exists then
        // we use this mutable root to fold checking the root slot into the below loop
        // for performance
        var root_to_check = if (vote_state_update.*.root) |root| root else null;
        var proposed_lockouts_index = 0;
        // index into the slot_hashes, starting at the oldest known
        // slot hash
        var slot_hashes_index = slot_hashes.entries.len;
        var proposed_lockouts_indices_to_filter = std.ArrayList(usize).init(allocator);
        // Note:
        //
        // 1) `proposed_lockouts` is sorted from oldest/smallest vote to newest/largest
        // vote, due to the way votes are applied to the vote state (newest votes
        // pushed to the back).
        //
        // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
        // the oldest/smallest vote
        //
        // We check every proposed lockout because have to ensure that every slot is actually part of
        // the history, not just the most recent ones
        while (proposed_lockouts_index < vote_state_update.*.lockouts.len and
            slot_hashes_index > 0)
        {
            const proposed_vote_slot: Slot = blk: {
                if (root_to_check) |root| {
                    break :blk root;
                } else {
                    break :blk vote_state_update.*.lockouts[proposed_lockouts_index].slot;
                }
            };

            if (root_to_check == null and
                proposed_lockouts_index > 0 and
                proposed_vote_slot <= vote_state_update.*.lockouts[
                try std.math.sub(proposed_lockouts_index, 1)
            ].slot) {
                return VoteError.slots_not_ordered;
            }
            const ancestor_slot = slot_hashes.entries[
                try std.math.sub(slot_hashes_index, 1)
            ].@"0";

            // Find if this slot in the proposed vote state exists in the SlotHashes history
            // to confirm if it was a valid ancestor on this fork
            const order = std.math.order(proposed_vote_slot, ancestor_slot);
            switch (order) {
                .lt => {
                    if (slot_hashes_index == slot_hashes.entries.len) {
                        // The vote slot does not exist in the SlotHashes history because it's too old,
                        // i.e. older than the oldest slot in the history.
                        if (proposed_vote_slot >= earliest_slot_hash_in_history) {
                            return VoteError.assertion_failed;
                        }
                        if (!self.contains_slot(proposed_vote_slot) and (root_to_check == null)) {
                            // If the vote slot is both:
                            // 1) Too old
                            // 2) Doesn't already exist in vote state
                            //
                            // Then filter it out
                            try proposed_lockouts_indices_to_filter.append(
                                @as(usize, proposed_lockouts_index),
                            );
                        }
                        if (root_to_check) |new_proposed_root| {
                            // 1. Because `root_to_check.is_some()`, then we know that
                            // we haven't checked the root yet in this loop, so
                            // `proposed_vote_slot` == `new_proposed_root` == `proposed_root`.
                            std.debug.assert(new_proposed_root == proposed_vote_slot);
                            // 2. We know from the assert earlier in the function that
                            // `proposed_vote_slot < earliest_slot_hash_in_history`,
                            // so from 1. we know that `new_proposed_root < earliest_slot_hash_in_history`.
                            if (new_proposed_root >= earliest_slot_hash_in_history) {
                                return VoteError.assertion_failed;
                            }
                            root_to_check = null;
                        } else {
                            proposed_lockouts_index = std.math.add(proposed_lockouts_index, 1) catch
                                return InstructionError.ArithmeticOverflow;
                        }
                        continue;
                    } else {
                        // If the vote slot is new enough to be in the slot history,
                        // but is not part of the slot history, then it must belong to another fork,
                        // which means this proposed vote state is invalid.
                        if (root_to_check != null) {
                            return VoteError.root_on_different_fork;
                        } else {
                            return VoteError.slots_mismatch;
                        }
                    }
                },
                .gt => {
                    // Decrement `slot_hashes_index` to find newer slots in the SlotHashes history
                    slot_hashes_index = std.math.sub(slot_hashes_index, 1) catch
                        return InstructionError.ArithmeticOverflow;
                    continue;
                },
                .eq => {
                    // Once the slot in `proposed_lockouts` is found, bump to the next slot
                    // in `proposed_lockouts` and continue. If we were checking the root,
                    // start checking the vote state instead.
                    if (root_to_check != null) {
                        root_to_check = null;
                    } else {
                        proposed_lockouts_index = std.math.add(proposed_lockouts_index, 1) catch
                            return InstructionError.ArithmeticOverflow;
                        slot_hashes_index = std.math.sub(slot_hashes_index, 1) catch
                            return InstructionError.ArithmeticOverflow;
                    }
                },
            }
        }

        if (proposed_lockouts_index != vote_state_update.*.lockouts.len) {
            // The last vote slot in the proposed vote state did not exist in SlotHashes
            return VoteError.slots_mismatch;
        }

        // This assertion must be true at this point because we can assume by now:
        // 1) proposed_lockouts_index == proposed_lockouts.len()
        // 2) last_proposed_slot >= earliest_slot_hash_in_history
        // 3) !proposed_lockouts.is_empty()
        //
        // 1) implies that during the last iteration of the loop above,
        // `proposed_lockouts_index` was equal to `proposed_lockouts.len() - 1`,
        // and was then incremented to `proposed_lockouts.len()`.
        // This means in that last loop iteration,
        // `proposed_vote_slot ==
        //  proposed_lockouts[proposed_lockouts.len() - 1] ==
        //  last_proposed_slot`.
        //
        // Then we know the last comparison `match proposed_vote_slot.cmp(&ancestor_slot)`
        // is equivalent to `match last_proposed_slot.cmp(&ancestor_slot)`. The result
        // of this match to increment `proposed_lockouts_index` must have been either:
        //
        // 1) The Equal case ran, in which case then we know this assertion must be true
        // 2) The Less case ran, and more specifically the case
        // `proposed_vote_slot < earliest_slot_hash_in_history` ran, which is equivalent to
        // `last_proposed_slot < earliest_slot_hash_in_history`, but this is impossible
        // due to assumption 3) above.
        std.debug.assert(last_proposed_slot == slot_hashes.entries[slot_hashes_index].@"0");

        if (slot_hashes[slot_hashes_index].@"1" != vote_state_update.*.hash) {
            return VoteError.slot_hash_mismatch;
        }

        // Filter out the irrelevant votes
        proposed_lockouts_index = 0;
        var filter_votes_index = 0;

        var i: usize = 0;
        while (i < vote_state_update.items.len) {
            const should_retain = blk: {
                if (filter_votes_index == proposed_lockouts_indices_to_filter.len) {
                    break :blk true;
                } else if (proposed_lockouts_index ==
                    proposed_lockouts_indices_to_filter[filter_votes_index])
                {
                    filter_votes_index +%= 1; // checked add with wrapping
                    break :blk true;
                } else {
                    break :blk true;
                }
            };

            proposed_lockouts_index +%= 1; // checked add with wrapping

            if (!should_retain) {
                _ = vote_state_update.*.lockouts.orderedRemove(i);
            } else {
                i += 1;
            }
        }
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
    withdrawer: Pubkey,
    commission: u8,
) !VoteState {
    if (!builtin.is_test) {
        @compileError("createTestVoteState should only be called in test mode");
    }

    return .{
        .node_pubkey = node_pubkey,
        .voters = if (authorized_voter) |authorized_voter_|
            try AuthorizedVoters.init(allocator, 0, authorized_voter_)
        else
            AuthorizedVoters{
                .voters = SortedMap(Epoch, Pubkey).init(allocator),
            },
        .withdrawer = withdrawer,
        .commission = commission,
        .votes = std.ArrayList(LandedVote).init(allocator),
        .root_slot = null,
        .prior_voters = RingBuffer(PriorVote, MAX_PRIOR_VOTERS).DEFAULT,
        .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
        .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
    };
}

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

test "Lockout.isLockedOutAtSlot" {
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
        try std.testing.expect(try lockout.isLockedOutAtSlot(16));
        try std.testing.expect(try lockout.isLockedOutAtSlot(17));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(18));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(19));
    }
    {
        const lockout = Lockout{
            .slot = 2,
            .confirmation_count = 3,
        };
        try std.testing.expect(try lockout.isLockedOutAtSlot(9));
        try std.testing.expect(try lockout.isLockedOutAtSlot(10));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(11));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(12));
    }
    {
        const lockout = Lockout{
            .slot = 3,
            .confirmation_count = 2,
        };
        try std.testing.expect(try lockout.isLockedOutAtSlot(6));
        try std.testing.expect(try lockout.isLockedOutAtSlot(7));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(8));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(9));
    }
    {
        const lockout = Lockout{
            .slot = 4,
            .confirmation_count = 1,
        };
        try std.testing.expect(try lockout.isLockedOutAtSlot(5));
        try std.testing.expect(try lockout.isLockedOutAtSlot(6));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(7));
        try std.testing.expect(!try lockout.isLockedOutAtSlot(8));
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
        try std.testing.expectEqual(1, vote_state.voters.count());
        var authorized_voter = vote_state.voters;
        try std.testing.expect(authorized_voter.getAuthorizedVoter(0).?.equals(&Pubkey.ZEROES));
        try std.testing.expect(vote_state.withdrawer.equals(&Pubkey.ZEROES));
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
        try std.testing.expectEqual(1, vote_state.voters.count());
        var authorized_voter = vote_state.voters;
        try std.testing.expect(authorized_voter.getAuthorizedVoter(0).?.equals(&Pubkey.ZEROES));
        try std.testing.expect(vote_state.withdrawer.equals(&Pubkey.ZEROES));
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
            expected.voters.count(),
            vote_state.voters.count(),
        );
        var authorized_voter = vote_state.voters;
        var expected_authorized_voter = expected.voters;
        try std.testing.expectEqual(
            expected_authorized_voter.getAuthorizedVoter(0).?,
            authorized_voter.getAuthorizedVoter(0).?,
        );
        try std.testing.expectEqual(
            expected.withdrawer,
            vote_state.withdrawer,
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
    const withdrawer = Pubkey.initRandom(prng.random());
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
        withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

    const target_epoch: Epoch = 5;
    _ = try vote_state.setNewAuthorizedVoter(new_voter, target_epoch);

    const retrived_voter = vote_state.voters.getAuthorizedVoter(target_epoch).?;
    try std.testing.expectEqual(new_voter, retrived_voter);
}

test "VoteState.setNewAuthorizedVoter: too soon to reauthorize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
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
        withdrawer,
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
    const withdrawer = Pubkey.initRandom(prng.random());
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
        withdrawer,
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

test "state.VoteState.isUninitialized: VoteState0_23_5 invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2, // epoch of current authorized voter
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = VoteStateVersions{ .v0_23_5 = try VoteState0_23_5.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
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
            withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "state.VoteState.isUninitialized: VoteStatev1_14_11 invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2, // epoch of current authorized voter
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = VoteStateVersions{ .v1_14_11 = try VoteState1_14_11.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
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
            withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "state.VoteState.isUninitialized: current invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
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
        withdrawer,
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
            withdrawer,
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

test "state.VoteState.lastLockout" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    try std.testing.expectEqual(null, vote_state.lastLockout());

    {
        try vote_state.votes.append(LandedVote{ .latency = 0, .lockout = Lockout{
            .slot = 1,
            .confirmation_count = 1,
        } });

        const actual = vote_state.lastLockout().?;
        try std.testing.expectEqualDeep(
            Lockout{ .slot = 1, .confirmation_count = 1 },
            actual,
        );
    }

    {
        try vote_state.votes.append(LandedVote{ .latency = 1, .lockout = Lockout{
            .slot = 2,
            .confirmation_count = 2,
        } });

        const actual = vote_state.lastLockout().?;
        try std.testing.expectEqualDeep(
            Lockout{ .slot = 2, .confirmation_count = 2 },
            actual,
        );
    }
}

test "state.VoteState.lastVotedSlot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2,
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    try std.testing.expectEqual(null, vote_state.lastVotedSlot());

    {
        try vote_state.votes.append(LandedVote{ .latency = 0, .lockout = Lockout{
            .slot = 1,
            .confirmation_count = 1,
        } });

        try std.testing.expectEqual(1, vote_state.lastVotedSlot().?);
    }

    {
        try vote_state.votes.append(LandedVote{ .latency = 1, .lockout = Lockout{
            .slot = 2,
            .confirmation_count = 2,
        } });

        try std.testing.expectEqual(2, vote_state.lastVotedSlot().?);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1275
test "state.VoteState.lastLockout extended" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 2, // epoch of current authorized voter
        .leader_schedule_epoch = 1,
        .unix_timestamp = 0,
    };

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    for (0..(MAX_LOCKOUT_HISTORY + 1)) |i| {
        try processSlotVoteUnchecked(&vote_state, (INITIAL_LOCKOUT * i));
    }

    // The last vote should have been popped b/c it reached a depth of MAX_LOCKOUT_HISTORY
    try std.testing.expectEqual(vote_state.votes.items.len, MAX_LOCKOUT_HISTORY);
    try std.testing.expectEqual(vote_state.root_slot, 0);
    try checkLockouts(&vote_state);

    // One more vote that confirms the entire stack,
    // the root_slot should change to the
    // second vote
    const top_vote = vote_state.votes.items[0].lockout.slot;
    const slot = try vote_state.lastLockout().?.lastLockedOutSlot();

    try processSlotVoteUnchecked(&vote_state, slot);
    try std.testing.expectEqual(top_vote, vote_state.root_slot);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1499
test "state.VoteState.lockout double lockout after expiration" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    for (0..3) |i| {
        try processSlotVoteUnchecked(&vote_state, (INITIAL_LOCKOUT * i));
    }
    try checkLockouts(&vote_state);

    // Expire the third vote (which was a vote for slot 2). The height of the
    // vote stack is unchanged, so none of the previous votes should have
    // doubled in lockout
    try processSlotVoteUnchecked(&vote_state, (2 + INITIAL_LOCKOUT + 1));
    try checkLockouts(&vote_state);

    // Vote again, this time the vote stack depth increases, so the votes should
    // double for everybody
    try processSlotVoteUnchecked(&vote_state, (2 + INITIAL_LOCKOUT + 2));
    try checkLockouts(&vote_state);

    // Vote again, this time the vote stack depth increases, so the votes should
    // double for everybody
    try processSlotVoteUnchecked(&vote_state, (2 + INITIAL_LOCKOUT + 3));
    try checkLockouts(&vote_state);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1527
test "state.VoteState.lockout expire multiple votes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    for (0..3) |i| {
        try processSlotVoteUnchecked(&vote_state, (INITIAL_LOCKOUT * i));
    }

    try std.testing.expectEqual(3, vote_state.votes.items[0].lockout.confirmation_count);

    // Expire the second and third votes
    const expire_slot =
        vote_state.votes.items[1].lockout.slot +
        (try vote_state.votes.items[1].lockout.lockout()) +
        1;
    try processSlotVoteUnchecked(&vote_state, expire_slot);
    try std.testing.expectEqual(2, vote_state.votes.items.len);

    // Check that the old votes expired
    try std.testing.expectEqual(0, vote_state.votes.items[0].lockout.slot);
    try std.testing.expectEqual(expire_slot, vote_state.votes.items[1].lockout.slot);

    // Process one more vote
    try processSlotVoteUnchecked(&vote_state, expire_slot + 1);

    // Confirmation count for the older first vote should remain unchanged
    try std.testing.expectEqual(3, vote_state.votes.items[0].lockout.confirmation_count);

    // The later votes should still have increasing confirmation counts
    try std.testing.expectEqual(2, vote_state.votes.items[1].lockout.confirmation_count);
    try std.testing.expectEqual(1, vote_state.votes.items[2].lockout.confirmation_count);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1558
test "state.VoteState.getCredits" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try processSlotVoteUnchecked(&vote_state, i);
    }

    try std.testing.expectEqual(0, vote_state.getCredits());

    try processSlotVoteUnchecked(&vote_state, (MAX_LOCKOUT_HISTORY + 1));
    try std.testing.expectEqual(1, vote_state.getCredits());
    try processSlotVoteUnchecked(&vote_state, (MAX_LOCKOUT_HISTORY + 2));
    try std.testing.expectEqual(2, vote_state.getCredits());
    try processSlotVoteUnchecked(&vote_state, (MAX_LOCKOUT_HISTORY + 3));
    try std.testing.expectEqual(3, vote_state.getCredits());
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1577
test "state.VoteState duplicate votes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    try processSlotVoteUnchecked(&vote_state, 0);
    try processSlotVoteUnchecked(&vote_state, 1);
    try processSlotVoteUnchecked(&vote_state, 0);

    try std.testing.expectEqual(1, nthRecentLockout(&vote_state, 0).?.slot);
    try std.testing.expectEqual(0, nthRecentLockout(&vote_state, 1).?.slot);
    try std.testing.expectEqual(null, nthRecentLockout(&vote_state, 2));
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1589
test "state.VoteState nth recent lockout" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        clock,
    );
    defer vote_state.deinit();

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try processSlotVoteUnchecked(&vote_state, i);
    }

    for (0..(MAX_LOCKOUT_HISTORY - 1)) |i| {
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY - i - 1,
            nthRecentLockout(&vote_state, i).?.slot,
        );
    }
    try std.testing.expectEqual(
        null,
        nthRecentLockout(&vote_state, MAX_LOCKOUT_HISTORY),
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1659
test "state.VoteState.processVote skips old votes" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, vote.hash },
        },
    };

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);
    const result = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L2856
test "state.VoteState filter old votes" {
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const allocator = std.testing.allocator;
    const old_vote_slot = 1;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{old_vote_slot};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    // Vote with all slots that are all older than the SlotHashe
    // error with `VotesTooOldAllFiltered`
    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 3, Hash.initRandom(random) },
            .{ 2, Hash.initRandom(random) },
        },
    };

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(VoteError.votes_too_old_all_filtered, maybe_error);

    // Vote with only some slots older than the SlotHashes history should
    // filter out those older slots
    const vote_slot = 2;
    const vote_slot_hash = for (slot_hashes.entries) |entry| {
        if (entry.@"0" == vote_slot) {
            break entry.@"1";
        }
    } else unreachable;

    var second_votes = [_]u64{vote_slot};

    const second_vote = Vote{
        .slots = &second_votes,
        .hash = vote_slot_hash,
        .timestamp = null,
    };
    _ = try vote_state.processVote(allocator, &second_vote, slot_hashes, 0, 0);

    try std.testing.expectEqualDeep(
        Lockout{ .slot = vote_slot, .confirmation_count = 1 },
        vote_state.votes.items[0].lockout,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1677
test "state.VoteState.processVote empty slot hashes" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{},
    };

    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1688
test "state.VoteState.checkSlotsAreValid new vote" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var votes = std.ArrayList(Slot).init(allocator);
    defer votes.deinit();

    try votes.append(0);
    const vote = Vote{
        .slots = votes,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ vote.slots.getLast(), vote.hash },
        },
    };

    try std.testing.expectEqual(
        null,
        try vote_state.checkSlotsAreValid(&vote, vote.slots.items, &slot_hashes),
    );
}

test "state.VoteState.checkSlotsAreValid bad timestamp" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ vote.slots[vote.slots.len - 1], vote.hash },
        },
    };

    try std.testing.expectEqual(
        null,
        try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes),
    );
}

test "state.VoteState.checkSlotsAreValid bad timestamp" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ vote.slots[vote.slots.len - 1], vote.hash },
        },
    };

    try std.testing.expectEqual(
        null,
        try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes),
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1700
test "state.VoteState.checkSlotsAreValid bad hash" {
    const allocator = std.testing.allocator;

    const vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ vote.slots[vote.slots.len - 1], Hash.generateSha256Hash(&vote.hash.data) },
        },
    };

    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.slot_hash_mismatch, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1712
test "state.VoteState.checkSlotsAreValid bad slot" {
    const allocator = std.testing.allocator;

    const vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{1};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, vote.hash },
        },
    };

    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.slots_mismatch, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1724
test "state.VoteState.checkSlotsAreValid duplicate vote" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, vote.hash },
        },
    };

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);
    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1740
test "state.VoteState.checkSlotsAreValid next vote" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, vote.hash },
        },
    };

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);

    var next_votes = [_]u64{ 0, 1 };

    const next_vote = Vote{
        .slots = &next_votes,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const next_slot_hashes = SlotHashes{
        .entries = &.{
            .{ 1, vote.hash },
            .{ 0, vote.hash },
        },
    };

    const result = try vote_state.checkSlotsAreValid(
        &next_vote,
        next_vote.slots,
        &next_slot_hashes,
    );
    try std.testing.expectEqual(null, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1759
test "state.VoteState.checkSlotsAreValid next vote only" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, vote.hash },
        },
    };

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);

    var next_votes = [_]u64{1};

    const next_vote = Vote{
        .slots = &next_votes,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const next_slot_hashes = SlotHashes{
        .entries = &.{
            .{ 1, vote.hash },
            .{ 0, vote.hash },
        },
    };

    const result = try vote_state.checkSlotsAreValid(
        &next_vote,
        next_vote.slots,
        &next_slot_hashes,
    );
    try std.testing.expectEqual(null, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1777
test "state.VoteState.processVote empty slots" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.default(allocator);
    defer vote_state.deinit();

    const vote = Vote{
        .slots = &[_]u64{},
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const maybe_error = try vote_state.processVote(
        allocator,
        &vote,
        SlotHashes{ .entries = &.{} },
        0,
        0,
    );
    try std.testing.expectEqual(VoteError.empty_slots, maybe_error);
}

test "state.VoteState.computeVoteLatency" {
    try std.testing.expectEqual(0, VoteState.computeVoteLatency(10, 10));
    try std.testing.expectEqual(0, VoteState.computeVoteLatency(10, 5));
    try std.testing.expectEqual(5, VoteState.computeVoteLatency(5, 10));
    try std.testing.expectEqual(
        std.math.maxInt(u8),
        VoteState.computeVoteLatency(0, std.math.maxInt(u16)),
    );
}

fn processSlotVoteUnchecked(
    vote_state: *VoteState,
    slot: Slot,
) !void {
    if (!builtin.is_test) {
        @panic("processSlotVoteUnchecked should only be called in test mode");
    }
    var slots = [_]u64{slot};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ vote.slots[vote.slots.len - 1], vote.hash },
        },
    };
    const epoch = if (vote_state.epoch_credits.items.len == 0)
        0
    else
        vote_state.epoch_credits.getLast().epoch;

    _ = try vote_state.processVoteUnfiltered(
        vote.slots,
        &vote,
        &slot_hashes,
        epoch,
        0,
    );
}

fn checkLockouts(vote_state: *const VoteState) !void {
    if (!builtin.is_test) {
        @panic("checkLockouts should only be called in test mode");
    }

    for (vote_state.votes.items, 0..) |*vote, i| {
        const num_votes = vote_state.votes.items.len - i;
        try std.testing.expect(
            try vote.lockout.lockout() == try std.math.powi(u64, INITIAL_LOCKOUT, num_votes),
        );
    }
}

pub fn nthRecentLockout(vote_state: *const VoteState, position: usize) ?Lockout {
    if (!builtin.is_test) {
        @panic("nthRecentLockout should only be called in test mode");
    }
    if (position < vote_state.votes.items.len) {
        const pos = std.math.sub(usize, vote_state.votes.items.len, (position + 1)) catch
            return null;
        return if (pos < vote_state.votes.items.len) vote_state.votes.items[pos].lockout else null;
    }
    return null;
}
