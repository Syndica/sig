/// Analogous to https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L1
const std = @import("std");
const sig = @import("../../../sig.zig");
const builtin = @import("builtin");

const InstructionError = sig.core.instruction.InstructionError;
const VoteError = sig.runtime.program.vote_program.VoteError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const SortedMap = sig.utils.collections.SortedMap;
const RingBuffer = sig.utils.collections.RingBuffer;

const Clock = sig.runtime.sysvar.Clock;

pub const MAX_PRIOR_VOTERS: usize = 32;

/// [Agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L357
pub const BlockTimestamp = struct {
    slot: Slot,
    timestamp: i64,
};

/// [Agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L85
pub const Lockout = struct {
    slot: Slot,
    confirmation_count: u32,
};

/// [Agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L135
pub const LandedVote = struct {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    latency: u8,
    lockout: Lockout,
};

/// Analogous tuple [(Pubkey, Epoch, Epoch)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L444.
pub const PriorVote = struct {
    /// authorized voter at the time of the vote.
    key: Pubkey,
    /// the start epoch of the vote (inlcusive).
    start: Epoch,
    /// the end epoch of the vote (exclusive).
    end: Epoch,
};

/// Analogous tuple [(Epoch, u64, u64)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L448
pub const EpochCredit = struct {
    epoch: Epoch,
    credits: u64,
    prev_credits: u64,
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

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L22
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

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L27
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

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L42
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
            _ = self.authorized_voters.orderedRemove(key);
        }

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

    // TODO Add method that returns iterator over authorized_voters

    /// https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L90
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

/// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L20
pub const VoteStateVersions = union(enum) {
    v0_23_5: VoteState0_23_5,
    v1_14_11: VoteState1_14_11,
    current: VoteState,

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L80
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

    // For bincode
    pub fn serializedSize(self: VoteStateVersions) !usize {
        return sig.bincode.sizeOf(self, .{});
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L31
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
};

/// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_0_23_5.rs#L11
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

    // For bincode.
    pub fn serializedSize(self: VoteState0_23_5) !usize {
        return sig.bincode.sizeOf(self, .{});
    }
};

/// https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_1_14_11.rs#L16
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

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3731;
    }

    // For bincode.
    pub fn serializedSize(self: VoteState1_14_11) !usize {
        return sig.bincode.sizeOf(self, .{});
    }
};

/// [Agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L422
///
/// Must support `bincode` and `serializedSize` methods for writing to the account data.
pub const VoteState = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
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

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteState) bool {
        return self.authorized_voters.count() == 0;
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3762;
    }

    /// https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L862
    pub fn setNewAuthorizedVoter(
        self: *VoteState,
        new_authorized_voter: Pubkey,
        target_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError || VoteError)!void {

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if (self.authorized_voters.contains(target_epoch)) {
            return VoteError.TooSoonToReauthorize;
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
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L922
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

    // For bincode.
    pub fn serializedSize(self: VoteState) !usize {
        return sig.bincode.sizeOf(self, .{});
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
) VoteState {
    if (!builtin.is_test) {
        @panic("createTestVoteState should only be called in test mode");
    }

    return .{
        .node_pubkey = node_pubkey,
        .authorized_voters = if (authorized_voter) |authorized_voter_|
            AuthorizedVoters.init(allocator, 0, authorized_voter_) catch unreachable
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
    try vote_state.setNewAuthorizedVoter(new_voter, target_epoch);

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
    try std.testing.expectError(
        VoteError.TooSoonToReauthorize,
        vote_state.setNewAuthorizedVoter(new_voter, target_epoch),
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

    var vote_state = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

    try std.testing.expect(!vote_state.isUninitialized());

    const uninitialized_state = createTestVoteState(
        allocator,
        node_publey,
        null, // Authorized voters not set
        authorized_withdrawer,
        commission,
    );

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
