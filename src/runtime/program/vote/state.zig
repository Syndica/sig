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
        }
        return null;
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L27
    pub fn getAndCacheAuthorizedVoterForEpoch(self: *AuthorizedVoters, epoch: Epoch) !?Pubkey {
        if (self.getOrCalculateAuthorizedVoterForEpoch(epoch)) |entry| {
            const pubkey, const existed = entry;
            if (!existed) {
                try self.authorized_voters.put(epoch, pubkey);
            }
            return pubkey;
        }
        return null;
    }

    pub fn insert(self: *AuthorizedVoters, epoch: Epoch, authorizedVoter: Pubkey) !void {
        try self.authorized_voters.put(epoch, authorizedVoter);
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L42
    pub fn purgeAuthorizedVoters(
        self: *AuthorizedVoters,
        allocator: std.mem.Allocator,
        currentEpoch: Epoch,
    ) bool {
        var expired_keys = std.ArrayList(Epoch).init(allocator);
        defer expired_keys.deinit();

        var voter_iter = self.authorized_voters.iterator();
        while (voter_iter.next()) |entry| {
            if (entry.key_ptr.* < currentEpoch) {
                expired_keys.append(entry.key_ptr.*) catch unreachable;
            }
        }

        for (expired_keys.items) |key| {
            _ = self.authorized_voters.orderedRemove(key);
        }

        std.debug.assert(self.authorized_voters.count() != 0);
        return true;
    }

    pub fn isEmpty(self: *const AuthorizedVoters) bool {
        return self.authorized_voters.count() == 0;
    }

    pub fn first(self: *const AuthorizedVoters) ?struct { epoch: Epoch, pubkey: Pubkey } {
        var voter_iter = self.authorized_voters.iterator();
        if (voter_iter.next()) |entry| {
            return .{ .epoch = entry.key_ptr.*, .pubkey = entry.value_ptr.* };
        }

        return null;
    }

    pub fn last(self: *const AuthorizedVoters) ?struct { Epoch, Pubkey } {
        const last_epoch = self.authorized_voters.max orelse return null;
        if (self.authorized_voters.get(last_epoch)) |last_pubkey| {
            return .{ last_epoch, last_pubkey };
        }
        return null;
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
        var landedVotes = std.ArrayList(LandedVote).init(allocator);
        errdefer landedVotes.deinit();

        for (lockouts.items) |lockout| {
            try landedVotes.append(LandedVote{
                .latency = 0,
                .lockout = lockout,
            });
        }

        return landedVotes;
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

    // TODO move to union.
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
        authorized_pubkey: Pubkey,
        target_epoch: Epoch,
    ) (InstructionError || VoteError)!void {

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if (self.authorized_voters.contains(target_epoch)) {
            return VoteError.TooSoonToReauthorize;
        }

        const epoch, const pubkey = self.authorized_voters.last() orelse
            return InstructionError.InvalidAccountData;

        if (!pubkey.equals(&authorized_pubkey)) {
            const epoch_of_last_authorized_switch = if (self.prior_voters.last()) |prior_voter|
                prior_voter.end
            else
                0;

            if (target_epoch <= epoch) {
                return InstructionError.InvalidAccountData;
            }

            self.prior_voters.append(PriorVote{
                .key = pubkey,
                .start = epoch_of_last_authorized_switch,
                .end = target_epoch,
            });
        }

        self.authorized_voters.insert(target_epoch, authorized_pubkey) catch
        // TODO: Is it okay to convert out of memory to InvalidAccountData?
            return InstructionError.InvalidAccountData;
    }

    /// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L922
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteState,
        allocator: std.mem.Allocator,
        current_epoch: Epoch,
    ) InstructionError!Pubkey {
        const pubkey = self.authorized_voters
            .getAndCacheAuthorizedVoterForEpoch(current_epoch) catch |err| {
            return switch (err) {
                // TODO: Okay to convert out of memory to InvalidAccountData?
                error.OutOfMemory => InstructionError.InvalidAccountData,
            };
        } orelse return InstructionError.InvalidAccountData;
        _ = self.authorized_voters.purgeAuthorizedVoters(allocator, current_epoch);
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
