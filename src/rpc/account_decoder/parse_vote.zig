/// Types for parsing a vote account for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const account_decoder = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const vote_program = sig.runtime.program.vote;
const ParseError = account_decoder.ParseError;

/// Parses a vote account's data into a `VoteAccountType` for JSON encoding in RPC responses.
/// TODO: somehow enforce arena allocation for all allocations here?
pub fn parse_vote(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
) ParseError!VoteAccountType {
    var vote_state_versions = sig.bincode.read(
        allocator,
        vote_program.state.VoteStateVersions,
        reader,
        .{},
    ) catch return ParseError.InvalidAccountData;
    defer vote_state_versions.deinit(allocator);

    var vote_state = vote_state_versions.convertToCurrent(allocator) catch
        return ParseError.OutOfMemory;
    defer vote_state.deinit(allocator);

    const votes = try allocator.alloc(
        UiLandedVote,
        vote_state.votes.items.len,
    );
    for (vote_state.votes.items, 0..) |vote, i| {
        votes[i] = UiLandedVote{
            .latency = vote.latency,
            .slot = vote.lockout.slot,
            .confirmation_count = vote.lockout.confirmation_count,
        };
    }

    const auth_voters = try allocator.alloc(
        UiAuthorizedVoter,
        vote_state.voters.len(),
    );
    const voter_keys = vote_state.voters.voters.keys();
    const voter_values = vote_state.voters.voters.values();
    for (auth_voters, voter_keys, voter_values) |*av, epoch, voter_pubkey| {
        av.* = UiAuthorizedVoter{
            .epoch = epoch,
            .authorized_voter = voter_pubkey.base58String(),
        };
    }

    const epoch_credits = try allocator.alloc(
        UiEpochCredits,
        vote_state.epoch_credits.items.len,
    );
    for (epoch_credits, vote_state.epoch_credits.items) |*ec, vote_state_ec| {
        ec.* = UiEpochCredits{
            .epoch = vote_state_ec.epoch,
            .credits = vote_state_ec.credits,
            .previous_credits = vote_state_ec.prev_credits,
        };
    }

    // TODO: handle prior voters. Right now agave does not handle them, and is slated to remove them when v4 is cut.
    // [agave] https://github.com/anza-xyz/agave/blob/f682b30e268bf89e7a9aa5799a1a0258b27d5dd3/account-decoder/src/parse_vote.rs#L37
    const prior_voters: []const UiPriorVoter = &.{};

    const ui_vote_state = UiVoteState{
        .node_pubkey = vote_state.node_pubkey.base58String(),
        .authorized_withdrawer = vote_state.withdrawer.base58String(),
        .commission = vote_state.commission,
        .votes = votes,
        .root_slot = vote_state.root_slot,
        .authorized_voters = auth_voters,
        .prior_voters = prior_voters,
        .epoch_credits = epoch_credits,
        .last_timestamp = UiBlockTimestamp{
            .slot = vote_state.last_timestamp.slot,
            .timestamp = vote_state.last_timestamp.timestamp,
        },
    };

    return VoteAccountType{
        .vote = ui_vote_state,
    };
}

/// Wrapper enum matching Agave's VoteAccountType.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L54
pub const VoteAccountType = union(enum) {
    vote: UiVoteState,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        switch (self) {
            .vote => |state| {
                try jw.objectField("type");
                try jw.write("vote");
                try jw.objectField("info");
                try state.jsonStringify(jw);
            },
        }

        try jw.endObject();
    }
};

/// The main vote state UI representation.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L61
pub const UiVoteState = struct {
    node_pubkey: Pubkey.Base58String,
    authorized_withdrawer: Pubkey.Base58String,
    commission: u8,
    votes: []const UiLandedVote,
    root_slot: ?u64,
    authorized_voters: []UiAuthorizedVoter,
    prior_voters: []const UiPriorVoter,
    epoch_credits: []const UiEpochCredits,
    last_timestamp: UiBlockTimestamp,
    // TODO: vote state v4 fields for SIMD-0185

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();

        try jw.objectField("nodePubkey");
        try jw.write(self.node_pubkey.slice());

        try jw.objectField("authorizedWithdrawer");
        try jw.write(self.authorized_withdrawer.slice());

        try jw.objectField("commission");
        try jw.write(self.commission);

        try jw.objectField("votes");
        try jw.beginArray();
        for (self.votes) |v| try v.jsonStringify(jw);
        try jw.endArray();

        try jw.objectField("rootSlot");
        try jw.write(self.root_slot);

        try jw.objectField("authorizedVoters");
        try jw.beginArray();
        for (self.authorized_voters) |av| try av.jsonStringify(jw);
        try jw.endArray();

        try jw.objectField("priorVoters");
        try jw.beginArray();
        for (self.prior_voters) |pv| try pv.jsonStringify(jw);
        try jw.endArray();

        try jw.objectField("epochCredits");
        try jw.beginArray();
        for (self.epoch_credits) |ec| try ec.jsonStringify(jw);
        try jw.endArray();

        try jw.objectField("lastTimestamp");
        try self.last_timestamp.jsonStringify(jw);

        try jw.endObject();
    }
};

/// Flattened vote with latency info.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L98
pub const UiLandedVote = struct {
    latency: u8,
    slot: u64,
    confirmation_count: u32,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("latency");
        try jw.write(self.latency);
        try jw.objectField("slot");
        try jw.write(self.slot);
        try jw.objectField("confirmationCount");
        try jw.write(self.confirmation_count);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L118
pub const UiAuthorizedVoter = struct {
    epoch: u64,
    authorized_voter: Pubkey.Base58String,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("epoch");
        try jw.write(self.epoch);
        try jw.objectField("authorizedVoter");
        try jw.write(self.authorized_voter.slice());
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L125
pub const UiPriorVoter = struct {
    authorized_pubkey: Pubkey.Base58String,
    epoch_of_last_authorized_switch: u64,
    target_epoch: u64,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("authorizedPubkey");
        try jw.write(self.authorized_pubkey.slice());
        try jw.objectField("epochOfLastAuthorizedSwitch");
        try jw.write(self.epoch_of_last_authorized_switch);
        try jw.objectField("targetEpoch");
        try jw.write(self.target_epoch);
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L133
pub const UiEpochCredits = struct {
    epoch: u64,
    credits: u64,
    previous_credits: u64,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("epoch");
        try jw.write(self.epoch);
        try jw.objectField("credits");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.credits});
        try jw.objectField("previousCredits");
        // NOTE: per agave, use string for JS compatibility
        try jw.print("\"{d}\"", .{self.previous_credits});
        try jw.endObject();
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/f2d15de6f7a1715ff806f0c39bba8f64bf6a587d/vote-interface/src/state/mod.rs#L148
pub const UiBlockTimestamp = struct {
    slot: u64,
    timestamp: i64,

    pub fn jsonStringify(self: @This(), jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("slot");
        try jw.write(self.slot);
        try jw.objectField("timestamp");
        try jw.write(self.timestamp);
        try jw.endObject();
    }
};
