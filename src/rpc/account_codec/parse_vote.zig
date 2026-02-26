/// Types for parsing a vote account for RPC responses using the `jsonParsed` encoding.
/// [agave]: https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs
const std = @import("std");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const account_codec = @import("lib.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const vote_program = sig.runtime.program.vote;
const ParseError = account_codec.ParseError;
const JsonString = account_codec.JsonString;

const BLS_PUBLIC_KEY_COMPRESSED_SIZE = vote_program.state.BLS_PUBLIC_KEY_COMPRESSED_SIZE;
const BLS_PUBLIC_KEY_BASE58_MAX_SIZE = base58.encodedMaxSize(BLS_PUBLIC_KEY_COMPRESSED_SIZE);

/// Parses a vote account's data into a `VoteAccountType` for JSON encoding in RPC responses.
/// TODO: somehow enforce arena allocation for all allocations here?
pub fn parseVote(
    allocator: Allocator,
    // std.io.Reader
    reader: anytype,
    vote_pubkey: Pubkey,
) ParseError!VoteAccountType {
    var vote_state_versions = sig.bincode.read(
        allocator,
        vote_program.state.VoteStateVersions,
        reader,
        .{},
    ) catch return ParseError.InvalidAccountData;
    defer vote_state_versions.deinit(allocator);

    var vote_state = vote_state_versions.convertToV4(allocator, vote_pubkey) catch
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
            .confirmationCount = vote.lockout.confirmation_count,
        };
    }

    const auth_voters = try allocator.alloc(
        UiAuthorizedVoter,
        vote_state.authorized_voters.len(),
    );

    const voter_keys = vote_state.authorized_voters.voters.keys();
    const voter_values = vote_state.authorized_voters.voters.values();
    for (auth_voters, voter_keys, voter_values) |*av, epoch, voter_pubkey| {
        av.* = UiAuthorizedVoter{
            .epoch = epoch,
            .authorizedVoter = voter_pubkey,
        };
    }

    const epoch_credits = try allocator.alloc(
        UiEpochCredits,
        vote_state.epoch_credits.items.len,
    );
    for (epoch_credits, vote_state.epoch_credits.items) |*ec, vote_state_ec| {
        ec.* = UiEpochCredits{
            .epoch = vote_state_ec.epoch,
            .credits = .{ .value = vote_state_ec.credits },
            .previousCredits = .{ .value = vote_state_ec.prev_credits },
        };
    }

    // Prior voters are not populated in VoteState v4 - AGave returns an empty Vec.
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs#L37
    const prior_voters: []const UiPriorVoter = &.{};

    const ui_vote_state = UiVoteState{
        .nodePubkey = vote_state.node_pubkey,
        .authorizedWithdrawer = vote_state.withdrawer,
        .commission = vote_state.commission(),
        .votes = votes,
        .rootSlot = vote_state.root_slot,
        .authorizedVoters = auth_voters,
        .priorVoters = prior_voters,
        .epochCredits = epoch_credits,
        .lastTimestamp = UiBlockTimestamp{
            .slot = vote_state.last_timestamp.slot,
            .timestamp = vote_state.last_timestamp.timestamp,
        },
        // Fields added with vote state v4 via SIMD-0185:
        .inflationRewardsCommissionBps = vote_state.inflation_rewards_commission_bps,
        .inflationRewardsCollector = vote_state.inflation_rewards_collector,
        .blockRevenueCollector = vote_state.block_revenue_collector,
        .blockRevenueCommissionBps = vote_state.block_revenue_commission_bps,
        .pendingDelegatorRewards = .{ .value = vote_state.pending_delegator_rewards },
        .blsPubkeyCompressed = if (vote_state.bls_pubkey_compressed) |bytes| blk: {
            var encoded_buf: [BLS_PUBLIC_KEY_BASE58_MAX_SIZE]u8 = undefined;
            const len = base58.Table.BITCOIN.encode(&encoded_buf, &bytes);
            break :blk JsonString(BLS_PUBLIC_KEY_BASE58_MAX_SIZE).fromSlice(encoded_buf[0..len]);
        } else null,
    };

    return VoteAccountType{
        .vote = ui_vote_state,
    };
}

/// Wrapper enum matching Agave's VoteAccountType.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L54
pub const VoteAccountType = union(enum) {
    vote: UiVoteState,

    pub fn jsonStringify(self: VoteAccountType, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();
        try jw.objectField("type");
        switch (self) {
            inline else => |v, tag| {
                try jw.write(@tagName(tag));
                try jw.objectField("info");
                try jw.write(v);
            },
        }
        try jw.endObject();
    }
};

/// The main vote state UI representation.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L61
pub const UiVoteState = struct {
    nodePubkey: Pubkey,
    authorizedWithdrawer: Pubkey,
    commission: u8,
    votes: []const UiLandedVote,
    rootSlot: ?u64,
    authorizedVoters: []UiAuthorizedVoter,
    priorVoters: []const UiPriorVoter,
    epochCredits: []const UiEpochCredits,
    lastTimestamp: UiBlockTimestamp,

    // Fields added with vote state v4 via SIMD-0185:
    inflationRewardsCommissionBps: u16,
    inflationRewardsCollector: Pubkey,
    blockRevenueCollector: Pubkey,
    blockRevenueCommissionBps: u16,
    pendingDelegatorRewards: account_codec.Stringified(u64),
    blsPubkeyCompressed: ?JsonString(BLS_PUBLIC_KEY_BASE58_MAX_SIZE),

    pub fn jsonStringify(self: UiVoteState, jw: anytype) @TypeOf(jw.*).Error!void {
        try jw.beginObject();

        try jw.objectField("nodePubkey");
        try jw.write(self.nodePubkey);

        try jw.objectField("authorizedWithdrawer");
        try jw.write(self.authorizedWithdrawer);

        try jw.objectField("commission");
        try jw.write(self.commission);

        try jw.objectField("votes");
        try jw.write(self.votes);

        try jw.objectField("rootSlot");
        try jw.write(self.rootSlot);

        try jw.objectField("authorizedVoters");
        try jw.write(self.authorizedVoters);

        try jw.objectField("priorVoters");
        try jw.write(self.priorVoters);

        try jw.objectField("epochCredits");
        try jw.write(self.epochCredits);

        try jw.objectField("lastTimestamp");
        try jw.write(self.lastTimestamp);

        try jw.objectField("inflationRewardsCommissionBps");
        try jw.write(self.inflationRewardsCommissionBps);

        try jw.objectField("inflationRewardsCollector");
        try jw.write(self.inflationRewardsCollector);

        try jw.objectField("blockRevenueCollector");
        try jw.write(self.blockRevenueCollector);

        try jw.objectField("blockRevenueCommissionBps");
        try jw.write(self.blockRevenueCommissionBps);

        try jw.objectField("pendingDelegatorRewards");
        try jw.write(self.pendingDelegatorRewards);

        try jw.objectField("blsPubkeyCompressed");
        try jw.write(self.blsPubkeyCompressed);

        try jw.endObject();
    }
};

/// Flattened vote with latency info.
/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L98
pub const UiLandedVote = struct {
    latency: u8,
    slot: u64,
    confirmationCount: u32,
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L118
pub const UiAuthorizedVoter = struct {
    epoch: u64,
    authorizedVoter: Pubkey,
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L125
pub const UiPriorVoter = struct {
    authorizedPubkey: Pubkey,
    epochOfLastAuthorizedSwitch: u64,
    targetEpoch: u64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/2717084afeeb7baad4342468c27f528ef617a3cf/account-decoder/src/parse_vote.rs#L133
pub const UiEpochCredits = struct {
    epoch: u64,
    credits: account_codec.Stringified(u64),
    previousCredits: account_codec.Stringified(u64),
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/f2d15de6f7a1715ff806f0c39bba8f64bf6a587d/vote-interface/src/state/mod.rs#L148
pub const UiBlockTimestamp = struct {
    slot: u64,
    timestamp: i64,
};

// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs#L140-L199
test "rpc.account_codec.parse_vote: parse vote accounts" {
    const allocator = std.testing.allocator;

    // Parse default vote state
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs#L145-L174
    {
        const vote_pubkey = Pubkey{ .data = [_]u8{1} ** 32 };

        // Create a default VoteStateV4 and serialize as VoteStateVersions.v4
        const vote_state = vote_program.state.VoteStateV4.DEFAULT;
        const vote_state_versions = vote_program.state.VoteStateVersions{ .v4 = vote_state };

        const serialized = try sig.bincode.writeAlloc(allocator, vote_state_versions, .{});
        defer allocator.free(serialized);

        var stream = std.io.fixedBufferStream(serialized);
        const result = try parseVote(allocator, stream.reader(), vote_pubkey);

        // Verify the result is a vote type
        try std.testing.expect(result == .vote);

        const ui_vote_state = result.vote;

        // Verify default field values match Agave's expectations
        // nodePubkey and authorizedWithdrawer should be default (zeroes)
        try std.testing.expectEqual(Pubkey.ZEROES, ui_vote_state.nodePubkey);
        try std.testing.expectEqual(Pubkey.ZEROES, ui_vote_state.authorizedWithdrawer);

        // Commission should be 0 (inflationRewardsCommissionBps / 100)
        try std.testing.expectEqual(@as(u8, 0), ui_vote_state.commission);

        // Votes should be empty
        try std.testing.expectEqual(@as(usize, 0), ui_vote_state.votes.len);

        // Root slot should be null
        try std.testing.expect(ui_vote_state.rootSlot == null);

        // Authorized voters should be empty (DEFAULT has EMPTY authorized_voters)
        try std.testing.expectEqual(@as(usize, 0), ui_vote_state.authorizedVoters.len);

        // Prior voters should be empty (v4 doesn't populate prior_voters)
        try std.testing.expectEqual(@as(usize, 0), ui_vote_state.priorVoters.len);

        // Epoch credits should be empty
        try std.testing.expectEqual(@as(usize, 0), ui_vote_state.epochCredits.len);

        // Last timestamp should be default (slot=0, timestamp=0)
        try std.testing.expectEqual(@as(u64, 0), ui_vote_state.lastTimestamp.slot);
        try std.testing.expectEqual(@as(i64, 0), ui_vote_state.lastTimestamp.timestamp);

        // SIMD-0185 fields
        try std.testing.expectEqual(@as(u16, 0), ui_vote_state.inflationRewardsCommissionBps);
        try std.testing.expectEqual(@as(u16, 10_000), ui_vote_state.blockRevenueCommissionBps);
        try std.testing.expectEqual(@as(u64, 0), ui_vote_state.pendingDelegatorRewards.value);
        try std.testing.expect(ui_vote_state.blsPubkeyCompressed == null);
    }

    // Bad data returns error
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs#L176-L177
    {
        const vote_pubkey = Pubkey{ .data = [_]u8{1} ** 32 };
        const bad_data = [_]u8{ 0, 0, 0, 0 };

        var stream = std.io.fixedBufferStream(&bad_data);
        const result = parseVote(allocator, stream.reader(), vote_pubkey);

        try std.testing.expectError(ParseError.InvalidAccountData, result);
    }

    // UiLandedVote JSON flattening
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/account-decoder/src/parse_vote.rs#L180-L199
    {
        // Verify that UiLandedVote serializes with flattened fields (no nested "lockout" object)
        // In Agave, UiLandedVote uses #[serde(flatten)] on the lockout field
        const ui_landed_vote = UiLandedVote{
            .latency = 5,
            .slot = 12345,
            .confirmationCount = 10,
        };

        var buf: [256]u8 = undefined;
        var out: std.io.Writer = .fixed(&buf);
        var jw: std.json.Stringify = .{ .writer = &out };

        try jw.write(ui_landed_vote);

        const json_output = out.buffered();

        // Parse the JSON to verify structure
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_output, .{});
        defer parsed.deinit();

        const root = parsed.value.object;

        // Verify that the lockout fields are flattened at the top level
        try std.testing.expectEqual(@as(i64, 5), root.get("latency").?.integer);
        try std.testing.expectEqual(@as(i64, 12345), root.get("slot").?.integer);
        try std.testing.expectEqual(@as(i64, 10), root.get("confirmationCount").?.integer);

        // Verify that there is no nested "lockout" field
        try std.testing.expect(root.get("lockout") == null);
    }
}
