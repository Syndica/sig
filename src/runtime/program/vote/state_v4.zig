/// [SIMD-0185] Vote account state v4: commission in bps, no prior_voters, collectors, BLS key.
const std = @import("std");
const sig = @import("../../../sig.zig");

const Allocator = std.mem.Allocator;

const vote_program = sig.runtime.program.vote;
const state = vote_program.state;
const InstructionError = sig.core.instruction.InstructionError;
const VoteError = vote_program.VoteError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.hash.Hash;
const SlotHashes = sig.runtime.sysvar.SlotHashes;

const AuthorizedVoters = state.AuthorizedVoters;
const BlockTimestamp = state.BlockTimestamp;
const EpochCredit = state.EpochCredit;
const LandedVote = state.LandedVote;
const Lockout = state.Lockout;
const TowerSync = state.TowerSync;
const Vote = state.Vote;
const VoteState = state.VoteState;
const VoteStateUpdate = state.VoteStateUpdate;
const VoteStateVersions = state.VoteStateVersions;

const MAX_LOCKOUT_HISTORY = state.MAX_LOCKOUT_HISTORY;
const MAX_EPOCH_CREDITS_HISTORY = state.MAX_EPOCH_CREDITS_HISTORY;
const VOTE_CREDITS_GRACE_SLOTS = state.VOTE_CREDITS_GRACE_SLOTS;
const VOTE_CREDITS_MAXIMUM_PER_SLOT = state.VOTE_CREDITS_MAXIMUM_PER_SLOT;

/// SIMD-0185: https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0185-vote-account-v4.md
pub const VoteStateV4 = struct {
    node_pubkey: Pubkey,
    withdrawer: Pubkey,

    /// REMOVED
    /// commission: u8,
    ///
    /// NEW: the collector accounts for validator income
    inflation_rewards_collector: Pubkey,
    block_revenue_collector: Pubkey,

    /// NEW: basis points (0-10,000) that represent how much of each income
    /// source should be given to this VoteAccount
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,

    /// NEW: reward amount pending distribution to stake delegators
    pending_delegator_rewards: u64,

    /// NEW: compressed bls pubkey for alpenglow
    bls_pubkey_compressed: ?[48]u8,

    votes: std.ArrayListUnmanaged(LandedVote),
    root_slot: ?Slot,

    /// UPDATED: serialization structure of the AuthorizedVoters map is
    /// unchanged but will now contain entries for the previous epoch.
    authorized_voters: AuthorizedVoters,

    /// REMOVED
    /// prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,
    epoch_credits: std.ArrayListUnmanaged(EpochCredit),
    last_timestamp: BlockTimestamp,

    pub const MAX_VOTE_STATE_SIZE: usize = 3762;

    pub const DEFAULT: VoteStateV4 = .{
        .node_pubkey = Pubkey.ZEROES,
        .withdrawer = Pubkey.ZEROES,
        .inflation_rewards_collector = Pubkey.ZEROES,
        .block_revenue_collector = Pubkey.ZEROES,
        .inflation_rewards_commission_bps = 10_000,
        .block_revenue_commission_bps = 0,
        .pending_delegator_rewards = 0,
        .bls_pubkey_compressed = null,
        .votes = .empty,
        .root_slot = null,
        .voters = .EMPTY,
        .epoch_credits = .empty,
        .last_timestamp = .{ .slot = 0, .timestamp = 0 },
    };

    /// Integer percentage (0-100) for backward compatibility; inflation_rewards_commission_bps / 100.
    pub fn commission(self: *const VoteStateV4) u8 {
        return @intCast(self.inflation_rewards_commission_bps / 100);
    }

    /// [SIMD-0185] Build VoteStateV4 from VoteState (e.g. for v3 InitializeAccount path).
    pub fn fromVoteStateV3(
        allocator: Allocator,
        v3: VoteState,
        vote_pubkey: Pubkey,
    ) Allocator.Error!VoteStateV4 {
        var votes = try v3.votes.clone(allocator);
        errdefer votes.deinit(allocator);

        const voters = try v3.voters.clone(allocator);
        errdefer voters.deinit(allocator);

        return .{
            .node_pubkey = v3.node_pubkey,
            .withdrawer = v3.withdrawer,
            .inflation_rewards_collector = vote_pubkey,
            .block_revenue_collector = v3.node_pubkey,
            .inflation_rewards_commission_bps = @as(u16, v3.commission) * 100,
            .block_revenue_commission_bps = 10_000,
            .pending_delegator_rewards = 0,
            .bls_pubkey_compressed = null,
            .votes = votes,
            .root_slot = v3.root_slot,
            .voters = voters,
            .epoch_credits = try v3.epoch_credits.clone(allocator),
            .last_timestamp = v3.last_timestamp,
        };
    }

    pub fn init(
        allocator: Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission_pct: u8,
        voter_epoch: Epoch,
        vote_pubkey: Pubkey,
    ) Allocator.Error!VoteStateV4 {
        const authorized_voters = try AuthorizedVoters.init(
            allocator,
            voter_epoch,
            authorized_voter,
        );
        errdefer authorized_voters.deinit(allocator);

        return .{
            .node_pubkey = node_pubkey,
            .withdrawer = withdrawer,
            .inflation_rewards_collector = vote_pubkey,
            .block_revenue_collector = node_pubkey,
            .inflation_rewards_commission_bps = @as(u16, commission_pct) * 100,
            .block_revenue_commission_bps = 10_000,
            .pending_delegator_rewards = 0,
            .bls_pubkey_compressed = null,
            .votes = .empty,
            .root_slot = null,
            .voters = authorized_voters,
            .epoch_credits = .empty,
            .last_timestamp = .{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: *VoteStateV4, allocator: Allocator) void {
        self.votes.deinit(allocator);
        self.authorized_voters.deinit(allocator);
        self.epoch_credits.deinit(allocator);
    }

    pub fn clone(self: VoteStateV4, allocator: Allocator) Allocator.Error!VoteStateV4 {
        var votes = try self.votes.clone(allocator);
        errdefer votes.deinit(allocator);

        const voters = try self.authorized_voters.clone(allocator);
        errdefer voters.deinit(allocator);

        return .{
            .node_pubkey = self.node_pubkey,
            .withdrawer = self.withdrawer,
            .inflation_rewards_collector = self.inflation_rewards_collector,
            .block_revenue_collector = self.block_revenue_collector,
            .inflation_rewards_commission_bps = self.inflation_rewards_commission_bps,
            .block_revenue_commission_bps = self.block_revenue_commission_bps,
            .pending_delegator_rewards = self.pending_delegator_rewards,
            .bls_pubkey_compressed = self.bls_pubkey_compressed,
            .votes = votes,
            .root_slot = self.root_slot,
            .voters = voters,
            .epoch_credits = try self.epoch_credits.clone(allocator),
            .last_timestamp = self.last_timestamp,
        };
    }

    pub fn equals(self: *const VoteStateV4, other: *const VoteStateV4) bool {
        if (self.votes.items.len != other.votes.items.len) return false;
        for (self.votes.items, other.votes.items) |a, b|
            if (!std.meta.eql(a, b)) return false;

        if (!self.authorized_voters.equals(&other.authorized_voters)) return false;

        if (self.epoch_credits.items.len != other.epoch_credits.items.len) return false;
        for (self.epoch_credits.items, other.epoch_credits.items) |a, b|
            if (!std.meta.eql(a, b)) return false;

        return self.node_pubkey.equals(&other.node_pubkey) and
            self.withdrawer.equals(&other.withdrawer) and
            self.inflation_rewards_collector.equals(&other.inflation_rewards_collector) and
            self.block_revenue_collector.equals(&other.block_revenue_collector) and
            self.inflation_rewards_commission_bps == other.inflation_rewards_commission_bps and
            self.block_revenue_commission_bps == other.block_revenue_commission_bps and
            self.pending_delegator_rewards == other.pending_delegator_rewards and
            blsPubkeyEql(self.bls_pubkey_compressed, other.bls_pubkey_compressed) and
            self.root_slot == other.root_slot and
            std.meta.eql(self.last_timestamp, other.last_timestamp);
    }

    /// Same as getCredits(); provided for compatibility with VoteState API.
    pub fn epochCredits(self: *const VoteStateV4) u64 {
        return self.getCredits();
    }

    pub fn lastLockout(self: *const VoteStateV4) ?Lockout {
        if (self.votes.getLastOrNull()) |vote| {
            return vote.lockout;
        }
        return null;
    }

    pub fn lastVotedSlot(self: *const VoteStateV4) ?Slot {
        if (self.lastLockout()) |lock_out| {
            return lock_out.slot;
        }
        return null;
    }

    /// [SIMD-0185] v4: no prior_voters; setNewAuthorizedVoter only updates authorized_voters.
    pub fn setNewAuthorizedVoter(
        self: *VoteStateV4,
        allocator: Allocator,
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

        if (!latest_pubkey.equals(&new_authorized_voter) and target_epoch <= latest_epoch) {
            return InstructionError.InvalidAccountData;
        }

        try self.authorized_voters.insert(allocator, target_epoch, new_authorized_voter);
        return null;
    }

    /// [SIMD-0185] v4: purge only entries < current_epoch - 1.
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteStateV4,
        allocator: Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!Pubkey {
        const maybe_pubkey = self.authorized_voters.getAndCacheAuthorizedVoterForEpoch(
            allocator,
            current_epoch,
        ) catch return error.OutOfMemory;
        const pubkey = maybe_pubkey orelse return InstructionError.InvalidAccountData;

        try self.authorized_voters.purgeAuthorizedVotersPreviousEpoch(allocator, current_epoch);

        return pubkey;
    }

    pub fn creditsForVoteAtIndex(self: *const VoteStateV4, index: usize) u64 {
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
            return VOTE_CREDITS_MAXIMUM_PER_SLOT;
        }

        // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
        const diff = latency - VOTE_CREDITS_GRACE_SLOTS;

        if (diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT) {
            // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
            return 1;
        }

        return VOTE_CREDITS_MAXIMUM_PER_SLOT - diff;
    }

    pub fn getCredits(self: *const VoteStateV4) u64 {
        return if (self.epoch_credits.items.len == 0)
            0
        else
            self.epoch_credits.getLast().credits;
    }

    pub fn incrementCredits(
        self: *VoteStateV4,
        allocator: Allocator,
        epoch: Epoch,
        credits: u64,
    ) error{OutOfMemory}!void {
        if (self.epoch_credits.items.len == 0) {
            try self.epoch_credits.append(
                allocator,
                .{ .epoch = epoch, .credits = 0, .prev_credits = 0 },
            );
        } else if (epoch != self.epoch_credits.getLast().epoch) {
            const last = self.epoch_credits.getLast();
            const last_credits = last.credits;
            const last_prev_credits = last.prev_credits;

            if (last_credits != last_prev_credits) {
                try self.epoch_credits.append(
                    allocator,
                    .{
                        .epoch = epoch,
                        .credits = last_credits,
                        .prev_credits = last_credits,
                    },
                );
            } else {
                const last_epoch_credit =
                    &self.epoch_credits.items[self.epoch_credits.items.len - 1];
                last_epoch_credit.*.epoch = epoch;
            }

            if (self.epoch_credits.items.len > MAX_EPOCH_CREDITS_HISTORY) {
                _ = self.epoch_credits.orderedRemove(0);
            }
        }

        {
            const last_epoch_credit = &self.epoch_credits.items[self.epoch_credits.items.len - 1];
            last_epoch_credit.*.credits = last_epoch_credit.credits +| credits;
        }
    }

    pub fn checkSlotsAreValid(
        self: *const VoteStateV4,
        vote: *const Vote,
        recent_vote_slots: []const Slot,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        const vote_hash = vote.hash;
        const slot_hash_entries = slot_hashes.entries.constSlice();

        // index into the vote's slots, starting at the oldest slot
        var i: usize = 0;

        // index into the slot_hashes, starting at the oldest known slot hash
        var j: usize = slot_hash_entries.len;

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
                i = std.math.add(usize, i, 1) catch
                    return InstructionError.ProgramArithmeticOverflow;
                continue;
            }

            // 2) Find the hash for this slot `s`.
            if (recent_vote_slots[i] !=
                slot_hash_entries[
                    std.math.sub(usize, j, 1) catch
                        return InstructionError.ProgramArithmeticOverflow
                ].slot)
            {
                // Decrement `j` to find newer slots
                j = std.math.sub(usize, j, 1) catch
                    return InstructionError.ProgramArithmeticOverflow;
                continue;
            }

            // 3) Once the hash for `s` is found, bump `s` to the next slot
            // in `vote_slots` and continue.
            i = std.math.add(usize, i, 1) catch
                return InstructionError.ProgramArithmeticOverflow;
            j = std.math.sub(usize, j, 1) catch
                return InstructionError.ProgramArithmeticOverflow;
        }

        if (j == slot_hash_entries.len) {
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
        if (!vote_hash.eql(slot_hash_entries[j].hash)) {
            // This means the newest slot in the `vote_slots` has a match that
            // doesn't match the expected hash for that slot on this
            // fork
            return VoteError.slot_hash_mismatch;
        }

        // If we made it here, all the slots in the vote were found in the slot_hashes
        // and the hashes matched, so the vote is valid
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L709
    pub fn processNextVoteSlot(
        self: *VoteStateV4,
        allocator: Allocator,
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

        self.popExpiredVotes(next_vote_slot);

        const landed_vote: LandedVote = .{
            .latency = VoteState.computeVoteLatency(next_vote_slot, current_slot),
            .lockout = Lockout{ .confirmation_count = 1, .slot = next_vote_slot },
        };

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if (self.votes.items.len == MAX_LOCKOUT_HISTORY) {
            const credits = self.creditsForVoteAtIndex(0);
            const popped_vote = self.votes.orderedRemove(0);
            self.root_slot = popped_vote.lockout.slot;
            try self.incrementCredits(allocator, epoch, credits);
        }

        try self.votes.append(allocator, landed_vote);
        try self.doubleLockouts();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L939
    ///
    /// Pop all recent votes that are not locked out at the next vote slot.
    /// This allows validators to switch forks once their votes for another fork have
    /// expired. This also allows validators to continue voting on recent blocks in
    /// the same fork without increasing lockouts.
    pub fn popExpiredVotes(self: *VoteStateV4, next_vote_slot: Slot) void {
        while (self.lastLockout()) |vote| {
            if (!vote.isLockedOutAtSlot(next_vote_slot)) {
                _ = self.votes.pop();
            } else {
                break;
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L949
    pub fn doubleLockouts(self: *VoteStateV4) !void {
        const stack_depth = self.votes.items.len;

        for (self.votes.items, 0..) |*vote, i| {
            const confirmation_count = vote.lockout.confirmation_count;
            if (stack_depth > std.math.add(usize, i, confirmation_count) catch
                return InstructionError.ProgramArithmeticOverflow)
            {
                vote.lockout.confirmation_count +|= 1;
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L963
    pub fn processTimestamp(
        self: *VoteStateV4,
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
        self: *VoteStateV4,
        allocator: Allocator,
        vote: *const Vote,
        slot_hashes: SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (vote.slots.len == 0) {
            return VoteError.empty_slots;
        }

        const slot_hash_entries = slot_hashes.entries.constSlice();
        const earliest_slot_in_history = if (slot_hash_entries.len != 0)
            slot_hash_entries[slot_hash_entries.len - 1].slot
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
            allocator,
            recent_vote_slots.items,
            vote,
            &slot_hashes,
            epoch,
            current_slot,
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/a0717a15d349dc5e0c30384bee6d039377b92167/programs/vote/src/vote_state/mod.rs#L603
    pub fn processVoteUnfiltered(
        self: *VoteStateV4,
        allocator: Allocator,
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
            try self.processNextVoteSlot(
                allocator,
                recent_vote_slot,
                epoch,
                current_slot,
            );
        }

        return null;
    }

    fn compareFn(key: Slot, mid_item: LandedVote) std.math.Order {
        return std.math.order(key, mid_item.lockout.slot);
    }

    pub fn containsSlot(self: *const VoteStateV4, candidate_slot: Slot) bool {
        return std.sort.binarySearch(
            LandedVote,
            self.votes.items,
            candidate_slot,
            compareFn,
        ) != null;
    }

    pub fn checkAndFilterProposedVoteState(
        self: *VoteStateV4,
        proposed_lockouts: *std.ArrayListUnmanaged(Lockout),
        proposed_root: *?Slot,
        proposed_hash: Hash,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (proposed_lockouts.items.len == 0) return VoteError.empty_slots;

        // If the proposed state is too old, return `vote_too_old`.
        const last_proposed_slot = proposed_lockouts.getLast().slot;
        if (self.votes.getLastOrNull()) |last_vote| {
            if (last_proposed_slot <= last_vote.lockout.slot) {
                return VoteError.vote_too_old;
            }
        }

        const slot_hash_entries = slot_hashes.entries.constSlice();
        if (slot_hash_entries.len == 0) return VoteError.slots_mismatch;
        const earliest_slot_hash_in_history = slot_hash_entries[slot_hash_entries.len - 1].slot;

        // Check if the proposed vote state is too old to be in the SlotHash history
        if (last_proposed_slot < earliest_slot_hash_in_history) {
            // If this is the last slot in the vote update, it must be in SlotHashes,
            // otherwise we have no way of confirming if the hash matches
            return VoteError.vote_too_old;
        }

        if (proposed_root.*) |root| {
            // If the new proposed root `R` is less than the earliest slot hash in the history
            // such that we cannot verify whether the slot was actually was on this fork, set
            // the root to the latest vote in the vote state that's less than R. If no
            // votes from the vote state are less than R, use its root instead.
            if (root < earliest_slot_hash_in_history) {
                // First overwrite the proposed root with the vote state's root
                proposed_root.* = self.root_slot;
                // Then try to find the latest vote in vote state that's less than R
                var iter = std.mem.reverseIterator(self.votes.items);
                while (iter.next()) |vote| {
                    if (vote.lockout.slot <= root) {
                        proposed_root.* = vote.lockout.slot;
                        break;
                    }
                }
            }
        }

        // Index into the new proposed vote state's slots, starting with the root if it exists then
        // we use this mutable root to fold checking the root slot into the below loop
        // for performance
        var root_to_check = proposed_root.*;
        var proposed_lockouts_index: u64 = 0;
        // index into the slot_hashes, starting at the oldest known slot hash
        var slot_hashes_index = slot_hash_entries.len;
        // The maximum number of elements is bounded by the maximum instruction size possible.
        var lockouts_to_filter: std.BoundedArray(
            u64,
            sig.vm.syscalls.cpi.MAX_DATA_LEN / @sizeOf(u64),
        ) = .{};

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
        while (proposed_lockouts_index < proposed_lockouts.items.len and slot_hashes_index > 0) {
            const proposed_vote_slot: Slot = if (root_to_check) |root|
                root
            else
                proposed_lockouts.items[proposed_lockouts_index].slot;

            if (root_to_check == null and
                proposed_lockouts_index > 0 and
                proposed_vote_slot <= proposed_lockouts.items[proposed_lockouts_index - 1].slot)
            {
                return VoteError.slots_not_ordered;
            }
            const ancestor_slot = slot_hash_entries[slot_hashes_index - 1].slot;

            // Find if this slot in the proposed vote state exists in the SlotHashes history
            // to confirm if it was a valid ancestor on this fork
            switch (std.math.order(proposed_vote_slot, ancestor_slot)) {
                .lt => {
                    if (slot_hashes_index == slot_hash_entries.len) {
                        // The vote slot does not exist in the SlotHashes history because it's too old,
                        // i.e. older than the oldest slot in the history.
                        if (proposed_vote_slot >= earliest_slot_hash_in_history) {
                            return VoteError.assertion_failed;
                        }
                        if (!self.containsSlot(proposed_vote_slot) and (root_to_check == null)) {
                            // If the vote slot is both:
                            // 1) Too old
                            // 2) Doesn't already exist in vote state
                            //
                            // Then filter it out
                            // NOTE: It is not possible for this to run out of capacity, as
                            // the instruction data could not contain enough lockouts.
                            lockouts_to_filter.appendAssumeCapacity(proposed_lockouts_index);
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
                            proposed_lockouts_index += 1;
                        }
                        continue;
                    } else {
                        // If the vote slot is new enough to be in the slot history,
                        // but is not part of the slot history, then it must belong to another fork,
                        // which means this proposed vote state is invalid.
                        if (root_to_check == null) {
                            return VoteError.slots_mismatch;
                        } else {
                            return VoteError.root_on_different_fork;
                        }
                    }
                },
                .gt => {
                    // Decrement `slot_hashes_index` to find newer slots in the SlotHashes history
                    slot_hashes_index -= 1;
                    continue;
                },
                .eq => {
                    // Once the slot in `proposed_lockouts` is found, bump to the next slot
                    // in `proposed_lockouts` and continue. If we were checking the root,
                    // start checking the vote state instead.
                    if (root_to_check != null) {
                        root_to_check = null;
                    } else {
                        proposed_lockouts_index += 1;
                        slot_hashes_index -= 1;
                    }
                },
            }
        }

        if (proposed_lockouts_index != proposed_lockouts.items.len) {
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
        std.debug.assert(last_proposed_slot == slot_hash_entries[slot_hashes_index].slot);

        // Only check the hash of the LAST proposed slot against the proposed_hash
        if (!slot_hash_entries[slot_hashes_index].hash.eql(proposed_hash)) {
            return VoteError.slot_hash_mismatch;
        }

        // Filter out the irrelevant votes
        proposed_lockouts_index = 0;
        var filter_votes_index: usize = 0;
        var i: usize = 0;
        while (i < proposed_lockouts.items.len) {
            const should_retain = retain: {
                if (filter_votes_index == lockouts_to_filter.len) {
                    break :retain true;
                } else if (proposed_lockouts_index == lockouts_to_filter.get(filter_votes_index)) {
                    filter_votes_index += 1;
                    break :retain false;
                } else break :retain true;
            };

            proposed_lockouts_index += 1;
            if (should_retain) {
                i += 1;
            } else {
                _ = proposed_lockouts.orderedRemove(i);
            }
        }
        return null;
    }

    pub fn processNewVoteState(
        self: *VoteStateV4,
        allocator: Allocator,
        new_state: []LandedVote,
        new_root: ?Slot,
        timestamp: ?i64,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        std.debug.assert(new_state.len != 0);

        if (new_state.len > MAX_LOCKOUT_HISTORY) {
            return VoteError.too_many_votes;
        }

        if (new_root) |proposed_new_root| {
            if (self.root_slot) |current_root| {
                if (proposed_new_root < current_root) {
                    return VoteError.root_roll_back;
                }
            }
        } else {
            if (self.root_slot != null) {
                return VoteError.root_roll_back;
            }
        }

        var maybe_previous_vote: ?*const LandedVote = null;

        for (new_state) |*vote| {
            if (vote.lockout.confirmation_count == 0) {
                return VoteError.zero_confirmations;
            } else if (vote.lockout.confirmation_count > MAX_LOCKOUT_HISTORY) {
                return VoteError.confirmation_too_large;
            } else if (new_root) |proposed_new_root| {
                if (vote.lockout.slot <= proposed_new_root and new_root != 0) {
                    return VoteError.slot_smaller_than_root;
                }
            }

            if (maybe_previous_vote) |previous_vote| {
                if (previous_vote.lockout.slot >= vote.lockout.slot) {
                    return VoteError.slots_not_ordered;
                } else if (previous_vote.lockout.confirmation_count <=
                    vote.lockout.confirmation_count)
                {
                    return VoteError.confirmations_not_ordered;
                } else if (vote.lockout.slot > previous_vote.lockout.lastLockedOutSlot()) {
                    return VoteError.new_vote_state_lockout_mismatch;
                }
            }
            maybe_previous_vote = vote;
        }

        var current_vote_state_index: usize = 0;
        var new_vote_state_index: usize = 0;
        var earned_credits: u64 = 0;

        if (new_root) |proposed_new_root| {
            for (self.votes.items) |current_vote| {
                if (current_vote.lockout.slot <= proposed_new_root) {
                    earned_credits = std.math.add(
                        u64,
                        earned_credits,
                        self.creditsForVoteAtIndex(current_vote_state_index),
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                    continue;
                }
                break;
            }
        }

        while (current_vote_state_index < self.votes.items.len and
            new_vote_state_index < new_state.len)
        {
            const current_vote = &self.votes.items[current_vote_state_index];
            const new_vote = &new_state[new_vote_state_index];

            switch (std.math.order(current_vote.lockout.slot, new_vote.lockout.slot)) {
                .lt => {
                    if (current_vote.lockout.lastLockedOutSlot() >= new_vote.lockout.slot) {
                        return VoteError.lockout_conflict;
                    }
                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                },
                .eq => {
                    if (new_vote.lockout.confirmation_count <
                        current_vote.lockout.confirmation_count)
                    {
                        return VoteError.confirmation_roll_back;
                    }

                    new_vote.latency = self.votes.items[current_vote_state_index].latency;

                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                    new_vote_state_index = std.math.add(usize, new_vote_state_index, 1) catch
                        return InstructionError.ProgramArithmeticOverflow;
                },
                .gt => {
                    new_vote_state_index = std.math.add(usize, new_vote_state_index, 1) catch
                        return InstructionError.ProgramArithmeticOverflow;
                },
            }
        }

        for (new_state) |*new_vote| {
            if (new_vote.latency == 0) {
                new_vote.latency = VoteState.computeVoteLatency(
                    new_vote.lockout.slot,
                    current_slot,
                );
            }
        }

        if (self.root_slot != new_root) {
            try self.incrementCredits(allocator, epoch, earned_credits);
        }
        if (timestamp) |tstamp| {
            const last_slot = new_state[new_state.len - 1].lockout.slot;
            if (self.processTimestamp(last_slot, tstamp)) |err| {
                return err;
            }
        }

        self.root_slot = new_root;
        self.votes.clearRetainingCapacity();
        try self.votes.appendSlice(allocator, new_state);

        return null;
    }

    pub fn processVoteStateUpdate(
        self: *VoteStateV4,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        vote_state_update: *VoteStateUpdate,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkAndFilterProposedVoteState(
            &vote_state_update.lockouts,
            &vote_state_update.root,
            vote_state_update.hash,
            slot_hashes,
        )) |err| {
            return err;
        }

        const lockouts = try VoteStateVersions.landedVotesFromLockouts(
            allocator,
            vote_state_update.lockouts.items,
        );
        defer allocator.free(lockouts);

        return try self.processNewVoteState(
            allocator,
            lockouts,
            vote_state_update.root,
            vote_state_update.timestamp,
            epoch,
            slot,
        );
    }

    pub fn processTowerSync(
        self: *VoteStateV4,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        tower_sync: *TowerSync,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            slot_hashes,
        )) |err| {
            return err;
        }

        const lockouts = try VoteStateVersions.landedVotesFromLockouts(
            allocator,
            tower_sync.lockouts.items,
        );
        defer allocator.free(lockouts);

        return try self.processNewVoteState(
            allocator,
            lockouts,
            tower_sync.root,
            tower_sync.timestamp,
            epoch,
            slot,
        );
    }

    /// v4 is always considered initialized per [SIMD-0185].
    pub fn isUninitialized(self: VoteStateV4) bool {
        _ = self;
        return false;
    }

    pub fn isCorrectSizeAndInitialized(data: []const u8) bool {
        if (data.len != MAX_VOTE_STATE_SIZE) return false;
        if (data.len < 4) return false;
        const version = std.mem.readInt(u32, data[0..4], .little);
        return version == 3; // v4 discriminant per [SIMD-0185]
    }
};

fn blsPubkeyEql(a: ?[48]u8, b: ?[48]u8) bool {
    if (a == null and b == null) return true;
    if (a != null and b != null) return std.mem.eql(u8, &a.?, &b.?);
    return false;
}

pub fn createTestVoteStateV4(
    allocator: Allocator,
    node_pubkey: Pubkey,
    maybe_authorized_voter: ?Pubkey,
    withdrawer: Pubkey,
    commission_pct: u8,
) !VoteStateV4 {
    if (!@import("builtin").is_test) {
        @compileError("createTestVoteStateV4 should only be called in test mode");
    }

    return .{
        .node_pubkey = node_pubkey,
        .withdrawer = withdrawer,
        .inflation_rewards_collector = Pubkey.ZEROES,
        .block_revenue_collector = node_pubkey,
        .inflation_rewards_commission_bps = @as(u16, commission_pct) * 100,
        .block_revenue_commission_bps = 10_000,
        .pending_delegator_rewards = 0,
        .bls_pubkey_compressed = null,
        .votes = .empty,
        .root_slot = null,
        .voters = if (maybe_authorized_voter) |authorized_voter|
            try AuthorizedVoters.init(allocator, 0, authorized_voter)
        else
            .EMPTY,
        .epoch_credits = .empty,
        .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
    };
}
