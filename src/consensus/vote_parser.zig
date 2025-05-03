//! Based on https://github.com/anza-xyz/agave/blob/182823ee353ee64fde230dbad96d8e24b6cd065a/vote/src/vote_parser.rs

// TODO: this is probably/definitely the wrong place for this file to be,
// but it's the only place it's needed right now, and I don't feel like
// committing to a solid structure yet.

const std = @import("std");
const sig = @import("../sig.zig");

const vote_program = sig.runtime.program.vote_program;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;

// #[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub const VoteTransaction = union(enum) {
    vote: sig.runtime.program.vote_program.state.Vote,
    vote_state_update: sig.runtime.program.vote_program.state.VoteStateUpdate,
    // #[serde(with = "serde_compact_vote_state_update")]
    compact_vote_state_update: sig.runtime.program.vote_program.state.VoteStateUpdate,
    // #[serde(with = "serde_tower_sync")]
    tower_sync: sig.runtime.program.vote_program.state.TowerSync,

    pub fn deinit(self: VoteTransaction, allocator: std.mem.Allocator) void {
        switch (self) {
            .vote => |vote| vote.deinit(allocator),
            .vote_state_update => |vsu| vsu.deinit(allocator),
            .compact_vote_state_update => |cvsu| cvsu.deinit(allocator),
            .tower_sync => |ts| ts.deinit(allocator),
        }
    }

    pub fn lastVotedSlot(self: VoteTransaction) ?Slot {
        return switch (self) {
            .vote => |vote| if (vote.slots.len != 0) vote.slots[vote.slots.len - 1] else null,
            inline //
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |vsu_or_ts| blk: {
                const lockouts = vsu_or_ts.lockouts.items;
                if (lockouts.len == 0) break :blk null;
                break :blk lockouts[lockouts.len - 1].slot;
            },
        };
    }
};

pub const ParsedVote = struct {
    key: Pubkey,
    vote: VoteTransaction,
    switch_proof_hash: ?Hash,
    signature: Signature,

    pub fn deinit(self: ParsedVote, allocator: std.mem.Allocator) void {
        self.vote.deinit(allocator);
    }
};

// Used for parsing gossip vote transactions
pub fn parseVoteTransaction(
    allocator: std.mem.Allocator,
    tx: Transaction,
) std.mem.Allocator.Error!?ParsedVote {
    // Check first instruction for a vote
    const message = tx.msg;

    if (message.instructions.len == 0) return null;
    const first_instruction = message.instructions[0];
    const program_id_index = first_instruction.program_index;

    if (program_id_index >= message.account_keys.len) return null;
    const program_id = message.account_keys[program_id_index];
    if (!vote_program.ID.equals(&program_id)) {
        return null;
    }

    if (first_instruction.account_indexes.len == 0) return null;
    const first_account = first_instruction.account_indexes[0];

    if (first_account >= message.account_keys.len) return null;
    const key = message.account_keys[first_account];

    const vote, const switch_proof_hash = try parseVoteInstructionData(
        allocator,
        first_instruction.data,
    ) orelse return null;
    errdefer vote.deinit(allocator);

    const signature = if (tx.signatures.len != 0) tx.signatures[0] else Signature.ZEROES;
    return .{
        .key = key,
        .vote = vote,
        .switch_proof_hash = switch_proof_hash,
        .signature = signature,
    };
}

fn parseVoteInstructionData(
    allocator: std.mem.Allocator,
    vote_instruction_data: []const u8,
) std.mem.Allocator.Error!?struct { VoteTransaction, ?Hash } {
    const vote_instruction = sig.bincode.readFromSlice(
        allocator,
        vote_program.Instruction,
        vote_instruction_data,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => return null,
    };
    return switch (vote_instruction) {
        .vote => |vote| .{
            .{ .vote = vote.vote },
            null,
        },
        .vote_switch => |vs| .{
            .{ .vote = vs.vote },
            vs.hash,
        },
        .update_vote_state => |vsu| .{
            .{ .vote_state_update = vsu.vote_state_update },
            null,
        },
        .update_vote_state_switch => |uvss| .{
            .{ .vote_state_update = uvss.vote_state_update },
            uvss.hash,
        },
        .compact_update_vote_state => |cuvs| .{
            .{ .vote_state_update = cuvs.vote_state_update },
            null,
        },
        .compact_update_vote_state_switch => |cuvss| .{
            .{ .vote_state_update = cuvss.vote_state_update },
            cuvss.hash,
        },
        .tower_sync => |ts| .{
            .{ .tower_sync = ts.tower_sync },
            null,
        },
        .tower_sync_switch => |tss| .{
            .{ .tower_sync = tss.tower_sync },
            tss.hash,
        },

        .authorize,
        .authorize_checked,
        .authorize_with_seed,
        .authorize_checked_with_seed,
        .initialize_account,
        .update_commission,
        .update_validator_identity,
        .withdraw,
        => null,
    };
}
