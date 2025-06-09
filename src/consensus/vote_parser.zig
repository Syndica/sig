//! Based on https://github.com/anza-xyz/agave/blob/182823ee353ee64fde230dbad96d8e24b6cd065a/vote/src/vote_parser.rs

// TODO: this is probably/definitely the wrong place for this file to be,
// but it's the only place it's needed right now, and I don't feel like
// committing to a solid structure yet.

const std = @import("std");
const sig = @import("../sig.zig");

const vote_program = sig.runtime.program.vote;
const vote_instruction = vote_program.vote_instruction;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const TransactionMessage = sig.core.transaction.Message;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;

pub const ParsedVote = struct {
    key: Pubkey,
    vote: VoteTransaction,
    switch_proof_hash: ?Hash,
    signature: Signature,

    pub fn deinit(self: ParsedVote, allocator: std.mem.Allocator) void {
        self.vote.deinit(allocator);
    }
};

/// Used for parsing gossip vote transactions
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
    const vote_inst = sig.bincode.readFromSlice(
        allocator,
        vote_program.Instruction,
        vote_instruction_data,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => |e| return e,
        else => return null,
    };
    errdefer vote_inst.deinit(allocator);

    return switch (vote_inst) {
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

test testParseVoteTransaction {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();
    try testParseVoteTransaction(null, random);
    try testParseVoteTransaction(Hash.generateSha256(&[_]u8{42}), random);
}

fn testParseVoteTransaction(input_hash: ?Hash, random: std.Random) !void {
    const allocator = std.testing.allocator;

    const node_keypair = try randomKeyPair(random);
    const auth_voter_keypair = try randomKeyPair(random);
    const vote_keypair = try randomKeyPair(random);

    const vote_key = Pubkey.fromPublicKey(&vote_keypair.public_key);

    {
        const bank_hash = Hash.ZEROES;
        const vote_tx = try testNewVoteTransaction(
            allocator,
            &.{42},
            bank_hash,
            Hash.ZEROES,
            node_keypair,
            vote_key,
            auth_voter_keypair,
            input_hash,
        );
        defer vote_tx.deinit(allocator);

        const maybe_parsed_tx = try parseVoteTransaction(allocator, vote_tx);
        defer if (maybe_parsed_tx) |parsed_tx| parsed_tx.deinit(allocator);

        try std.testing.expectEqualDeep(ParsedVote{
            .key = vote_key,
            .vote = .{ .vote = .{
                .slots = &.{42},
                .hash = bank_hash,
                .timestamp = null,
            } },
            .switch_proof_hash = input_hash,
            .signature = vote_tx.signatures[0],
        }, maybe_parsed_tx);
    }

    // Test bad program id fails
    var vote_ix = try vote_instruction.createVote(
        allocator,
        vote_key,
        Pubkey.fromPublicKey(&auth_voter_keypair.public_key),
        .{ .vote = .{
            .slots = &.{ 1, 2 },
            .hash = Hash.ZEROES,
            .timestamp = null,
        } },
    );
    defer vote_ix.deinit(allocator);
    vote_ix.program_id = Pubkey.ZEROES;

    const vote_tx = blk: {
        const vote_tx_msg: TransactionMessage = try .initCompile(
            allocator,
            &.{vote_ix},
            Pubkey.fromPublicKey(&node_keypair.public_key),
            Hash.ZEROES,
            null,
        );
        errdefer vote_tx_msg.deinit(allocator);
        break :blk try Transaction.initOwnedMsgWithSigningKeypairs(
            allocator,
            .legacy,
            vote_tx_msg,
            &.{},
        );
    };
    defer vote_tx.deinit(allocator);
    try std.testing.expectEqual(null, parseVoteTransaction(allocator, vote_tx));
}

/// Reimplemented locally from Vote program.
fn testNewVoteTransaction(
    allocator: std.mem.Allocator,
    slots: []const sig.core.Slot,
    bank_hash: Hash,
    blockhash: Hash,
    node_keypair: sig.identity.KeyPair,
    vote_key: Pubkey,
    authorized_voter_keypair: sig.identity.KeyPair,
    maybe_switch_proof_hash: ?Hash,
) !Transaction {
    comptime std.debug.assert(@import("builtin").is_test);
    const vote_ix = try newVoteInstruction(
        allocator,
        slots,
        bank_hash,
        vote_key,
        Pubkey.fromPublicKey(&authorized_voter_keypair.public_key),
        maybe_switch_proof_hash,
    );
    defer vote_ix.deinit(allocator);

    const vote_tx_msg: TransactionMessage = try .initCompile(
        allocator,
        &.{vote_ix},
        Pubkey.fromPublicKey(&node_keypair.public_key),
        blockhash,
        null,
    );
    errdefer vote_tx_msg.deinit(allocator);
    return try Transaction.initOwnedMsgWithSigningKeypairs(
        allocator,
        .legacy,
        vote_tx_msg,
        &.{ node_keypair, authorized_voter_keypair },
    );
}

fn newVoteInstruction(
    allocator: std.mem.Allocator,
    slots: []const sig.core.Slot,
    bank_hash: Hash,
    vote_key: Pubkey,
    authorized_voter_key: Pubkey,
    maybe_switch_proof_hash: ?Hash,
) !sig.core.Instruction {
    const vote_state: vote_program.state.Vote = .{
        .slots = slots,
        .hash = bank_hash,
        .timestamp = null,
    };

    if (maybe_switch_proof_hash) |switch_proof_hash| {
        return try vote_instruction.createVoteSwitch(
            allocator,
            vote_key,
            authorized_voter_key,
            .{
                .vote = vote_state,
                .hash = switch_proof_hash,
            },
        );
    }
    return try vote_instruction.createVote(
        allocator,
        vote_key,
        authorized_voter_key,
        .{
            .vote = vote_state,
        },
    );
}

fn randomKeyPair(random: std.Random) !sig.identity.KeyPair {
    var seed: [sig.identity.KeyPair.seed_length]u8 = undefined;
    random.bytes(&seed);
    return try sig.identity.KeyPair.generateDeterministic(seed);
}
