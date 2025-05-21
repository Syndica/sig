const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const vote_program = sig.runtime.program.vote;

pub const InitializeAccount = struct {
    node_pubkey: Pubkey,
    /// The vote authority keypair signs vote transactions. Can be the same as the identity account.
    authorized_voter: Pubkey,
    /// The authorized withdrawer keypair is used to withdraw funds from a vote account,
    /// including validator rewards. Only this keypair can access the funds.
    authorized_withdrawer: Pubkey,
    /// Commission is the percentage of network rewards kept by the validator.
    /// The rest is distributed to delegators based on their stake weight.
    commission: u8,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Uninitialized vote account
        account = 0,
        /// `[]` Rent sysvar
        rent_sysvar = 1,
        /// `[]` Clock sysvar
        clock_sysvar = 2,
        /// `[SIGNER]` New validator identity (node_pubkey)
        signer = 3,
    };
};

pub const Authorize = struct {
    /// Public Key to be made the new authority for the vote account.
    new_authority: Pubkey,
    /// Type of autorization to grant.
    vote_authorize: vote_program.state.VoteAuthorize,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to be updated with the Pubkey for authorization
        account = 0,
        /// `[]` Clock sysvar
        clock_sysvar = 1,
        /// `[SIGNER]` Vote or withdraw authority
        current_authority = 2,
    };
};

pub const VoteAuthorizeWithSeedArgs = struct {
    authorization_type: vote_program.state.VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
    new_authority: Pubkey,

    pub const @"!bincode-config:current_authority_derived_key_seed" =
        sig.bincode.utf8StringCodec([]const u8);

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to be updated
        account = 0,
        /// `[]` Clock sysvar
        clock_sysvar = 1,
        /// `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
        current_base_authority = 2,
    };
};

pub const VoteAuthorizeCheckedWithSeedArgs = struct {
    authorization_type: vote_program.state.VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,

    pub const @"!bincode-config:current_authority_derived_key_seed" =
        sig.bincode.utf8StringCodec([]const u8);

    pub const AccountIndex = enum(u8) {
        /// `[Write]` Vote account to be updated
        account = 0,
        /// `[]` Clock sysvar
        clock_sysvar = 1,
        ///  `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
        current_base_authority = 2,
        /// `[SIGNER]` New vote or withdraw authority
        new_authority = 3,
    };
};

pub const VoteAuthorize = enum {
    voter,
    withdrawer,

    pub const AccountIndex = enum(u8) {
        /// `[Write]` Vote account to be updated with the Pubkey for authorization
        account = 0,
        /// `[]` Clock sysvar
        clock_sysvar = 1,
        ///  `[SIGNER]` Vote or withdraw authority
        current_authority = 2,
        /// `[SIGNER]` New vote or withdraw authority
        new_authority = 3,
    };
};

pub const UpdateVoteIdentity = struct {
    pub const AccountIndex = enum(u8) {
        /// `[Write]` Vote account to be updated with the given authority public key
        account = 0,
        /// `[SIGNER]` New validator identity (node_pubkey)
        new_identity = 1,
        ///  `[SIGNER]` Withdraw authority
        current_authority = 2,
    };
};

pub const UpdateCommission = struct {
    pub const AccountIndex = enum(u8) {
        /// `[Write]` Vote account to be updated
        account = 0,
        /// `[SIGNER]` Withdraw authority
        current_authority = 1,
    };
};

pub const Withdraw = struct {
    pub const AccountIndex = enum(u8) {
        /// `[Write]` Vote account to be updated
        account = 0,
        /// `[Write]` Recipient account
        recipient_authority = 1,
        /// `[SIGNER]` Withdraw authority
        current_authority = 2,
    };
};

pub const Vote = struct {
    vote: vote_program.state.Vote,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Slot hashes sysvar
        slot_sysvar = 1,
        ///  `[]` Clock sysvar
        clock_sysvar = 2,
        /// `[SIGNER]` Vote authority
        vote_authority = 3,
    };

    pub fn deinit(self: Vote, allocator: std.mem.Allocator) void {
        self.vote.deinit(allocator);
    }
};

pub const VoteSwitch = struct {
    vote: vote_program.state.Vote,
    hash: Hash,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Slot hashes sysvar
        slot_sysvar = 1,
        ///  `[]` Clock sysvar
        clock_sysvar = 2,
        /// `[SIGNER]` Vote authority
        vote_authority = 3,
    };

    pub fn deinit(self: VoteSwitch, allocator: std.mem.Allocator) void {
        self.vote.deinit(allocator);
    }
};

pub const VoteStateUpdate = struct {
    vote_state_update: vote_program.state.VoteStateUpdate,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: VoteStateUpdate, allocator: std.mem.Allocator) void {
        self.vote_state_update.deinit(allocator);
    }
};

pub const CompactVoteStateUpdate = struct {
    vote_state_update: vote_program.state.VoteStateUpdate,

    pub const @"!bincode-config:vote_state_update": sig.bincode.FieldConfig(
        vote_program.state.VoteStateUpdate,
    ) = .{
        .deserializer = vote_program.state.deserializeCompactVoteStateUpdate,
        .serializer = vote_program.state.serializeCompactVoteStateUpdate,
    };

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: CompactVoteStateUpdate, allocator: std.mem.Allocator) void {
        self.vote_state_update.deinit(allocator);
    }
};

pub const VoteStateUpdateSwitch = struct {
    vote_state_update: vote_program.state.VoteStateUpdate,
    hash: Hash,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: VoteStateUpdateSwitch, allocator: std.mem.Allocator) void {
        self.vote_state_update.deinit(allocator);
    }
};

pub const CompactVoteStateUpdateSwitch = struct {
    vote_state_update: vote_program.state.VoteStateUpdate,
    hash: Hash,

    pub const @"!bincode-config:vote_state_update": sig.bincode.FieldConfig(
        vote_program.state.VoteStateUpdate,
    ) = .{
        .deserializer = vote_program.state.deserializeCompactVoteStateUpdate,
        .serializer = vote_program.state.serializeCompactVoteStateUpdate,
    };

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: CompactVoteStateUpdateSwitch, allocator: std.mem.Allocator) void {
        self.vote_state_update.deinit(allocator);
    }
};

pub const TowerSync = struct {
    tower_sync: vote_program.state.TowerSync,

    pub const @"!bincode-config:tower_sync": sig.bincode.FieldConfig(
        vote_program.state.TowerSync,
    ) = .{
        .deserializer = vote_program.state.deserializeTowerSync,
        .serializer = vote_program.state.serializeTowerSync,
    };

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: TowerSync, allocator: std.mem.Allocator) void {
        self.tower_sync.deinit(allocator);
    }
};

pub const TowerSyncSwitch = struct {
    tower_sync: vote_program.state.TowerSync,
    hash: Hash,

    pub const @"!bincode-config:tower_sync": sig.bincode.FieldConfig(
        vote_program.state.TowerSync,
    ) = .{
        .deserializer = vote_program.state.deserializeTowerSync,
        .serializer = vote_program.state.serializeTowerSync,
    };

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to vote with
        account = 0,
        /// `[]` Vote authority
        vote_authority = 1,
    };

    pub fn deinit(self: TowerSyncSwitch, allocator: std.mem.Allocator) void {
        self.tower_sync.deinit(allocator);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L26
pub const Instruction = union(enum(u32)) {
    /// Initialize a vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` New validator identity (node_pubkey)
    initialize_account: InitializeAccount,

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Current vote or withdraw authority
    authorize: Authorize,

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    vote: Vote,

    /// Withdraw some amount of funds
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to withdraw from
    ///   1. `[WRITE]` Recipient account
    ///   2. `[SIGNER]` Withdraw authority
    withdraw: u64,

    /// Update the vote account's validator identity (node_pubkey)
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the given authority public key
    ///   1. `[SIGNER]` New validator identity (node_pubkey)
    ///   2. `[SIGNER]` Withdraw authority
    update_validator_identity,

    /// Update the commission for the vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated
    ///   1. `[SIGNER]` Withdraw authority
    update_commission: u8,

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    vote_switch: VoteSwitch,

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new vote
    /// or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    ///   3. `[SIGNER]` New vote or withdraw authority
    authorize_checked: VoteAuthorize,

    /// Update the onchain vote state for the signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    update_vote_state: VoteStateUpdate,

    /// Update the onchain vote state for the signer along with a switching proof.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    update_vote_state_switch: VoteStateUpdateSwitch,

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    authorize_with_seed: VoteAuthorizeWithSeedArgs,

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement
    /// that the new vote or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    ///   3. `[SIGNER]` New vote or withdraw authority
    authorize_checked_with_seed: VoteAuthorizeCheckedWithSeedArgs,

    /// Update the onchain vote state for the signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    compact_update_vote_state: CompactVoteStateUpdate,

    /// Update the onchain vote state for the signer along with a switching proof.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    compact_update_vote_state_switch: CompactVoteStateUpdateSwitch,

    /// Sync the onchain vote state with local tower
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    tower_sync: TowerSync,

    /// Sync the onchain vote state with local tower along with a switching proof
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    tower_sync_switch: TowerSyncSwitch,

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        switch (self) {
            .initialize_account,
            .authorize,
            .withdraw,
            .update_validator_identity,
            .update_commission,
            .authorize_checked,
            .authorize_with_seed,
            .authorize_checked_with_seed,
            => {},

            inline //
            .vote,
            .vote_switch,
            .update_vote_state,
            .update_vote_state_switch,
            .compact_update_vote_state,
            .compact_update_vote_state_switch,
            .tower_sync,
            .tower_sync_switch,
            => |payload| payload.deinit(allocator),
        }
    }
};

test "CompactVoteStateUpdate.serialize" {
    const allocator = std.testing.allocator;

    const agave_bytes = &[_]u8{
        12,  0,   0,   0,   25,  86,  252, 14,
        0,   0,   0,   0,   31,  1,   31,  1,
        30,  1,   29,  1,   28,  1,   27,  1,
        26,  1,   25,  1,   24,  1,   23,  1,
        22,  2,   21,  1,   20,  1,   19,  1,
        18,  1,   17,  1,   16,  1,   15,  1,
        14,  1,   13,  1,   12,  1,   11,  1,
        10,  1,   9,   1,   8,   1,   7,   1,
        6,   1,   5,   1,   4,   1,   3,   1,
        2,   1,   1,   60,  42,  236, 183, 151,
        41,  95,  57,  187, 211, 148, 57,  37,
        64,  58,  122, 118, 135, 9,   28,  126,
        75,  207, 204, 187, 237, 77,  45,  36,
        179, 249, 67,  1,   187, 227, 225, 101,
        0,   0,   0,   0,
    };

    const instruction = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        agave_bytes,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    const sig_bytes = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(sig_bytes);

    try std.testing.expectEqualSlices(u8, agave_bytes, sig_bytes);
}

test "CompactVoteStateUpdateSwitch.serialize" {
    const allocator = std.testing.allocator;

    const agave_bytes = &[_]u8{
        13,  0,   0,   0,   182, 43,  211, 24,
        45,  224, 50,  209, 2,   0,   236, 211,
        38,  162, 0,   0,   0,   0,   0,   0,
        150, 176, 183, 252, 249, 170, 254, 195,
        174, 1,   12,  0,   0,   0,   151, 176,
        183, 252, 249, 170, 254, 195, 174, 1,
        16,  0,   0,   0,   39,  218, 241, 244,
        212, 193, 180, 122, 61,  8,   85,  77,
        95,  245, 154, 126, 120, 97,  109, 228,
        174, 171, 3,   251, 127, 29,  84,  154,
        233, 13,  128,
    };

    const instruction = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        agave_bytes,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    const sig_bytes = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(sig_bytes);

    try std.testing.expectEqualSlices(u8, agave_bytes, sig_bytes);
}

test "TowerSync.serialize" {
    const allocator = std.testing.allocator;

    const agave_bytes = &[_]u8{
        14,  0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   152, 37,  40,
        198, 22,  214, 101, 1,   25,  200, 93,
        191, 155, 112, 229, 7,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   89,  155,
        222, 237, 128, 161, 213, 175, 149, 138,
        16,  150, 218, 58,  71,  143,
    };

    const instruction = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        agave_bytes,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    const sig_bytes = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(sig_bytes);

    try std.testing.expectEqualSlices(u8, agave_bytes, sig_bytes);
}

test "TowerSyncSwitch.serialize" {
    const allocator = std.testing.allocator;

    const agave_bytes = &[_]u8{
        15,  0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   232, 184, 201,
        184, 145, 188, 175, 166, 91,  23,  138,
        245, 249, 45,  207, 79,  53,  237, 207,
        167, 120, 125, 209, 182, 29,  54,  216,
        211, 24,  156, 212, 121, 0,   0,   0,
        0,   0,   0,   0,   0,   0,   1,   134,
        170, 174, 144, 211, 216, 199, 232, 238,
        227, 124, 10,  144, 114, 0,   220, 249,
        248, 77,  0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   1,   137,
        43,  198, 168, 186, 242, 201, 48,  253,
        140, 83,  207, 142, 22,  214, 51,  185,
        238, 103, 192, 0,   0,   0,
    };

    const instruction = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        agave_bytes,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    const sig_bytes = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(sig_bytes);

    try std.testing.expectEqualSlices(u8, agave_bytes, sig_bytes);
}
