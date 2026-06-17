const std = @import("std");
const sig = @import("../../../lib.zig");

const vote_program = sig.runtime.program.vote;
const vote_state = vote_program.state;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const InstructionAccount = sig.core.instruction.InstructionAccount;

const SEED_FIELD_CONFIG = sig.runtime.program.SEED_FIELD_CONFIG;

const BLS_PUBLIC_KEY_COMPRESSED_SIZE = vote_state.BLS_PUBLIC_KEY_COMPRESSED_SIZE;
const BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE = vote_state.BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L25
pub const CommissionKind = enum(u8) {
    inflation_rewards = 0,
    block_revenue = 1,
};

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
    vote_authorize: VoteAuthorize,

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
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
    new_authority: Pubkey,

    pub const @"!bincode-config:current_authority_derived_key_seed" = SEED_FIELD_CONFIG;

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Vote account to be updated
        account = 0,
        /// `[]` Clock sysvar
        clock_sysvar = 1,
        /// `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
        current_base_authority = 2,
    };

    pub fn deinit(
        self: VoteAuthorizeWithSeedArgs,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.current_authority_derived_key_seed);
    }
};

pub const VoteAuthorizeCheckedWithSeedArgs = struct {
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,

    pub const @"!bincode-config:current_authority_derived_key_seed" = SEED_FIELD_CONFIG;

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

    pub fn deinit(
        self: VoteAuthorizeCheckedWithSeedArgs,
        allocator: std.mem.Allocator,
    ) void {
        allocator.free(self.current_authority_derived_key_seed);
    }
};

pub const VoteAuthorize = union(enum(u32)) {
    voter,
    withdrawer,
    /// SIMD-0387: bind a new voter authority and register the BLS pubkey
    /// used by Alpenglow consensus voting.
    voter_with_bls: VoterWithBLSArgs,

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

/// Payload of `VoteAuthorize::VoterWithBLS` (SIMD-0387).
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb87296b6af322d63627f5341fb2e942c55275b5/vote-interface/src/state/vote_instruction_data.rs#L258-L269
pub const VoterWithBLSArgs = struct {
    bls_pubkey: [BLS_PUBLIC_KEY_COMPRESSED_SIZE]u8,
    bls_proof_of_possession: [BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]u8,
};

/// Payload of `VoteInstruction::InitializeAccountV2` (SIMD-0464).
/// Bundles SIMD-0185 (V4 layout), SIMD-0387 (BLS pubkey + PoP),
/// SIMD-0291 (basis-points commission), SIMD-0232 (commission collectors)
/// initialization in a single instruction. The instruction itself is gated
/// on `vote_account_initialize_v2`; the executor wiring is added later.
/// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb87296b6af322d63627f5341fb2e942c55275b5/vote-interface/src/state/vote_instruction_data.rs#L222-L238
pub const VoteInitV2 = struct {
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_voter_bls_pubkey: [BLS_PUBLIC_KEY_COMPRESSED_SIZE]u8,
    authorized_voter_bls_proof_of_possession: [BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]u8,
    authorized_withdrawer: Pubkey,
    inflation_rewards_commission_bps: u16,
    block_revenue_commission_bps: u16,

    pub const AccountIndex = enum(u8) {
        /// `[WRITE]` Uninitialized vote account
        account = 0,
        /// `[SIGNER]` New validator identity (node_pubkey)
        signer = 1,
        /// `[WRITE]` Inflation rewards collector
        inflation_rewards_collector = 2,
        /// `[WRITE]` Block revenue collector
        block_revenue_collector = 3,
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

/// SIMD-0291: Commission Rate in Basis Points
pub const UpdateCommissionBps = struct {
    commission_bps: u16,
    kind: CommissionKind,

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

    /// Initialize a vote account (V2)
    ///
    /// Convergence instruction for SIMD-0185, SIMD-0387, SIMD-0291,
    /// SIMD-0232, SIMD-0123. Requires all feature gates active.
    /// The variant payload is fully wired through bincode but the
    /// executor still rejects this instruction with
    /// `InvalidInstructionData` until the
    /// `vote_account_initialize_v2` feature is implemented.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/programs/vote/src/vote_processor.rs#L307-L324
    initialize_account_v2: VoteInitV2,

    /// Update the commission collector for the vote account (SIMD-0232)
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the new collector public key
    ///   1. `[WRITE]` New collector account. Must be set to the vote account or
    ///      a system program owned account. Must be writable to ensure the
    ///      account is not reserved.
    ///   2. `[SIGNER]` Vote account withdraw authority
    ///
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L202
    update_commission_collector: CommissionKind,

    /// Update the commission for the vote account, measured in basis points (SIMD-0291).
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated
    ///   1. `[SIGNER]` Withdraw authority
    ///
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L212-L221
    update_commission_bps: UpdateCommissionBps,

    /// Deposit delegator rewards into the vote account (SIMD-0123).
    ///
    /// TODO: implement when SIMD-0123 (block_revenue_sharing) lands in sig.
    ///
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L223-L228
    _reserved_deposit_delegator_rewards: void,

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        switch (self) {
            .initialize_account,
            .authorize,
            .withdraw,
            .update_validator_identity,
            .update_commission,
            .initialize_account_v2,
            .update_commission_collector,
            .update_commission_bps,
            ._reserved_deposit_delegator_rewards,
            .authorize_checked,
            => {},

            inline //
            .authorize_with_seed,
            .authorize_checked_with_seed,
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

    pub fn serialize(
        vote_instruction: Instruction,
        allocator: std.mem.Allocator,
        account_metas: []const InstructionAccount,
    ) std.mem.Allocator.Error!sig.core.Instruction {
        const accounts_duped = try allocator.dupe(InstructionAccount, account_metas);
        errdefer allocator.free(accounts_duped);
        return try sig.core.Instruction.initUsingBincodeAlloc(
            allocator,
            Instruction,
            vote_program.ID,
            accounts_duped,
            &vote_instruction,
        );
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/programs/vote/src/vote_state/handler.rs#L639-L645
pub const Version = enum(u32) {
    v3,
    v4,
};

/// Helper function for more concisely initializing the account lists when serializing an instruction.
fn accountMeta(
    pubkey: Pubkey,
    flags: enum { none, signer, writable, signer_writable },
) InstructionAccount {
    const is_signer, const is_writable = switch (flags) {
        .none => .{ false, false },
        .signer => .{ true, false },
        .writable => .{ false, true },
        .signer_writable => .{ true, true },
    };
    return .{
        .pubkey = pubkey,
        .is_signer = is_signer,
        .is_writable = is_writable,
    };
}

pub fn createInitializeAccount(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    init_account: InitializeAccount,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .initialize_account = init_account };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Rent.ID, .none),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(init_account.node_pubkey, .signer),
    });
}

pub fn createAuthorize(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    /// currently authorized
    authorized_pubkey: Pubkey,
    authorize: Authorize,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .authorize = authorize };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(authorized_pubkey, .signer),
    });
}

pub fn createAuthorizeChecked(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_pubkey: Pubkey, // currently authorized
    new_authorized_pubkey: Pubkey,
    vote_authorize: VoteAuthorize,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .authorize_checked = vote_authorize };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(authorized_pubkey, .signer),
        accountMeta(new_authorized_pubkey, .signer),
    });
}

/// SIMD-0387: bind a new voter authority along with its BLS pubkey and
/// proof-of-possession in a single `Authorize` instruction.
pub fn createAuthorizeVoterWithBls(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    /// currently authorized voter or withdrawer
    authorized_pubkey: Pubkey,
    new_authority: Pubkey,
    args: VoterWithBLSArgs,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .authorize = .{
        .new_authority = new_authority,
        .vote_authorize = .{ .voter_with_bls = args },
    } };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(authorized_pubkey, .signer),
    });
}

pub fn createAuthorizeWithSeed(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    current_authority_base_key: Pubkey,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
    new_authority: Pubkey,
    authorization_type: VoteAuthorize,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .authorize_with_seed = .{
        .authorization_type = authorization_type,
        .current_authority_derived_key_owner = current_authority_derived_key_owner,
        .current_authority_derived_key_seed = current_authority_derived_key_seed,
        .new_authority = new_authority,
    } };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(current_authority_base_key, .signer),
    });
}

pub fn createAuthorizeCheckedWithSeed(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    current_authority_base_key: Pubkey,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
    new_authority: Pubkey,
    authorization_type: VoteAuthorize,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .authorize_checked_with_seed = .{
        .authorization_type = authorization_type,
        .current_authority_derived_key_owner = current_authority_derived_key_owner,
        .current_authority_derived_key_seed = current_authority_derived_key_seed,
    } };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(current_authority_base_key, .signer),
        accountMeta(new_authority, .signer),
    });
}

pub fn createUpdateValidatorIdentity(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_withdrawer_pubkey: Pubkey,
    node_pubkey: Pubkey,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .update_validator_identity;
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(node_pubkey, .signer),
        accountMeta(authorized_withdrawer_pubkey, .signer),
    });
}

pub fn createUpdateCommission(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_withdrawer_pubkey: Pubkey,
    commission: u8,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .update_commission = commission };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_withdrawer_pubkey, .signer),
    });
}

pub fn createVote(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote: Vote,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .vote = vote };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.SlotHashes.ID, .none),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createVoteSwitch(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote_switch: VoteSwitch,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .vote_switch = vote_switch };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(sig.runtime.sysvar.SlotHashes.ID, .none),
        accountMeta(sig.runtime.sysvar.Clock.ID, .none),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createUpdateVoteState(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote_state_update: VoteStateUpdate,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .update_vote_state = vote_state_update };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createUpdateVoteStateSwitch(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote_state_update_switch: VoteStateUpdateSwitch,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .update_vote_state_switch = vote_state_update_switch };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createCompactUpdateVoteState(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote_state_update: CompactVoteStateUpdate,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .compact_update_vote_state = vote_state_update };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createCompactUpdateVoteStateSwitch(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    vote_state_update_switch: CompactVoteStateUpdateSwitch,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .compact_update_vote_state_switch = vote_state_update_switch };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createTowerSync(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    tower_sync: TowerSync,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .tower_sync = tower_sync };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createTowerSyncSwitch(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    tower_sync_switch: TowerSyncSwitch,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .tower_sync_switch = tower_sync_switch };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(authorized_voter_pubkey, .signer),
    });
}

pub fn createWithdraw(
    allocator: std.mem.Allocator,
    vote_pubkey: Pubkey,
    authorized_withdrawer_pubkey: Pubkey,
    lamports: u64,
    to_pubkey: Pubkey,
) std.mem.Allocator.Error!sig.core.Instruction {
    const ix: Instruction = .{ .withdraw = lamports };
    return try ix.serialize(allocator, &.{
        accountMeta(vote_pubkey, .writable),
        accountMeta(to_pubkey, .writable),
        accountMeta(authorized_withdrawer_pubkey, .signer),
    });
}

fn executeRoundTrip(
    allocator: std.mem.Allocator,
    instruction: Instruction,
) !struct { Instruction, Instruction } {
    const serialized = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(serialized);

    const deserialized = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        serialized,
        .{},
    );

    return .{ instruction, deserialized };
}

test "InitializeAccount: roundtrip" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const pre, const post = try executeRoundTrip(
        allocator,
        .{
            .initialize_account = .{
                .node_pubkey = Pubkey.initRandom(prng.random()),
                .authorized_voter = Pubkey.initRandom(prng.random()),
                .authorized_withdrawer = Pubkey.initRandom(prng.random()),
                .commission = 10,
            },
        },
    );

    try std.testing.expectEqualSlices(
        u8,
        &pre.initialize_account.node_pubkey.data,
        &post.initialize_account.node_pubkey.data,
    );
    try std.testing.expectEqualSlices(
        u8,
        &pre.initialize_account.authorized_voter.data,
        &post.initialize_account.authorized_voter.data,
    );
    try std.testing.expectEqualSlices(
        u8,
        &pre.initialize_account.authorized_withdrawer.data,
        &post.initialize_account.authorized_withdrawer.data,
    );
    try std.testing.expectEqual(
        pre.initialize_account.commission,
        post.initialize_account.commission,
    );
}

test "Authorize: roundtrip" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const pre, const post = try executeRoundTrip(
        allocator,
        .{
            .authorize = .{
                .new_authority = Pubkey.initRandom(prng.random()),
                .vote_authorize = .voter,
            },
        },
    );

    try std.testing.expectEqualSlices(
        u8,
        &pre.authorize.new_authority.data,
        &post.authorize.new_authority.data,
    );
    try std.testing.expectEqual(
        pre.authorize.vote_authorize,
        post.authorize.vote_authorize,
    );
}

test "VoteAuthorizeWithSeedArgs: roundtrip" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const pre, const post = try executeRoundTrip(
        allocator,
        .{
            .authorize_with_seed = .{
                .authorization_type = .voter,
                .current_authority_derived_key_owner = Pubkey.initRandom(prng.random()),
                .current_authority_derived_key_seed = try allocator.dupe(u8, "test_seed"),
                .new_authority = Pubkey.initRandom(prng.random()),
            },
        },
    );
    defer {
        pre.deinit(allocator);
        post.deinit(allocator);
    }

    try std.testing.expectEqual(
        pre.authorize_with_seed.authorization_type,
        post.authorize_with_seed.authorization_type,
    );
    try std.testing.expectEqualSlices(
        u8,
        &pre.authorize_with_seed.current_authority_derived_key_owner.data,
        &post.authorize_with_seed.current_authority_derived_key_owner.data,
    );
    try std.testing.expectEqualSlices(
        u8,
        pre.authorize_with_seed.current_authority_derived_key_seed,
        post.authorize_with_seed.current_authority_derived_key_seed,
    );
    try std.testing.expectEqualSlices(
        u8,
        &pre.authorize_with_seed.new_authority.data,
        &post.authorize_with_seed.new_authority.data,
    );
}

test "VoteAuthorizeCheckedWithSeedArgs: roundtrip" {
    const allocator = std.testing.allocator;

    const pre, const post = try executeRoundTrip(
        allocator,
        .{
            .authorize_checked_with_seed = .{
                .authorization_type = .voter,
                .current_authority_derived_key_owner = Pubkey.ZEROES,
                .current_authority_derived_key_seed = try allocator.dupe(u8, "test_seed"),
            },
        },
    );
    defer {
        pre.deinit(allocator);
        post.deinit(allocator);
    }

    try std.testing.expectEqual(
        pre.authorize_checked_with_seed.authorization_type,
        post.authorize_checked_with_seed.authorization_type,
    );
    try std.testing.expect(
        pre.authorize_checked_with_seed.current_authority_derived_key_owner.equals(
            &post.authorize_checked_with_seed.current_authority_derived_key_owner,
        ),
    );
    try std.testing.expectEqualSlices(
        u8,
        pre.authorize_checked_with_seed.current_authority_derived_key_seed,
        post.authorize_checked_with_seed.current_authority_derived_key_seed,
    );
}

test "UpdateCommission: roundtrip" {
    const allocator = std.testing.allocator;

    const pre, const post = try executeRoundTrip(
        allocator,
        .{ .update_commission = 20 },
    );

    try std.testing.expectEqual(pre.update_commission, post.update_commission);
}

test "Withdraw: roundtrip" {
    const allocator = std.testing.allocator;

    const pre, const post = try executeRoundTrip(
        allocator,
        .{ .withdraw = 1000 },
    );

    try std.testing.expectEqual(pre.withdraw, post.withdraw);
}

test "Vote: roundtrip" {
    const allocator = std.testing.allocator;

    const pre, const post = try executeRoundTrip(
        allocator,
        .{ .vote = .{ .vote = .{
            .slots = try allocator.dupe(u64, &[_]Slot{ 1, 2, 3 }),
            .hash = Hash.ZEROES,
            .timestamp = null,
        } } },
    );
    defer {
        pre.deinit(allocator);
        post.deinit(allocator);
    }

    try std.testing.expectEqualSlices(
        u8,
        &pre.vote.vote.hash.data,
        &post.vote.vote.hash.data,
    );
    try std.testing.expectEqualSlices(
        u64,
        pre.vote.vote.slots,
        post.vote.vote.slots,
    );
    try std.testing.expectEqual(
        pre.vote.vote.timestamp,
        post.vote.vote.timestamp,
    );
}

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

test createInitializeAccount {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createInitializeAccount(
        allocator,
        Pubkey.initRandom(prng.random()),
        .{
            .node_pubkey = Pubkey.initRandom(prng.random()),
            .authorized_voter = Pubkey.initRandom(prng.random()),
            .authorized_withdrawer = Pubkey.initRandom(prng.random()),
            .commission = 10,
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createAuthorize {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createAuthorize(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .new_authority = Pubkey.initRandom(prng.random()),
            .vote_authorize = .voter,
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createVote {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createVote(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{ .vote = .{
            .slots = &[_]Slot{ 1, 2, 3 },
            .hash = Hash.ZEROES,
            .timestamp = null,
        } },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createWithdraw {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createWithdraw(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        1000,
        Pubkey.initRandom(prng.random()),
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createUpdateValidatorIdentity {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createUpdateValidatorIdentity(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createUpdateCommission {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createUpdateCommission(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        20,
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createVoteSwitch {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createVoteSwitch(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .vote = .{
                .slots = &[_]Slot{ 1, 2, 3 },
                .hash = Hash.ZEROES,
                .timestamp = null,
            },
            .hash = Hash.initRandom(prng.random()),
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createAuthorizeChecked {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createAuthorizeChecked(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .voter,
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createUpdateVoteState {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createUpdateVoteState(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{ .vote_state_update = .{
            .lockouts = .{},
            .root = 42,
            .hash = Hash.initRandom(prng.random()),
            .timestamp = null,
        } },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createUpdateVoteStateSwitch {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createUpdateVoteStateSwitch(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .vote_state_update = .{
                .lockouts = .{},
                .root = 42,
                .hash = Hash.initRandom(prng.random()),
                .timestamp = null,
            },
            .hash = Hash.initRandom(prng.random()),
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createAuthorizeWithSeed {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createAuthorizeWithSeed(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        "test_seed",
        Pubkey.initRandom(prng.random()),
        .voter,
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createAuthorizeCheckedWithSeed {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createAuthorizeCheckedWithSeed(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        "test_seed",
        Pubkey.initRandom(prng.random()),
        .voter,
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createCompactUpdateVoteState {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createCompactUpdateVoteState(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{ .vote_state_update = .{
            .lockouts = .{},
            .root = 42,
            .hash = Hash.initRandom(prng.random()),
            .timestamp = null,
        } },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createCompactUpdateVoteStateSwitch {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createCompactUpdateVoteStateSwitch(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .vote_state_update = .{
                .lockouts = .{},
                .root = 42,
                .hash = Hash.initRandom(prng.random()),
                .timestamp = null,
            },
            .hash = Hash.initRandom(prng.random()),
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createTowerSync {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createTowerSync(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .tower_sync = .{
                .lockouts = .{},
                .root = null,
                .hash = Hash.initRandom(prng.random()),
                .timestamp = null,
                .block_id = Hash.initRandom(prng.random()),
            },
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test createTowerSyncSwitch {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const instruction = try createTowerSyncSwitch(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        .{
            .tower_sync = .{
                .lockouts = .{},
                .root = null,
                .hash = Hash.initRandom(prng.random()),
                .timestamp = null,
                .block_id = Hash.initRandom(prng.random()),
            },
            .hash = Hash.initRandom(prng.random()),
        },
    );
    defer sig.bincode.free(allocator, instruction);

    const message = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{instruction},
        null,
        Hash.initRandom(prng.random()),
        null,
    );
    defer message.deinit(allocator);
}

test "VoteAuthorize bincode: Voter and Withdrawer discriminants" {
    const allocator = std.testing.allocator;

    // Discriminant 0 -> Voter, 1 -> Withdrawer, 2 -> VoterWithBLS.
    // Bincode encodes the union tag as little-endian u32.
    {
        const v = VoteAuthorize.voter;
        const bytes = try sig.bincode.writeAlloc(allocator, v, .{});
        defer allocator.free(bytes);
        try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, bytes);

        const decoded = try sig.bincode.readFromSlice(allocator, VoteAuthorize, bytes, .{});
        try std.testing.expect(decoded == .voter);
    }
    {
        const v = VoteAuthorize.withdrawer;
        const bytes = try sig.bincode.writeAlloc(allocator, v, .{});
        defer allocator.free(bytes);
        try std.testing.expectEqualSlices(u8, &.{ 1, 0, 0, 0 }, bytes);

        const decoded = try sig.bincode.readFromSlice(allocator, VoteAuthorize, bytes, .{});
        try std.testing.expect(decoded == .withdrawer);
    }
}

test "VoteAuthorize bincode: VoterWithBLS payload roundtrip" {
    const allocator = std.testing.allocator;

    var bls_pubkey: [BLS_PUBLIC_KEY_COMPRESSED_SIZE]u8 = undefined;
    for (&bls_pubkey, 0..) |*b, i| b.* = @intCast(0x10 +% (i % 256));
    var bls_proof: [BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]u8 = undefined;
    for (&bls_proof, 0..) |*b, i| b.* = @intCast(0xA0 +% (i % 256));

    const v: VoteAuthorize = .{ .voter_with_bls = .{
        .bls_pubkey = bls_pubkey,
        .bls_proof_of_possession = bls_proof,
    } };

    const bytes = try sig.bincode.writeAlloc(allocator, v, .{});
    defer allocator.free(bytes);

    // 4-byte LE tag (2) + 48 byte pubkey + 96 byte PoP = 148 bytes.
    try std.testing.expectEqual(@as(usize, 4 + 48 + 96), bytes.len);
    try std.testing.expectEqualSlices(u8, &.{ 2, 0, 0, 0 }, bytes[0..4]);
    try std.testing.expectEqualSlices(u8, &bls_pubkey, bytes[4..][0..48]);
    try std.testing.expectEqualSlices(u8, &bls_proof, bytes[4 + 48 ..][0..96]);

    const decoded = try sig.bincode.readFromSlice(allocator, VoteAuthorize, bytes, .{});
    try std.testing.expect(decoded == .voter_with_bls);
    try std.testing.expectEqualSlices(u8, &bls_pubkey, &decoded.voter_with_bls.bls_pubkey);
    try std.testing.expectEqualSlices(
        u8,
        &bls_proof,
        &decoded.voter_with_bls.bls_proof_of_possession,
    );
}

test "VoteInitV2 bincode: 244-byte fixed layout" {
    const allocator = std.testing.allocator;

    const init: VoteInitV2 = .{
        .node_pubkey = Pubkey.ZEROES,
        .authorized_voter = Pubkey.ZEROES,
        .authorized_voter_bls_pubkey = @splat(0),
        .authorized_voter_bls_proof_of_possession = @splat(0),
        .authorized_withdrawer = Pubkey.ZEROES,
        .inflation_rewards_commission_bps = 0x1234,
        .block_revenue_commission_bps = 0xABCD,
    };

    const bytes = try sig.bincode.writeAlloc(allocator, init, .{});
    defer allocator.free(bytes);

    // 32*3 (pubkeys) + 48 + 96 + 2 + 2 = 244 bytes.
    try std.testing.expectEqual(@as(usize, 32 + 32 + 48 + 96 + 32 + 2 + 2), bytes.len);
    // Trailing two little-endian u16s.
    try std.testing.expectEqualSlices(u8, &.{ 0x34, 0x12 }, bytes[240..242]);
    try std.testing.expectEqualSlices(u8, &.{ 0xCD, 0xAB }, bytes[242..244]);

    const decoded = try sig.bincode.readFromSlice(allocator, VoteInitV2, bytes, .{});
    try std.testing.expectEqual(init, decoded);
}

test "Instruction bincode: initialize_account_v2 discriminant unchanged" {
    const allocator = std.testing.allocator;

    // The vote `Instruction` enum has 18 variants; `InitializeAccountV2`
    // sits at index 16 (after `TowerSyncSwitch`, before
    // `UpdateCommissionCollector`). Confirm the bincode discriminant
    // matches what agave wires up.
    const ix: Instruction = .{ .initialize_account_v2 = .{
        .node_pubkey = Pubkey.ZEROES,
        .authorized_voter = Pubkey.ZEROES,
        .authorized_voter_bls_pubkey = @splat(0),
        .authorized_voter_bls_proof_of_possession = @splat(0),
        .authorized_withdrawer = Pubkey.ZEROES,
        .inflation_rewards_commission_bps = 0,
        .block_revenue_commission_bps = 0,
    } };

    const bytes = try sig.bincode.writeAlloc(allocator, ix, .{});
    defer allocator.free(bytes);
    try std.testing.expectEqualSlices(u8, &.{ 16, 0, 0, 0 }, bytes[0..4]);
}

test "createAuthorizeVoterWithBls: roundtrips through bincode" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var bls_pubkey: [BLS_PUBLIC_KEY_COMPRESSED_SIZE]u8 = undefined;
    var bls_proof: [BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]u8 = undefined;
    prng.random().bytes(&bls_pubkey);
    prng.random().bytes(&bls_proof);

    const vote_pk = Pubkey.initRandom(prng.random());
    const current_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());

    const compiled = try createAuthorizeVoterWithBls(
        allocator,
        vote_pk,
        current_voter,
        new_voter,
        .{ .bls_pubkey = bls_pubkey, .bls_proof_of_possession = bls_proof },
    );
    defer sig.bincode.free(allocator, compiled);

    const decoded = try sig.bincode.readFromSlice(
        allocator,
        Instruction,
        compiled.data,
        .{},
    );
    defer decoded.deinit(allocator);

    try std.testing.expect(decoded == .authorize);
    try std.testing.expect(decoded.authorize.new_authority.equals(&new_voter));
    try std.testing.expect(decoded.authorize.vote_authorize == .voter_with_bls);
    try std.testing.expectEqualSlices(
        u8,
        &bls_pubkey,
        &decoded.authorize.vote_authorize.voter_with_bls.bls_pubkey,
    );
    try std.testing.expectEqualSlices(
        u8,
        &bls_proof,
        &decoded.authorize.vote_authorize.voter_with_bls.bls_proof_of_possession,
    );
}
