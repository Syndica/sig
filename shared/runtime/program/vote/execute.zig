const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../lib.zig");

const vote_program = sig.runtime.program.vote;
const pubkey_utils = sig.runtime.pubkey_utils;
const vote_instruction = vote_program.vote_instruction;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const VoteState = vote_program.state.VoteState;
const VoteStateV3 = vote_program.state.VoteStateV3;
const VoteStateV4 = vote_program.state.VoteStateV4;
const LandedVote = vote_program.state.LandedVote;
const Lockout = vote_program.state.Lockout;
const Vote = vote_program.state.Vote;
const VoteStateUpdate = vote_program.state.VoteStateUpdate;
const TowerSync = vote_program.state.TowerSync;
const VoteStateVersions = vote_program.state.VoteStateVersions;
const VoteAuthorize = vote_program.state.VoteAuthorize;
const VoteError = vote_program.VoteError;

const bls12_381 = sig.crypto.bls12_381;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const Rent = sig.runtime.sysvar.Rent;
const Clock = sig.runtime.sysvar.Clock;
const EpochSchedule = sig.core.EpochSchedule;
const SlotHashes = sig.runtime.sysvar.SlotHashes;

const VoteProgramInstruction = vote_instruction.Instruction;
const VoteVersion = vote_instruction.Version;

/// [agave] https://github.com/anza-xyz/agave/blob/2b0966de426597399ed4570d4e6c0635db2f80bf/programs/vote/src/vote_processor.rs#L54
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "vote: execute" });
    defer zone.deinit();

    const tc = ic.tc;

    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/programs/vote/src/vote_processor.rs#L55
    try tc.consumeCompute(vote_program.COMPUTE_UNITS);

    var vote_account = try ic.borrowInstructionAccount(
        @intFromEnum(vote_instruction.InitializeAccount.AccountIndex.account),
    );
    defer vote_account.release();

    if (!vote_account.account.owner.equals(&vote_program.ID)) {
        return InstructionError.InvalidAccountOwner;
    }

    const target_version: VoteVersion = if (tc.feature_set.active(.vote_state_v4, tc.slot))
        .v4
    else
        .v3;

    const instruction = try ic.ixn_info.deserializeInstruction(
        allocator,
        VoteProgramInstruction,
    );
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .initialize_account => |args| try executeIntializeAccount(
            allocator,
            ic,
            &vote_account,
            args.node_pubkey,
            args.authorized_voter,
            args.authorized_withdrawer,
            args.commission,
            target_version,
        ),
        .authorize => |args| try executeAuthorize(
            allocator,
            ic,
            &vote_account,
            args.new_authority,
            args.vote_authorize,
        ),
        .authorize_with_seed => |args| try executeAuthorizeWithSeed(
            allocator,
            ic,
            &vote_account,
            args.new_authority,
            args.authorization_type,
            args.current_authority_derived_key_owner,
            args.current_authority_derived_key_seed,
        ),
        .authorize_checked_with_seed => |args| try executeAuthorizeCheckedWithSeed(
            allocator,
            ic,
            &vote_account,
            args.authorization_type,
            args.current_authority_derived_key_owner,
            args.current_authority_derived_key_seed,
        ),
        .authorize_checked => |args| try executeAuthorizeChecked(
            allocator,
            ic,
            &vote_account,
            args,
        ),
        .update_validator_identity => try executeUpdateValidatorIdentity(
            allocator,
            ic,
            &vote_account,
        ),
        .update_commission => |args| try executeUpdateCommission(
            allocator,
            ic,
            &vote_account,
            args,
        ),
        .withdraw => |args| try executeWithdraw(
            allocator,
            ic,
            &vote_account,
            args,
        ),
        .vote => |args| try executeProcessVoteWithAccount(
            allocator,
            ic,
            &vote_account,
            args.vote,
        ),
        .vote_switch => |args| try executeProcessVoteWithAccount(
            allocator,
            ic,
            &vote_account,
            args.vote,
        ),
        .update_vote_state => |args| return try executeUpdateVoteState(
            allocator,
            ic,
            &vote_account,
            args.vote_state_update,
        ),
        .update_vote_state_switch => |args| return try executeUpdateVoteState(
            allocator,
            ic,
            &vote_account,
            args.vote_state_update,
        ),
        .compact_update_vote_state => |args| return try executeUpdateVoteState(
            allocator,
            ic,
            &vote_account,
            args.vote_state_update,
        ),
        .compact_update_vote_state_switch => |args| return try executeUpdateVoteState(
            allocator,
            ic,
            &vote_account,
            args.vote_state_update,
        ),
        .tower_sync => |args| return try executeTowerSync(
            allocator,
            ic,
            &vote_account,
            args.tower_sync,
        ),
        .tower_sync_switch => |args| return try executeTowerSync(
            allocator,
            ic,
            &vote_account,
            args.tower_sync,
        ),
        .initialize_account_v2 => |args| try executeIntializeAccountV2(
            allocator,
            ic,
            &vote_account,
            args,
        ),
        .update_commission_collector => |kind| return try executeUpdateCommissionCollector(
            allocator,
            ic,
            &vote_account,
            kind,
            target_version,
        ),
        .update_commission_bps => |args| return try executeUpdateCommissionBps(
            allocator,
            ic,
            &vote_account,
            args,
            target_version,
        ),
        ._reserved_deposit_delegator_rewards => return InstructionError.InvalidInstructionData,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/vote/src/vote_processor.rs#L68-L76
///
/// Initialize the vote_state for a vote account
/// Assumes that the account is being init as part of a account creation or balance transfer and
/// that the transaction must be signed by the staker's keys
fn executeIntializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    const rent = try ic.getSysvarWithAccountCheck(
        Rent,
        @intFromEnum(vote_instruction.InitializeAccount.AccountIndex.rent_sysvar),
    );

    const min_balance = rent.minimumBalance(vote_account.constAccountData().len);
    if (vote_account.account.lamports < min_balance) {
        return InstructionError.InsufficientFunds;
    }

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.InitializeAccount.AccountIndex.clock_sysvar),
    );

    try intializeAccount(
        allocator,
        ic,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        vote_account,
        clock,
        target_version,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/ddec7bdbcf308a853d464f865ae4962acbc2b9cd/programs/vote/src/vote_state/mod.rs#L884-L903
///
/// Note: Versioned state is not implemented for creating new vote account, as current check in Agaave implementation
/// here https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/programs/vote/src/vote_state/mod.rs#L890-L892
/// suggests creating only current version is supported.
fn intializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    vote_account: *BorrowedAccount,
    clock: Clock,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    if (vote_account.constAccountData().len != VoteStateV3.MAX_VOTE_STATE_SIZE) {
        return InstructionError.InvalidAccountData;
    }

    var versioned_vote_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    defer versioned_vote_state.deinit(allocator);

    if (!versioned_vote_state.isUninitialized()) {
        return InstructionError.AccountAlreadyInitialized;
    }

    // node must agree to accept this vote account
    if (!ic.ixn_info.isPubkeySigner(node_pubkey)) {
        try ic.tc.log("IntializeAccount: 'node' {f} must sign", .{node_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    var vote_state: VoteState = switch (target_version) {
        .v4 => .{ .v4 = try VoteStateV4.init(
            allocator,
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
            clock.epoch,
            vote_account.pubkey,
        ) },
        .v3 => .{ .v3 = try VoteStateV3.init(
            allocator,
            node_pubkey,
            authorized_voter,
            authorized_withdrawer,
            commission,
            clock.epoch,
        ) },
    };
    defer vote_state.deinit(allocator);

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// SIMD-0387: `is_init_account_v2_enabled` gate.
///
/// Mirrors agave's predicate, which AND-combines five SIMD-0387 / SIMD-0291 /
/// SIMD-0232 / SIMD-0123 / SIMD-0464 feature gates.
///
/// [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_processor.rs#L63-L70
fn isInitAccountV2Enabled(ic: *InstructionContext) bool {
    const slot = ic.tc.slot;
    const fs = ic.tc.feature_set;
    return fs.active(.bls_pubkey_management_in_vote_account, slot) and
        fs.active(.commission_rate_in_basis_points, slot) and
        fs.active(.custom_commission_collector, slot) and
        fs.active(.block_revenue_sharing, slot) and
        fs.active(.vote_account_initialize_v2, slot);
}

/// SIMD-0232 / SIMD-0464 commission-collector argument: either the
/// vote account itself (escape-hatch) or a separately borrowed
/// instruction account pending validation via `validateAndResolveKey`.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_state/mod.rs#L876-L912
const NewCommissionCollector = union(enum) {
    vote_account,
    new_account: BorrowedAccount,

    /// Release the borrowed write-lock on `.new_account`. No-op for
    /// `.vote_account` (the vote account is held by the dispatcher).
    pub fn release(self: *const NewCommissionCollector) void {
        switch (self.*) {
            .vote_account => {},
            .new_account => |account| account.release(),
        }
    }

    /// Validates the collector per SIMD-0232 and returns its pubkey.
    ///
    /// The collector must either equal the vote account's address, or
    /// be a writable, system-program-owned, rent-exempt account.
    ///
    /// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_state/mod.rs#L883-L912
    pub fn validateAndResolveKey(
        self: *const NewCommissionCollector,
        rent: *const Rent,
        vote_account: *const BorrowedAccount,
    ) InstructionError!Pubkey {
        switch (self.*) {
            .vote_account => return vote_account.pubkey,
            .new_account => |collector_account| {
                // 1. Must be a system program owned account.
                const system_program = sig.runtime.program.system;
                if (!collector_account.account.owner.equals(&system_program.ID)) {
                    return InstructionError.InvalidAccountOwner;
                }

                // 2. Must be rent-exempt.
                if (!rent.isExempt(
                    collector_account.account.lamports,
                    collector_account.constAccountData().len,
                )) {
                    return InstructionError.InsufficientFunds;
                }

                // 3. Must not be a reserved account (checked via writable flag).
                if (!collector_account.context.is_writable) {
                    return InstructionError.InvalidArgument;
                }

                return collector_account.pubkey;
            },
        }
    }
};

/// Returns `.vote_account` if the collector meta aliases the vote account,
/// otherwise borrows the collector account.
///
/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_processor.rs#L83-L97
fn readNewCollectorAccount(
    ic: *InstructionContext,
    vote_account: *const BorrowedAccount,
    collector_index_in_instruction: u16,
) InstructionError!NewCommissionCollector {
    const collector_meta = ic.ixn_info.getAccountMetaAtIndex(
        collector_index_in_instruction,
    ) orelse return InstructionError.MissingAccount;

    if (collector_meta.pubkey.equals(&vote_account.pubkey)) {
        return .vote_account;
    }

    return .{
        .new_account = try ic.borrowInstructionAccount(
            collector_index_in_instruction,
        ),
    };
}

/// SIMD-0387: `InitializeAccountV2`.
///
/// Bundles SIMD-0185 (V4 layout), SIMD-0387 (BLS pubkey + PoP),
/// SIMD-0291 (basis-points commission) and SIMD-0232 (commission collectors)
/// initialization into a single instruction. Only available once
/// `isInitAccountV2Enabled` returns true.
///
/// [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_processor.rs#L334-L361
/// [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L1140-L1187
fn executeIntializeAccountV2(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote_init: vote_instruction.VoteInitV2,
) (error{OutOfMemory} || InstructionError)!void {
    if (!isInitAccountV2Enabled(ic)) {
        return InstructionError.InvalidInstructionData;
    }

    // check_number_of_instruction_accounts(4)
    if (ic.ixn_info.account_metas.items.len < 4) {
        return InstructionError.MissingAccount;
    }

    const inflation_rewards_collector = try readNewCollectorAccount(
        ic,
        vote_account,
        @intFromEnum(vote_instruction.VoteInitV2.AccountIndex.inflation_rewards_collector),
    );
    defer inflation_rewards_collector.release();

    const block_revenue_collector = try readNewCollectorAccount(
        ic,
        vote_account,
        @intFromEnum(vote_instruction.VoteInitV2.AccountIndex.block_revenue_collector),
    );
    defer block_revenue_collector.release();

    const clock = try ic.tc.sysvar_cache.get(Clock);
    const rent = try ic.tc.sysvar_cache.get(Rent);

    // check_vote_account_length: V4 only.
    if (vote_account.constAccountData().len != VoteStateV4.MAX_VOTE_STATE_SIZE) {
        return InstructionError.InvalidAccountData;
    }

    var versioned_vote_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    defer versioned_vote_state.deinit(allocator);

    if (!versioned_vote_state.isUninitialized()) {
        return InstructionError.AccountAlreadyInitialized;
    }

    // node must agree to accept this vote account
    if (!ic.ixn_info.isPubkeySigner(vote_init.node_pubkey)) {
        try ic.tc.log(
            "InitializeAccountV2: 'node' {f} must sign",
            .{vote_init.node_pubkey},
        );
        return InstructionError.MissingRequiredSignature;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_state/mod.rs#L1014-L1043
    const inflation_rewards_collector_key = try inflation_rewards_collector
        .validateAndResolveKey(&rent, vote_account);
    const block_revenue_collector_key = try block_revenue_collector
        .validateAndResolveKey(&rent, vote_account);

    // Verify the BLS pubkey proof of possession (consumes 34,500 CUs first,
    // matching agave's `consume_pop_compute_units` ordering).
    try verifyBlsProofOfPossession(
        ic.tc,
        &vote_account.pubkey,
        &vote_init.authorized_voter_bls_pubkey,
        &vote_init.authorized_voter_bls_proof_of_possession,
    );

    // Build the new V4 state. Mirrors `VoteStateV4::new(&VoteInitV2, ...)`:
    // basis-points commissions are taken straight from `vote_init`, the BLS
    // pubkey is populated, and the collector keys are the validated
    // values from above.
    const authorized_voters = try vote_program.state.AuthorizedVoters.init(
        allocator,
        clock.epoch,
        vote_init.authorized_voter,
    );

    var vote_state: VoteState = .{ .v4 = .{
        .node_pubkey = vote_init.node_pubkey,
        .withdrawer = vote_init.authorized_withdrawer,
        .inflation_rewards_collector = inflation_rewards_collector_key,
        .block_revenue_collector = block_revenue_collector_key,
        .inflation_rewards_commission_bps = vote_init.inflation_rewards_commission_bps,
        .block_revenue_commission_bps = vote_init.block_revenue_commission_bps,
        .pending_delegator_rewards = 0,
        .bls_pubkey_compressed = vote_init.authorized_voter_bls_pubkey,
        .votes = .empty,
        .root_slot = null,
        .authorized_voters = authorized_voters,
        .epoch_credits = .empty,
        .last_timestamp = .{ .slot = 0, .timestamp = 0 },
    } };
    defer vote_state.deinit(allocator);

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L77-L79
fn executeAuthorize(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    pubkey: Pubkey,
    vote_authorize: VoteAuthorize,
) (error{OutOfMemory} || InstructionError)!void {
    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.Authorize.AccountIndex.clock_sysvar),
    );

    const signers = try ic.ixn_info.getSigners(allocator);
    defer allocator.free(signers);
    try authorize(
        allocator,
        ic,
        vote_account,
        pubkey,
        vote_authorize,
        clock,
        signers,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L716
///
/// Authorize the given pubkey to withdraw or sign votes. This may be called multiple times,
/// but will implicitly withdraw authorization from the previously authorized
/// key.
fn authorize(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    authorized: Pubkey,
    vote_authorize: VoteAuthorize,
    clock: Clock,
    signers: []const Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(allocator, vote_account, targetVersion(ic.tc), false);
    defer vote_state.deinit(allocator);

    // [SIMD-0387] When `bls_pubkey_management_in_vote_account` is active:
    //   * `Authorize::Voter` MUST NOT be used to overwrite a voter that
    //     already has a BLS pubkey set; clients have to use
    //     `Authorize::VoterWithBLS` so the new voter ↔ BLS pubkey
    //     pairing is verified atomically.
    //   * `Authorize::VoterWithBLS` is gated on the same feature.
    // [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L703-L772
    const is_with_bls_enabled = ic.tc.feature_set.active(
        .bls_pubkey_management_in_vote_account,
        ic.tc.slot,
    );

    switch (vote_authorize) {
        .voter => {
            // [SIMD-0387] reject `Authorize::Voter` when a BLS pubkey
            // is already pinned to the vote account.
            if (is_with_bls_enabled and vote_state.hasBlsPubkey()) {
                return InstructionError.InvalidInstructionData;
            }

            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/vote/src/vote_state/mod.rs#L697-L701
            const target_epoch = std.math.add(u64, clock.leader_schedule_epoch, 1) catch {
                return InstructionError.InvalidAccountData;
            };

            // [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L872
            const epoch_authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
                allocator,
                clock.epoch,
            );

            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/vote/src/vote_state/mod.rs#L701-L709
            // The current authorized withdrawer or the epoch authorized voter must sign the transaction.
            validateIsSigner(vote_state.withdrawerKey().*, signers) catch {
                // If the vote state isn't a valid signer, check if the epoch voter is.
                try validateIsSigner(epoch_authorized_voter, signers);
            };

            // V3's setNewAuthorizedVoter handles prior_voters internally.
            // V4's setNewAuthorizedVoter has no prior_voters (by design).
            const maybe_err = try vote_state.setNewAuthorizedVoter(
                allocator,
                authorized,
                target_epoch,
                null,
            );
            if (maybe_err) |err| {
                ic.tc.custom_error = @intFromEnum(err);
                return InstructionError.Custom;
            }
        },
        .withdrawer => {
            try validateIsSigner(vote_state.withdrawerKey().*, signers);
            vote_state.withdrawerMut().* = authorized;
        },
        .voter_with_bls => |args| {
            // [SIMD-0387] Authorize a new voter together with its BLS
            // pubkey. The PoP is verified against the vote account
            // pubkey (the message domain binds the two together) and
            // 34_500 CUs are consumed regardless of the verification
            // result, matching agave's `consume_pop_compute_units`.
            // [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L736-L770
            if (!is_with_bls_enabled) {
                return InstructionError.InvalidInstructionData;
            }

            // Match agave's call order strictly: the BLS PoP is verified
            // (consuming 34,500 CUs and returning InvalidArgument on
            // failure) BEFORE the target epoch is computed and the epoch
            // authorized voter is looked up. In agave both of the latter
            // happen as an argument to / inside `set_new_authorized_voter`,
            // which is called *after* `verify_bls_proof_of_possession(...)?`.
            // Computing `leader_schedule_epoch + 1` first would let an
            // overflow (e.g. leader_schedule_epoch == u64::MAX) short-circuit
            // with InvalidAccountData and skip the PoP verify + CU charge.
            // [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L732-L763
            try verifyBlsProofOfPossession(
                ic.tc,
                &vote_account.pubkey,
                &args.bls_pubkey,
                &args.bls_proof_of_possession,
            );

            const target_epoch = std.math.add(u64, clock.leader_schedule_epoch, 1) catch {
                return InstructionError.InvalidAccountData;
            };

            const epoch_authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
                allocator,
                clock.epoch,
            );

            // The withdrawer-signer check is non-fatal here (its result is
            // OR-ed against the epoch voter).
            validateIsSigner(vote_state.withdrawerKey().*, signers) catch {
                try validateIsSigner(epoch_authorized_voter, signers);
            };

            const maybe_err = try vote_state.setNewAuthorizedVoter(
                allocator,
                authorized,
                target_epoch,
                &args.bls_pubkey,
            );
            if (maybe_err) |err| {
                ic.tc.custom_error = @intFromEnum(err);
                return InstructionError.Custom;
            }
        },
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L82-L92
fn executeAuthorizeWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    new_account: Pubkey,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.ixn_info.checkNumberOfAccounts(3);

    try authorizeWithSeed(
        allocator,
        ic,
        vote_account,
        new_account,
        authorization_type,
        current_authority_derived_key_owner,
        current_authority_derived_key_seed,
        @intFromEnum(
            vote_instruction.VoteAuthorizeWithSeedArgs.AccountIndex.current_base_authority,
        ),
        @intFromEnum(vote_instruction.VoteAuthorizeWithSeedArgs.AccountIndex.clock_sysvar),
    );
}

/// [agave] Analogous to [process_authorize_with_seed_instruction] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L19
fn authorizeWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    new_authority: Pubkey,
    authorization_type: VoteAuthorize,
    owner: Pubkey,
    seed: []const u8,
    signer_index: u8,
    clock_index: u8,
) (error{OutOfMemory} || InstructionError)!void {
    const clock = try ic.getSysvarWithAccountCheck(Clock, clock_index);

    const signer_meta = ic.ixn_info.getAccountMetaAtIndex(signer_index) orelse
        return InstructionError.MissingAccount;

    const expected_authority_keys = if (signer_meta.is_signer)
        &[_]Pubkey{pubkey_utils.createWithSeed(
            signer_meta.pubkey,
            seed,
            owner,
        ) catch |err| {
            ic.tc.custom_error = pubkey_utils.mapError(err);
            return InstructionError.Custom;
        }}
    else
        &[_]Pubkey{};

    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority,
        authorization_type,
        clock,
        expected_authority_keys,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L96-L102
fn executeAuthorizeCheckedWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.ixn_info.checkNumberOfAccounts(4);

    // Safe since there are at least 4 accounts, and the new_authority index is 3.
    const new_authority_meta = &ic.ixn_info.account_metas.items[
        @intFromEnum(vote_instruction.VoteAuthorizeCheckedWithSeedArgs.AccountIndex.new_authority)
    ];
    if (!new_authority_meta.is_signer) {
        return InstructionError.MissingRequiredSignature;
    }

    try authorizeWithSeed(
        allocator,
        ic,
        vote_account,
        new_authority_meta.pubkey,
        authorization_type,
        current_authority_derived_key_owner,
        current_authority_derived_key_seed,
        @intFromEnum(
            vote_instruction.VoteAuthorizeCheckedWithSeedArgs.AccountIndex.current_base_authority,
        ),
        @intFromEnum(vote_instruction.VoteAuthorizeCheckedWithSeedArgs.AccountIndex.clock_sysvar),
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L239-L248
fn executeAuthorizeChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote_authorize: vote_instruction.VoteAuthorize,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.ixn_info.checkNumberOfAccounts(4);

    // Safe since there are at least 4 accounts, and the new_authority index is 3.
    const new_authority_meta = &ic.ixn_info.account_metas.items[
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.new_authority)
    ];
    if (!new_authority_meta.is_signer) {
        return InstructionError.MissingRequiredSignature;
    }

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.clock_sysvar),
    );

    const signers = try ic.ixn_info.getSigners(allocator);
    defer allocator.free(signers);
    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority_meta.pubkey,
        vote_authorize,
        clock,
        signers,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/24e62248d7a91c090790e7b812e23321fa1f53b1/programs/vote/src/vote_processor.rs#L114-L118
fn executeUpdateValidatorIdentity(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.ixn_info.checkNumberOfAccounts(2);

    // Safe since there are at least 2 accounts, and the new_identity index is 1.
    const new_identity_meta = &ic.ixn_info.account_metas.items[
        @intFromEnum(vote_instruction.UpdateVoteIdentity.AccountIndex.new_identity)
    ];

    try updateValidatorIdentity(
        allocator,
        ic,
        vote_account,
        new_identity_meta.pubkey,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L762
///
/// Update the node_pubkey, requires signature of the authorized voter
fn updateValidatorIdentity(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    new_identity: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(allocator, vote_account, targetVersion(ic.tc), false);
    defer vote_state.deinit(allocator);

    // Both the current authorized withdrawer and new identity must sign.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawerKey().*) or
        !ic.ixn_info.isPubkeySigner(new_identity))
    {
        return InstructionError.MissingRequiredSignature;
    }

    vote_state.nodePubkeyMut().* = new_identity;
    // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/programs/vote/src/vote_state/mod.rs#L828-L832
    // Before SIMD-0232, block_revenue_collector is always synced with node_pubkey.
    // After SIMD-0232, the collector can be set independently.
    if (!ic.tc.feature_set.active(.custom_commission_collector, ic.tc.slot)) {
        if (vote_state.blockRevenueCollectorMut()) |collector| {
            collector.* = new_identity;
        }
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_processor.rs#L383
fn executeUpdateCommissionCollector(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    kind: vote_instruction.CommissionKind,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    // SIMD-0232: Custom Commission Collector Account
    // Requires SIMD-0185: Vote State V4
    const custom_collector_enabled =
        ic.tc.feature_set.active(.custom_commission_collector, ic.tc.slot);
    if (!(custom_collector_enabled and target_version == .v4)) {
        return InstructionError.InvalidInstructionData;
    }

    if (ic.ixn_info.account_metas.items.len < 3) {
        return InstructionError.MissingAccount;
    }

    const new_collector = try readNewCollectorAccount(
        ic,
        vote_account,
        1,
    );
    defer new_collector.release();

    const rent = try ic.tc.sysvar_cache.get(Rent);

    try updateCommissionCollector(
        allocator,
        ic,
        vote_account,
        kind,
        new_collector,
        &rent,
        target_version,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/programs/vote/src/vote_state/mod.rs#L1102-L1144
fn updateCommissionCollector(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    kind: vote_instruction.CommissionKind,
    new_collector: NewCommissionCollector,
    rent: *const Rent,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(
        allocator,
        vote_account,
        target_version,
        true,
    );
    defer vote_state.deinit(allocator);

    // Require authorized withdrawer to sign.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawerKey().*)) {
        return InstructionError.MissingRequiredSignature;
    }

    const new_collector_key = try new_collector.validateAndResolveKey(
        rent,
        vote_account,
    );

    switch (kind) {
        .inflation_rewards => {
            if (vote_state.inflationRewardsCollectorMut()) |collector| {
                collector.* = new_collector_key;
            }
        },
        .block_revenue => {
            if (vote_state.blockRevenueCollectorMut()) |collector| {
                collector.* = new_collector_key;
            }
        },
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/programs/vote/src/vote_processor.rs#L361-L379
///
/// SIMD-0291: Commission Rate in Basis Points. Requires SIMD-0185 (Vote State V4)
/// and SIMD-0249 (Delay Commission Updates).
fn executeUpdateCommissionBps(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    args: vote_instruction.UpdateCommissionBps,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    const commission_rate_in_basis_points =
        ic.tc.feature_set.active(.commission_rate_in_basis_points, ic.tc.slot);
    const delay_commission_updates =
        ic.tc.feature_set.active(.delay_commission_updates, ic.tc.slot);
    if (!commission_rate_in_basis_points or
        !delay_commission_updates or
        target_version != .v4)
    {
        return InstructionError.InvalidInstructionData;
    }

    try updateCommissionBps(
        allocator,
        ic,
        vote_account,
        args.commission_bps,
        args.kind,
        target_version,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/programs/vote/src/vote_state/mod.rs#L829-L862
///
/// Update the vote account's commission in basis points (SIMD-0291, SIMD-0123).
fn updateCommissionBps(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    commission_bps: u16,
    kind: vote_instruction.CommissionKind,
    target_version: VoteVersion,
) (error{OutOfMemory} || InstructionError)!void {
    // Per SIMD-0291: BlockRevenue returns InvalidInstructionData unless
    // SIMD-0123 (block_revenue_sharing) is enabled.
    // TODO: replace with `ic.tc.feature_set.active(.block_revenue_sharing, ic.tc.slot)`
    // when SIMD-0123 lands in sig.
    const block_revenue_sharing_enabled = false;
    if (kind == .block_revenue and !block_revenue_sharing_enabled) {
        return InstructionError.InvalidInstructionData;
    }

    var vote_state = try getVoteStateChecked(
        allocator,
        vote_account,
        target_version,
        true,
    );
    defer vote_state.deinit(allocator);

    // No commission update rule, per SIMD-0249 and SIMD-0291.

    // Require authorized withdrawer to sign.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawerKey().*)) {
        return InstructionError.MissingRequiredSignature;
    }

    switch (kind) {
        .inflation_rewards => vote_state.setInflationRewardsCommissionBps(commission_bps),
        .block_revenue => vote_state.setBlockRevenueCommissionBps(commission_bps),
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/24e62248d7a91c090790e7b812e23321fa1f53b1/programs/vote/src/vote_processor.rs#L121-L131
fn executeUpdateCommission(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    commission: u8,
) (error{OutOfMemory} || InstructionError)!void {
    try updateCommission(
        allocator,
        ic,
        vote_account,
        commission,
        try ic.tc.sysvar_cache.get(EpochSchedule),
        try ic.tc.sysvar_cache.get(Clock),
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L788
///
/// Update the vote account's commission
fn updateCommission(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    commission: u8,
    epoch_schedule: EpochSchedule,
    clock: Clock,
) (error{OutOfMemory} || InstructionError)!void {
    const disable_commission_update_rule =
        ic.tc.feature_set.active(.delay_commission_updates, ic.tc.slot);

    var vote_state = getVoteStateChecked(
        allocator,
        vote_account,
        targetVersion(ic.tc),
        false,
    ) catch |err| {
        // Deserialization failed - enforce the commission update rule
        if (!disable_commission_update_rule and
            !isCommissionUpdateAllowed(clock.slot, &epoch_schedule))
        {
            ic.tc.custom_error = @intFromEnum(VoteError.commission_update_too_late);
            return InstructionError.Custom;
        }
        return err;
    };
    defer vote_state.deinit(allocator);

    const enforce_commission_update_rule = !disable_commission_update_rule and
        commission > vote_state.commission();

    if (enforce_commission_update_rule and !isCommissionUpdateAllowed(clock.slot, &epoch_schedule)) {
        ic.tc.custom_error = @intFromEnum(VoteError.commission_update_too_late);
        return InstructionError.Custom;
    }

    // Current authorized withdrawer must sign transaction.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawerKey().*)) {
        return InstructionError.MissingRequiredSignature;
    }

    // [SIMD-0185] Store as basis points (integer percentage * 100).
    vote_state.setCommission(commission);

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/a7092a20bb2f5d16375bdc531b71d2a164b43b93/programs/vote/src/vote_state/mod.rs#L798
///
/// Given the current slot and epoch schedule, determine if a commission change
/// is allowed
pub fn isCommissionUpdateAllowed(slot: u64, epoch_schedule: *const EpochSchedule) bool {
    // Always allowed during warmup epochs
    const maybe_relative_slot: ?u64 = std.math.rem(
        u64,
        (slot -| epoch_schedule.first_normal_slot),
        epoch_schedule.slots_per_epoch,
    ) catch null;

    if (maybe_relative_slot) |relative_slot| {
        return (relative_slot *| 2 <= epoch_schedule.slots_per_epoch);
    } else {
        return true;
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/e363f52b5bb4bfb131c647d4dbd6043d23575c78/programs/vote/src/vote_processor.rs#L222-L227
fn executeWithdraw(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    try ic.ixn_info.checkNumberOfAccounts(2);
    const rent = try ic.tc.sysvar_cache.get(Rent);
    const clock = try ic.tc.sysvar_cache.get(Clock);

    vote_account.release();

    try widthraw(
        allocator,
        ic,
        @intFromEnum(vote_instruction.Withdraw.AccountIndex.account),
        lamports,
        @intFromEnum(vote_instruction.Withdraw.AccountIndex.recipient_authority),
        rent,
        clock,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L848
fn widthraw(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account_index: u16,
    lamports: u64,
    to_account_index: u16,
    rent: Rent,
    clock: Clock,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_account = try ic.borrowInstructionAccount(vote_account_index);
    defer vote_account.release();

    var vote_state = try getVoteStateChecked(allocator, &vote_account, targetVersion(ic.tc), false);
    defer vote_state.deinit(allocator);

    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawerKey().*)) {
        return InstructionError.MissingRequiredSignature;
    }

    const remaining_balance = std.math.sub(u64, vote_account.account.lamports, lamports) catch {
        return InstructionError.InsufficientFunds;
    };

    const pending_delegator_rewards = vote_state.pendingDelegatorRewards();

    if (remaining_balance == 0) {
        if (pending_delegator_rewards > 0) {
            return InstructionError.InsufficientFunds;
        }

        const reject_active_vote_account_close = blk: {
            const epoch_credits = vote_state.epochCreditsList();
            if (epoch_credits.len > 0) {
                const last_epoch_credit = epoch_credits[epoch_credits.len - 1];
                const current_epoch = clock.epoch;
                const last_epoch_with_credits = last_epoch_credit.epoch;
                // if current_epoch - last_epoch_with_credits < 2 then the validator has received credits
                // either in the current epoch or the previous epoch. If it's >= 2 then it has been at least
                // one full epoch since the validator has received credits.
                break :blk (current_epoch -| last_epoch_with_credits) < 2;
            } else {
                break :blk false;
            }
        };

        if (reject_active_vote_account_close) {
            ic.tc.custom_error = @intFromEnum(VoteError.active_vote_account_close);
            return InstructionError.Custom;
        } else {
            // [SIMD-0185] Withdraw: completely zero vote account data for fully withdrawn v4 accounts.
            if (vote_state == .v4) {
                const data = try vote_account.mutableAccountData();
                @memset(data, 0);
            } else {
                var deinitialized_state: VoteState = .{ .v3 = VoteStateV3.DEFAULT };

                try setVoteState(
                    allocator,
                    &vote_account,
                    &deinitialized_state,
                    &ic.tc.rent,
                    &ic.tc.accounts_resize_delta,
                );
            }
        }
    } else {
        const min_rent_exempt_balance = rent.minimumBalance(vote_account.constAccountData().len);
        const min_balance = std.math.add(
            u64,
            min_rent_exempt_balance,
            pending_delegator_rewards,
        ) catch return InstructionError.ProgramArithmeticOverflow;

        if (remaining_balance < min_balance) {
            return InstructionError.InsufficientFunds;
        }
    }

    try vote_account.subtractLamports(lamports);
    vote_account.release();

    var recipient_account = try ic.borrowInstructionAccount(to_account_index);
    defer recipient_account.release();
    try recipient_account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/e17340519f792d97cf4af7b9eb81056d475c70f9/programs/vote/src/vote_processor.rs#L133
fn executeProcessVoteWithAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote: Vote,
) (error{OutOfMemory} || InstructionError)!void {
    if (ic.tc.feature_set.active(.deprecate_legacy_vote_ixs, ic.tc.slot) and
        ic.tc.feature_set.active(.enable_tower_sync_ix, ic.tc.slot))
    {
        return InstructionError.InvalidInstructionData;
    }

    const slot_hashes = try ic.getSysvarWithAccountCheck(
        SlotHashes,
        @intFromEnum(vote_instruction.Vote.AccountIndex.slot_sysvar),
    );
    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.Vote.AccountIndex.clock_sysvar),
    );

    try processVoteWithAccount(
        allocator,
        ic,
        vote_account,
        vote,
        slot_hashes,
        clock,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L928
fn processVoteWithAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote: Vote,
    slot_hashes: SlotHashes,
    clock: Clock,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(allocator, vote_account, targetVersion(ic.tc), true);
    defer vote_state.deinit(allocator);

    const authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
        allocator,
        clock.epoch,
    );
    if (!ic.ixn_info.isPubkeySigner(authorized_voter)) {
        return InstructionError.MissingRequiredSignature;
    }

    const maybe_err = try vote_state.processVote(
        allocator,
        &vote,
        slot_hashes,
        clock.epoch,
        clock.slot,
    );

    if (maybe_err) |err| {
        ic.tc.custom_error = @intFromEnum(err);
        return InstructionError.Custom;
    }

    if (vote.timestamp) |timestamp| {
        if (vote.slots.len == 0) {
            ic.tc.custom_error = @intFromEnum(VoteError.empty_slots);
            return InstructionError.Custom;
        }

        const max_slot: u64 = if (vote.slots.len > 0)
            std.mem.max(u64, vote.slots)
        else
            0;

        if (vote_state.processTimestamp(max_slot, timestamp)) |err| {
            ic.tc.custom_error = @intFromEnum(err);
            return InstructionError.Custom;
        }
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_processor.rs#L156-L169
fn executeUpdateVoteState(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote_state_update: VoteStateUpdate,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state_update_mut = vote_state_update;
    if (ic.tc.feature_set.active(.deprecate_legacy_vote_ixs, ic.tc.slot) and
        ic.tc.feature_set.active(.enable_tower_sync_ix, ic.tc.slot))
    {
        return InstructionError.InvalidInstructionData;
    }

    const slot_hashes = try ic.tc.sysvar_cache.get(SlotHashes);
    const clock = try ic.tc.sysvar_cache.get(Clock);

    try voteStateUpdate(
        allocator,
        ic,
        vote_account,
        slot_hashes,
        clock,
        &vote_state_update_mut,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L955
fn voteStateUpdate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    slot_hashes: SlotHashes,
    clock: Clock,
    vote_state_update: *VoteStateUpdate,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(allocator, vote_account, targetVersion(ic.tc), true);
    defer vote_state.deinit(allocator);

    const authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
        allocator,
        clock.epoch,
    );
    if (!ic.ixn_info.isPubkeySigner(authorized_voter)) {
        return InstructionError.MissingRequiredSignature;
    }

    const maybe_err = try vote_state.processVoteStateUpdate(
        allocator,
        &slot_hashes,
        clock.epoch,
        clock.slot,
        vote_state_update,
    );

    if (maybe_err) |err| {
        ic.tc.custom_error = @intFromEnum(err);
        return InstructionError.Custom;
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_processor.rs#L202-L212
fn executeTowerSync(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    tower_sync: TowerSync,
) (error{OutOfMemory} || InstructionError)!void {
    var tower_sync_mut = tower_sync;
    if (!ic.tc.feature_set.active(.enable_tower_sync_ix, ic.tc.slot)) {
        return InstructionError.InvalidInstructionData;
    }

    const slot_hashes = try ic.tc.sysvar_cache.get(SlotHashes);
    const clock = try ic.tc.sysvar_cache.get(Clock);

    try towerSync(
        allocator,
        ic,
        vote_account,
        slot_hashes,
        clock,
        &tower_sync_mut,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L1009
fn towerSync(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    slot_hashes: SlotHashes,
    clock: Clock,
    tower_sync: *TowerSync,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try getVoteStateChecked(allocator, vote_account, targetVersion(ic.tc), true);
    defer vote_state.deinit(allocator);

    const authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
        allocator,
        clock.epoch,
    );
    if (!ic.ixn_info.isPubkeySigner(authorized_voter)) {
        return InstructionError.MissingRequiredSignature;
    }

    const maybe_err = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        clock.epoch,
        clock.slot,
        tower_sync,
    );

    if (maybe_err) |err| {
        ic.tc.custom_error = @intFromEnum(err);
        return InstructionError.Custom;
    }

    try setVoteState(
        allocator,
        vote_account,
        &vote_state,
        &ic.tc.rent,
        &ic.tc.accounts_resize_delta,
    );
}

/// Deserialize and validate the vote state from an account.
/// Matches `get_vote_state_handler_checked` in agave v3.1.8.
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L45-L77
fn getVoteStateChecked(
    allocator: std.mem.Allocator,
    vote_account: *BorrowedAccount,
    target_version: VoteVersion,
    check_initialized: bool,
) (error{OutOfMemory} || InstructionError)!VoteState {
    // Peek the leading u32 variant tag before attempting a full bincode decode,
    // mirroring agave's `VoteStateV3::deserialize_into_ptr` (V3 path) and
    // `VoteStateVersions::deserialize` (V4 path). Both helpers shortcut on
    // variant 0 (the unsupported V0_23_5 layout) with InvalidAccountData
    // rather than letting bincode propagate a generic error on a short or
    // zero-tagged buffer.
    // [agave] https://github.com/anza-xyz/solana-sdk/blob/vote-interface@v5.1.1/vote-interface/src/state/vote_state_v3.rs#L159
    // [agave] https://github.com/anza-xyz/solana-sdk/blob/vote-interface@v5.1.1/vote-interface/src/state/vote_state_versions.rs#L155
    const data = vote_account.constAccountData();
    if (data.len < @sizeOf(u32)) {
        return InstructionError.InvalidAccountData;
    }
    const variant = std.mem.readInt(u32, data[0..@sizeOf(u32)], .little);
    if (variant == 0) {
        return switch (target_version) {
            .v3, .v4 => InstructionError.InvalidAccountData,
        };
    }

    var versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    errdefer versioned_state.deinit(allocator);

    const target_v4 = target_version == .v4;

    switch (target_version) {
        .v3 => {
            // Existing flow before v4 feature gate activation:
            // Deserialize as VoteStateVersions (converting during deserialization).
            // Some callsites deserialize without checking initialization status.
            if (check_initialized and versioned_state.isUninitialized()) {
                return InstructionError.UninitializedAccount;
            }
        },
        .v4 => {
            // New flow after v4 feature gate activation:
            // Always checks uninitialized.
            if (versioned_state.isUninitialized()) {
                return InstructionError.UninitializedAccount;
            }
        },
    }

    return versioned_state.convertToVoteState(allocator, vote_account.pubkey, target_v4);
}

fn targetVersion(tc: *const sig.runtime.TransactionContext) VoteVersion {
    return if (tc.feature_set.active(.vote_state_v4, tc.slot)) .v4 else .v3;
}

fn validateIsSigner(
    authorized: Pubkey,
    signers: []const Pubkey,
) InstructionError!void {
    for (signers) |signer| {
        if (signer.equals(&authorized)) {
            return;
        }
    }
    return InstructionError.MissingRequiredSignature;
}

/// [SIMD-0387] Verify the BLS proof-of-possession for a vote account.
///
/// Always consumes `BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS`
/// (34_500 CUs) up front, even if the verification subsequently fails.
/// This mirrors agave's `verify_bls_proof_of_possession` which consumes
/// CUs unconditionally before the elliptic-curve work, and matches
/// firedancer's `fd_bls12_381_proof_of_possession_verify` charging
/// model. On success returns `void`; on a malformed pubkey/signature
/// or pairing-check failure returns `InstructionError.InvalidArgument`,
/// matching agave's mapping.
///
/// [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L1045-L1061
fn verifyBlsProofOfPossession(
    tc: *sig.runtime.TransactionContext,
    vote_account_pubkey: *const Pubkey,
    bls_pubkey_compressed: *const [vote_program.state.BLS_PUBLIC_KEY_COMPRESSED_SIZE]u8,
    // zig fmt: off
    bls_proof_of_possession_compressed: *const [vote_program.state.BLS_PROOF_OF_POSSESSION_COMPRESSED_SIZE]u8,
    // zig fmt: on
) InstructionError!void {
    try tc.consumeCompute(
        vote_program.state.BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS,
    );

    var message: [vote_program.state.BLS_PROOF_OF_POSSESSION_MESSAGE_SIZE]u8 = undefined;
    vote_program.state.generateBlsPopMessage(
        &message,
        vote_account_pubkey,
        bls_pubkey_compressed,
    );

    bls12_381.proofOfPossessionVerify(
        &message,
        bls_proof_of_possession_compressed,
        bls_pubkey_compressed,
    ) catch return InstructionError.InvalidArgument;
}

fn setVoteState(
    allocator: std.mem.Allocator,
    account: *BorrowedAccount,
    state: *const VoteState,
    rent: *const Rent,
    resize_delta: *i64,
) (error{OutOfMemory} || InstructionError)!void {
    switch (state.*) {
        .v4 => |v4_state| {
            // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/programs/vote/src/vote_state/handler.rs#L655-L673
            // [SIMD-0185] v4: check rent exempt first, then resize, then serialize v4.
            // Unlike v3, do not gracefully fall back to storing v1_14_11.
            if (account.constAccountData().len < VoteStateV4.MAX_VOTE_STATE_SIZE) {
                if (!rent.isExempt(account.account.lamports, VoteStateV4.MAX_VOTE_STATE_SIZE)) {
                    return InstructionError.AccountNotRentExempt;
                }
                account.setDataLength(
                    allocator,
                    resize_delta,
                    VoteStateV4.MAX_VOTE_STATE_SIZE,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    // [agave] a failed resize maps to AccountNotRentExempt (the
                    // `set_data_length(...).is_err()` arm of set_vote_account_state),
                    // not the raw InstructionError (e.g. ReadonlyDataModified).
                    else => return InstructionError.AccountNotRentExempt,
                };
            }
            return account.serializeIntoAccountData(VoteStateVersions{ .v4 = v4_state });
        },
        .v3 => |v3_state| {
            const resize_needed = account.constAccountData().len < VoteStateV3.MAX_VOTE_STATE_SIZE;
            const resize_failed = resize_needed and blk: {
                if (!rent.isExempt(account.account.lamports, VoteStateV3.MAX_VOTE_STATE_SIZE)) {
                    break :blk true;
                }
                account.setDataLength(
                    allocator,
                    resize_delta,
                    VoteStateV3.MAX_VOTE_STATE_SIZE,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => break :blk true, // InstructionError
                };
                break :blk false;
            };

            if (resize_failed) {
                const landed_votes = v3_state.votes.items;
                const votes = try allocator.alloc(Lockout, landed_votes.len);
                defer allocator.free(votes);

                for (votes, landed_votes) |*vote, landed| vote.* = landed.lockout;

                return account.serializeIntoAccountData(VoteStateVersions{ .v1_14_11 = .{
                    .node_pubkey = v3_state.node_pubkey,
                    .withdrawer = v3_state.withdrawer,
                    .commission = v3_state.commission,
                    .votes = .fromOwnedSlice(votes),
                    .root_slot = v3_state.root_slot,
                    .voters = v3_state.voters,
                    .prior_voters = v3_state.prior_voters,
                    .epoch_credits = v3_state.epoch_credits,
                    .last_timestamp = v3_state.last_timestamp,
                } });
            }

            return account.serializeIntoAccountData(VoteStateVersions{ .v3 = v3_state });
        },
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3659
test "isCommissionUpdateAllowed epoch half check" {
    const DEFAULT_SLOTS_PER_EPOCH = sig.core.time.DEFAULT_SLOTS_PER_EPOCH;
    const DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET =
        sig.core.epoch_schedule.DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET;

    const TestCase = struct {
        slot: sig.core.Slot,
        expected_allowed: bool,
        name: []const u8,
    };

    const test_cases = [_]TestCase{
        .{
            .slot = 0,
            .expected_allowed = true,
            .name = "first slot",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH / 2,
            .expected_allowed = true,
            .name = "halfway through epoch",
        },
        .{
            .slot = (DEFAULT_SLOTS_PER_EPOCH / 2) +| 1,
            .expected_allowed = false,
            .name = "halfway through epoch plus one",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH -| 1,
            .expected_allowed = false,
            .name = "last slot in epoch",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH,
            .expected_allowed = true,
            .name = "first slot in second epoch",
        },
    };

    for (test_cases) |tc| {
        const epoch_schedule = try testEpochSchedule(
            DEFAULT_SLOTS_PER_EPOCH,
            DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
            false,
        );

        const actual_allowed = isCommissionUpdateAllowed(tc.slot, &epoch_schedule);
        try std.testing.expectEqual(tc.expected_allowed, actual_allowed);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3668
test "isCommissionUpdateAllowed warmup epoch half check with warmup" {
    const DEFAULT_SLOTS_PER_EPOCH = sig.core.time.DEFAULT_SLOTS_PER_EPOCH;
    const DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET =
        sig.core.epoch_schedule.DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET;

    const epoch_schedule = try testEpochSchedule(
        DEFAULT_SLOTS_PER_EPOCH,
        DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
        true,
    );

    const first_normal_slot = epoch_schedule.first_normal_slot;
    // first slot works
    try std.testing.expect(isCommissionUpdateAllowed(0, &epoch_schedule));
    // right before first normal slot works, since all warmup slots allow
    // commission updates
    try std.testing.expect(
        isCommissionUpdateAllowed(first_normal_slot - 1, &epoch_schedule),
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3686
test "isCommissionUpdateAllowed epoch half check with warmup" {
    const DEFAULT_SLOTS_PER_EPOCH = sig.core.time.DEFAULT_SLOTS_PER_EPOCH;
    const DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET =
        sig.core.epoch_schedule.DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET;

    const TestCase = struct {
        slot: sig.core.Slot,
        expected_allowed: bool,
        name: []const u8,
    };

    const test_cases = [_]TestCase{
        .{
            .slot = 0,
            .expected_allowed = true,
            .name = "first slot",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH / 2,
            .expected_allowed = true,
            .name = "halfway through epoch",
        },
        .{
            .slot = (DEFAULT_SLOTS_PER_EPOCH / 2) +| 1,
            .expected_allowed = false,
            .name = "halfway through epoch plus one",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH -| 1,
            .expected_allowed = false,
            .name = "last slot in epoch",
        },
        .{
            .slot = DEFAULT_SLOTS_PER_EPOCH,
            .expected_allowed = true,
            .name = "first slot in second epoch",
        },
    };

    for (test_cases) |tc| {
        const epoch_schedule = try testEpochSchedule(
            DEFAULT_SLOTS_PER_EPOCH,
            DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
            true,
        );

        const actual_allowed = isCommissionUpdateAllowed(
            epoch_schedule.first_normal_slot +| tc.slot,
            &epoch_schedule,
        );
        try std.testing.expectEqual(tc.expected_allowed, actual_allowed);
    }
}

fn testEpochSchedule(
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
) !EpochSchedule {
    if (!@import("builtin").is_test) {
        @panic("testEpochSchedule should only in test");
    }

    const MINIMUM_SLOTS_PER_EPOCH = sig.core.epoch_schedule.MINIMUM_SLOTS_PER_EPOCH;
    std.debug.assert(slots_per_epoch >= MINIMUM_SLOTS_PER_EPOCH);

    var first_normal_epoch: u64 = 0;
    var first_normal_slot: u64 = 0;

    if (warmup) {
        const next_power_of_two = try std.math.ceilPowerOfTwo(u64, slots_per_epoch);
        const log2_slots_per_epoch = @ctz(next_power_of_two) -| @ctz(MINIMUM_SLOTS_PER_EPOCH);
        first_normal_epoch = log2_slots_per_epoch;
        first_normal_slot = next_power_of_two -| MINIMUM_SLOTS_PER_EPOCH;
    }

    return EpochSchedule{
        .slots_per_epoch = slots_per_epoch,
        .leader_schedule_slot_offset = leader_schedule_slot_offset,
        .warmup = warmup,
        .first_normal_epoch = first_normal_epoch,
        .first_normal_slot = first_normal_slot,
    };
}

test "vote_program: executeIntializeAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Insturction data.
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Account data.
    const vote_account = Pubkey.initRandom(prng.random());
    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .initialize_account = .{
                .node_pubkey = node_publey,
                .authorized_voter = authorized_voter,
                .authorized_withdrawer = authorized_withdrawer,
                .commission = commission,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = ([_]u8{0} ** 3762)[0..],
                },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = node_publey },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = node_publey },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: executeAuthorize withdrawer signed by current withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Insturction data.
    const new_authorized_withdrawer = Pubkey.initRandom(prng.random());

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Account data.
    const vote_account = Pubkey.initRandom(prng.random());

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_withdrawer,
                .vote_authorize = VoteAuthorize.withdrawer,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: executeAuthorize voter signed by current withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Insturction data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Account data.
    const vote_account = Pubkey.initRandom(prng.random());

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );
    try final_vote_state.voters.insert(allocator, 1, new_authorized_voter);
    final_vote_state.prior_voters.append(.{
        .key = authorized_voter,
        .start = 0,
        .end = 1,
    });

    var final_current_vote_state: VoteStateVersions = .{ .v3 = final_vote_state };
    defer final_current_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_current_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_voter,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: authorizeWithSeed withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Insturction data.
    const new_authorized_withdrawer = Pubkey.initRandom(prng.random());

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Account data.
    const vote_account = Pubkey.initRandom(prng.random());
    const base = Pubkey.initRandom(prng.random());
    const current_withdrawer_owner = Pubkey.initRandom(prng.random());
    const current_withdrawer_seed = &[_]u8{0x10} ** 32;

    const authorized_withdrawer = try pubkey_utils.createWithSeed(
        base,
        current_withdrawer_seed,
        current_withdrawer_owner,
    );

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize_with_seed = .{
                .authorization_type = VoteAuthorize.withdrawer,
                .current_authority_derived_key_owner = current_withdrawer_owner,
                .current_authority_derived_key_seed = current_withdrawer_seed,
                .new_authority = new_authorized_withdrawer,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = base },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = base },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: authorizeCheckedWithSeed withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Insturction data.
    const new_authorized_withdrawer = Pubkey.initRandom(prng.random());
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Account data.
    const vote_account = Pubkey.initRandom(prng.random());
    const base = Pubkey.initRandom(prng.random());
    const current_withdrawer_owner = Pubkey.initRandom(prng.random());
    const current_withdrawer_seed = &[_]u8{0x10} ** 32;

    const authorized_withdrawer = try pubkey_utils.createWithSeed(
        base,
        current_withdrawer_seed,
        current_withdrawer_owner,
    );

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize_checked_with_seed = .{
                .authorization_type = VoteAuthorize.withdrawer,
                .current_authority_derived_key_owner = current_withdrawer_owner,
                .current_authority_derived_key_seed = current_withdrawer_seed,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = base },
                .{ .pubkey = new_authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = base },
                .{ .pubkey = new_authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: authorizeChecked withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_authorized_withdrawer = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());

    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize_checked = vote_program.vote_instruction.VoteAuthorize.withdrawer,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = new_authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = new_authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_validator_identity" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const new_node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction.update_validator_identity,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_validator_identity new authority did not sign" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const new_node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const result = testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction.update_validator_identity,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            // new authority did not sign.
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(InstructionError.MissingRequiredSignature, result);
}

test "vote_program: update_validator_identity current authority did not sign" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const new_node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const result = testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction.update_validator_identity,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            // current authority did not sign.
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(InstructionError.MissingRequiredSignature, result);
}

test "vote_program: update_commission increasing commission" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 8192,
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 20;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_commission decreasing commission" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 8192,
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 5;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_commission commission update too late is always enforced" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 1060, // needed to make isCommissionUpdateAllowed return false
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 100, // needed to make isCommissionUpdateAllowed return false
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 100, // needed to make isCommissionUpdateAllowed return false
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 15;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // [agave v3.1.8] Commission timing check is always enforced (features baked in).
    // A commission increase at a too-late slot should fail even without feature flags.
    try testing.expectProgramExecuteError(
        InstructionError.Custom,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{}, // No feature flags needed - timing check is always enforced
        },
        .{},
    );
}

test "vote_program: update_commission too late allowed with delay feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 1060,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 100,
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 100,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 15;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .feature = .delay_commission_updates,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_commission error commission update too late failure" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 1060, // needed to make isCommissionUpdateAllowed return false
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 100, // needed to make isCommissionUpdateAllowed return false
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 100, // needed to make isCommissionUpdateAllowed return false
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 15;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        // TODO is there a way to assert VoteError.CommissionUpdateTooLate
        // is stored in ic.tc.custom_error
        try std.testing.expectEqual(InstructionError.Custom, err);
    };
}

test "vote_program: update_commission missing signature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 8192,
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 20;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var final_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock.epoch,
    ) };
    defer final_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            // missing signature.
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{},
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        try std.testing.expectEqual(InstructionError.MissingRequiredSignature, err);
    };
}

test "vote_program: widthdraw no changes" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(vote_state_bytes[0..], vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = 0,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                // no lamports withdrawn
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer, .lamports = 0 },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: widthdraw some amount below with balance above rent exempt" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(vote_state_bytes[0..], vote_state, .{});

    const withdraw_amount = 400;
    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = withdraw_amount,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD + withdraw_amount,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = withdraw_amount },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: widthdraw all and close account with active vote account" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 30, // current_epoch
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );
    try state.epoch_credits.append(allocator, .{
        // Condition for account close down not met.
        // current_epoch - last_epoch_with_credits > 2
        .epoch = 30,
        .credits = 1000,
        .prev_credits = 1000,
    });

    var initial_vote_state = VoteStateVersions{ .v3 = state };
    defer initial_vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var initial_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state = VoteStateVersions{ .v3 = .DEFAULT };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = RENT_EXEMPT_THRESHOLD, // withdrawal will close down account.
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 0,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..], // account closed down,
                },
                .{ .pubkey = recipient_withdrawer, .lamports = RENT_EXEMPT_THRESHOLD },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        // TODO is there a way to assert VoteError.ActiveVoteAccountClose
        // is stored in ic.tc.custom_error
        try std.testing.expectEqual(InstructionError.Custom, err);
    };
}

test "vote_program: widthdraw some amount below with balance below rent exempt" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(vote_state_bytes[0..], vote_state, .{});

    const withdraw_amount = 400;
    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = withdraw_amount,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    // withdrawal will leave account below rent exempt.
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = withdraw_amount },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        try std.testing.expectEqual(InstructionError.InsufficientFunds, err);
    };
}

test "vote_program: widthdraw insufficient funds" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(vote_state_bytes[0..], vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = RENT_EXEMPT_THRESHOLD + 1, // withdraw more than account balance
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        try std.testing.expectEqual(InstructionError.InsufficientFunds, err);
    };
}

test "vote_program: widthdraw with missing signature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    // TODO use VoteStateV3.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(vote_state_bytes[0..], vote_state, .{});

    const withdraw_amount = 400;
    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = withdraw_amount,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            // missing signature for authorized_withdrawer
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD + withdraw_amount,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = 0 },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = vote_state_bytes[0..],
                },
                .{ .pubkey = recipient_withdrawer, .lamports = withdraw_amount },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        try std.testing.expectEqual(InstructionError.MissingRequiredSignature, err);
    };
}

test "vote_program: vote" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = slots[slots.len - 1], .hash = vote.hash }},
    );
    // deinitialised by expectProgramExecuteResult

    var final_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteStateV3.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(allocator, landed_vote);
    try final_state.doubleLockouts();

    var final_vote_state = VoteStateVersions{ .v3 = final_state };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .vote = .{ .vote = vote },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: vote switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = slots[slots.len - 1], .hash = vote.hash }},
    );
    // deinitialised by expectProgramExecuteResult

    var final_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteStateV3.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(allocator, landed_vote);
    try final_state.doubleLockouts();

    var final_vote_state = VoteStateVersions{ .v3 = final_state };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .vote_switch = .{ .vote = vote, .hash = sig.core.Hash.ZEROES },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: vote missing signature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = slots[slots.len - 1], .hash = vote.hash }},
    );
    // deinitialised by expectProgramExecuteResult

    var final_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteStateV3.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(allocator, landed_vote);
    try final_state.doubleLockouts();

    var final_vote_state = VoteStateVersions{ .v3 = final_state };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .vote = .{ .vote = vote },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            // Signature of signer is not set.
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        try std.testing.expectEqual(InstructionError.MissingRequiredSignature, err);
    };
}

test "vote_program: empty vote" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer vote_state.deinit(allocator);

    var initial_state_bytes: [VoteStateV3.MAX_VOTE_STATE_SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        // No vote added
        .slots = &slots,
        .hash = .ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = 0, .hash = .ZEROES }},
    );
    // deinitialised by expectProgramExecuteResult

    var final_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteStateV3.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(allocator, landed_vote);
    try final_state.doubleLockouts();

    var final_vote_state = VoteStateVersions{ .v3 = final_state };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .vote = .{ .vote = vote },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    ) catch |err| {
        // TODO is there a way to assert VoteError.empty_slots
        // is stored in ic.tc.custom_error
        try std.testing.expectEqual(InstructionError.Custom, err);
    };
}

test "vote_program: vote state update" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const vote_state_update = VoteStateUpdate{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_vote_state = .{
                .vote_state_update = vote_state_update,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: vote state update switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const vote_state_update = VoteStateUpdate{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = .ZEROES },
            .{ .slot = 4, .hash = .ZEROES },
            .{ .slot = 2, .hash = .ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_vote_state_switch = .{
                .vote_state_update = vote_state_update,
                .hash = .ZEROES,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: compact vote state update" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const vote_state_update = VoteStateUpdate{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .compact_update_vote_state = .{
                .vote_state_update = vote_state_update,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: compact vote state update switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const vote_state_update = VoteStateUpdate{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .compact_update_vote_state_switch = .{
                .vote_state_update = vote_state_update,
                .hash = sig.core.Hash.ZEROES,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: tower sync" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const tower_sync = TowerSync{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
        .block_id = sig.core.Hash.ZEROES,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .tower_sync = .{
                .tower_sync = tower_sync,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
            .feature_set = &.{
                .{
                    .feature = .enable_tower_sync_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: tower sync switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var vote_state = VoteStateVersions{ .v3 = vote_state_init };
    defer vote_state.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    // VoteStateUpdate.
    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const tower_sync = TowerSync{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(
            &lockouts,
        ),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
        .block_id = sig.core.Hash.ZEROES,
    };

    var final_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try final_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    var final_vote_state = VoteStateVersions{ .v3 = final_state_init };
    defer final_vote_state.deinit(allocator);

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );
    // deinitialised by expectProgramExecuteResult

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .tower_sync_switch = .{
                .tower_sync = tower_sync,
                .hash = sig.core.Hash.ZEROES,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
            .feature_set = &.{
                .{
                    .feature = .enable_tower_sync_ix,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: executeIntializeAccount v4" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const vote_account = Pubkey.initRandom(prng.random());

    // When v4 feature is active, initializeAccount uses VoteStateV4.init directly
    // and serializes as VoteStateVersions.v4
    var final_vote_state_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
        vote_account,
    );
    defer final_vote_state_v4.deinit(allocator);

    const final_versioned = VoteStateVersions{ .v4 = final_vote_state_v4 };

    var final_vote_state_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .initialize_account = .{
                .node_pubkey = node_pubkey,
                .authorized_voter = authorized_voter,
                .authorized_withdrawer = authorized_withdrawer,
                .commission = commission,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = ([_]u8{0} ** 3762)[0..],
                },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = node_pubkey },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = node_pubkey },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: tower sync with v4 feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state serialized as V3 current
    var vote_state_init = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    try vote_state_init.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    var initial_versioned = VoteStateVersions{ .v3 = vote_state_init };
    defer initial_versioned.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], initial_versioned, .{});

    const vote_slot_hash = sig.core.Hash.initRandom(prng.random());

    var lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = 8, .confirmation_count = 1 },
    };
    const tower_sync = TowerSync{
        .lockouts = std.ArrayListUnmanaged(Lockout).fromOwnedSlice(&lockouts),
        .hash = vote_slot_hash,
        .root = null,
        .timestamp = null,
        .block_id = sig.core.Hash.ZEROES,
    };

    // Build the expected final V4 state: V3→V4 conversion + tower sync applied
    var final_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        vote_state_init,
        vote_account,
    );
    defer final_v4.deinit(allocator);

    final_v4.votes.clearRetainingCapacity();
    try final_v4.votes.appendSlice(
        allocator,
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_versioned = VoteStateVersions{ .v4 = final_v4 };

    // Start from initial V3 bytes since serializeIntoAccountData only overwrites
    // the serialized portion, leaving trailing bytes from the original V3 data.
    var final_vote_state_bytes = initial_state_bytes;
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    const slot_hashes = SlotHashes.initWithEntries(
        &.{
            .{ .slot = 8, .hash = vote_slot_hash },
            .{ .slot = 6, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 4, .hash = sig.core.Hash.ZEROES },
            .{ .slot = 2, .hash = sig.core.Hash.ZEROES },
        },
    );

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .tower_sync = .{
                .tower_sync = tower_sync,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
            .feature_set = &.{
                .{
                    .feature = .enable_tower_sync_ix,
                    .slot = 0,
                },
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_validator_identity with v4 feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const new_node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial V3 state
    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // Final V4 state: with v4 feature, updateValidatorIdentity sets
    // both node_pubkey and block_revenue_collector to new_identity
    var final_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        initial_vote_state.v3,
        vote_account,
    );
    defer final_v4.deinit(allocator);
    final_v4.node_pubkey = new_node_pubkey;
    final_v4.block_revenue_collector = new_node_pubkey;

    const final_versioned = VoteStateVersions{ .v4 = final_v4 };

    // Start from initial V3 bytes since serializeIntoAccountData only overwrites
    // the serialized portion, leaving trailing bytes from the original V3 data.
    var final_vote_state_bytes = initial_vote_state_bytes;
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction.update_validator_identity,
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = new_node_pubkey },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: widthdraw all with v4 zeros account data" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };
    const rent = Rent.INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const recipient = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const lamports: u64 = 27074400;

    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // With V4 feature: full withdrawal zeros account data
    const final_data = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = lamports,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = lamports,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = 0,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 0,
                    .owner = vote_program.ID,
                    .data = final_data[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = lamports,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

// Regression test for: SIMD-0185 V4 withdraw deinit must zero the vote account
// data in place (preserving its existing length) rather than resizing the
// account to VoteStateV4.MAX_VOTE_STATE_SIZE. A legacy VoteState1_14_11-sized
// (3731 bytes) account being fully withdrawn under the v4 target must remain
// 3731 bytes long.
//
// Before the fix, the v4 deinit branch in `widthraw` called
// `setDataFromSlice` with a `VoteStateV4.MAX_VOTE_STATE_SIZE` zero buffer,
// which resized the account from 3731 to 3762 bytes and produced an output
// mismatch against agave (which zeroes in place).
test "vote_program: widthdraw all with v4 preserves v1_14_11-sized account length" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const VoteState1_14_11 = vote_program.state.VoteState1_14_11;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };
    const rent = Rent.INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const recipient = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const lamports: u64 = 27074400;

    // Use legacy v1_14_11 (3731-byte) layout — smaller than VoteStateV4's
    // 3762-byte max — to detect any erroneous resize during the V4 deinit
    // path.
    comptime std.debug.assert(
        VoteState1_14_11.MAX_VOTE_STATE_SIZE < VoteStateV4.MAX_VOTE_STATE_SIZE,
    );

    var initial_vote_state = VoteStateVersions{ .v1_14_11 = try VoteState1_14_11.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** VoteState1_14_11.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // Expected post-state: same length (3731), all zeros.
    const final_data = ([_]u8{0} ** VoteState1_14_11.MAX_VOTE_STATE_SIZE);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = lamports,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = lamports,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = 0,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 0,
                    .owner = vote_program.ID,
                    .data = final_data[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = lamports,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: widthdraw all with v4 pending rewards fails" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };
    const rent = Rent.INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const recipient = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const lamports: u64 = 27074400;

    var initial_vote_state_v3 = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state_v3.deinit(allocator);

    var initial_vote_state_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        initial_vote_state_v3.v3,
        vote_account,
    );
    defer initial_vote_state_v4.deinit(allocator);
    initial_vote_state_v4.pending_delegator_rewards = 1;

    const initial_versioned = VoteStateVersions{ .v4 = initial_vote_state_v4 };
    var initial_vote_state_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_versioned, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InsufficientFunds,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = lamports,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = lamports,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = 0,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{},
    );
}

test "vote_program: widthdraw with v4 pending rewards below minimum fails" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const recipient = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const pending_delegator_rewards: u64 = 500;
    const withdraw_amount: u64 = 1;
    const min_rent_exempt_balance = rent.minimumBalance(VoteStateV4.MAX_VOTE_STATE_SIZE);
    const initial_lamports = min_rent_exempt_balance + pending_delegator_rewards;

    var initial_vote_state_v3 = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state_v3.deinit(allocator);

    var initial_vote_state_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        initial_vote_state_v3.v3,
        vote_account,
    );
    defer initial_vote_state_v4.deinit(allocator);
    initial_vote_state_v4.pending_delegator_rewards = pending_delegator_rewards;

    const initial_versioned = VoteStateVersions{ .v4 = initial_vote_state_v4 };
    var initial_vote_state_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_versioned, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InsufficientFunds,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .withdraw = withdraw_amount,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = initial_lamports,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{
                    .pubkey = recipient,
                    .lamports = 0,
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{},
    );
}

test "vote_program: executeAuthorize withdrawer with v4 feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const new_authorized_withdrawer = Pubkey.initRandom(prng.random());
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const vote_account = Pubkey.initRandom(prng.random());

    // Initial V3 state
    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // Final V4 state with new withdrawer
    var final_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        initial_vote_state.v3,
        vote_account,
    );
    defer final_v4.deinit(allocator);
    final_v4.withdrawer = new_authorized_withdrawer;

    const final_versioned = VoteStateVersions{ .v4 = final_v4 };

    // Start from initial V3 bytes since serializeIntoAccountData only overwrites
    // the serialized portion, leaving trailing bytes from the original V3 data.
    var final_vote_state_bytes = initial_vote_state_bytes;
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_withdrawer,
                .vote_authorize = VoteAuthorize.withdrawer,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: update_commission with v4 feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const epoch_schedule = EpochSchedule{
        .slots_per_epoch = 8192,
        .leader_schedule_slot_offset = 0,
        .warmup = false,
        .first_normal_epoch = 0,
        .first_normal_slot = 0,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const initial_commission: u8 = 10;
    const final_commission: u8 = 20;

    // Initial V3 state
    var initial_vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock.epoch,
    ) };
    defer initial_vote_state.deinit(allocator);

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    // Final V4 state with new commission
    var final_v4 = try VoteStateV4.fromVoteStateV3(
        allocator,
        initial_vote_state.v3,
        vote_account,
    );
    defer final_v4.deinit(allocator);
    final_v4.inflation_rewards_commission_bps = @as(u16, final_commission) * 100;

    const final_versioned = VoteStateVersions{ .v4 = final_v4 };

    // Start from initial V3 bytes since serializeIntoAccountData only overwrites
    // the serialized portion, leaving trailing bytes from the original V3 data.
    var final_vote_state_bytes = initial_vote_state_bytes;
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission = final_commission,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "vote_program: vote with v4 feature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial V3 state
    const vote_state_v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
    );

    var initial_versioned = VoteStateVersions{ .v3 = vote_state_v3 };
    defer initial_versioned.deinit(allocator);

    var initial_state_bytes = ([_]u8{0} ** VoteStateV3.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], initial_versioned, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = slots[slots.len - 1], .hash = vote.hash }},
    );

    // Build expected final V4 state
    var final_v4 = try VoteStateV4.fromVoteStateV3(allocator, vote_state_v3, vote_account);
    defer final_v4.deinit(allocator);

    const landed_vote: LandedVote = .{
        .latency = VoteStateV3.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };
    try final_v4.votes.append(allocator, landed_vote);
    try final_v4.doubleLockouts();

    const final_versioned = VoteStateVersions{ .v4 = final_v4 };

    // Start from initial V3 bytes since serializeIntoAccountData only overwrites
    // the serialized portion, leaving trailing bytes from the original V3 data.
    var final_vote_state_bytes = initial_state_bytes;
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_versioned, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .vote = .{ .vote = vote },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 3 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = initial_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
            .feature_set = &.{
                .{
                    .feature = .vote_state_v4,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_vote_state_bytes[0..],
                },
                .{ .pubkey = SlotHashes.ID },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_voter },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

// ── SIMD-0232: UpdateCommissionCollector tests ──────────────────────

test "update_commission_collector inflation_rewards" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    var final_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer final_v4.deinit(allocator);
    final_v4.inflation_rewards_collector = new_collector;

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    const final_ver = VoteStateVersions{ .v4 = final_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    var final_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        final_bytes[0..],
        final_ver,
        .{},
    );

    // [agave] vote_processor.rs test_vote_update_commission_collector
    try testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "update_commission_collector block_revenue" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    var final_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer final_v4.deinit(allocator);
    final_v4.block_revenue_collector = new_collector;

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    const final_ver = VoteStateVersions{ .v4 = final_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    var final_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        final_bytes[0..],
        final_ver,
        .{},
    );

    try testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .block_revenue,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

test "update_commission_collector feature disabled" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    // Feature disabled → InvalidInstructionData.
    const result = testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            // vote_state_v4 active, custom_commission_collector NOT
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(
        InstructionError.InvalidInstructionData,
        result,
    );
}

test "update_commission_collector withdrawer not signer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    // Withdrawer not signer → MissingRequiredSignature.
    const result = testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            // withdrawer NOT signing
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(
        InstructionError.MissingRequiredSignature,
        result,
    );
}

test "update_commission_collector not system owned" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());
    const bad_owner = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    // Not system-owned → InvalidAccountOwner.
    const result = testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = bad_owner,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = bad_owner,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(
        InstructionError.InvalidAccountOwner,
        result,
    );
}

test "update_commission_collector not rent exempt" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    // Not rent-exempt → InsufficientFunds.
    const result = testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = 1, // not rent exempt
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = 1,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(
        InstructionError.InsufficientFunds,
        result,
    );
}

test "update_commission_collector not writable" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock = Clock{
        .slot = 0,
        .epoch_start_timestamp = 0,
        .epoch = 0,
        .leader_schedule_epoch = 0,
        .unix_timestamp = 0,
    };

    const rent = Rent{
        .lamports_per_byte_year = 3480,
        .exemption_threshold = 2.0,
        .burn_percent = 50,
    };

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());
    const new_collector = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };

    var init_bytes =
        ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(
        init_bytes[0..],
        init_ver,
        .{},
    );

    // Not writable → InvalidArgument.
    const result = testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_collector = .inflation_rewards,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            // collector NOT writable
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{
                    .feature = .custom_commission_collector,
                    .slot = 0,
                },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{
                    .pubkey = new_collector,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = sig.runtime.program.system.ID,
                },
                .{ .pubkey = withdrawer },
                .{
                    .pubkey = vote_program.ID,
                    .owner = ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = 0,
        },
        .{},
    );

    try std.testing.expectError(
        InstructionError.InvalidArgument,
        result,
    );
}

// Regression: authorize against a vote account whose data is shorter than a
// valid VoteStateVersions encoding and whose leading u32 variant tag is 0
// (the discontinued V0_23_5 / Uninitialized slot per SIMD-0185).
//
// Both target versions must shortcut on the tag rather than letting bincode
// surface a generic InvalidAccountData from the truncated body, matching
// solana-vote-interface 5.0.0:
//   - V3 path -> InvalidAccountData
//     [agave] https://github.com/anza-xyz/solana-sdk/blob/ddbf3430b08eb375de695328ae298dd61c2e1471/vote-interface/src/state/vote_state_v3.rs#L159
//   - V4 path -> UninitializedAccount
//     [agave] https://github.com/anza-xyz/solana-sdk/blob/ddbf3430b08eb375de695328ae298dd61c2e1471/vote-interface/src/state/vote_state_versions.rs#L155
test "vote_program: authorize zero-tag short data returns InvalidAccountData (v3 target)" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const vote_account = Pubkey.initRandom(prng.random());
    const authority = Pubkey.initRandom(prng.random());
    const new_authority = Pubkey.initRandom(prng.random());

    // 40 bytes of zeros: leading u32 tag is 0 and body is too short to
    // bincode-decode as any VoteStateVersions variant.
    var short_zero_data = [_]u8{0} ** 40;

    try testing.expectProgramExecuteError(
        InstructionError.InvalidAccountData,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authority,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = short_zero_data[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authority },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{}, // vote_state_v4 NOT active -> V3 target
        },
        .{},
    );
}

test "vote_program: authorize zero-tag short data returns InvalidAccountData (v4 target)" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const vote_account = Pubkey.initRandom(prng.random());
    const authority = Pubkey.initRandom(prng.random());
    const new_authority = Pubkey.initRandom(prng.random());

    // 40 bytes of zeros: leading u32 tag is 0 and body is too short to
    // bincode-decode as any VoteStateVersions variant.
    var short_zero_data = [_]u8{0} ** 40;

    try testing.expectProgramExecuteError(
        InstructionError.InvalidAccountData,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authority,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = short_zero_data[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authority },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
            },
        },
        .{},
    );
}

// Regression: vote account whose data is shorter than the leading u32 variant
// tag must short-circuit with InvalidAccountData before any bincode decode.
// Exercises the `data.len < @sizeOf(u32)` guard in getVoteStateChecked,
// matching agave's `VoteStateV3::deserialize_into_ptr` /
// `VoteStateVersions::deserialize` which both reject buffers that cannot
// contain a discriminant. The guard is target-independent, so a single
// fixture (V4 active) covers both code paths.
test "vote_program: authorize sub-tag-length data returns InvalidAccountData" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const vote_account = Pubkey.initRandom(prng.random());
    const authority = Pubkey.initRandom(prng.random());
    const new_authority = Pubkey.initRandom(prng.random());

    // 3 bytes: less than @sizeOf(u32), so the length guard must fire before
    // peeking the variant tag or invoking bincode.
    var tiny_data = [_]u8{ 0xAA, 0xBB, 0xCC };

    try testing.expectProgramExecuteError(
        InstructionError.InvalidAccountData,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authority,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = tiny_data[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authority },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
            },
        },
        .{},
    );
}

// Regression: under the V4 feature gate, getVoteStateChecked must reject an
// uninitialized vote account even when the callsite passes
// `check_initialized = false` (e.g. authorize / update_validator_identity /
// update_commission / withdraw). The V3 path keeps the legacy behavior of
// honoring the flag, so the same fixture only fails on the V4 target.
//
// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/programs/vote/src/vote_state/mod.rs#L45-L77
test "vote_program: authorize uninitialized v3-tagged returns UninitializedAccount (v4 target)" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const vote_account = Pubkey.initRandom(prng.random());
    const authority = Pubkey.initRandom(prng.random());
    const new_authority = Pubkey.initRandom(prng.random());

    // Bincode-encoded VoteStateVersions{ .v3 = VoteStateV3.DEFAULT }: leading
    // u32 tag is 2 (non-zero, so the variant-0 shortcut does not fire) and the
    // embedded VoteStateV3 has zero voters -> isUninitialized() == true.
    const uninit_state: VoteStateVersions = .{ .v3 = VoteStateV3.DEFAULT };
    var uninit_bytes = [_]u8{0} ** 3762;
    _ = try sig.bincode.writeToSlice(uninit_bytes[0..], uninit_state, .{});

    try testing.expectProgramExecuteError(
        InstructionError.UninitializedAccount,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authority,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = uninit_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authority },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
            },
        },
        .{},
    );
}

// [SIMD-0387] When `bls_pubkey_management_in_vote_account` is active and
// the vote account already has a BLS pubkey set, the legacy
// `Authorize::Voter` variant MUST be rejected. Clients have to use
// `Authorize::VoterWithBLS` so the new voter ↔ BLS pubkey pairing is
// verified atomically. With the feature INactive the same instruction
// would succeed.
//
// [agave] https://github.com/anza-xyz/agave/blob/a64b6358a247b7f16426aa1f070cd2f0f21aba15/programs/vote/src/vote_state/mod.rs#L703-L706
test "vote_program: authorize voter rejected when bls_pubkey set and SIMD-0387 active" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const new_authorized_voter = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
        vote_account,
    );
    defer initial_v4.deinit(allocator);
    initial_v4.bls_pubkey_compressed = [_]u8{0xAB} ** 48;

    const initial_versioned: VoteStateVersions = .{ .v4 = initial_v4 };
    var initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_bytes[0..], initial_versioned, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_voter,
                .vote_authorize = VoteAuthorize.voter,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .bls_pubkey_management_in_vote_account, .slot = 0 },
            },
        },
        .{},
    );
}

// [SIMD-0387] When `bls_pubkey_management_in_vote_account` is inactive,
// `Authorize::VoterWithBLS` must be rejected with InvalidInstructionData
// (the bincode for the instruction parses fine but the executor refuses
// to apply it).
test "vote_program: authorize voter_with_bls rejected when SIMD-0387 inactive" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const new_authorized_voter = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
        vote_account,
    );
    defer initial_v4.deinit(allocator);

    const initial_versioned: VoteStateVersions = .{ .v4 = initial_v4 };
    var initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_bytes[0..], initial_versioned, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_voter,
                .vote_authorize = .{ .voter_with_bls = .{
                    .bls_pubkey = [_]u8{0} ** 48,
                    .bls_proof_of_possession = [_]u8{0} ** 96,
                } },
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
            },
        },
        .{},
    );
}

// [SIMD-0387] `Authorize::VoterWithBLS` with the feature ACTIVE but a
// malformed BLS pubkey / proof must:
//   (a) consume the full 34,500 CU PoP cost up front, and
//   (b) fail with `InvalidArgument` (mapped from the crypto-layer
//       `error.Failed`), matching agave's `verify_bls_proof_of_possession`.
// The fixture supplies an all-zero pubkey + proof which can never satisfy
// the PoP pairing check.
test "vote_program: authorize voter_with_bls bad proof consumes CUs and returns InvalidArgument" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const new_authorized_voter = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock.epoch,
        vote_account,
    );
    defer initial_v4.deinit(allocator);

    const initial_versioned: VoteStateVersions = .{ .v4 = initial_v4 };
    var initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_bytes[0..], initial_versioned, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidArgument,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .authorize = .{
                .new_authority = new_authorized_voter,
                .vote_authorize = .{ .voter_with_bls = .{
                    .bls_pubkey = [_]u8{0} ** 48,
                    .bls_proof_of_possession = [_]u8{0} ** 96,
                } },
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_bytes[0..],
                },
                .{ .pubkey = Clock.ID },
                .{ .pubkey = authorized_withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS +
                vote_program.state.BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .bls_pubkey_management_in_vote_account, .slot = 0 },
            },
        },
        .{},
    );
}

const PopFixture = struct {
    vote_pubkey: Pubkey,
    bls_pubkey: [48]u8,
    bls_proof: [96]u8,
};

// Two valid Alpenglow PoP fixtures for InitializeAccountV2 success paths.
//
// In every callsite the fixture's `vote_pubkey` MUST be used as the vote
// account's pubkey, otherwise the middle 32 bytes of the PoP envelope
// ("ALPENGLOW" || vote_pubkey || bls_pubkey) no longer match the signed
// message and verification fails.
//
// [0] Self-generated by sig (independent of any external implementation).
//     Produced via blst directly with the recipe below; hardcoded so the
//     test path stays cheap (decompress + pairing only).
//       ikm     = "sig-alpenglow-pop-fixture-bls-2!" (32 bytes)
//       vote_pk = "sig-alpenglow-pop-vote-acct-key!" (32 bytes ASCII)
//       msg     = "ALPENGLOW" || vote_pk || bls_pk
//       sk      = c.keygen(ikm)
//       bls_pk  = c.p1_compress(c.sk_to_pk_in_g1(sk))
//       sig     = c.p2_compress(c.sign_pk_in_g1(c.hash_to_g2(msg, PROOF_OF_POSSESSION_DST), sk))
//
// [1] Cross-check vector taken from firedancer's POP success case 1 (also
//     exercised by `proofOfPossessionVerify` test in lib.zig). Catches
//     DST / encoding drift that a self-generated vector alone would not
//     surface.
//       vote_pubkey hex: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//       bls_pk hex:      b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc
//       pop hex:         b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2
//                        d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f
//                        88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d
fn alpenglowPopFixtures() [2]PopFixture {
    var fixtures: [2]PopFixture = undefined;
    inline for (.{
        // zig fmt: off
        // [0] Self-generated by sig.
        // vote_pubkey is the ASCII bytes of "sig-alpenglow-pop-vote-acct-key!".
        .{
            "7369672d616c70656e676c6f772d706f702d766f74652d616363742d6b657921",
            "8af3bdd945e3cd2f35d865a35e55d22605108d7c936e78837621f99bf25fc9d0a03badbe58d3c978fa5f682363d231a9",
            "8291bb74331512536b0e1d11936ed473704a09900bcabd2ede576e28d8eee1b0af6e6e6fed8ca03bd64c3a967246083c0bb548415cd4bc9a672766c8b46e0fc1c434401d0211da085b050b3fc243f26bba088496eb4925f3b8cc73d957894085",
        },
        // [1] Firedancer POP success case 1 cross-check.
        // [firedancer] https://github.com/firedancer-io/firedancer/blob/f213d050148bf2a01f879a17f61547aa212b528d/src/ballet/bls/test_bls12_381.c#L1162-L1166
        .{
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc",
            "b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d",
        },
        // zig fmt: on
    }, 0..) |v, i| {
        var vote: [32]u8 = undefined;
        var bls: [48]u8 = undefined;
        var proof: [96]u8 = undefined;
        _ = std.fmt.hexToBytes(&vote, v[0]) catch unreachable;
        _ = std.fmt.hexToBytes(&bls, v[1]) catch unreachable;
        _ = std.fmt.hexToBytes(&proof, v[2]) catch unreachable;
        fixtures[i] = .{
            .vote_pubkey = .{ .data = vote },
            .bls_pubkey = bls,
            .bls_proof = proof,
        };
    }
    return fixtures;
}

// [SIMD-0387] initialize_account_v2 success path: all five co-dep features
// active, a valid BLS PoP, and both commission collectors set to the vote
// account itself (the SIMD-0232/SIMD-0464 escape hatch). The resulting
// VoteStateV4 must carry the BLS pubkey, basis-points commissions and
// collectors derived from the VoteInitV2 payload.
test "vote_program: initialize_account_v2 success (escape-hatch collectors)" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const rent = Rent.INIT;
    const clock: Clock = .INIT;
    const RENT_EXEMPT_THRESHOLD = 27074400;

    // Iterate over every valid PoP fixture: a sig self-generated vector and
    // a firedancer cross-check vector. Both must drive the executor through
    // the same successful path. The firedancer iteration would catch any
    // DST / encoding drift that the self-generated vector alone could mask
    // (since sig generates and verifies with the same code path).
    for (alpenglowPopFixtures()) |fixture| {
        const node_pubkey = Pubkey.initRandom(prng.random());
        const authorized_voter = Pubkey.initRandom(prng.random());
        const authorized_withdrawer = Pubkey.initRandom(prng.random());

        const vote_init: vote_instruction.VoteInitV2 = .{
            .node_pubkey = node_pubkey,
            .authorized_voter = authorized_voter,
            .authorized_voter_bls_pubkey = fixture.bls_pubkey,
            .authorized_voter_bls_proof_of_possession = fixture.bls_proof,
            .authorized_withdrawer = authorized_withdrawer,
            .inflation_rewards_commission_bps = 0x1234,
            .block_revenue_commission_bps = 0xABCD,
        };

        // Construct the expected final V4 state.
        const authorized_voters = try vote_program.state.AuthorizedVoters.init(
            allocator,
            clock.epoch,
            authorized_voter,
        );
        var final_v4: VoteStateV4 = .{
            .node_pubkey = node_pubkey,
            .withdrawer = authorized_withdrawer,
            .inflation_rewards_collector = fixture.vote_pubkey,
            .block_revenue_collector = fixture.vote_pubkey,
            .inflation_rewards_commission_bps = 0x1234,
            .block_revenue_commission_bps = 0xABCD,
            .pending_delegator_rewards = 0,
            .bls_pubkey_compressed = fixture.bls_pubkey,
            .votes = .empty,
            .root_slot = null,
            .authorized_voters = authorized_voters,
            .epoch_credits = .empty,
            .last_timestamp = .{ .slot = 0, .timestamp = 0 },
        };
        defer final_v4.deinit(allocator);

        const final_versioned: VoteStateVersions = .{ .v4 = final_v4 };
        var final_state_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
        _ = try sig.bincode.writeToSlice(final_state_bytes[0..], final_versioned, .{});

        // Initial account is uninitialized but pre-sized to VoteStateV4 length.
        const initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);

        try testing.expectProgramExecuteResult(
            std.testing.allocator,
            vote_program.ID,
            VoteProgramInstruction{ .initialize_account_v2 = vote_init },
            &.{
                // 0: vote_account (writable)
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                // 1: node identity (signer)
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
                // 2: inflation-rewards collector == vote_account (escape hatch)
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                // 3: block-revenue collector == vote_account (escape hatch)
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = fixture.vote_pubkey,
                        .lamports = RENT_EXEMPT_THRESHOLD,
                        .owner = vote_program.ID,
                        .data = initial_bytes[0..],
                    },
                    .{ .pubkey = node_pubkey },
                    .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
                },
                .compute_meter = vote_program.COMPUTE_UNITS +
                    vote_program.state.BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS,
                .sysvar_cache = .{ .rent = rent, .clock = clock },
                .feature_set = &.{
                    .{ .feature = .vote_state_v4, .slot = 0 },
                    .{ .feature = .bls_pubkey_management_in_vote_account, .slot = 0 },
                    .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
                    .{ .feature = .custom_commission_collector, .slot = 0 },
                    .{ .feature = .block_revenue_sharing, .slot = 0 },
                    .{ .feature = .vote_account_initialize_v2, .slot = 0 },
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = fixture.vote_pubkey,
                        .lamports = RENT_EXEMPT_THRESHOLD,
                        .owner = vote_program.ID,
                        .data = final_state_bytes[0..],
                    },
                    .{ .pubkey = node_pubkey },
                    .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 0,
            },
            .{},
        );
    }
}

// [SIMD-0387] When `is_init_account_v2_enabled` is false (any one of the
// co-dep features inactive), InitializeAccountV2 must be rejected up front
// with InvalidInstructionData — agave's `if (!is_init_account_v2_enabled)`
// branch in vote_processor.rs.
test "vote_program: initialize_account_v2 rejected when gate inactive" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;
    const rent = Rent.INIT;

    for (alpenglowPopFixtures()) |fixture| {
        const node_pubkey = Pubkey.initRandom(prng.random());
        const authorized_voter = Pubkey.initRandom(prng.random());
        const authorized_withdrawer = Pubkey.initRandom(prng.random());

        const vote_init: vote_instruction.VoteInitV2 = .{
            .node_pubkey = node_pubkey,
            .authorized_voter = authorized_voter,
            .authorized_voter_bls_pubkey = fixture.bls_pubkey,
            .authorized_voter_bls_proof_of_possession = fixture.bls_proof,
            .authorized_withdrawer = authorized_withdrawer,
            .inflation_rewards_commission_bps = 0,
            .block_revenue_commission_bps = 0,
        };

        const initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);

        try testing.expectProgramExecuteError(
            InstructionError.InvalidInstructionData,
            std.testing.allocator,
            vote_program.ID,
            VoteProgramInstruction{ .initialize_account_v2 = vote_init },
            &.{
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = fixture.vote_pubkey,
                        .lamports = 27074400,
                        .owner = vote_program.ID,
                        .data = initial_bytes[0..],
                    },
                    .{ .pubkey = node_pubkey },
                    .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
                },
                .compute_meter = vote_program.COMPUTE_UNITS,
                .sysvar_cache = .{ .rent = rent, .clock = clock },
                // Only `vote_state_v4` active: SIMD-0387 + co-deps all inactive.
                .feature_set = &.{
                    .{ .feature = .vote_state_v4, .slot = 0 },
                },
            },
            .{},
        );
    }
}

// [SIMD-0387] InitializeAccountV2 with all gate features active but a
// malformed PoP must return InvalidArgument after consuming the 34,500-CU
// PoP cost (mirrors `verify_bls_proof_of_possession` semantics).
test "vote_program: initialize_account_v2 bad proof returns InvalidArgument" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;
    const rent = Rent.INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());

    const vote_init: vote_instruction.VoteInitV2 = .{
        .node_pubkey = node_pubkey,
        .authorized_voter = authorized_voter,
        .authorized_voter_bls_pubkey = [_]u8{0} ** 48,
        .authorized_voter_bls_proof_of_possession = [_]u8{0} ** 96,
        .authorized_withdrawer = authorized_withdrawer,
        .inflation_rewards_commission_bps = 0,
        .block_revenue_commission_bps = 0,
    };

    const initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);

    try testing.expectProgramExecuteError(
        InstructionError.InvalidArgument,
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{ .initialize_account_v2 = vote_init },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_account,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = initial_bytes[0..],
                },
                .{ .pubkey = node_pubkey },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS +
                vote_program.state.BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS,
            .sysvar_cache = .{ .rent = rent, .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .bls_pubkey_management_in_vote_account, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
                .{ .feature = .custom_commission_collector, .slot = 0 },
                .{ .feature = .block_revenue_sharing, .slot = 0 },
                .{ .feature = .vote_account_initialize_v2, .slot = 0 },
            },
        },
        .{},
    );
}

// [SIMD-0387] check_number_of_instruction_accounts(4): when fewer than 4
// instruction accounts are provided, agave returns NotEnoughAccountKeys. Sig
// has no dedicated NotEnoughAccountKeys variant in this code path; the
// implementation surfaces this via MissingAccount when the executor reaches
// for the absent collector meta. Either way it must reject before touching
// account state.
test "vote_program: initialize_account_v2 rejects when too few accounts" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;
    const rent = Rent.INIT;

    for (alpenglowPopFixtures()) |fixture| {
        const node_pubkey = Pubkey.initRandom(prng.random());
        const authorized_voter = Pubkey.initRandom(prng.random());
        const authorized_withdrawer = Pubkey.initRandom(prng.random());

        const vote_init: vote_instruction.VoteInitV2 = .{
            .node_pubkey = node_pubkey,
            .authorized_voter = authorized_voter,
            .authorized_voter_bls_pubkey = fixture.bls_pubkey,
            .authorized_voter_bls_proof_of_possession = fixture.bls_proof,
            .authorized_withdrawer = authorized_withdrawer,
            .inflation_rewards_commission_bps = 0,
            .block_revenue_commission_bps = 0,
        };

        const initial_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);

        try testing.expectProgramExecuteError(
            InstructionError.MissingAccount,
            std.testing.allocator,
            vote_program.ID,
            VoteProgramInstruction{ .initialize_account_v2 = vote_init },
            &.{
                // Only 2 instruction accounts: vote_account + node. Missing both
                // collectors.
                .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
                .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = fixture.vote_pubkey,
                        .lamports = 27074400,
                        .owner = vote_program.ID,
                        .data = initial_bytes[0..],
                    },
                    .{ .pubkey = node_pubkey },
                    .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
                },
                .compute_meter = vote_program.COMPUTE_UNITS +
                    vote_program.state.BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS,
                .sysvar_cache = .{ .rent = rent, .clock = clock },
                .feature_set = &.{
                    .{ .feature = .vote_state_v4, .slot = 0 },
                    .{ .feature = .bls_pubkey_management_in_vote_account, .slot = 0 },
                    .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
                    .{ .feature = .custom_commission_collector, .slot = 0 },
                    .{ .feature = .block_revenue_sharing, .slot = 0 },
                    .{ .feature = .vote_account_initialize_v2, .slot = 0 },
                },
            },
            .{},
        );
    }
}

// ── SIMD-0291: UpdateCommissionBps tests ────────────────────────────

// Happy path: V4 + both feature gates active, withdrawer signs, kind =
// inflation_rewards. inflation_rewards_commission_bps must be updated.
test "update_commission_bps inflation_rewards" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    const initial_bps: u16 = 1000;
    const final_bps: u16 = 2500;

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);
    initial_v4.inflation_rewards_commission_bps = initial_bps;

    var final_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer final_v4.deinit(allocator);
    final_v4.inflation_rewards_commission_bps = final_bps;

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    const final_ver = VoteStateVersions{ .v4 = final_v4 };

    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    var final_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_bytes[0..], final_ver, .{});

    try testing.expectProgramExecuteResult(
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = final_bps,
                .kind = .inflation_rewards,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .delay_commission_updates, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = final_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 0,
        },
        .{},
    );
}

// kind = block_revenue currently fails with InvalidInstructionData because
// SIMD-0123 (block_revenue_sharing) is hard-coded off in updateCommissionBps.
// When that feature lands and is wired up, this test must be updated.
test "update_commission_bps block_revenue rejected without block_revenue_sharing" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = 5000,
                .kind = .block_revenue,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .delay_commission_updates, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{},
    );
}

// commission_rate_in_basis_points feature gate inactive => InvalidInstructionData.
test "update_commission_bps feature commission_rate_in_basis_points disabled" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = 2500,
                .kind = .inflation_rewards,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            // commission_rate_in_basis_points NOT active
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .delay_commission_updates, .slot = 0 },
            },
        },
        .{},
    );
}

// delay_commission_updates feature gate inactive => InvalidInstructionData.
test "update_commission_bps feature delay_commission_updates disabled" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = 2500,
                .kind = .inflation_rewards,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            // delay_commission_updates NOT active
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{},
    );
}

// vote_state_v4 inactive => target_version is V3 => InvalidInstructionData.
test "update_commission_bps v3 target rejected" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v3 = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
    ) };
    defer initial_v3.deinit(allocator);

    var init_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], initial_v3, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = 2500,
                .kind = .inflation_rewards,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = 27074400,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            // vote_state_v4 NOT active => V3 target
            .feature_set = &.{
                .{ .feature = .delay_commission_updates, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{},
    );
}

// Withdrawer not a signer => MissingRequiredSignature.
test "update_commission_bps withdrawer not signer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    try testing.expectProgramExecuteError(
        InstructionError.MissingRequiredSignature,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_commission_bps = .{
                .commission_bps = 2500,
                .kind = .inflation_rewards,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            // withdrawer NOT signing
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .delay_commission_updates, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{},
    );
}

// _reserved_deposit_delegator_rewards (discriminant 19, SIMD-0123 placeholder)
// must always fail with InvalidInstructionData since SIMD-0123 is not yet
// implemented in sig. Update this test when DepositDelegatorRewards lands.
test "update_commission_bps reserved deposit_delegator_rewards rejected" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const clock: Clock = .INIT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const vote_acct = Pubkey.initRandom(prng.random());

    var initial_v4 = try VoteStateV4.init(
        allocator,
        node_pubkey,
        authorized_voter,
        withdrawer,
        10,
        clock.epoch,
        vote_acct,
    );
    defer initial_v4.deinit(allocator);

    const init_ver = VoteStateVersions{ .v4 = initial_v4 };
    var init_bytes = ([_]u8{0} ** VoteStateV4.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(init_bytes[0..], init_ver, .{});

    try testing.expectProgramExecuteError(
        InstructionError.InvalidInstructionData,
        allocator,
        vote_program.ID,
        VoteProgramInstruction{ ._reserved_deposit_delegator_rewards = {} },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = vote_acct,
                    .lamports = RENT_EXEMPT_THRESHOLD,
                    .owner = vote_program.ID,
                    .data = init_bytes[0..],
                },
                .{ .pubkey = withdrawer },
                .{ .pubkey = vote_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = vote_program.COMPUTE_UNITS,
            .sysvar_cache = .{ .clock = clock },
            .feature_set = &.{
                .{ .feature = .vote_state_v4, .slot = 0 },
                .{ .feature = .delay_commission_updates, .slot = 0 },
                .{ .feature = .commission_rate_in_basis_points, .slot = 0 },
            },
        },
        .{},
    );
}
