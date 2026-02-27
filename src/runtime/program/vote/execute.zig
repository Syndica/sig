const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../sig.zig");

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

    const signers = ic.ixn_info.getSigners();
    try authorize(
        allocator,
        ic,
        vote_account,
        pubkey,
        vote_authorize,
        clock,
        signers.constSlice(),
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

    switch (vote_authorize) {
        .voter => {
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

    const signers = ic.ixn_info.getSigners();
    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority_meta.pubkey,
        vote_authorize,
        clock,
        signers.constSlice(),
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
    if (vote_state.blockRevenueCollectorMut()) |collector| {
        collector.* = new_identity; // [SIMD-0185] until SIMD-0232
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
    var vote_state = getVoteStateChecked(
        allocator,
        vote_account,
        targetVersion(ic.tc),
        false,
    ) catch |err| {
        // Deserialization failed - enforce the commission update rule
        if (!isCommissionUpdateAllowed(clock.slot, &epoch_schedule)) {
            ic.tc.custom_error = @intFromEnum(VoteError.commission_update_too_late);
            return InstructionError.Custom;
        }
        return err;
    };
    defer vote_state.deinit(allocator);

    // [SIMD-0185] New commission value multiplied by 100 for bps; compare with current bps.
    const current_bps = vote_state.inflationRewardsCommissionBps() orelse
        @as(u16, vote_state.commission()) * 100;
    const enforce_commission_update_rule = @as(u16, commission) * 100 > current_bps;

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

    if (remaining_balance == 0) {
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
                var zeros: [VoteStateV4.MAX_VOTE_STATE_SIZE]u8 = undefined;
                @memset(&zeros, 0);
                try vote_account.setDataFromSlice(
                    allocator,
                    &ic.tc.accounts_resize_delta,
                    &zeros,
                );
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
        if (remaining_balance < min_rent_exempt_balance) {
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
            // V4 path rejects V0_23_5 at deserialization in agave;
            // check explicitly here. Always checks uninitialized.
            if (versioned_state == .v0_23_5 or versioned_state.isUninitialized()) {
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

fn setVoteState(
    allocator: std.mem.Allocator,
    account: *BorrowedAccount,
    state: *const VoteState,
    rent: *const Rent,
    resize_delta: *i64,
) (error{OutOfMemory} || InstructionError)!void {
    switch (state.*) {
        .v4 => |v4_state| {
            // [SIMD-0185] v4: resize to 3762 if smaller, then check rent exempt, then serialize v4.
            if (account.constAccountData().len < VoteStateV4.MAX_VOTE_STATE_SIZE) {
                try account.setDataLength(
                    allocator,
                    resize_delta,
                    VoteStateV4.MAX_VOTE_STATE_SIZE,
                );
                if (!rent.isExempt(account.account.lamports, VoteStateV4.MAX_VOTE_STATE_SIZE)) {
                    return InstructionError.AccountNotRentExempt;
                }
            }
            return account.serializeIntoAccountData(VoteStateVersions{ .v4 = v4_state });
        },
        .v3 => |v3_state| {
            if (account.constAccountData().len < VoteStateV3.MAX_VOTE_STATE_SIZE and
                (!rent.isExempt(account.account.lamports, VoteStateV3.MAX_VOTE_STATE_SIZE) or
                    std.meta.isError(account.setDataLength(
                        allocator,
                        resize_delta,
                        VoteStateV3.MAX_VOTE_STATE_SIZE,
                    ))))
            {
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
            .feature_set = &.{
                .{
                    .feature = .allow_commission_decrease_at_any_time,
                    .slot = 0,
                },
                .{
                    .feature = .commission_updates_only_allowed_in_first_half_of_epoch,
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
            .feature_set = &.{
                .{
                    .feature = .allow_commission_decrease_at_any_time,
                    .slot = 0,
                },
                .{
                    .feature = .commission_updates_only_allowed_in_first_half_of_epoch,
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
            .feature_set = &.{
                .{
                    .feature = .allow_commission_decrease_at_any_time,
                    .slot = 0,
                },
                .{
                    .feature = .commission_updates_only_allowed_in_first_half_of_epoch,
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
            .feature_set = &.{
                .{
                    .feature = .allow_commission_decrease_at_any_time,
                    .slot = 0,
                },
                .{
                    .feature = .commission_updates_only_allowed_in_first_half_of_epoch,
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
    const EpochCredit = sig.runtime.program.vote.state.EpochCredit;
    _ = EpochCredit; // autofix
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
                .{
                    .feature = .allow_commission_decrease_at_any_time,
                    .slot = 0,
                },
                .{
                    .feature = .commission_updates_only_allowed_in_first_half_of_epoch,
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
