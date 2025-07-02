const std = @import("std");
const sig = @import("../../../sig.zig");

const vote_program = sig.runtime.program.vote;
const pubkey_utils = sig.runtime.pubkey_utils;
const vote_instruction = vote_program.vote_instruction;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const VoteState = vote_program.state.VoteState;
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
const features = sig.runtime.features;

const VoteProgramInstruction = vote_instruction.Instruction;

/// [agave] https://github.com/anza-xyz/agave/blob/2b0966de426597399ed4570d4e6c0635db2f80bf/programs/vote/src/vote_processor.rs#L54
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L55C40-L55C45
    try ic.tc.consumeCompute(vote_program.COMPUTE_UNITS);

    var vote_account = try ic.borrowInstructionAccount(
        @intFromEnum(vote_instruction.InitializeAccount.AccountIndex.account),
    );
    defer vote_account.release();

    if (!vote_account.account.owner.equals(&vote_program.ID)) {
        return InstructionError.InvalidAccountOwner;
    }

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
) (error{OutOfMemory} || InstructionError)!void {
    if (vote_account.constAccountData().len != VoteState.MAX_VOTE_STATE_SIZE) {
        return InstructionError.InvalidAccountData;
    }

    const versioned_vote_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );

    if (!versioned_vote_state.isUninitialized()) {
        return InstructionError.AccountAlreadyInitialized;
    }

    // node must agree to accept this vote account
    if (!ic.ixn_info.isPubkeySigner(node_pubkey)) {
        try ic.tc.log("IntializeAccount: 'node' {} must sign", .{node_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    const vote_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();

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

/// [agave] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_state/mod.rs#L678
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
    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    var vote_state = try versioned_state.convertToCurrent(allocator);
    defer vote_state.deinit();

    switch (vote_authorize) {
        .voter => {
            const authorized_withdrawer_signer = !std.meta.isError(validateIsSigner(
                vote_state.withdrawer,
                signers,
            ));

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
            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/vote/src/vote_state/mod.rs#L701-L709
            // current authorized withdrawer or epoch authorized voter must sign transaction.
            if (!authorized_withdrawer_signer) {
                _ = try validateIsSigner(
                    epoch_authorized_voter,
                    signers,
                );
            }

            const maybe_err = try vote_state.setNewAuthorizedVoter(
                authorized,
                target_epoch,
            );
            if (maybe_err) |err| {
                ic.tc.custom_error = @intFromEnum(err);
                return InstructionError.Custom;
            }
        },
        .withdrawer => {
            // current authorized withdrawer must say "yay".
            const authorized_withdrawer_signer = !std.meta.isError(validateIsSigner(
                vote_state.withdrawer,
                signers,
            ));

            if (!authorized_withdrawer_signer) {
                return InstructionError.MissingRequiredSignature;
            }
            vote_state.withdrawer = authorized;
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
        return InstructionError.NotEnoughAccountKeys;

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
    const new_authority_meta = &ic.ixn_info.account_metas.buffer[
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
    const new_authority_meta = &ic.ixn_info.account_metas.buffer[
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.new_authority)
    ];
    if (!new_authority_meta.is_signer) {
        return InstructionError.MissingRequiredSignature;
    }

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.clock_sysvar),
    );

    const authorize_pubkey = switch (vote_authorize) {
        .voter => VoteAuthorize.voter,
        .withdrawer => VoteAuthorize.withdrawer,
    };

    const signers = ic.ixn_info.getSigners();

    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority_meta.pubkey,
        authorize_pubkey,
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
    const new_identity_meta = &ic.ixn_info.account_metas.buffer[
        @intFromEnum(vote_instruction.UpdateVoteIdentity.AccountIndex.new_identity)
    ];

    try updateValidatorIdentity(
        allocator,
        ic,
        vote_account,
        new_identity_meta.pubkey,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/24e62248d7a91c090790e7b812e23321fa1f53b1/programs/vote/src/vote_state/mod.rs#L722
///
/// Update the node_pubkey, requires signature of the authorized voter
fn updateValidatorIdentity(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    new_identity: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );

    var vote_state = try versioned_state.convertToCurrent(allocator);
    defer vote_state.deinit();

    // Both the current authorized withdrawer and new identity must sign.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawer) or
        !ic.ixn_info.isPubkeySigner(new_identity))
    {
        return InstructionError.MissingRequiredSignature;
    }

    vote_state.node_pubkey = new_identity;

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

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/69edb584ac17df2f5d8b5e817d7afede7877eded/vote-interface/src/instruction.rs#L415
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
    // Decode vote state only once, and only if needed
    var maybe_vote_state: ?VoteState = null;

    const enforce_commission_update_rule = blk: {
        if (ic.tc.feature_set.active.contains(
            features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
        )) {
            const versioned_state = vote_account.deserializeFromAccountData(
                allocator,
                VoteStateVersions,
            ) catch {
                break :blk true;
            };
            const vote_state = try versioned_state.convertToCurrent(allocator);
            maybe_vote_state = vote_state;
            // [agave] https://github.com/anza-xyz/agave/blob/9806724b6d49dec06a9d50396adf26565d6b7745/programs/vote/src/vote_state/mod.rs#L792
            //
            // Given a proposed new commission, returns true if this would be a commission increase, false otherwise
            break :blk commission > vote_state.commission;
        } else {
            break :blk true;
        }
    };

    if (enforce_commission_update_rule and
        ic.tc.feature_set.active.contains(
            features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
        ))
    {
        if (!isCommissionUpdateAllowed(clock.slot, &epoch_schedule)) {
            // Clean up before returning, if we have a vote_state already.
            if (maybe_vote_state) |*vote_state| {
                vote_state.deinit();
            }
            ic.tc.custom_error = @intFromEnum(VoteError.commission_update_too_late);
            return InstructionError.Custom;
        }
    }

    var vote_state = blk: {
        if (maybe_vote_state) |vote_state| {
            break :blk vote_state;
        } else {
            const versioned_state = try vote_account.deserializeFromAccountData(
                allocator,
                VoteStateVersions,
            );

            break :blk versioned_state.convertToCurrent(allocator) catch {
                return InstructionError.InvalidAccountData;
            };
        }
    };
    defer vote_state.deinit();

    // Current authorized withdrawer must sign transaction.
    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawer)) {
        return InstructionError.MissingRequiredSignature;
    }

    vote_state.commission = commission;

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

/// [agave] https://github.com/anza-xyz/agave/blob/e363f52b5bb4bfb131c647d4dbd6043d23575c78/programs/vote/src/vote_state/mod.rs#L824
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

    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );

    var vote_state = try versioned_state.convertToCurrent(allocator);
    defer vote_state.deinit();

    if (!ic.ixn_info.isPubkeySigner(vote_state.withdrawer)) {
        return InstructionError.MissingRequiredSignature;
    }

    const remaining_balance = std.math.sub(u64, vote_account.account.lamports, lamports) catch {
        return InstructionError.InsufficientFunds;
    };

    if (remaining_balance == 0) {
        const reject_active_vote_account_close = blk: {
            if (vote_state.epoch_credits.getLastOrNull()) |last_epoch_credit| {
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
            // Deinitialize upon zero-balance
            const deinitialized_state = VoteState.default(allocator);
            defer deinitialized_state.deinit();

            try setVoteState(
                allocator,
                &vote_account,
                &deinitialized_state,
                &ic.tc.rent,
                &ic.tc.accounts_resize_delta,
            );
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
    if (ic.tc.feature_set.active.contains(
        features.DEPRECATE_LEGACY_VOTE_IXS,
    ) and
        ic.tc.feature_set.active.contains(
            features.ENABLE_TOWER_SYNC_IX,
        ))
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

/// [agave] https://github.com/anza-xyz/agave/blob/e17340519f792d97cf4af7b9eb81056d475c70f9/programs/vote/src/vote_state/mod.rs#L923
fn processVoteWithAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote: Vote,
    slot_hashes: SlotHashes,
    clock: Clock,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try verifyAndGetVoteState(
        allocator,
        ic,
        vote_account,
        clock,
    );
    defer vote_state.deinit();

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
    if (ic.tc.feature_set.active.contains(features.DEPRECATE_LEGACY_VOTE_IXS) and
        ic.tc.feature_set.active.contains(features.ENABLE_TOWER_SYNC_IX))
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

/// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L944
fn voteStateUpdate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    slot_hashes: SlotHashes,
    clock: Clock,
    vote_state_update: *VoteStateUpdate,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try verifyAndGetVoteState(
        allocator,
        ic,
        vote_account,
        clock,
    );
    defer vote_state.deinit();

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
    if (!ic.tc.feature_set.active.contains(features.ENABLE_TOWER_SYNC_IX)) {
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

/// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L994
fn towerSync(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    slot_hashes: SlotHashes,
    clock: Clock,
    tower_sync: *TowerSync,
) (error{OutOfMemory} || InstructionError)!void {
    var vote_state = try verifyAndGetVoteState(
        allocator,
        ic,
        vote_account,
        clock,
    );
    defer vote_state.deinit();

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

/// [agave] https://github.com/anza-xyz/agave/blob/e17340519f792d97cf4af7b9eb81056d475c70f9/programs/vote/src/vote_state/mod.rs#L905
fn verifyAndGetVoteState(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    clock: Clock,
) (error{OutOfMemory} || InstructionError)!VoteState {
    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );

    if (versioned_state.isUninitialized()) {
        versioned_state.deinit();
        return InstructionError.UninitializedAccount;
    }

    var vote_state = try versioned_state.convertToCurrent(allocator);
    errdefer vote_state.deinit();

    const authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(allocator, clock.epoch);
    if (!ic.ixn_info.isPubkeySigner(authorized_voter)) {
        return InstructionError.MissingRequiredSignature;
    }

    return vote_state;
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
    if (account.constAccountData().len < VoteState.MAX_VOTE_STATE_SIZE and
        (!rent.isExempt(account.account.lamports, VoteState.MAX_VOTE_STATE_SIZE) or
            std.meta.isError(account.setDataLength(
                allocator,
                resize_delta,
                VoteState.MAX_VOTE_STATE_SIZE,
            ))))
    {
        var votes = try std.ArrayList(Lockout).initCapacity(allocator, state.votes.items.len);
        defer votes.deinit();
        for (state.votes.items) |vote| votes.appendAssumeCapacity(vote.lockout);
        return account.serializeIntoAccountData(VoteStateVersions{ .v1_14_11 = .{
            .node_pubkey = state.node_pubkey,
            .withdrawer = state.withdrawer,
            .commission = state.commission,
            .votes = votes,
            .root_slot = state.root_slot,
            .voters = state.voters,
            .prior_voters = state.prior_voters,
            .epoch_credits = state.epoch_credits,
            .last_timestamp = state.last_timestamp,
        } });
    }
    return account.serializeIntoAccountData(VoteStateVersions{ .current = state.* });
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
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
    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: executeAuthorize withdrawer signed by current withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: executeAuthorize voter signed by current withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const PriorVote = sig.runtime.program.vote.state.PriorVote;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    var final_vote_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    try final_vote_state.voters.insert(1, new_authorized_voter);
    final_vote_state.prior_voters.append(PriorVote{
        .key = authorized_voter,
        .start = 0,
        .end = 1,
    });

    var final_current_vote_state = VoteStateVersions{ .current = final_vote_state };
    defer final_current_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: authorizeWithSeed withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: authorizeCheckedWithSeed withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: authorizeChecked withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        new_authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: update_validator_identity" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );
}

test "vote_program: update_validator_identity new authority did not sign" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );

    try std.testing.expectError(InstructionError.MissingRequiredSignature, result);
}

test "vote_program: update_validator_identity current authority did not sign" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        new_node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .sysvar_cache = .{
                .clock = clock,
            },
        },
        .{},
    );

    try std.testing.expectError(InstructionError.MissingRequiredSignature, result);
}

test "vote_program: update_commission increasing commission" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
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
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
                    .slot = 0,
                },
            },
        },
        .{},
    );
}

test "vote_program: update_commission decreasing commission" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
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
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
                    .slot = 0,
                },
            },
        },
        .{},
    );
}

test "vote_program: update_commission commission update too late passes with feature set off" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
            .feature_set = &.{}, // None of the required feature_set is set,
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
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{}, // None of the required feature_set is set,
        },
        .{},
    );
}

test "vote_program: update_commission error commission update too late failure" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
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
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
                    .slot = 0,
                },
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

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

    const initial_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        initial_commission,
        clock,
    ) };
    defer initial_vote_state.deinit();

    const final_vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        final_commission,
        clock,
    ) };
    defer final_vote_state.deinit();

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
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
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
            .sysvar_cache = .{
                .clock = clock,
                .epoch_schedule = epoch_schedule,
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ALLOW_COMMISSION_DECREASE_AT_ANY_TIME,
                    .slot = 0,
                },
                .{
                    .pubkey = features.COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH,
                    .slot = 0,
                },
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
    const clock = Clock.DEFAULT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
    const clock = Clock.DEFAULT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
        },
        .{},
    );
}

test "vote_program: widthdraw all and close account with active vote account" {
    const EpochCredit = sig.runtime.program.vote.state.EpochCredit;
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    // TODO use constant in other tests.
    // Do in a clean up PR after all instructions has been added.
    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
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

    var state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    try state.epoch_credits.append(EpochCredit{
        // Condition for account close down not met.
        // current_epoch - last_epoch_with_credits > 2
        .epoch = 30,
        .credits = 1000,
        .prev_credits = 1000,
    });

    const initial_vote_state = VoteStateVersions{ .current = state };
    defer initial_vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var initial_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    const final_vote_state = VoteStateVersions{ .current = VoteState.default(allocator) };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
    const clock = Clock.DEFAULT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
    const clock = Clock.DEFAULT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const rent = Rent.DEFAULT;
    const clock = Clock.DEFAULT;

    // Account data.
    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const recipient_withdrawer = Pubkey.initRandom(prng.random());

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    // TODO use VoteState.MAX_VOTE_STATE_SIZE instead of hardcoding the size.
    // Do in a clean up PR after all instructions has been added.
    var vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .rent = rent,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ slots[slots.len - 1], vote.hash },
        },
    };

    var final_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteState.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(landed_vote);
    try final_state.doubleLockouts();

    const final_vote_state = VoteStateVersions{ .current = final_state };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{},
    );
}

test "vote_program: vote switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ slots[slots.len - 1], vote.hash },
        },
    };

    var final_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteState.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(landed_vote);
    try final_state.doubleLockouts();

    const final_vote_state = VoteStateVersions{ .current = final_state };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
        },
        .{},
    );
}

test "vote_program: vote missing signature" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ slots[slots.len - 1], vote.hash },
        },
    };

    var final_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteState.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(landed_vote);
    try final_state.doubleLockouts();

    const final_vote_state = VoteStateVersions{ .current = final_state };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    const vote_state = VoteStateVersions{ .current = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ) };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(initial_state_bytes[0..], vote_state, .{});

    var slots = [_]u64{0};

    const vote = Vote{
        // No vote added
        .slots = &slots,
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes{
        .entries = &.{
            .{ 0, sig.core.Hash.ZEROES },
        },
    };

    var final_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    const landed_vote: LandedVote = .{
        .latency = VoteState.computeVoteLatency(0, 0),
        .lockout = Lockout{ .confirmation_count = 1, .slot = 0 },
    };

    try final_state.votes.append(landed_vote);
    try final_state.doubleLockouts();

    const final_vote_state = VoteStateVersions{ .current = final_state };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = slot_hashes,
            },
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
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}

test "vote_program: vote state update switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        vote_program.ID,
        VoteProgramInstruction{
            .update_vote_state_switch = .{
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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}

test "vote_program: compact vote state update" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}

test "vote_program: compact vote state update switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}

test "vote_program: tower sync" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ENABLE_TOWER_SYNC_IX,
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}

test "vote_program: tower sync switch" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    const RENT_EXEMPT_THRESHOLD = 27074400;
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    const clock = Clock.DEFAULT;

    const node_pubkey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const authorized_withdrawer = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;

    // Initial state.
    var vote_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try vote_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 1 } },
        },
    );

    const vote_state = VoteStateVersions{ .current = vote_state_init };
    defer vote_state.deinit();

    var initial_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
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

    var final_state_init = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );

    try final_state_init.votes.appendSlice(
        &[_]LandedVote{
            .{ .latency = 0, .lockout = .{ .slot = 2, .confirmation_count = 4 } },
            .{ .latency = 0, .lockout = .{ .slot = 4, .confirmation_count = 3 } },
            .{ .latency = 0, .lockout = .{ .slot = 6, .confirmation_count = 2 } },
            .{ .latency = 0, .lockout = .{ .slot = 8, .confirmation_count = 1 } },
        },
    );

    const final_vote_state = VoteStateVersions{ .current = final_state_init };
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** VoteState.MAX_VOTE_STATE_SIZE);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

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
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
            .feature_set = &.{
                .{
                    .pubkey = features.ENABLE_TOWER_SYNC_IX,
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
            .sysvar_cache = .{
                .clock = clock,
                .slot_hashes = SlotHashes{
                    .entries = &.{
                        .{ 8, vote_slot_hash },
                        .{ 6, sig.core.Hash.ZEROES },
                        .{ 4, sig.core.Hash.ZEROES },
                        .{ 2, sig.core.Hash.ZEROES },
                    },
                },
            },
        },
        .{},
    );
}
