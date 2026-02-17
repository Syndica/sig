const std = @import("std");
const tracy = @import("tracy");
const std14 = @import("std14");
const sig = @import("../../../sig.zig");

pub const state = @import("state.zig");
const instruction = @import("instruction.zig");
const program = @import("lib.zig");

const runtime = sig.runtime;
const sysvar = runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const FeatureSet = sig.core.FeatureSet;

const InstructionError = sig.core.instruction.InstructionError;
const VoteState = runtime.program.vote.state.VoteState;
const VoteStateVersions = runtime.program.vote.state.VoteStateVersions;
const VoteStateV3 = runtime.program.vote.state.VoteStateV3;
const VoteStateV4 = runtime.program.vote.state.VoteStateV4;
const ExecuteContextsParams = runtime.testing.ExecuteContextsParams;

const Instruction = instruction.Instruction;

const InstructionContext = runtime.InstructionContext;
const BorrowedAccount = runtime.BorrowedAccount;

pub const StakeStateV2 = state.StakeStateV2;
const Authorized = StakeStateV2.Authorized;
const Lockup = StakeStateV2.Lockup;
const StakeAuthorize = StakeStateV2.StakeAuthorize;

const MAX_RETURN_DATA = runtime.transaction_context.TransactionReturnData.MAX_RETURN_DATA;
const MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION = 5;

pub const ID: Pubkey = .parse("Stake11111111111111111111111111111111111111");
pub const SOURCE_ID: Pubkey = .parse("8t3vv6v99tQA6Gp7fVdsBH66hQMaswH5qsJVqJqo8xvG");

pub const COMPUTE_UNITS = 750;

/// [agave] https://github.com/anza-xyz/agave/blob/dd15884337be94f39b7bf7c3c4ae3c92d4fad760/programs/stake/src/stake_instruction.rs#L51
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "stake: execute" });
    defer zone.deinit();

    // agave: consumed in declare_process_instruction
    try ic.tc.consumeCompute(program.COMPUTE_UNITS);

    const epoch_rewards_active: bool = if (ic.tc.sysvar_cache.get(sysvar.EpochRewards)) |x|
        x.active
    else |_|
        false;

    var stake_instruction_buf: [sig.net.Packet.DATA_SIZE]u8 = undefined;
    const stake_instruction = try ic.ixn_info.limitedDeserializeInstruction(
        Instruction,
        &stake_instruction_buf,
    );

    if (epoch_rewards_active and stake_instruction != .get_minimum_delegation) {
        ic.tc.custom_error = @intFromEnum(StakeError.epoch_rewards_active);
        return error.Custom;
    }

    return switch (stake_instruction) {
        .initialize => |args| {
            const authorized, const lockup = args;
            var me = try getStakeAccount(ic);
            defer me.release();

            const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, 1);
            try initialize(allocator, &me, &authorized, &lockup, &rent);
        },
        .authorize => |args| {
            const authorized_pubkey, const stake_authorize = args;

            var me = try getStakeAccount(ic);
            defer me.release();

            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 1);
            try ic.ixn_info.checkNumberOfAccounts(3);
            const custodian_pubkey = try getOptionalPubkey(ic, 3, false);

            try authorize(
                allocator,
                ic,
                &me,
                ic.ixn_info.getSigners().constSlice(),
                &authorized_pubkey,
                stake_authorize,
                &clock,
                custodian_pubkey,
            );
        },
        .authorize_with_seed => |args| {
            var me = try getStakeAccount(ic);
            defer me.release();

            try ic.ixn_info.checkNumberOfAccounts(2);
            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 2);
            const custodian_pubkey = try getOptionalPubkey(ic, 3, false);

            try authorizeWithSeed(
                allocator,
                ic,
                &me,
                1,
                args.authority_seed,
                &args.authority_owner,
                &args.new_authorized_pubkey,
                args.stake_authorize,
                &clock,
                custodian_pubkey,
            );
        },
        .delegate_stake => {
            const clock, const stake_history = blk: {
                // NOTE agave gets this borrwed account and drops it, not doing anything with it?
                var me = try getStakeAccount(ic);
                defer me.release();

                try ic.ixn_info.checkNumberOfAccounts(2);
                const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 2);
                const stake_history = try ic.getSysvarWithAccountCheck(sysvar.StakeHistory, 3);
                try ic.ixn_info.checkNumberOfAccounts(5);

                break :blk .{ clock, stake_history };
            };

            try delegate(
                allocator,
                ic,
                0,
                1,
                &clock,
                &stake_history,
                ic.ixn_info.getSigners().constSlice(),
                ic.tc.feature_set,
            );
        },
        .split => |lamports| {
            // NOTE agave gets this borrwed account and drops it, not doing anything with it?
            {
                var me = try getStakeAccount(ic);
                defer me.release();
                try ic.ixn_info.checkNumberOfAccounts(2);
            }
            try split(
                allocator,
                ic,
                0,
                lamports,
                1,
                ic.ixn_info.getSigners().constSlice(),
                ic.tc.feature_set,
            );
        },
        .merge => {
            // NOTE agave gets this borrowed account and drops it, not doing anything with it?
            const clock, const stake_history = blk: {
                var me = try getStakeAccount(ic);
                defer me.release();
                try ic.ixn_info.checkNumberOfAccounts(2);

                const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 2);
                const stake_history = try ic.getSysvarWithAccountCheck(sysvar.StakeHistory, 3);

                break :blk .{ clock, stake_history };
            };

            try merge(
                allocator,
                ic,
                0,
                1,
                &clock,
                &stake_history,
                ic.ixn_info.getSigners().constSlice(),
            );
        },
        .withdraw => |lamports| {
            // NOTE agave gets this borrwed account and drops it, not doing anything with it?
            const clock, const stake_history = blk: {
                var me = try getStakeAccount(ic);
                defer me.release();

                try ic.ixn_info.checkNumberOfAccounts(2);

                const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 2);
                const stake_history = try ic.getSysvarWithAccountCheck(sysvar.StakeHistory, 3);

                try ic.ixn_info.checkNumberOfAccounts(5);

                break :blk .{ clock, stake_history };
            };

            try withdraw(
                allocator,
                ic,
                0,
                lamports,
                1,
                &clock,
                &stake_history,
                4,
                if (ic.ixn_info.account_metas.items.len >= 6) 5 else null,
                newWarmupCooldownRateEpoch(ic),
            );
        },
        .deactivate => {
            var me = try getStakeAccount(ic);
            defer me.release();
            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 1);

            try deactivate(
                allocator,
                ic,
                &me,
                &clock,
                ic.ixn_info.getSigners().constSlice(),
            );
        },
        .set_lockup => |lockup| {
            var me = try getStakeAccount(ic);
            defer me.release();
            const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

            try setLockup(
                allocator,
                &me,
                &lockup,
                ic.ixn_info.getSigners().constSlice(),
                &clock,
            );
        },
        .initialize_checked => {
            var me = try getStakeAccount(ic);
            defer me.release();

            try ic.ixn_info.checkNumberOfAccounts(4);

            const staker = ic.ixn_info.getAccountMetaAtIndex(2) orelse
                return error.MissingAccount;
            const withdrawer = ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount;

            if (!(ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount).is_signer)
            {
                return error.MissingRequiredSignature;
            }

            const authorized = Authorized{
                .staker = staker.pubkey,
                .withdrawer = withdrawer.pubkey,
            };

            const rent = try ic.getSysvarWithAccountCheck(sysvar.Rent, 1);
            try initialize(allocator, &me, &authorized, &Lockup.DEFAULT, &rent);
        },
        .authorize_checked => |stake_authorize| {
            var me = try getStakeAccount(ic);
            defer me.release();

            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 1);
            try ic.ixn_info.checkNumberOfAccounts(4);

            const authorized = ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount;

            if (!(ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount).is_signer)
            {
                return error.MissingRequiredSignature;
            }

            const custodian_pubkey = try getOptionalPubkey(ic, 4, false);

            try authorize(
                allocator,
                ic,
                &me,
                ic.ixn_info.getSigners().slice(),
                &authorized.pubkey,
                stake_authorize,
                &clock,
                custodian_pubkey,
            );
        },
        .authorize_checked_with_seed => |args| {
            var me = try getStakeAccount(ic);
            defer me.release();

            try ic.ixn_info.checkNumberOfAccounts(2);

            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 2);

            try ic.ixn_info.checkNumberOfAccounts(4);

            const authorized = ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount;

            if (!(ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.MissingAccount).is_signer)
            {
                return error.MissingRequiredSignature;
            }

            const custodian_pubkey = try getOptionalPubkey(ic, 4, false);

            try authorizeWithSeed(
                allocator,
                ic,
                &me,
                1,
                args.authority_seed,
                &args.authority_owner,
                &authorized.pubkey,
                args.stake_authorize,
                &clock,
                custodian_pubkey,
            );
        },
        .set_lockup_checked => |lockup_checked| {
            var me = try getStakeAccount(ic);
            defer me.release();
            const custodian_pubkey = try getOptionalPubkey(ic, 2, true);

            const lockup: instruction.LockupArgs = .{
                .unix_timestamp = lockup_checked.unix_timestamp,
                .epoch = lockup_checked.epoch,
                .custodian = if (custodian_pubkey) |key| key.* else null,
            };

            const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
            try setLockup(
                allocator,
                &me,
                &lockup,
                ic.ixn_info.getSigners().constSlice(),
                &clock,
            );
        },
        .get_minimum_delegation => {
            const min_delegation = getMinimumDelegation(ic.tc.slot, ic.tc.feature_set);
            const bytes = std.mem.asBytes(&std.mem.nativeToLittle(u64, min_delegation));

            std.debug.assert(bytes.len == 8);
            const data = std14.BoundedArray(u8, MAX_RETURN_DATA).fromSlice(bytes) catch unreachable;

            ic.tc.return_data = .{
                .program_id = ID,
                .data = data,
            };
        },
        .deactivate_delinquent => {
            var me = try getStakeAccount(ic);
            defer me.release();

            try ic.ixn_info.checkNumberOfAccounts(3);
            const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

            try deactivateDelinquent(allocator, ic, &me, 1, 2, clock.epoch);
        },
        // deprecated
        ._redelegate => {
            var me = try getStakeAccount(ic);
            defer me.release();
            return error.InvalidInstructionData;
        },
        .move_stake => |lamports| {
            if (!ic.tc.feature_set.active(
                .move_stake_and_move_lamports_ixs,
                ic.tc.slot,
            )) return error.InvalidInstructionData;

            try ic.ixn_info.checkNumberOfAccounts(3);
            try moveStake(allocator, ic, 0, lamports, 1, 2);
        },
        .move_lamports => |lamports| {
            if (!ic.tc.feature_set.active(
                .move_stake_and_move_lamports_ixs,
                ic.tc.slot,
            )) return error.InvalidInstructionData;

            try ic.ixn_info.checkNumberOfAccounts(3);
            try moveLamports(allocator, ic, 0, lamports, 1, 2);
        },
    };
}

fn getStakeAccount(ic: *InstructionContext) InstructionError!BorrowedAccount {
    const me = try ic.borrowInstructionAccount(0);
    if (!me.account.owner.equals(&ID)) return error.InvalidAccountOwner;
    return me;
}

/// [agave] https://github.com/solana-program/stake/blob/a1c20c8033f29f6015a691325df433dcfeaf5cea/interface/src/error.rs#L14
pub const StakeError = enum(u32) {
    /// Not enough credits to redeem.
    no_credits_to_redeem,
    /// Lockup has not yet expired.
    lockup_in_force,
    /// Stake already deactivated.
    already_deactivated,
    /// One re-delegation permitted per epoch.
    too_soon_to_redelegate,
    /// Split amount is more than is staked.
    insufficient_stake,
    /// Stake account with transient stake cannot be merged.
    merge_transient_stake,
    /// Stake account merge failed due to different authority, lockups or state.
    merge_mismatch,
    /// Custodian address not present.
    custodian_missing,
    /// Custodian signature not present.
    custodian_signature_missing,
    /// Insufficient voting activity in the reference vote account.
    insufficient_reference_votes,
    /// Stake account is not delegated to the provided vote account.
    vote_address_mismatch,
    /// Stake account has not been delinquent for the minimum epochs required
    /// for deactivation.
    minimum_delinquent_epochs_for_deactivation_not_met,
    /// Delegation amount is less than the minimum.
    insufficient_delegation,
    /// Stake account with transient or inactive stake cannot be redelegated.
    redelegate_transient_or_inactive_stake,
    /// Stake redelegation to the same vote account is not permitted.
    redelegate_to_same_vote_account,
    /// Redelegated stake must be fully activated before deactivation.
    redelegated_stake_must_fully_activate_before_deactivation_is_permitted,
    /// Stake action is not permitted while the epoch rewards period is active.
    epoch_rewards_active,
};

fn getOptionalPubkey(
    ic: *const InstructionContext,
    instruction_account_index: u16,
    should_be_signer: bool,
) InstructionError!?*const Pubkey {
    const meta = ic.ixn_info.getAccountMetaAtIndex(instruction_account_index) orelse
        return null;

    if (should_be_signer and !meta.is_signer)
        return error.MissingRequiredSignature;

    return &meta.pubkey;
}

fn initialize(
    allocator: std.mem.Allocator,
    stake_account: *BorrowedAccount,
    authorized: *const Authorized,
    lockup: *const Lockup,
    rent: *const sysvar.Rent,
) (error{OutOfMemory} || InstructionError)!void {
    if (stake_account.account.data.len != StakeStateV2.SIZE) {
        return error.InvalidAccountData;
    }

    const stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);
    switch (stake_state) {
        .uninitialized => {
            const rent_exempt_reserve = rent.minimumBalance(stake_account.account.data.len);
            if (stake_account.account.lamports < rent_exempt_reserve)
                return error.InsufficientFunds;

            try stake_account.serializeIntoAccountData(StakeStateV2{
                .initialized = .{
                    .rent_exempt_reserve = rent_exempt_reserve,
                    .authorized = authorized.*,
                    .lockup = lockup.*,
                },
            });
        },
        else => return error.InvalidAccountData,
    }
}

/// Authorize the given pubkey to manage stake (deactivate, withdraw). This may be called
/// multiple times, but will implicitly withdraw authorization from the previously authorized
/// staker. The default staker is the owner of the stake account's pubkey.
fn authorize(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account: *BorrowedAccount,
    signers: []const Pubkey,
    new_authority: *const Pubkey,
    stake_authorize: StakeAuthorize,
    clock: *const sysvar.Clock,
    custodian: ?*const Pubkey,
) InstructionError!void {
    var stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);

    return switch (stake_state) {
        .stake => |*stake_args| {
            if (stake_args.meta.authorized.authorize(
                signers,
                new_authority,
                stake_authorize,
                .{ &stake_args.meta.lockup, clock, custodian },
            )) |err| {
                const maybe_custom_err, const instruction_err = err;
                if (maybe_custom_err) |custom_err| ic.tc.custom_error = @intFromEnum(custom_err);
                return instruction_err;
            }

            try stake_account.serializeIntoAccountData(StakeStateV2{ .stake = .{
                .meta = stake_args.meta,
                .stake = stake_args.stake,
                .flags = stake_args.flags,
            } });
        },
        .initialized => |*meta| {
            if (meta.authorized.authorize(
                signers,
                new_authority,
                stake_authorize,
                .{ &meta.lockup, clock, custodian },
            )) |err| {
                const maybe_custom_err, const instruction_err = err;
                if (maybe_custom_err) |custom_err| ic.tc.custom_error = @intFromEnum(custom_err);
                return instruction_err;
            }

            try stake_account.serializeIntoAccountData(StakeStateV2{ .initialized = meta.* });
        },
        else => error.InvalidAccountData,
    };
}

fn authorizeWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account: *BorrowedAccount,
    authority_base_index: u16,
    authority_seed: []const u8,
    authority_owner: *const Pubkey,
    new_authority: *const Pubkey,
    stake_authorize: StakeAuthorize,
    clock: *const sysvar.Clock,
    custodian: ?*const Pubkey,
) InstructionError!void {
    const meta = ic.ixn_info.getAccountMetaAtIndex(authority_base_index) orelse
        return error.MissingAccount;

    var signers: std14.BoundedArray(Pubkey, 1) = .{};
    if (meta.is_signer) {
        const account = ic.tc.getAccountAtIndex(meta.index_in_transaction) orelse
            return error.MissingAccount;

        signers.appendAssumeCapacity(sig.runtime.pubkey_utils.createWithSeed(
            account.pubkey,
            authority_seed,
            authority_owner.*,
        ) catch |err| {
            ic.tc.custom_error = sig.runtime.pubkey_utils.mapError(err);
            return error.Custom;
        });
    }

    return try authorize(
        allocator,
        ic,
        stake_account,
        signers.constSlice(),
        new_authority,
        stake_authorize,
        clock,
        custodian,
    );
}

pub fn getMinimumDelegation(slot: Slot, feature_set: *const FeatureSet) u64 {
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    return if (feature_set.active(.stake_raise_minimum_delegation_to_1_sol, slot))
        1 * LAMPORTS_PER_SOL
    else
        1;
}

const ValidatedDelegatedInfo = struct { stake_amount: u64 };

fn validateDelegatedAmount(
    ic: *InstructionContext,
    account: *const BorrowedAccount,
    meta: *const StakeStateV2.Meta,
    feature_set: *const FeatureSet,
) InstructionError!ValidatedDelegatedInfo {
    const stake_amount = account.account.lamports -| meta.rent_exempt_reserve;
    if (stake_amount < getMinimumDelegation(ic.tc.slot, feature_set)) {
        ic.tc.custom_error = @intFromEnum(StakeError.insufficient_delegation);
        return error.Custom;
    }
    return .{ .stake_amount = stake_amount };
}

fn newStake(
    stake: u64,
    voter_pubkey: *const Pubkey,
    vote_state: *const VoteState,
    activation_epoch: Epoch,
) StakeStateV2.Stake {
    return .{
        .delegation = .{
            .voter_pubkey = voter_pubkey.*,
            .stake = stake,
            .activation_epoch = activation_epoch,
        },
        .credits_observed = vote_state.getCredits(),
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/dd15884337be94f39b7bf7c3c4ae3c92d4fad760/programs/stake/src/stake_state.rs#L60
fn newWarmupCooldownRateEpoch(ic: *InstructionContext) ?Epoch {
    const epoch_schedule = ic.tc.sysvar_cache.get(sysvar.EpochSchedule) catch
        @panic("failed to get epoch schedule"); // agave calls .unwrap here (!!).
    return ic.tc.feature_set.newWarmupCooldownRateEpoch(&epoch_schedule);
}

fn redelegateStake(
    ic: *InstructionContext,
    stake: *StakeStateV2.Stake,
    stake_lamports: u64,
    voter_pubkey: *const Pubkey,
    vote_state: *const VoteState,
    clock: *const sysvar.Clock,
    stake_history: *const sysvar.StakeHistory,
) ?StakeError {
    const new_rate_activation_epoch = newWarmupCooldownRateEpoch(ic);

    if (stake.delegation.getEffectiveStake(
        clock.epoch,
        stake_history,
        new_rate_activation_epoch,
    ) != 0) {
        if (stake.delegation.voter_pubkey.equals(voter_pubkey) and
            clock.epoch == stake.delegation.deactivation_epoch)
        {
            stake.delegation.deactivation_epoch = std.math.maxInt(u64);
            return null;
        } else {
            return .too_soon_to_redelegate;
        }
    }

    stake.delegation.stake = stake_lamports;
    stake.delegation.activation_epoch = clock.epoch;
    stake.delegation.deactivation_epoch = std.math.maxInt(u64);
    stake.delegation.voter_pubkey = voter_pubkey.*;
    stake.credits_observed = vote_state.getCredits();
    return null;
}

fn delegate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account_index: u16,
    vote_account_index: u16,
    clock: *const sysvar.Clock,
    stake_history: *const sysvar.StakeHistory,
    signers: []const Pubkey,
    feature_set: *const FeatureSet,
) (error{OutOfMemory} || InstructionError)!void {
    const vote_pubkey, const vote_state = blk: {
        const vote_account = try ic.borrowInstructionAccount(vote_account_index);
        defer vote_account.release();

        if (!vote_account.account.owner.equals(&sig.runtime.program.vote.ID)) {
            return error.IncorrectProgramId;
        }

        break :blk .{
            vote_account.pubkey,
            // weirdness: error handling for this is done later
            vote_account.deserializeFromAccountData(allocator, VoteStateVersions),
        };
    };

    var stake_account = try ic.borrowInstructionAccount(stake_account_index);
    defer stake_account.release();

    var stake = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);

    return switch (stake) {
        .initialized => |*meta| {
            try meta.authorized.check(signers, .staker);

            const validated = try validateDelegatedAmount(ic, &stake_account, meta, feature_set);
            const stake_amount = validated.stake_amount;

            const payload = try vote_state;
            var current_vote_state = try payload.convertToVoteState(allocator, vote_pubkey, false);
            defer current_vote_state.deinit(allocator);

            const new_stake = newStake(
                stake_amount,
                &vote_pubkey,
                &current_vote_state,
                clock.epoch,
            );

            try stake_account.serializeIntoAccountData(StakeStateV2{
                .stake = .{ .flags = .EMPTY, .stake = new_stake, .meta = meta.* },
            });
        },
        .stake => |*args| {
            try args.meta.authorized.check(signers, .staker);
            const validated = try validateDelegatedAmount(
                ic,
                &stake_account,
                &args.meta,
                feature_set,
            );
            const stake_amount = validated.stake_amount;

            const payload = try vote_state;
            var current_vote_state = try payload.convertToVoteState(allocator, vote_pubkey, false);
            defer current_vote_state.deinit(allocator);
            if (redelegateStake(
                ic,
                &args.stake,
                stake_amount,
                &vote_pubkey,
                &current_vote_state,
                clock,
                stake_history,
            )) |stake_err| {
                ic.tc.custom_error = @intFromEnum(stake_err);
                return error.Custom;
            }
            try stake_account.serializeIntoAccountData(StakeStateV2{
                .stake = .{ .flags = args.flags, .stake = args.stake, .meta = args.meta },
            });
        },
        else => error.InvalidAccountData,
    };
}

fn getStakeStatus(
    ic: *InstructionContext,
    stake: *const StakeStateV2.Stake,
    clock: *const sysvar.Clock,
) InstructionError!sysvar.StakeHistory.StakeState {
    const stake_history = try ic.tc.sysvar_cache.get(sysvar.StakeHistory);
    return stake.delegation.getStakeState(
        clock.epoch,
        &stake_history,
        newWarmupCooldownRateEpoch(ic),
    );
}

const ValidatedSplitInfo = struct {
    source_remaining_balance: u64,
    destination_rent_exempt_reserve: u64,
};

fn validateSplitAmount(
    ic: *InstructionContext,
    source_account_index: u16,
    destination_account_index: u16,
    lamports: u64,
    source_meta: *const StakeStateV2.Meta,
    additional_required_lamports: u64,
    source_is_active: bool,
) InstructionError!ValidatedSplitInfo {
    const source_lamports = blk: {
        const source_account = try ic.borrowInstructionAccount(source_account_index);
        defer source_account.release();
        break :blk source_account.account.lamports;
    };

    const destination_data_len, const destination_lamports = blk: {
        const destination_account = try ic.borrowInstructionAccount(destination_account_index);
        defer destination_account.release();
        break :blk .{
            destination_account.account.data.len,
            destination_account.account.lamports,
        };
    };

    if (lamports == 0) return error.InsufficientFunds;
    if (lamports > source_lamports) return error.InsufficientFunds;

    const source_minimum_balance = source_meta.rent_exempt_reserve +| additional_required_lamports;
    const source_remaining_balance = source_lamports -| lamports;
    if (source_remaining_balance == 0) {
        // nothing to do here, full amount if withdrawal.
    } else if (source_remaining_balance < source_minimum_balance) {
        return error.InsufficientFunds;
    }

    const rent = try ic.tc.sysvar_cache.get(sysvar.Rent);
    const destination_rent_exempt_reserve = rent.minimumBalance(destination_data_len);

    if (source_is_active and
        source_remaining_balance != 0 and
        destination_lamports < destination_rent_exempt_reserve)
        return error.InsufficientFunds;

    const destination_minimum_balance = destination_rent_exempt_reserve +|
        additional_required_lamports;
    const destination_balance_deficit = destination_minimum_balance -|
        destination_lamports;
    if (lamports < destination_balance_deficit) return error.InsufficientFunds;

    return .{
        .source_remaining_balance = source_remaining_balance,
        .destination_rent_exempt_reserve = destination_rent_exempt_reserve,
    };
}

fn split(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account_index: u16,
    lamports: u64,
    split_account_index: u16,
    signers: []const Pubkey,
    feature_set: *const FeatureSet,
) (error{OutOfMemory} || InstructionError)!void {
    const split_lamport_balance = balance: {
        const split_account = try ic.borrowInstructionAccount(split_account_index);
        defer split_account.release();

        if (!split_account.account.owner.equals(&ID)) return error.IncorrectProgramId;
        if (split_account.account.data.len != StakeStateV2.SIZE) return error.InvalidAccountData;

        const split_state = try split_account.deserializeFromAccountData(allocator, StakeStateV2);
        if (split_state != .uninitialized) return error.InvalidAccountData;

        break :balance split_account.account.lamports;
    };

    const stake_state = state: {
        const stake_account = try ic.borrowInstructionAccount(stake_account_index);
        defer stake_account.release();

        if (lamports > stake_account.account.lamports) return error.InsufficientFunds;
        break :state try stake_account.deserializeFromAccountData(allocator, StakeStateV2);
    };

    switch (stake_state) {
        .stake => |stake_args| {
            var args = stake_args;
            try args.meta.authorized.check(signers, .staker);

            const minimum_delegation = getMinimumDelegation(ic.tc.slot, feature_set);
            const is_active = blk: {
                const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
                const status = try getStakeStatus(ic, &args.stake, &clock);
                break :blk status.effective > 0;
            };

            const validated_split_info = try validateSplitAmount(
                ic,
                stake_account_index,
                split_account_index,
                lamports,
                &args.meta,
                minimum_delegation,
                is_active,
            );

            const remaining_stake_delta, const split_stake_amount = blk: {
                if (validated_split_info.source_remaining_balance == 0) {
                    const remaining_stake_delta = lamports -| args.meta.rent_exempt_reserve;
                    break :blk .{ remaining_stake_delta, remaining_stake_delta };
                }

                if (args.stake.delegation.stake -| lamports < minimum_delegation) {
                    ic.tc.custom_error = @intFromEnum(StakeError.insufficient_delegation);
                    return error.Custom;
                }

                break :blk .{
                    lamports,
                    lamports -|
                        (validated_split_info.destination_rent_exempt_reserve -|
                            split_lamport_balance),
                };
            };

            if (split_stake_amount < minimum_delegation) {
                ic.tc.custom_error = @intFromEnum(StakeError.insufficient_delegation);
                return error.Custom;
            }

            const split_stake = try args.stake.split(ic, remaining_stake_delta, split_stake_amount);
            var split_meta = args.meta;
            split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

            {
                var stake_account = try ic.borrowInstructionAccount(stake_account_index);
                defer stake_account.release();

                try stake_account.serializeIntoAccountData(StakeStateV2{
                    .stake = .{ .meta = args.meta, .stake = args.stake, .flags = args.flags },
                });
            }

            {
                var split_account = try ic.borrowInstructionAccount(split_account_index);
                defer split_account.release();

                try split_account.serializeIntoAccountData(StakeStateV2{
                    .stake = .{ .meta = split_meta, .stake = split_stake, .flags = args.flags },
                });
            }
        },
        .initialized => |meta| {
            try meta.authorized.check(signers, .staker);
            const validated_split_info = try validateSplitAmount(
                ic,
                stake_account_index,
                split_account_index,
                lamports,
                &meta,
                0,
                false,
            );

            var split_meta = meta;
            split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

            {
                var split_account = try ic.borrowInstructionAccount(split_account_index);
                defer split_account.release();

                try split_account.serializeIntoAccountData(StakeStateV2{
                    .initialized = split_meta,
                });
            }
        },
        .uninitialized => {
            const account_meta = ic.ixn_info.getAccountMetaAtIndex(stake_account_index) orelse
                return error.MissingAccount;
            const stake_pubkey = &account_meta.pubkey;

            const has_signer = for (signers) |signer| {
                if (signer.equals(stake_pubkey)) break true;
            } else false;

            if (!has_signer) return error.MissingRequiredSignature;
        },
        else => return error.InvalidAccountData,
    }

    // Deinitialize state upon zero balance
    {
        var stake_account = try ic.borrowInstructionAccount(stake_account_index);
        defer stake_account.release();
        if (lamports == stake_account.account.lamports) {
            try stake_account.serializeIntoAccountData(StakeStateV2{ .uninitialized = {} });
        }
    }

    {
        var split_account = try ic.borrowInstructionAccount(split_account_index);
        defer split_account.release();
        try split_account.addLamports(lamports);
    }

    {
        var stake_account = try ic.borrowInstructionAccount(stake_account_index);
        defer stake_account.release();
        try stake_account.subtractLamports(lamports);
    }
}

fn stakeWeightedCreditsObserved(
    stake: *const StakeStateV2.Stake,
    absorbed_lamports: u64,
    absorbed_credits_observed: u64,
) ?u64 {
    if (stake.credits_observed == absorbed_credits_observed) return stake.credits_observed;

    const total_stake: u128 =
        std.math.add(u64, stake.delegation.stake, absorbed_lamports) catch return null;

    const stake_weighted_credits =
        std.math.mul(u128, stake.credits_observed, stake.delegation.stake) catch return null;

    const absorbed_weighted_credits =
        std.math.mul(u128, absorbed_credits_observed, absorbed_lamports) catch return null;

    var total_weighted_credits = stake_weighted_credits;
    total_weighted_credits =
        std.math.add(u128, total_weighted_credits, absorbed_weighted_credits) catch return null;
    total_weighted_credits =
        std.math.add(u128, total_weighted_credits, total_stake) catch return null;
    total_weighted_credits =
        std.math.sub(u128, total_weighted_credits, 1) catch return null;

    if (total_stake == 0) return null;

    return std.math.cast(u64, total_weighted_credits / total_stake) orelse return null;
}

const MergeKind = union(enum) {
    inactive: struct { StakeStateV2.Meta, u64, StakeStateV2.StakeFlags },
    activation_epoch: struct { StakeStateV2.Meta, StakeStateV2.Stake, StakeStateV2.StakeFlags },
    fully_active: struct { StakeStateV2.Meta, StakeStateV2.Stake },

    fn meta(self: *const MergeKind) StakeStateV2.Meta {
        return switch (self.*) {
            .inactive => |inactive| inactive.@"0",
            .activation_epoch => |activation_epoch| activation_epoch.@"0",
            .fully_active => |fully_active| fully_active.@"0",
        };
    }

    fn activeStake(self: *const MergeKind) ?StakeStateV2.Stake {
        return switch (self.*) {
            .inactive => null,
            .activation_epoch => |activation_epoch| activation_epoch.@"1",
            .fully_active => |fully_active| fully_active.@"1",
        };
    }

    fn getIfMergeable(
        ic: *InstructionContext,
        stake_state: *const StakeStateV2,
        stake_lamports: u64,
        clock: *const sysvar.Clock,
        stake_history: *const sysvar.StakeHistory,
    ) (error{OutOfMemory} || InstructionError)!MergeKind {
        switch (stake_state.*) {
            .stake => |args| {
                const status = args.stake.delegation.getStakeState(
                    clock.epoch,
                    stake_history,
                    newWarmupCooldownRateEpoch(ic),
                );

                const effec = status.effective;
                const activ = status.activating;
                const deact = status.deactivating;

                if (effec == 0 and activ == 0 and deact == 0) return .{
                    .inactive = .{ args.meta, stake_lamports, args.flags },
                };
                if (effec == 0) return .{
                    .activation_epoch = .{ args.meta, args.stake, args.flags },
                };
                if (activ == 0 and deact == 0) return .{
                    .fully_active = .{ args.meta, args.stake },
                };

                const err = StakeError.merge_transient_stake;
                try ic.tc.log("{any}", .{err});
                ic.tc.custom_error = @intFromEnum(err);
                return error.Custom;
            },

            .initialized => |stake_meta| {
                return .{ .inactive = .{ stake_meta, stake_lamports, .EMPTY } };
            },
            else => return error.InvalidAccountData,
        }
    }

    fn metasCanMerge(
        ic: *InstructionContext,
        stake: *const StakeStateV2.Meta,
        source: *const StakeStateV2.Meta,
        clock: *const sysvar.Clock,
    ) (error{OutOfMemory} || InstructionError)!void {
        const can_merge_lookups = stake.lockup.equals(&source.lockup) or
            (!stake.lockup.isInForce(clock, null) and !source.lockup.isInForce(clock, null));

        if (!stake.authorized.equals(&source.authorized) or !can_merge_lookups) {
            try ic.tc.log("Unable to merge due to metadata mismatch", .{});
            ic.tc.custom_error = @intFromEnum(StakeError.merge_mismatch);
            return error.Custom;
        }
    }

    fn activeDelegationsCanMerge(
        ic: *InstructionContext,
        stake: *const StakeStateV2.Delegation,
        source: *const StakeStateV2.Delegation,
    ) (error{OutOfMemory} || InstructionError)!void {
        if (!stake.voter_pubkey.equals(&source.voter_pubkey)) {
            try ic.tc.log("Unable to merge due to voter mismatch", .{});
            ic.tc.custom_error = @intFromEnum(StakeError.merge_mismatch);
            return error.Custom;
        }
        if (stake.deactivation_epoch != std.math.maxInt(Epoch) or
            source.deactivation_epoch != std.math.maxInt(Epoch))
        {
            try ic.tc.log("Unable to merge due to stake deactivation", .{});
            ic.tc.custom_error = @intFromEnum(StakeError.merge_mismatch);
            return error.Custom;
        }
    }

    fn mergeDelegationStakeAndCreditsObserved(
        stake: *StakeStateV2.Stake,
        absorbed_lamports: u64,
        absorbed_credits_observed: u64,
    ) InstructionError!void {
        stake.credits_observed = stakeWeightedCreditsObserved(
            stake,
            absorbed_lamports,
            absorbed_credits_observed,
        ) orelse return error.ProgramArithmeticOverflow;

        stake.delegation.stake = std.math.add(
            u64,
            stake.delegation.stake,
            absorbed_lamports,
        ) catch return error.InsufficientFunds;
    }

    /// returns merged state
    fn merge(
        self: MergeKind,
        ic: *InstructionContext,
        source: MergeKind,
        clock: *const sysvar.Clock,
    ) (error{OutOfMemory} || InstructionError)!?StakeStateV2 {
        try metasCanMerge(ic, &self.meta(), &source.meta(), clock);

        blk: {
            const self_stake = self.activeStake() orelse break :blk;
            const source_stake = source.activeStake() orelse break :blk;
            try activeDelegationsCanMerge(
                ic,
                &self_stake.delegation,
                &source_stake.delegation,
            );
        }

        if (self == .inactive and (source == .inactive or source == .activation_epoch)) return null;

        if (self == .activation_epoch and source == .inactive) {
            const self_meta = self.activation_epoch.@"0";
            var stake = self.activation_epoch.@"1";
            const stake_flags = self.activation_epoch.@"2";

            const source_lamports = source.inactive.@"1";
            const source_stake_flags = source.inactive.@"2";

            stake.delegation.stake = std.math.add(
                u64,
                stake.delegation.stake,
                source_lamports,
            ) catch return error.InsufficientFunds;

            return .{ .stake = .{
                .meta = self_meta,
                .stake = stake,
                .flags = stake_flags.combine(source_stake_flags),
            } };
        }

        if (self == .activation_epoch and source == .activation_epoch) {
            const self_meta = self.activation_epoch.@"0";
            var stake = self.activation_epoch.@"1";
            const stake_flags = self.activation_epoch.@"2";

            const source_meta = source.activation_epoch.@"0";
            const source_stake = source.activation_epoch.@"1";
            const source_stake_flags = source.activation_epoch.@"2";

            const source_lamports = std.math.add(
                u64,
                source_meta.rent_exempt_reserve,
                source_stake.delegation.stake,
            ) catch return error.InsufficientFunds;

            try mergeDelegationStakeAndCreditsObserved(
                &stake,
                source_lamports,
                source_stake.credits_observed,
            );

            return StakeStateV2{ .stake = .{
                .meta = self_meta,
                .stake = stake,
                .flags = stake_flags.combine(source_stake_flags),
            } };
        }

        if (self == .fully_active and source == .fully_active) {
            var stake = self.fully_active.@"1";
            const active_meta = self.fully_active.@"0";
            const source_stake = source.fully_active.@"1";

            try mergeDelegationStakeAndCreditsObserved(
                &stake,
                source_stake.delegation.stake,
                source_stake.credits_observed,
            );

            return StakeStateV2{
                .stake = .{ .flags = .EMPTY, .meta = active_meta, .stake = stake },
            };
        }

        ic.tc.custom_error = @intFromEnum(StakeError.merge_mismatch);
        return error.Custom;
    }
};

fn merge(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account_index: u16,
    source_account_index: u16,
    clock: *const sysvar.Clock,
    stake_history: *const sysvar.StakeHistory,
    signers: []const Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    var source_account = try ic.borrowInstructionAccount(source_account_index);
    defer source_account.release();

    if (!source_account.account.owner.equals(&ID)) return error.IncorrectProgramId;

    {
        const stake_meta = ic.ixn_info.getAccountMetaAtIndex(stake_account_index) orelse
            return error.MissingAccount;
        const source_meta = ic.ixn_info.getAccountMetaAtIndex(source_account_index) orelse
            return error.MissingAccount;
        if (stake_meta.index_in_transaction == source_meta.index_in_transaction)
            return error.InvalidArgument;
    }

    var stake_account = try ic.borrowInstructionAccount(stake_account_index);
    defer stake_account.release();

    try ic.tc.log("Checking if destination stake is mergeable", .{});
    const stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);
    const stake_merge_kind = try MergeKind.getIfMergeable(
        ic,
        &stake_state,
        stake_account.account.lamports,
        clock,
        stake_history,
    );

    try stake_merge_kind.meta().authorized.check(signers, .staker);

    try ic.tc.log("Checking if source stake is mergeable", .{});
    const source_state = try source_account.deserializeFromAccountData(allocator, StakeStateV2);
    const source_merge_kind = try MergeKind.getIfMergeable(
        ic,
        &source_state,
        source_account.account.lamports,
        clock,
        stake_history,
    );

    try ic.tc.log("Merging stake accounts", .{});
    if (try stake_merge_kind.merge(ic, source_merge_kind, clock)) |merged_state| {
        try stake_account.serializeIntoAccountData(merged_state);
    }

    try source_account.serializeIntoAccountData(StakeStateV2.uninitialized);

    const lamports = source_account.account.lamports;
    try source_account.subtractLamports(lamports);
    try stake_account.addLamports(lamports);
}

fn withdraw(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account_index: u16,
    lamports: u64,
    to_index: u16,
    clock: *const sysvar.Clock,
    stake_history: *const sysvar.StakeHistory,
    withdraw_authority_index: u16,
    custodian_index: ?u16,
    new_rate_activation_epoch: ?Epoch,
) (error{OutOfMemory} || InstructionError)!void {
    const withdraw_authority = ic.ixn_info.getAccountMetaAtIndex(withdraw_authority_index) orelse
        return error.MissingAccount;

    if (!withdraw_authority.is_signer) return error.MissingRequiredSignature;

    const signers: []const Pubkey = &.{withdraw_authority.pubkey};
    {
        var stake_account = try ic.borrowInstructionAccount(stake_account_index);
        defer stake_account.release();

        const stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);

        const lockup: Lockup, const reserve, const is_staked = switch (stake_state) {
            .stake => |args| blk: {
                try args.meta.authorized.check(signers, .withdrawer);

                const staked = if (clock.epoch >= args.stake.delegation.deactivation_epoch)
                    args.stake.delegation.getEffectiveStake(
                        clock.epoch,
                        stake_history,
                        new_rate_activation_epoch,
                    )
                else
                    args.stake.delegation.stake;

                const staked_and_reserve = std.math.add(
                    u64,
                    staked,
                    args.meta.rent_exempt_reserve,
                ) catch return error.InsufficientFunds;

                break :blk .{ args.meta.lockup, staked_and_reserve, staked != 0 };
            },
            .initialized => |meta| blk: {
                try meta.authorized.check(signers, .withdrawer);
                break :blk .{ meta.lockup, meta.rent_exempt_reserve, false };
            },
            .uninitialized => blk: {
                if (!signers[0].equals(&stake_account.pubkey))
                    return error.MissingRequiredSignature;
                break :blk .{ Lockup.DEFAULT, 0, false };
            },
            else => return error.InvalidAccountData,
        };

        const custodian_pubkey = if (custodian_index) |idx| key: {
            const meta = ic.ixn_info.getAccountMetaAtIndex(idx) orelse
                return error.MissingAccount;
            if (!meta.is_signer) break :key null;

            break :key &meta.pubkey;
        } else null;

        if (lockup.isInForce(clock, custodian_pubkey)) {
            ic.tc.custom_error = @intFromEnum(StakeError.lockup_in_force);
            return error.Custom;
        }

        const lamports_and_reserve: u64 = std.math.add(u64, lamports, reserve) catch
            return error.InsufficientFunds;

        if (is_staked and lamports_and_reserve > stake_account.account.lamports)
            return error.InsufficientFunds;

        if (lamports != stake_account.account.lamports and
            lamports_and_reserve > stake_account.account.lamports)
        {
            std.debug.assert(!is_staked);
            return error.InsufficientFunds;
        }

        if (lamports == stake_account.account.lamports) {
            try stake_account.serializeIntoAccountData(StakeStateV2.uninitialized);
        }

        try stake_account.subtractLamports(lamports);
    }

    var to = try ic.borrowInstructionAccount(to_index);
    defer to.release();
    try to.addLamports(lamports);
}

fn deactivate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account: *BorrowedAccount,
    clock: *const sysvar.Clock,
    signers: []const Pubkey,
) InstructionError!void {
    const data = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);
    const stake_state = if (data == .stake) data.stake else return error.InvalidAccountData;

    try stake_state.meta.authorized.check(signers, .staker);

    var stake = stake_state.stake;
    if (stake.deactivate(clock.epoch)) |stake_err| {
        ic.tc.custom_error = @intFromEnum(stake_err);
        return error.Custom;
    }
    try stake_account.serializeIntoAccountData(StakeStateV2{
        .stake = .{
            .meta = stake_state.meta,
            .stake = stake,
            .flags = stake_state.flags,
        },
    });
}

fn deactivateDelinquent(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    stake_account: *BorrowedAccount,
    delinquent_vote_account_index: u16,
    reference_vote_account_index: u16,
    current_epoch: Epoch,
) (error{OutOfMemory} || InstructionError)!void {
    const delinquent_vote_account_meta = ic.ixn_info.getAccountMetaAtIndex(
        delinquent_vote_account_index,
    ) orelse return error.MissingAccount;

    const delinquent_vote_account = try ic.borrowInstructionAccount(delinquent_vote_account_index);
    defer delinquent_vote_account.release();
    if (!delinquent_vote_account.account.owner.equals(&runtime.program.vote.ID))
        return error.IncorrectProgramId;

    var delinquent_vote_state_raw = try delinquent_vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    defer delinquent_vote_state_raw.deinit(allocator);

    var delinquent_vote_state = try delinquent_vote_state_raw.convertToVoteState(allocator, null, false);
    defer delinquent_vote_state.deinit(allocator);

    const reference_vote_account = try ic.borrowInstructionAccount(reference_vote_account_index);
    defer reference_vote_account.release();
    if (!reference_vote_account.account.owner.equals(&runtime.program.vote.ID))
        return error.IncorrectProgramId;

    var reference_vote_state_raw = try reference_vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    defer reference_vote_state_raw.deinit(allocator);

    var reference_vote_state = try reference_vote_state_raw.convertToVoteState(allocator, null, false);
    defer reference_vote_state.deinit(allocator);

    if (!acceptableReferenceEpochCredits(reference_vote_state.epochCreditsList().items, current_epoch)) {
        ic.tc.custom_error = @intFromEnum(StakeError.insufficient_reference_votes);
        return error.Custom;
    }

    const stake_account_state = try stake_account.deserializeFromAccountData(
        allocator,
        StakeStateV2,
    );

    if (stake_account_state != .stake) return error.InvalidAccountData;

    var stake = stake_account_state.stake.stake;
    const meta = stake_account_state.stake.meta;
    const stake_flags = stake_account_state.stake.flags;

    if (!stake.delegation.voter_pubkey.equals(&delinquent_vote_account_meta.pubkey)) {
        ic.tc.custom_error = @intFromEnum(StakeError.vote_address_mismatch);
        return error.Custom;
    }

    if (!eligibleForAccountDelinquent(delinquent_vote_state.epochCreditsList().items, current_epoch)) {
        ic.tc.custom_error = @intFromEnum(
            StakeError.minimum_delinquent_epochs_for_deactivation_not_met,
        );
        return error.Custom;
    }

    if (stake.deactivate(current_epoch)) |err| {
        ic.tc.custom_error = @intFromEnum(err);
        return error.Custom;
    }
    try stake_account.serializeIntoAccountData(StakeStateV2{
        .stake = .{
            .meta = meta,
            .stake = stake,
            .flags = stake_flags,
        },
    });
}

fn acceptableReferenceEpochCredits(
    epoch_credits: []const runtime.program.vote.state.EpochCredit,
    current_epoch: Epoch,
) bool {
    const epoch_index = std.math.sub(
        usize,
        epoch_credits.len,
        MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION,
    ) catch return false;

    var epoch = current_epoch;

    const slice = epoch_credits[epoch_index..];
    for (0..slice.len) |i| {
        const vote_epoch = slice[slice.len - i - 1].epoch;
        if (vote_epoch != epoch) return false;
        epoch -|= 1;
    }

    return true;
}

fn setLockup(
    allocator: std.mem.Allocator,
    stake_account: *BorrowedAccount,
    lockup: *const instruction.LockupArgs,
    signers: []const Pubkey,
    clock: *const sysvar.Clock,
) InstructionError!void {
    const stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);

    switch (stake_state) {
        .initialized => |arg| {
            var meta = arg;
            try meta.setLockup(lockup, signers, clock);
            try stake_account.serializeIntoAccountData(StakeStateV2{ .initialized = meta });
        },
        .stake => |args| {
            var meta = args.meta;
            try meta.setLockup(lockup, signers, clock);
            try stake_account.serializeIntoAccountData(StakeStateV2{
                .stake = .{
                    .meta = meta,
                    .stake = args.stake,
                    .flags = args.flags,
                },
            });
        },
        else => return error.InvalidAccountData,
    }
}

fn eligibleForAccountDelinquent(
    epoch_credits: []const runtime.program.vote.state.EpochCredit,
    current_epoch: Epoch,
) bool {
    if (epoch_credits.len == 0) return true;

    const last = epoch_credits[epoch_credits.len - 1];

    const minimum_epoch = std.math.sub(
        u64,
        current_epoch,
        MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION,
    ) catch return false;

    return last.epoch <= minimum_epoch;
}

fn moveStake(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    source_account_index: u16,
    lamports: u64,
    destination_account_index: u16,
    stake_authority_index: u16,
) (error{OutOfMemory} || InstructionError)!void {
    var source_account = try ic.borrowInstructionAccount(source_account_index);
    defer source_account.release();

    var destination_account = try ic.borrowInstructionAccount(destination_account_index);
    defer destination_account.release();

    const source_merge_kind, const destination_merge_kind = try moveStakeOrLamportsSharedChecks(
        allocator,
        ic,
        &source_account,
        lamports,
        &destination_account,
        stake_authority_index,
    );

    if (source_account.account.data.len != StakeStateV2.SIZE or
        destination_account.account.data.len != StakeStateV2.SIZE)
        return error.InvalidAccountData;

    if (source_merge_kind != .fully_active) return error.InvalidAccountData;
    var source_stake = source_merge_kind.fully_active.@"1";
    const source_meta = source_merge_kind.fully_active.@"0";

    const min_delegation = getMinimumDelegation(ic.tc.slot, ic.tc.feature_set);
    const source_effective_stake = source_stake.delegation.stake;

    const source_final_stake = std.math.sub(u64, source_effective_stake, lamports) catch
        return error.InvalidArgument;

    if (source_final_stake != 0 and source_final_stake < min_delegation)
        return error.InvalidArgument;

    const destination_meta = switch (destination_merge_kind) {
        .fully_active => |args| blk: {
            const destination_meta = args.@"0";
            var destination_stake = args.@"1";

            if (!source_stake.delegation.voter_pubkey.equals(
                &destination_stake.delegation.voter_pubkey,
            )) {
                ic.tc.custom_error = @intFromEnum(StakeError.vote_address_mismatch);
                return error.Custom;
            }

            const destination_effective_stake = destination_stake.delegation.stake;
            const destination_final_stake = std.math.add(
                u64,
                destination_effective_stake,
                lamports,
            ) catch return error.ProgramArithmeticOverflow;

            if (destination_final_stake < min_delegation) return error.InvalidArgument;

            try mergeDelegationStakeAndCreditsObserbed(
                &destination_stake,
                lamports,
                source_stake.credits_observed,
            );

            try destination_account.serializeIntoAccountData(StakeStateV2{
                .stake = .{
                    .flags = .EMPTY,
                    .meta = destination_meta,
                    .stake = destination_stake,
                },
            });

            break :blk destination_meta;
        },
        .inactive => |args| blk: {
            const destination_meta = args.@"0";
            if (lamports < min_delegation) return error.InvalidArgument;

            var destination_stake = source_stake;
            destination_stake.delegation.stake = lamports;

            try destination_account.serializeIntoAccountData(StakeStateV2{
                .stake = .{
                    .flags = .EMPTY,
                    .meta = destination_meta,
                    .stake = destination_stake,
                },
            });

            break :blk destination_meta;
        },
        else => return error.InvalidAccountData,
    };

    if (source_final_stake == 0) {
        try source_account.serializeIntoAccountData(StakeStateV2{ .initialized = source_meta });
    } else {
        source_stake.delegation.stake = source_final_stake;

        try source_account.serializeIntoAccountData(StakeStateV2{
            .stake = .{
                .meta = source_meta,
                .stake = source_stake,
                .flags = .EMPTY,
            },
        });
    }

    try source_account.subtractLamports(lamports);
    try destination_account.addLamports(lamports);

    if (source_account.account.lamports < source_meta.rent_exempt_reserve or
        destination_account.account.lamports < destination_meta.rent_exempt_reserve)
    {
        try ic.tc.log("Delegation calculations violated lamport balance assumptions", .{});
        return error.InvalidArgument;
    }
}

// Intentionally mispelled Obserbed to not conflict with the one in MergeKind
fn mergeDelegationStakeAndCreditsObserbed(
    stake: *StakeStateV2.Stake,
    absorbed_lamports: u64,
    absorbed_credits_observed: u64,
) InstructionError!void {
    stake.credits_observed = stakeWeightedCreditsObserved(
        stake,
        absorbed_lamports,
        absorbed_credits_observed,
    ) orelse return error.ProgramArithmeticOverflow;

    stake.delegation.stake = std.math.add(u64, stake.delegation.stake, absorbed_lamports) catch
        return error.InsufficientFunds;
}

fn moveStakeOrLamportsSharedChecks(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    source_account: *const BorrowedAccount,
    lamports: u64,
    destination_account: *const BorrowedAccount,
    stake_authority_index: u16,
) (error{OutOfMemory} || InstructionError)!struct { MergeKind, MergeKind } {
    const stake_authority_meta = ic.ixn_info.getAccountMetaAtIndex(stake_authority_index) orelse
        return error.MissingAccount;

    if (!stake_authority_meta.is_signer) return error.MissingRequiredSignature;
    const signers: []const Pubkey = &.{stake_authority_meta.pubkey};

    if (!source_account.account.owner.equals(&ID) or !destination_account.account.owner.equals(&ID))
        return error.IncorrectProgramId;

    if (source_account.pubkey.equals(&destination_account.pubkey))
        return error.InvalidInstructionData;

    if (!source_account.context.is_writable or !destination_account.context.is_writable)
        return error.InvalidInstructionData;

    if (lamports == 0) return error.InvalidArgument;

    const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);
    const stake_history = try ic.tc.sysvar_cache.get(sysvar.StakeHistory);

    const source_account_state = try source_account.deserializeFromAccountData(
        allocator,
        StakeStateV2,
    );

    const source_merge_kind = try MergeKind.getIfMergeable(
        ic,
        &source_account_state,
        source_account.account.lamports,
        &clock,
        &stake_history,
    );
    try source_merge_kind.meta().authorized.check(signers, .staker);

    const destination_account_state = try destination_account.deserializeFromAccountData(
        allocator,
        StakeStateV2,
    );

    const destination_merge_kind = try MergeKind.getIfMergeable(
        ic,
        &destination_account_state,
        destination_account.account.lamports,
        &clock,
        &stake_history,
    );

    try MergeKind.metasCanMerge(
        ic,
        &source_merge_kind.meta(),
        &destination_merge_kind.meta(),
        &clock,
    );

    return .{ source_merge_kind, destination_merge_kind };
}

fn moveLamports(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    source_account_index: u16,
    lamports: u64,
    destination_account_index: u16,
    stake_authority_index: u16,
) (error{OutOfMemory} || InstructionError)!void {
    var source_account = try ic.borrowInstructionAccount(source_account_index);
    defer source_account.release();

    var destination_account = try ic.borrowInstructionAccount(destination_account_index);
    defer destination_account.release();

    const source_merge_kind, _ = try moveStakeOrLamportsSharedChecks(
        allocator,
        ic,
        &source_account,
        lamports,
        &destination_account,
        stake_authority_index,
    );

    const source_free_lamports = switch (source_merge_kind) {
        .fully_active => |args| blk: {
            const source_meta = args.@"0";
            const source_stake = args.@"1";

            break :blk source_account.account.lamports -|
                source_stake.delegation.stake -|
                source_meta.rent_exempt_reserve;
        },
        .inactive => |args| args.@"1" -| args.@"0".rent_exempt_reserve,

        else => return error.InvalidAccountData,
    };

    if (lamports > source_free_lamports) return error.InvalidArgument;

    try source_account.subtractLamports(lamports);
    try destination_account.addLamports(lamports);
}

test "stake.initialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const sysvar_cache_without_slot_hashes = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = undefined,
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
    };

    {
        var sysvar_cache = sysvar_cache_without_slot_hashes;
        sysvar_cache.slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }});

        const accounts: []const ExecuteContextsParams.AccountParams = &.{
            .{ .pubkey = Pubkey.initRandom(random), .owner = ID },
            .{ .pubkey = sysvar.Rent.ID },
            .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
        };

        try runtime.program.testing.expectProgramExecuteError(
            error.InvalidAccountData,
            allocator,
            ID,
            Instruction{ .initialize = .{ Authorized.DEFAULT, Lockup.DEFAULT } },
            &.{
                .{ .index_in_transaction = 0 },
                .{ .index_in_transaction = 1 },
                .{ .index_in_transaction = 2 },
            },
            .{ .accounts = accounts, .compute_meter = 10_000, .sysvar_cache = sysvar_cache },
            .{},
        );
    }

    // success
    {
        var sysvar_cache = sysvar_cache_without_slot_hashes;
        sysvar_cache.slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }});

        var buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&buf, StakeStateV2.uninitialized, .{});

        var buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&buf_after, StakeStateV2{
            .initialized = .{
                .authorized = .DEFAULT,
                .lockup = .DEFAULT,
                .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
            },
        }, .{});

        const initial_accounts: []const ExecuteContextsParams.AccountParams = &.{
            .{
                .pubkey = Pubkey.initRandom(random),
                .owner = ID,
                .data = &buf,
                .lamports = 1_000_000_000,
            },
            .{ .pubkey = sysvar.Rent.ID },
            .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
        };

        const after_accounts: []const ExecuteContextsParams.AccountParams = &.{
            .{
                .pubkey = initial_accounts[0].pubkey,
                .owner = ID,
                .data = &buf_after,
                .lamports = 1_000_000_000,
            },
            .{ .pubkey = sysvar.Rent.ID },
            .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
        };

        try runtime.program.testing.expectProgramExecuteResult(
            allocator,
            ID,
            Instruction{ .initialize = .{ Authorized.DEFAULT, Lockup.DEFAULT } },
            &.{
                .{ .index_in_transaction = 0, .is_writable = true },
                .{ .index_in_transaction = 1 },
                .{ .index_in_transaction = 2 },
            },
            .{
                .accounts = initial_accounts,
                .compute_meter = 10_000,
                .sysvar_cache = sysvar_cache,
            },
            .{
                .accounts = after_accounts,
                .compute_meter = 10_000 - COMPUTE_UNITS,
                .sysvar_cache = sysvar_cache,
            },
            .{},
        );
    }
}

test "stake.authorize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = .INIT,
        .slot_hashes = runtime.sysvar.SlotHashes.initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = .INIT,
        .epoch_rewards = .INIT,
    };

    const old_staker_auth = Pubkey.initRandom(prng.random());
    const new_staker_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = old_staker_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = new_staker_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{
            .authorize = .{ new_staker_auth, .staker },
        },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2, .is_signer = true },
            .{ .index_in_transaction = 3, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = new_staker_auth },
                .{ .pubkey = old_staker_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = new_staker_auth },
                .{ .pubkey = old_staker_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.delegate_stake" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const staker_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());
    const vote_account = Pubkey.initRandom(prng.random());

    var vote_buf: [@sizeOf(VoteStateVersions)]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(
        &vote_buf,
        VoteStateVersions{ .v3 = .DEFAULT },
        .{},
    );

    for ([_]bool{ false, true }) |use_stake| {
        var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
            .clock = runtime.sysvar.Clock.INIT,
            .slot_hashes = .initWithEntries(&.{.{
                .slot = std.math.maxInt(Slot),
                .hash = sig.core.Hash.ZEROES,
            }}),
            .rent = runtime.sysvar.Rent.INIT,
            .stake_history = .INIT,
            .epoch_rewards = .INIT,
            .epoch_schedule = .INIT,
        };

        const stake_lamports = 1_000_000_000;
        const stake_rent = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE);

        const stake: @TypeOf(@as(StakeStateV2, undefined).stake) = .{
            .meta = .{
                .authorized = .{
                    .staker = staker_auth,
                    .withdrawer = Pubkey.ZEROES,
                },
                .lockup = .DEFAULT,
                .rent_exempt_reserve = stake_rent,
            },
            .stake = .{
                .credits_observed = 0,
                .delegation = .{
                    .activation_epoch = 0,
                    .deactivation_epoch = std.math.maxInt(u64),
                    .stake = 0,
                    .voter_pubkey = Pubkey.ZEROES,
                },
            },
            .flags = .EMPTY,
        };

        var buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(
            &buf,
            if (use_stake)
                StakeStateV2{ .stake = stake }
            else
                StakeStateV2{ .initialized = stake.meta },
            .{},
        );

        var buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&buf_after, StakeStateV2{
            .stake = .{
                .flags = .EMPTY,
                .meta = .{
                    .authorized = .{
                        .staker = staker_auth,
                        .withdrawer = Pubkey.ZEROES,
                    },
                    .lockup = .DEFAULT,
                    .rent_exempt_reserve = stake_rent,
                },
                .stake = .{
                    .credits_observed = VoteStateV4.DEFAULT.getCredits(),
                    .delegation = .{
                        .voter_pubkey = vote_account,
                        .stake = stake_lamports -| stake_rent,
                        .activation_epoch = sysvar_cache.clock.?.epoch,
                    },
                },
            },
        }, .{});

        try runtime.program.testing.expectProgramExecuteResult(
            allocator,
            ID,
            Instruction{ .delegate_stake = {} },
            &.{
                .{ .index_in_transaction = 0, .is_writable = true },
                .{ .index_in_transaction = 1 },
                .{ .index_in_transaction = 2 },
                .{ .index_in_transaction = 3 },
                .{ .index_in_transaction = 0 }, // unused account
                .{ .index_in_transaction = 4, .is_signer = true }, // stake auth
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &buf,
                        .lamports = stake_lamports,
                    },
                    .{
                        .pubkey = vote_account,
                        .owner = sig.runtime.program.vote.ID,
                        .data = &vote_buf,
                        .lamports = 1_000_000_000,
                    },
                    .{ .pubkey = sysvar.Clock.ID },
                    .{ .pubkey = sysvar.StakeHistory.ID },
                    .{ .pubkey = staker_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000,
                .sysvar_cache = sysvar_cache,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &buf_after,
                        .lamports = stake_lamports,
                    },
                    .{
                        .pubkey = vote_account,
                        .owner = sig.runtime.program.vote.ID,
                        .data = &vote_buf,
                        .lamports = 1_000_000_000,
                    },
                    .{ .pubkey = sysvar.Clock.ID },
                    .{ .pubkey = sysvar.StakeHistory.ID },
                    .{ .pubkey = staker_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000 - COMPUTE_UNITS,
                .sysvar_cache = sysvar_cache,
            },
            .{},
        );
    }
}

test "stake.split" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const stake_lamports = 1_000_000_000;
    const split_lamports = 1_000_000_000;
    const stake_rent = sysvar.Rent.INIT.minimumBalance(StakeStateV2.SIZE);
    const to_split = stake_lamports; // split all to test empty case

    const staker_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());
    const split_account = Pubkey.initRandom(prng.random());

    var stake: @TypeOf(@as(StakeStateV2, undefined).stake) = .{
        .meta = .{
            .authorized = .{
                .staker = staker_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = stake_rent,
        },
        .stake = .{
            .credits_observed = 0,
            .delegation = .{
                .activation_epoch = 0,
                .deactivation_epoch = std.math.maxInt(u64),
                .stake = 0,
                .voter_pubkey = staker_auth,
            },
        },
        .flags = .EMPTY,
    };

    for ([_]bool{ false, true }) |use_stake| {
        const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
            .clock = runtime.sysvar.Clock.INIT,
            .slot_hashes = .initWithEntries(&.{.{
                .slot = std.math.maxInt(Slot),
                .hash = sig.core.Hash.ZEROES,
            }}),
            .stake_history = .INIT,
            .rent = runtime.sysvar.Rent.INIT,
            .epoch_rewards = .INIT,
            .epoch_schedule = .INIT,
        };

        stake.stake.delegation.stake = stake_lamports;

        var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(
            &stake_buf,
            if (use_stake)
                StakeStateV2{ .stake = stake }
            else
                StakeStateV2{ .initialized = stake.meta },
            .{},
        );

        var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf; // must be copy from original
        // emulate extra write with modified delegation.stake
        if (use_stake) {
            stake.stake.delegation.stake = stake_rent;
            _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{ .stake = stake }, .{});
        }
        // before then writing uninitialized
        _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{ .uninitialized = {} }, .{});

        var split_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&split_buf, StakeStateV2{ .uninitialized = {} }, .{});

        stake.stake.delegation.stake = stake_lamports - stake_rent;

        var split_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(
            &split_buf_after,
            if (use_stake)
                StakeStateV2{ .stake = stake }
            else
                StakeStateV2{ .initialized = stake.meta },
            .{},
        );

        try runtime.program.testing.expectProgramExecuteResult(
            allocator,
            ID,
            Instruction{ .split = to_split },
            &.{
                .{ .index_in_transaction = 0, .is_writable = true },
                .{ .index_in_transaction = 1, .is_writable = true },
                .{ .index_in_transaction = 2, .is_signer = true },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &stake_buf,
                        .lamports = stake_lamports,
                    },
                    .{
                        .pubkey = split_account,
                        .owner = ID,
                        .data = &split_buf,
                        .lamports = split_lamports,
                    },
                    .{ .pubkey = staker_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000,
                .sysvar_cache = sysvar_cache,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &stake_buf_after,
                        .lamports = stake_lamports - to_split,
                    },
                    .{
                        .pubkey = split_account,
                        .owner = ID,
                        .data = &split_buf_after,
                        .lamports = split_lamports + to_split,
                    },
                    .{ .pubkey = staker_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000 - COMPUTE_UNITS,
                .sysvar_cache = sysvar_cache,
            },
            .{},
        );
    }
}

test "stake.withdraw" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .stake_history = .INIT,
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
        .epoch_schedule = .initRandom(prng.random()),
    };

    const stake_lamports = 1_000_000_000;
    const withdrawer_lamports = 1_000;
    const to_withdraw = 100_000;
    const stake_rent = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE);

    const withdrawer_account = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = withdrawer_account,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = stake_rent,
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .withdraw = to_withdraw },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_writable = true },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3 },
            .{ .index_in_transaction = 1, .is_signer = true }, // withdraw_auth
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = stake_lamports,
                },
                .{
                    .pubkey = withdrawer_account,
                    .lamports = withdrawer_lamports,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = sysvar.StakeHistory.ID },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = stake_lamports - to_withdraw,
                },
                .{
                    .pubkey = withdrawer_account,
                    .lamports = withdrawer_lamports + to_withdraw,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = sysvar.StakeHistory.ID },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.deactivate" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .rent = runtime.sysvar.Rent.INIT,
    };

    const stake_account = Pubkey.initRandom(prng.random());
    const stake_auth = Pubkey.initRandom(prng.random());
    const voter_pubkey = Pubkey.initRandom(prng.random());

    const stake_state = StakeStateV2{
        .stake = .{
            .meta = .{
                .authorized = .{
                    .staker = stake_auth,
                    .withdrawer = Pubkey.ZEROES,
                },
                .lockup = .DEFAULT,
                .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
            },
            .stake = .{
                .credits_observed = 0,
                .delegation = .{
                    .activation_epoch = 0,
                    .deactivation_epoch = std.math.maxInt(u64),
                    .stake = 0,
                    .voter_pubkey = voter_pubkey,
                },
            },
            .flags = .EMPTY,
        },
    };

    var deactivated_stake_state = stake_state;
    try std.testing.expectEqual(
        deactivated_stake_state.stake.stake.deactivate(sysvar_cache.clock.?.epoch),
        null,
    );

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, stake_state, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf; // must be copy
    _ = try sig.bincode.writeToSlice(&stake_buf_after, deactivated_stake_state, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .deactivate = {} },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = stake_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = stake_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.set_lockup" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .rent = runtime.sysvar.Rent.INIT,
    };

    const withdraw_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    const old_lockup: Lockup = .{
        .custodian = Pubkey.initRandom(prng.random()),
        .epoch = sysvar_cache.clock.?.epoch + 42,
        .unix_timestamp = sysvar_cache.clock.?.epoch_start_timestamp + 1000,
    };
    const new_lockup: Lockup = .{
        .custodian = Pubkey.initRandom(prng.random()),
        .epoch = sysvar_cache.clock.?.epoch + 42,
        .unix_timestamp = sysvar_cache.clock.?.epoch_start_timestamp + 1000,
    };

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = withdraw_auth,
            },
            .lockup = old_lockup,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = withdraw_auth,
            },
            .lockup = new_lockup,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .set_lockup = .{
            .custodian = new_lockup.custodian,
            .epoch = new_lockup.epoch,
            .unix_timestamp = new_lockup.unix_timestamp,
        } },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = true }, // lockup/withdraw auth
            .{ .index_in_transaction = 2, .is_signer = true }, // old custodoian
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = old_lockup.custodian },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = old_lockup.custodian },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.merge" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const stake_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());
    const source_account = Pubkey.initRandom(prng.random());

    const source_lamports = 10_000;
    const stake_lamports = 1_000_000_000;
    const stake_rent = sysvar.Rent.INIT.minimumBalance(StakeStateV2.SIZE);

    const stake_credits = 5;
    const source_credits = 10;

    const stake_state = StakeStateV2{
        .stake = .{
            .flags = .EMPTY,
            .meta = .{
                .authorized = .{
                    .staker = stake_auth,
                    .withdrawer = stake_auth,
                },
                .lockup = .DEFAULT,
                .rent_exempt_reserve = stake_rent,
            },
            .stake = .{
                .credits_observed = stake_credits,
                .delegation = .{
                    .activation_epoch = 0,
                    .deactivation_epoch = std.math.maxInt(Epoch),
                    .stake = 10_000,
                    .voter_pubkey = stake_auth,
                },
            },
        },
    };

    for ([_]bool{ false, true }) |use_stake| {
        const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
            .clock = runtime.sysvar.Clock.INIT,
            .slot_hashes = .initWithEntries(&.{.{
                .slot = std.math.maxInt(Slot),
                .hash = sig.core.Hash.ZEROES,
            }}),
            .stake_history = .INIT,
            .rent = runtime.sysvar.Rent.INIT,
            .epoch_rewards = .INIT,
            .epoch_schedule = .initRandom(prng.random()),
        };

        var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&stake_buf, stake_state, .{});

        var new_stake_state = stake_state;
        new_stake_state.stake.stake.delegation.stake = 20_000 + (if (use_stake) stake_rent else 0);
        new_stake_state.stake.stake.credits_observed =
            if (use_stake) source_credits else stake_credits;

        var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf;
        _ = try sig.bincode.writeToSlice(&stake_buf_after, new_stake_state, .{});

        var source_state = stake_state;
        source_state.stake.stake.credits_observed = source_credits;

        var source_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(
            &source_buf,
            if (use_stake) source_state else StakeStateV2{ .initialized = stake_state.stake.meta },
            .{},
        );

        var source_buf_after: [StakeStateV2.SIZE]u8 = source_buf; // must be copy
        _ = try sig.bincode.writeToSlice(
            &source_buf_after,
            StakeStateV2{ .uninitialized = {} },
            .{},
        );

        try runtime.program.testing.expectProgramExecuteResult(
            allocator,
            ID,
            Instruction{ .merge = {} },
            &.{
                .{ .index_in_transaction = 0, .is_writable = true },
                .{ .index_in_transaction = 1, .is_writable = true },
                .{ .index_in_transaction = 2 },
                .{ .index_in_transaction = 3 },
                .{ .index_in_transaction = 4, .is_signer = true },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &stake_buf,
                        .lamports = stake_lamports,
                    },
                    .{
                        .pubkey = source_account,
                        .owner = ID,
                        .data = &source_buf,
                        .lamports = source_lamports,
                    },
                    .{ .pubkey = sysvar.Clock.ID },
                    .{ .pubkey = sysvar.StakeHistory.ID },
                    .{ .pubkey = stake_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000,
                .sysvar_cache = sysvar_cache,
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = stake_account,
                        .owner = ID,
                        .data = &stake_buf_after,
                        .lamports = stake_lamports + source_lamports,
                    },
                    .{
                        .pubkey = source_account,
                        .owner = ID,
                        .data = &source_buf_after,
                        .lamports = 0,
                    },
                    .{ .pubkey = sysvar.Clock.ID },
                    .{ .pubkey = sysvar.StakeHistory.ID },
                    .{ .pubkey = stake_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000 - COMPUTE_UNITS,
                .sysvar_cache = sysvar_cache,
            },
            .{},
        );
    }
}

test "stake.authorize_with_seed" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
    };

    const auth_owner = Pubkey.initRandom(prng.random());
    const auth_base = Pubkey.initRandom(prng.random());
    const auth_seed = "hello world";

    const old_withdrawer = try sig.runtime.pubkey_utils.createWithSeed(
        auth_base,
        auth_seed,
        auth_owner,
    );
    const new_withdrawer = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = old_withdrawer,
            },
            .lockup = .{
                .custodian = old_withdrawer,
                .unix_timestamp = sysvar_cache.clock.?.unix_timestamp + 1,
                .epoch = sysvar_cache.clock.?.epoch,
            },
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf;
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = new_withdrawer,
            },
            .lockup = .{
                .custodian = old_withdrawer,
                .unix_timestamp = sysvar_cache.clock.?.unix_timestamp + 1,
                .epoch = sysvar_cache.clock.?.epoch,
            },
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .authorize_with_seed = .{
            .new_authorized_pubkey = new_withdrawer,
            .stake_authorize = .withdrawer,
            .authority_owner = auth_owner,
            .authority_seed = auth_seed,
        } },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = true },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = auth_base },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = old_withdrawer },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = auth_base },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = old_withdrawer },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.initialize_checked" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .rent = runtime.sysvar.Rent.INIT,
    };

    const stake_account = Pubkey.initRandom(prng.random());
    const stake_auth = Pubkey.initRandom(prng.random());
    const withdraw_auth = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{ .uninitialized = {} }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = stake_auth,
                .withdrawer = withdraw_auth,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .initialize_checked = {} },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = stake_auth },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Rent.ID },
                .{ .pubkey = stake_auth },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.authorize_checked" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
    };

    const old_staker_auth = Pubkey.initRandom(prng.random());
    const new_staker_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = old_staker_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = new_staker_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .authorize_checked = .staker },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2, .is_signer = true },
            .{ .index_in_transaction = 3, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = old_staker_auth },
                .{ .pubkey = new_staker_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = old_staker_auth },
                .{ .pubkey = new_staker_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.authorize_checked_with_seed" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
    };

    const auth_owner = Pubkey.initRandom(prng.random());
    const auth_base = Pubkey.initRandom(prng.random());
    const auth_seed = "hello world";

    const old_withdrawer = try sig.runtime.pubkey_utils.createWithSeed(
        auth_base,
        auth_seed,
        auth_owner,
    );
    const new_withdrawer = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = old_withdrawer,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf;
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = new_withdrawer,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .authorize_checked_with_seed = .{
            .stake_authorize = .withdrawer,
            .authority_owner = auth_owner,
            .authority_seed = auth_seed,
        } },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = true },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = auth_base },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = new_withdrawer },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = auth_base },
                .{ .pubkey = sysvar.Clock.ID },
                .{ .pubkey = new_withdrawer },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.set_lockup_checked" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .rent = runtime.sysvar.Rent.INIT,
    };

    const withdraw_auth = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    const new_lockup: Lockup = .{
        .custodian = Pubkey.initRandom(prng.random()),
        .epoch = sysvar_cache.clock.?.epoch + 42,
        .unix_timestamp = sysvar_cache.clock.?.epoch_start_timestamp + 1000,
    };

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = withdraw_auth,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf;
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = withdraw_auth,
            },
            .lockup = new_lockup,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .set_lockup_checked = .{
            .epoch = new_lockup.epoch,
            .unix_timestamp = new_lockup.unix_timestamp,
        } },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = true },
            .{ .index_in_transaction = 2, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = new_lockup.custodian },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{ .pubkey = withdraw_auth },
                .{ .pubkey = new_lockup.custodian },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.get_minimum_delegation" {
    const allocator = std.testing.allocator;
    const min_delegation = std.mem.nativeToLittle(u64, 1_000_000_000);

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .get_minimum_delegation = {} },
        &.{},
        .{
            .accounts = &.{
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .feature_set = &.{
                .{ .feature = .stake_raise_minimum_delegation_to_1_sol },
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .return_data = .{
                .program_id = ID,
                .data = std.mem.asBytes(&min_delegation),
            },
        },
        .{},
    );
}

test "stake.deactivate_delinquent" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = .{
            .epoch = 100,
            .epoch_start_timestamp = 100,
            .leader_schedule_epoch = 0,
            .slot = 0,
            .unix_timestamp = 100,
        },
        .rent = runtime.sysvar.Rent.INIT,
    };

    var reference_vote_state: VoteStateV3 = .DEFAULT;
    defer reference_vote_state.deinit(allocator);

    var delinquent_vote_state: VoteStateV3 = .DEFAULT;
    defer delinquent_vote_state.deinit(allocator);

    for (0..MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION) |i| {
        const epoch_offset = MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION - (i + 1);
        try reference_vote_state.epoch_credits.append(allocator, .{
            .credits = 100,
            .epoch = sysvar_cache.clock.?.epoch - epoch_offset,
            .prev_credits = 10,
        });
        try delinquent_vote_state.epoch_credits.append(allocator, .{
            .credits = 100,
            .epoch = sysvar_cache.clock.?.epoch - epoch_offset,
            .prev_credits = 10,
        });
    }

    try delinquent_vote_state.epoch_credits.append(allocator, .{
        .credits = 100,
        .epoch = sysvar_cache.clock.?.epoch - MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION,
        .prev_credits = 10,
    });

    var reference_vote_buf: [@sizeOf(VoteStateVersions)]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&reference_vote_buf, VoteStateVersions{
        .v3 = reference_vote_state,
    }, .{});

    var delinquent_vote_buf: [@sizeOf(VoteStateVersions)]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&delinquent_vote_buf, VoteStateVersions{
        .v3 = delinquent_vote_state,
    }, .{});

    const delinquent_account = Pubkey.initRandom(prng.random());
    const reference_account = Pubkey.initRandom(prng.random());
    const stake_account = Pubkey.initRandom(prng.random());

    const stake = @TypeOf(@as(StakeStateV2, undefined).stake){
        .meta = .{
            .authorized = .{
                .staker = Pubkey.ZEROES,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
        .stake = .{
            .credits_observed = 0,
            .delegation = .{
                .activation_epoch = sysvar_cache.clock.?.epoch,
                .stake = 1000,
                .voter_pubkey = delinquent_account,
            },
        },
        .flags = .EMPTY,
    };

    var stake_buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&stake_buf, StakeStateV2{
        .stake = stake,
    }, .{});

    var deactivated_stake = stake;
    try std.testing.expectEqual(
        null,
        deactivated_stake.stake.deactivate(sysvar_cache.clock.?.epoch),
    );

    var stake_buf_after: [StakeStateV2.SIZE]u8 = stake_buf;
    _ = try sig.bincode.writeToSlice(&stake_buf_after, StakeStateV2{
        .stake = deactivated_stake,
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .deactivate_delinquent = {} },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf,
                    .lamports = 1_000_000_000,
                },
                .{
                    .pubkey = delinquent_account,
                    .owner = runtime.program.vote.ID,
                    .data = &delinquent_vote_buf,
                },
                .{
                    .pubkey = reference_account,
                    .owner = runtime.program.vote.ID,
                    .data = &reference_vote_buf,
                },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = stake_account,
                    .owner = ID,
                    .data = &stake_buf_after,
                    .lamports = 1_000_000_000,
                },
                .{
                    .pubkey = delinquent_account,
                    .owner = runtime.program.vote.ID,
                    .data = &delinquent_vote_buf,
                },
                .{
                    .pubkey = reference_account,
                    .owner = runtime.program.vote.ID,
                    .data = &reference_vote_buf,
                },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}

test "stake.move_stake" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const stake_entries = [_]sysvar.StakeHistory.Entry{
        .{
            .epoch = 42,
            .stake = .{
                .activating = 100,
                .deactivating = 100,
                .effective = 100,
            },
        },
        .{
            .epoch = 41,
            .stake = .{
                .activating = 100,
                .deactivating = 100,
                .effective = 100,
            },
        },
        .{
            .epoch = 40,
            .stake = .{
                .activating = 100,
                .deactivating = 100,
                .effective = 100,
            },
        },
        .{
            .epoch = 39,
            .stake = .{
                .activating = 100,
                .deactivating = 100,
                .effective = 100,
            },
        },
    };

    for ([_]struct { num_entries: usize, active: u64, deactive: u64, maybe_error: ?anyerror }{
        // success case
        .{ .num_entries = 1, .active = 41, .deactive = std.math.maxInt(u64), .maybe_error = null },
        // failing case (full history, valid active & deactive, hits more code)
        .{ .num_entries = 4, .active = 39, .deactive = 40, .maybe_error = error.Custom },
    }) |args| {
        var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
            .clock = runtime.sysvar.Clock{
                .epoch = stake_entries[0].epoch,
                .epoch_start_timestamp = 0,
                .leader_schedule_epoch = 0,
                .unix_timestamp = 0,
                .slot = 0,
            },
            .slot_hashes = .initWithEntries(&.{.{
                .slot = std.math.maxInt(Slot),
                .hash = .ZEROES,
            }}),
            .stake_history = .initWithEntries(stake_entries[0..args.num_entries]),
            .rent = .INIT,
            .epoch_rewards = .INIT,
            .epoch_schedule = .initRandom(prng.random()),
        };

        const stake_rent = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE);
        const src_lamports = stake_rent * 100;
        const dst_lamports = stake_rent * 50;
        const to_move = stake_rent * 5;

        const dst_account = Pubkey.initRandom(prng.random());
        const src_account = Pubkey.initRandom(prng.random());
        const stake_auth = Pubkey.initRandom(prng.random());

        const stake_meta = StakeStateV2.Meta{
            .authorized = .{
                .staker = stake_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = stake_rent,
        };

        const stake = @TypeOf(@as(StakeStateV2, undefined).stake){
            .meta = stake_meta,
            .stake = .{
                .credits_observed = 0,
                .delegation = .{
                    .activation_epoch = args.active,
                    .deactivation_epoch = args.deactive,
                    .stake = to_move,
                    .voter_pubkey = stake_auth,
                },
            },
            .flags = .EMPTY,
        };

        var src_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&src_buf, StakeStateV2{
            .stake = stake,
        }, .{});

        var src_buf_after: [StakeStateV2.SIZE]u8 = src_buf;
        _ = try sig.bincode.writeToSlice(&src_buf_after, StakeStateV2{
            .initialized = stake_meta,
        }, .{});

        var dst_buf: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&dst_buf, StakeStateV2{
            .initialized = stake_meta,
        }, .{});

        var dst_buf_after: [StakeStateV2.SIZE]u8 = @splat(0);
        _ = try sig.bincode.writeToSlice(&dst_buf_after, StakeStateV2{
            .stake = stake,
        }, .{});

        const result = runtime.program.testing.expectProgramExecuteResult(
            allocator,
            ID,
            Instruction{ .move_stake = to_move },
            &.{
                .{ .index_in_transaction = 0, .is_writable = true },
                .{ .index_in_transaction = 1, .is_writable = true },
                .{ .index_in_transaction = 2, .is_signer = true },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = src_account,
                        .owner = ID,
                        .data = &src_buf,
                        .lamports = src_lamports,
                    },
                    .{
                        .pubkey = dst_account,
                        .owner = ID,
                        .data = &dst_buf,
                        .lamports = dst_lamports,
                    },
                    .{ .pubkey = stake_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000,
                .sysvar_cache = sysvar_cache,
                .feature_set = &.{
                    .{ .feature = .move_stake_and_move_lamports_ixs },
                },
            },
            .{
                .accounts = &.{
                    .{
                        .pubkey = src_account,
                        .owner = ID,
                        .data = &src_buf_after,
                        .lamports = src_lamports - to_move,
                    },
                    .{
                        .pubkey = dst_account,
                        .owner = ID,
                        .data = &dst_buf_after,
                        .lamports = dst_lamports + to_move,
                    },
                    .{ .pubkey = stake_auth },
                    .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
                },
                .compute_meter = 10_000 - COMPUTE_UNITS,
                .sysvar_cache = sysvar_cache,
            },
            .{},
        );

        if (args.maybe_error) |expected_error| {
            try std.testing.expectError(expected_error, result);
        } else {
            try result;
        }
    }
}

test "stake.move_lamports" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var sysvar_cache = ExecuteContextsParams.SysvarCacheParams{
        .clock = runtime.sysvar.Clock.INIT,
        .slot_hashes = .initWithEntries(&.{.{
            .slot = std.math.maxInt(Slot),
            .hash = sig.core.Hash.ZEROES,
        }}),
        .stake_history = .INIT,
        .rent = runtime.sysvar.Rent.INIT,
        .epoch_rewards = .INIT,
        .epoch_schedule = .initRandom(prng.random()),
    };

    const src_lamports = 1_000_000_000;
    const dst_lamports = 1_000;
    const to_move = 100_000;

    const dst_account = Pubkey.initRandom(prng.random());
    const src_account = Pubkey.initRandom(prng.random());
    const stake_auth = Pubkey.initRandom(prng.random());

    var buf: [StakeStateV2.SIZE]u8 = @splat(0);
    _ = try sig.bincode.writeToSlice(&buf, StakeStateV2{
        .initialized = .{
            .authorized = .{
                .staker = stake_auth,
                .withdrawer = Pubkey.ZEROES,
            },
            .lockup = .DEFAULT,
            .rent_exempt_reserve = sysvar_cache.rent.?.minimumBalance(StakeStateV2.SIZE),
        },
    }, .{});

    try runtime.program.testing.expectProgramExecuteResult(
        allocator,
        ID,
        Instruction{ .move_lamports = to_move },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1, .is_writable = true },
            .{ .index_in_transaction = 2, .is_signer = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = src_account,
                    .owner = ID,
                    .data = &buf,
                    .lamports = src_lamports,
                },
                .{
                    .pubkey = dst_account,
                    .owner = ID,
                    .data = &buf,
                    .lamports = dst_lamports,
                },
                .{ .pubkey = stake_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000,
            .sysvar_cache = sysvar_cache,
            .feature_set = &.{
                .{ .feature = .move_stake_and_move_lamports_ixs },
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = src_account,
                    .owner = ID,
                    .data = &buf,
                    .lamports = src_lamports - to_move,
                },
                .{
                    .pubkey = dst_account,
                    .owner = ID,
                    .data = &buf,
                    .lamports = dst_lamports + to_move,
                },
                .{ .pubkey = stake_auth },
                .{ .pubkey = ID, .owner = runtime.ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 10_000 - COMPUTE_UNITS,
            .sysvar_cache = sysvar_cache,
        },
        .{},
    );
}
