const std = @import("std");
const sig = @import("../../../sig.zig");

const state = @import("state.zig");
const instruction = @import("instruction.zig");
const program = @import("lib.zig");

const runtime = sig.runtime;
const sysvar = runtime.sysvar;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const VoteStateVersions = runtime.program.vote.state.VoteStateVersions;
const VoteState = runtime.program.vote.state.VoteState;

const Instruction = instruction.Instruction;

const InstructionContext = runtime.InstructionContext;
const BorrowedAccount = runtime.BorrowedAccount;
const TransactionContext = runtime.TransactionContext;

const StakeStateV2 = state.StakeStateV2;
const Authorized = StakeStateV2.Authorized;
const Lockup = StakeStateV2.Lockup;
const StakeAuthorize = StakeStateV2.StakeAuthorize;

const MAX_ACCOUNT_METAS = runtime.InstructionInfo.MAX_ACCOUNT_METAS;

pub const ID: Pubkey = .parse("Stake11111111111111111111111111111111111111");
pub const SOURCE_ID: Pubkey = .parse("8t3vv6v99tQA6Gp7fVdsBH66hQMaswH5qsJVqJqo8xvG");

pub const COMPUTE_UNITS = 750;

/// [agave] https://github.com/anza-xyz/agave/blob/dd15884337be94f39b7bf7c3c4ae3c92d4fad760/programs/stake/src/stake_instruction.rs#L51
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    // agave: consumed in declare_process_instruction
    try ic.tc.consumeCompute(program.COMPUTE_UNITS);

    const epoch_rewards_active = (try ic.tc.sysvar_cache.get(sysvar.EpochRewards)).active;

    const stake_instruction = try ic.ixn_info.deserializeInstruction(
        allocator,
        Instruction,
    );
    defer sig.bincode.free(allocator, stake_instruction);

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
                ic.ixn_info.getSigners().slice(),
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
                ic.ixn_info.getSigners().slice(),
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
                ic.ixn_info.getSigners().slice(),
                ic.tc.feature_set,
            );
        },
        .merge => {
            // NOTE agave gets this borrwed account and drops it, not doing anything with it?
            const clock, const stake_history = blk: {
                var me = try getStakeAccount(ic);
                defer me.release();

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
                ic.ixn_info.getSigners().slice(),
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
                if (ic.ixn_info.account_metas.len >= 6) 5 else null,
                newWarmupCooldownRateEpoch(ic),
            );
        },
        .deactivate => {
            var me = try getStakeAccount(ic);
            defer me.release();
            const clock = try ic.getSysvarWithAccountCheck(sysvar.Clock, 1);

            try deactivate(allocator, ic, &me, &clock, ic.ixn_info.getSigners().slice());
        },
        .set_lockup => |lockup| {
            var me = try getStakeAccount(ic);
            defer me.release();
            const clock = try ic.tc.sysvar_cache.get(sysvar.Clock);

            try setLockup(allocator, &me, &lockup, ic.ixn_info.getSigners().slice(), &clock);
        },
        .initialize_checked => {
            var me = try getStakeAccount(ic);
            defer me.release();

            try ic.ixn_info.checkNumberOfAccounts(4);

            const staker = ic.ixn_info.getAccountMetaAtIndex(2) orelse
                return error.NotEnoughAccountKeys;
            const withdrawer = ic.ixn_info.getAccountMetaAtIndex(3) orelse
                return error.NotEnoughAccountKeys;

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
        .authorize_checked => @panic("TODO"),
        .authorize_checked_with_seed => {},
        .set_lockup_checked => |args| {
            _ = args;
            @panic("TODO");
        },
        .get_minimum_delegation => @panic("TODO"),
        .deactivate_delinquent => @panic("TODO"),
        ._redelegate => @panic("TODO"),
        .move_stake => |lamports| {
            _ = lamports;
            @panic("TODO");
        },
        .move_lamports => |lamports| {
            _ = lamports;
            @panic("TODO");
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

    const signers = if (meta.is_signer)
        &.{
            sig.runtime.pubkey_utils.createWithSeed(
                meta.pubkey,
                authority_seed,
                authority_owner.*,
            ) catch |err| {
                ic.tc.custom_error = @intFromError(err);
                return error.Custom;
            },
        }
    else
        &.{};

    return try authorize(
        allocator,
        ic,
        stake_account,
        signers,
        new_authority,
        stake_authorize,
        clock,
        custodian,
    );
}

fn getMinimumDelegation(feature_set: *const runtime.FeatureSet) u64 {
    return if (feature_set.active.contains(runtime.features.STAKE_RAISE_MINIMUM_DELEGATION_TO_1_SOL))
        1_000_000_000
    else
        1;
}

const ValidatedDelegatedInfo = struct { stake_amount: u64 };

fn validateDelegatedAmount(
    ic: *InstructionContext,
    account: *const BorrowedAccount,
    meta: *const StakeStateV2.Meta,
    feature_set: *const runtime.FeatureSet,
) InstructionError!ValidatedDelegatedInfo {
    const stake_amount = account.account.lamports -| meta.rent_exempt_reserve;
    if (stake_amount < getMinimumDelegation(feature_set)) {
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
fn newWarmupCooldownRateEpoch(
    ic: *InstructionContext,
) ?Epoch {
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

    if (stake.delegation.effectiveStake(clock.epoch, stake_history, new_rate_activation_epoch) != 0) {
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
    feature_set: *const runtime.FeatureSet,
) (error{OutOfMemory} || InstructionError)!void {
    const vote_pubkey, const vote_state = blk: {
        const vote_account = try ic.borrowInstructionAccount(vote_account_index);
        defer vote_account.release();
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

            const current_vote_state = try (try vote_state).convertToCurrent(allocator);
            defer current_vote_state.deinit();

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
            const validated = try validateDelegatedAmount(ic, &stake_account, &args.meta, feature_set);
            const stake_amount = validated.stake_amount;

            const current_vote_state = try (try vote_state).convertToCurrent(allocator);
            defer current_vote_state.deinit();
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
) InstructionError!sysvar.StakeHistory.EntryNoEpoch {
    const stake_history = try ic.tc.sysvar_cache.get(sysvar.StakeHistory);
    return stake.delegation.stakeActivatingAndDeactivating(
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

    if (lamports > source_lamports) return error.InsufficientFunds;

    const source_minimum_balance = source_meta.rent_exempt_reserve +| additional_required_lamports;
    const source_remaining_balance = source_lamports -| lamports;
    if (source_remaining_balance < source_minimum_balance) return error.InsufficientFunds;

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
    feature_set: *const runtime.FeatureSet,
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

    var stake_state = state: {
        const stake_account = try ic.borrowInstructionAccount(stake_account_index);
        defer stake_account.release();

        const stake_state = try stake_account.deserializeFromAccountData(allocator, StakeStateV2);

        if (lamports > stake_account.account.lamports) return error.InsufficientFunds;
        break :state stake_state;
    };

    switch (stake_state) {
        .stake => |*args| {
            const minimum_delegation = getMinimumDelegation(feature_set);
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
        .initialized => |*meta| {
            try meta.authorized.check(signers, .staker);
            const validated_split_info = try validateSplitAmount(
                ic,
                stake_account_index,
                split_account_index,
                lamports,
                meta,
                0,
                false,
            );

            var split_meta = meta;
            split_meta.rent_exempt_reserve = validated_split_info.destination_rent_exempt_reserve;

            {
                var split_account = try ic.borrowInstructionAccount(stake_account_index);
                defer split_account.release();

                try split_account.serializeIntoAccountData(StakeStateV2{
                    .initialized = split_meta.*,
                });
            }
        },
        .uninitialized => {
            const account_metas = ic.ixn_info.account_metas.slice();
            if (stake_account_index <= account_metas.len) return error.NotEnoughAccountKeys;

            const stake_pubkey = &ic.ixn_info.account_metas.slice()[stake_account_index].pubkey;

            const has_signer = for (signers) |signer| {
                if (signer.equals(stake_pubkey)) break true;
            } else false;

            if (!has_signer) return error.MissingRequiredSignature;
        },
        else => return error.InvalidAccountData,
    }
}

// checked_add equivalent
fn add(a: anytype, b: anytype) ?@TypeOf(a, b) {
    const sum, const overflow = @addWithOverflow(a, b);
    if (overflow == 1) return null;
    return sum;
}

// checked_sub equivalent
fn sub(a: anytype, b: anytype) ?@TypeOf(a, b) {
    const subbed, const overflow = @subWithOverflow(a, b);
    if (overflow == 1) return null;
    return subbed;
}

// checked_mul equivalent
fn mul(a: anytype, b: anytype) ?@TypeOf(a, b) {
    const product, const overflow = @mulWithOverflow(a, b);
    if (overflow == 1) return null;
    return product;
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
                const status = args.stake.delegation.stakeActivatingAndDeactivating(
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
                try ic.tc.log("{}", .{err});
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

    fn stakeWeightedCreditsObserved(
        stake: *const StakeStateV2.Stake,
        absorbed_lamports: u64,
        absorbed_credits_observed: u64,
    ) ?u64 {
        if (stake.credits_observed == absorbed_credits_observed) return stake.credits_observed;

        const total_stake = add(@as(u128, stake.delegation.stake), absorbed_lamports) orelse
            return null;

        const stake_weighted_credits = add(
            @as(u128, stake.credits_observed),
            stake.delegation.stake,
        ) orelse return null;

        const absorbed_weighted_credits = mul(
            @as(u128, absorbed_credits_observed),
            absorbed_lamports,
        ) orelse return null;

        // porting this checked_{add,sub,mul,div} heavy code is annoying.
        var total_weighted_credits = stake_weighted_credits;
        total_weighted_credits = add(total_weighted_credits, absorbed_weighted_credits) orelse
            return null;
        total_weighted_credits = add(total_weighted_credits, total_stake) orelse
            return null;
        total_weighted_credits = sub(total_weighted_credits, 1) orelse
            return null;

        if (total_stake == 0) return null;

        return std.math.cast(u64, total_weighted_credits / total_stake) orelse return null;
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

        {
            const self_stake = self.activeStake() orelse return null;
            const source_stake = source.activeStake() orelse return null;
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

            stake.delegation.stake = add(stake.delegation.stake, source_lamports) orelse
                return error.InsufficientFunds;

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

            const source_lamports = add(
                source_meta.rent_exempt_reserve,
                source_stake.delegation.stake,
            ) orelse return error.InsufficientFunds;

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
    if (stake_account_index == source_account_index) return error.InvalidArgument;

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

    try source_account.serializeIntoAccountData(StakeStateV2.initialized);

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
        return error.NotEnoughAccountKeys;

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
                    args.stake.delegation.effectiveStake(
                        clock.epoch,
                        stake_history,
                        new_rate_activation_epoch,
                    )
                else
                    args.stake.delegation.stake;

                const staked_and_reserve = add(staked, args.meta.rent_exempt_reserve) orelse
                    return error.InsufficientFunds;

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
                return error.NotEnoughAccountKeys;
            if (!meta.is_signer) break :key null;

            break :key &meta.pubkey;
        } else null;

        if (lockup.isInForce(clock, custodian_pubkey)) {
            ic.tc.custom_error = @intFromEnum(StakeError.lockup_in_force);
            return error.Custom;
        }

        const lamports_and_reserve: u64 = add(lamports, reserve) orelse
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
