const std = @import("std");
const sig = @import("../../../sig.zig");

const state = @import("state.zig");
const instruction = @import("instruction.zig");
const program = @import("lib.zig");
const runtime = sig.runtime;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const Instruction = instruction.Instruction;

const InstructionContext = runtime.InstructionContext;
const EpochRewards = runtime.sysvar.EpochRewards;
const BorrowedAccount = runtime.BorrowedAccount;

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

    const epoch_rewards_active = (try ic.tc.sysvar_cache.get(EpochRewards)).active;

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
            const me = try getStakeAccount(ic);
            _ = args;
            _ = me;
        },
        .authorize => |args| {
            _ = args;
        },
        .authorize_with_seed => |args| {
            _ = args;
        },
        .delegate_stake => @panic("TODO"),
        .split => |lamports| {
            _ = lamports;
            @panic("TODO");
        },
        .merge => @panic("TODO"),
        .withdraw => |lamports| {
            _ = lamports;
            @panic("TODO");
        },
        .deactivate => @panic("TODO"),
        .set_lockup => |args| {
            _ = args;
            @panic("TODO");
        },
        .initialize_checked => @panic("TODO"),
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
