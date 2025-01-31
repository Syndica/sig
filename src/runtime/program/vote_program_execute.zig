const std = @import("std");
const sig = @import("../../sig.zig");

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const BorrowedAccount = sig.runtime.BorrowedAccount;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const FeatureSet = sig.runtime.FeatureSet;

const Clock = sig.runtime.sysvar.Clock;
const Rent = sig.runtime.sysvar.Rent;

const VoteAuthorize = sig.runtime.program.vote_program.VoteAuthorize;
const VoteInit = sig.runtime.program.vote_program.VoteInit;
const VoteError = sig.runtime.program.vote_program.VoteProgramError;
const VoteProgramInstruction = sig.runtime.program.vote_program.VoteProgramInstruction;

// TODO: Handle allocator errors with .Custom and return InstructionError

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L57
pub fn executeVoteProgramInstruction(allocator: std.mem.Allocator, eic: *ExecuteInstructionContext) !void {
    // Default compute units for the vote program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L55
    try eic.etc.consumeCompute(2_100);

    // Borrow the first instruction account and check that the owner is the vote program
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L64-L67
    const account = try eic.getBorrowedAccount(0);
    if (account.getOwner().equals(sig.runtime.ids.VOTE_PROGRAM_ID))
        return InstructionError.InvalidAccountOwner;

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L70
    const instruction = try sig.bincode.readFromSlice(
        allocator,
        VoteProgramInstruction,
        eic.instruction_data,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    switch (instruction) {
        .initialize_account => |arg| executeInitializeAccount(eic, account, arg),
        .authorize => |args| executeAuthorize(eic, args.voter_pubkey, args.vote_authorize),
        else => @panic("Instruction not implemented"),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L71-84
pub fn executeInitializeAccount(eic: *ExecuteInstructionContext, account: BorrowedAccount, vote_init: VoteInit) !void {
    const rent = try eic.getSysvarWithAccountCheck(Rent, 1);
    if (!rent.isExempt(account.getLamports(), account.getData().len))
        return InstructionError.InsufficientFunds;

    const clock = try eic.getSysvarWithAccountCheck(Clock, 2);

    try initializeAccount(
        account,
        vote_init,
        clock,
        eic.etc.getFeatureSet(),
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L86-L96
pub fn executeAuthorize(eic: *ExecuteInstructionContext, account: BorrowedAccount, voter_pubkey: Pubkey, vote_authorize: VoteAuthorize) !void {
    _ = eic;
    _ = account;
    _ = voter_pubkey;
    _ = vote_authorize;
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_state/mod.rs#L1060
pub fn initializeAccount(account: BorrowedAccount, vote_init: VoteInit, clock: Clock, feature_set: FeatureSet) !void {
    _ = account;
    _ = vote_init;
    _ = clock;
    _ = feature_set;
}
