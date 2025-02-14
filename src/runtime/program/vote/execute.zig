const std = @import("std");
const sig = @import("../../../sig.zig");

const vote_program = sig.runtime.program.vote_program;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const CircBuf = sig.utils.collections.CircBuf;
const SortedMap = sig.utils.collections.SortedMap;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Rent = sig.runtime.sysvar.Rent;
const Clock = sig.runtime.sysvar.Clock;

const VoteProgramInstruction = vote_program.Instruction;

pub const AuthorizedVoters = struct {
    authorized_voters: std.AutoArrayHashMap(Epoch, Pubkey),
};

pub const BlockTimestamp = struct {
    slot: Slot,
    timestamp: i64,
};

pub const Lockout = struct {
    slot: Slot,
    confirmation_count: u32,
};

pub const LandedVote = struct {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    latency: u8,
    lockout: Lockout,
};

pub const VoteState = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(LandedVote),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBuf(struct { Pubkey, Epoch, Epoch }),

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(struct { Epoch, u64, u64 }),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    pub fn init(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState {
        const authorized_voters = SortedMap(Epoch, Pubkey).init();
        defer authorized_voters.deinit();

        try authorized_voters.put(clock.epoch, authorized_voter);

        return .{
            .node_pubkey = node_pubkey,
            .authorized_voters = AuthorizedVoters{ .authorized_voters = authorized_voters },
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
        };
    }

    pub fn isUninitialized(self: VoteState) bool {
        return self.authorized_voters.len == 0;
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3762;
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/2b0966de426597399ed4570d4e6c0635db2f80bf/programs/vote/src/vote_processor.rs#L54
pub fn voteProgramExecute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L55C40-L55C45
    try ic.tc.consumeCompute(vote_program.COMPUTE_UNITS);

    const instruction = try ic.deserializeInstruction(allocator, VoteProgramInstruction);
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .initialize_account => |args| try executeIntializeAccount(
            allocator,
            ic,
            args.node_pubkey,
            args.authorized_voter,
            args.authorized_withdrawer,
            args.commission,
        ),
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/ddec7bdbcf308a853d464f865ae4962acbc2b9cd/programs/vote/src/vote_state/mod.rs#L884
/// Initialize the vote_state for a vote account
/// Assumes that the account is being init as part of a account creation or balance transfer and
/// that the transaction must be signed by the staker's keys
fn executeIntializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
) !void {
    const rent = try ic.getSysvarWithAccountCheck(
        Rent,
        VoteProgramInstruction.InitializeAccountIndex.RentSysvar,
    );
    // TODO maybe bring back the rent check here? That would have the benefit of an early return in case the check fails.
    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        VoteProgramInstruction.InitializeAccountIndex.ClockSysvar,
    );

    const vote_account = try ic.borrowInstructionAccount(
        VoteProgramInstruction.InitializeAccountIndex.Account,
    );
    defer vote_account.release();

    try intializeAccount(
        allocator,
        ic,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        &vote_account,
        rent,
        clock,
    );
}

fn intializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    vote_account: *BorrowedAccount,
    rent: Rent,
    clock: Clock,
) InstructionError!void {
    const min_balance = rent.minimumBalance(vote_account.getData().len);
    // TODO Consider adding this to Rent as is_exempt
    if (vote_account.getLamports() < min_balance) {
        return InstructionError.InsufficientFundsForRent;
    }

    if (vote_account.getData().len != VoteState.sizeOf()) {
        return InstructionError.InvalidAccountData;
    }

    const versioned = try vote_account.getState(allocator, VoteState);

    if (!versioned.is_uninitialized()) {
        return (InstructionError.AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    if (!ic.isPubkeySigner(node_pubkey)) {
        try ic.tc.log("IntializeAccount: 'node' {} must sign", .{node_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    vote_account.setState(VoteState.init(
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ));
}

test "executeIntializeAccount" {}
