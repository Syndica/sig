const std = @import("std");
const sig = @import("../../sig.zig");

const vote_program_instruction = sig.runtime.program.vote_program_instruction;
const InitializeAccountIndex = sig.runtime.program.vote_program_instruction.InitializeAccountIndex;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Rent = sig.runtime.sysvar.Rent;
const Clock = sig.runtime.sysvar.Clock;

const VoteProgramInstruction = vote_program_instruction.VoteProgramInstruction;

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
    // TODO: Implement analogous ds for CircBuf
    // prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,

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
        // TODO maybe change to unmanaged
        const authorized_voters = std.AutoArrayHashMap(Epoch, Pubkey).init();
        defer authorized_voters.deinit();

        try authorized_voters.put(clock.epoch, authorized_voter);

        return .{
            .node_pubkey = node_pubkey,
            .authorized_voters = AuthorizedVoters{ .authorized_voters = authorized_voters },
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
        };
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3762;
    }
};

pub const VoteState0_23_5 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for vote transactions
    authorized_voter: Pubkey,
    /// when the authorized voter was set/initialized
    authorized_voter_epoch: Epoch,

    // /// history of prior authorized voters and the epoch ranges for which
    // ///  they were set
    // TODO
    // prior_voters: CircBuf<(Pubkey, Epoch, Epoch, Slot)>,

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayList(LandedVote),

    root_slot: ?Slot,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(struct { Epoch, u64, u64 }),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,
};

pub const VoteState1_14_11 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    votes: std.ArrayList(LandedVote),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    /// TODO
    // prior_voters: CircBuf<(Pubkey, Epoch, Epoch)>,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(struct { Epoch, u64, u64 }),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3731;
    }
};

pub const VoteStateVersions = union(enum) {
    V0_23_5: *VoteState0_23_5,
    V1_14_11: *VoteState1_14_11,
    Current: *VoteState,

    pub fn voteStateSizeOf(is_current: bool) usize {
        return if (is_current) VoteState.sizeOf() else VoteState1_14_11.sizeOf();
    }

    pub fn isUninitialized(self: VoteStateVersions) bool {
        return switch (self) {
            .V0_23_5 => |vote_state| vote_state.authorized_voter == Pubkey.ZEROES,
            .V1_14_11 => |vote_state| vote_state.authorized_voters.len == 0,
            .Current => |vote_state| vote_state.authorized_voters.len == 0,
        };
    }
};

/// Updates the vote account state with a new VoteState instance. This is required temporarily during the
/// upgrade of vote account state from V1_14_11 to Current.
/// TODO is this temporary requirement still valid?
fn setVoteAccountState(
    voteAccount: *BorrowedAccount,
    voteState: VoteState,
) !void {
    // TODO is this still needed?
    // const requiredSize = VoteStateVersions.voteStateSizeOf(true);

    // // If the account is not large enough to store the vote state, attempt a realloc to make it large enough.
    // // The realloc can only proceed if the vote account has balance sufficient for rent exemption at the new size.
    // if (voteAccount.getData().len < requiredSize) {
    //     const isRentExempt = voteAccount.isRentExemptAtDataLength(requiredSize);
    //     const resizeSuccess = voteAccount.setDataLength(requiredSize) catch false;

    //     if (!isRentExempt or !resizeSuccess) {
    //         // Account cannot be resized to the size of a vote state as it will not be rent exempt, or failed to be
    //         // resized for other reasons. So store the V1_14_11 version.
    //         const v1_14_11_state = VoteState1_14_11.from(voteState);
    //         const versionedState = VoteStateVersions{ .v1_14_11 = &v1_14_11_state };
    //         return voteAccount.setState(&versionedState);
    //     }
    // }

    // Vote account is large enough to store the newest version of vote state
    const currentState = VoteStateVersions.newCurrent(voteState);
    return voteAccount.setState(&currentState);
}

/// [agave] https://github.com/anza-xyz/agave/blob/2b0966de426597399ed4570d4e6c0635db2f80bf/programs/vote/src/vote_processor.rs#L54
pub fn voteProgramExecute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L55C40-L55C45
    try ic.tc.consumeCompute(vote_program_instruction.COMPUTE_UNITS);

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

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/vote/src/vote_processor.rs#L71
fn executeIntializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
) !void {
    try ic.checkNumberOfAccounts(2);
    const account = try ic.borrowInstructionAccount(InitializeAccountIndex.Account);
    defer account.release();
    const rent = try ic.getSysvarWithAccountCheck(Rent, InitializeAccountIndex.RentSysvar);
    const clock = try ic.getSysvarWithAccountCheck(Clock, InitializeAccountIndex.ClockSysvar);
    const autority = ic.accounts[1].pubkey;

    try intializeAccount(
        allocator,
        ic,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        &account,
        rent,
        clock,
        autority,
    );
}

fn intializeAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    account: *BorrowedAccount,
    rent: Rent,
    clock: Clock,
    authority: Pubkey,
) InstructionError!void {
    const min_balance = rent.minimumBalance(account.getData().len);
    // TODO Consider adding this to Rent as is_exempt
    if (account.getLamports() < min_balance) {
        return InstructionError.InsufficientFundsForRent;
    }

    if (account.getData().len != VoteStateVersions.voteStateSizeOf(true)) {
        return InstructionError.InvalidAccountData;
    }

    // TODO/Question how is this a state within account?
    const versioned = try account.getState(allocator, VoteStateVersions);

    if (!versioned.is_uninitialized()) {
        return (InstructionError.AccountAlreadyInitialized);
    }

    // TODO authority is passed in to check, but account.getPubkey() is used in logs
    if (!ic.isPubkeySigner(authority)) {
        try ic.tc.log("Assign: 'base' account {} must sign", .{account.getPubkey()});
        return InstructionError.MissingRequiredSignature;
    }

    _ = try setVoteAccountState(account, VoteState.init(
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    ));
}

test "executeIntializeAccount" {}
