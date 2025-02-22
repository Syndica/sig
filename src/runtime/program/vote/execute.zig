const std = @import("std");
const sig = @import("../../../sig.zig");

const vote_program = sig.runtime.program.vote_program;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const CircBuf = sig.utils.collections.CircBuf;
const MAX_ITEMS = sig.utils.collections.MAX_ITEMS;
const SortedMap = sig.utils.collections.SortedMap;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const Rent = sig.runtime.sysvar.Rent;
const Clock = sig.runtime.sysvar.Clock;

const VoteProgramInstruction = vote_program.Instruction;

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

pub const PriorVote = struct {
    /// authorized voter at the time of the vote.
    key: Pubkey,
    /// the start epoch of the vote (inlcusive).
    start: Epoch,
    /// the end epoch of the vote (exclusive).
    end: Epoch,
};

pub const EpochCredit = struct {
    epoch: Epoch,
    credits: u64,
    prev_credits: u64,
};

/// Must support `bincode` and `serializedSize` methods for writing to the account data.
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
    authorized_voters: SortedMap(Epoch, Pubkey),

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBuf(PriorVote, MAX_ITEMS),

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayList(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    pub fn init(
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        authorized_withdrawer: Pubkey,
        commission: u8,
        clock: Clock,
    ) !VoteState {
        var authorized_voters = SortedMap(Epoch, Pubkey).init(allocator);
        errdefer authorized_voters.deinit();

        authorized_voters.put(clock.epoch, authorized_voter) catch {
            return InstructionError.Custom;
        };

        return .{
            .node_pubkey = node_pubkey,
            .authorized_voters = authorized_voters,
            .authorized_withdrawer = authorized_withdrawer,
            .commission = commission,
            .votes = std.ArrayList(LandedVote).init(allocator),
            .root_slot = null,
            .prior_voters = CircBuf(PriorVote, MAX_ITEMS).DEFAULT,
            .epoch_credits = std.ArrayList(EpochCredit).init(allocator),
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: VoteState) void {
        self.votes.deinit();
        self.authorized_voters.deinit();
        self.epoch_credits.deinit();
    }

    pub fn isUninitialized(self: VoteState) bool {
        return self.authorized_voters.count() == 0;
    }

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub fn sizeOf() usize {
        return 3762;
    }

    pub fn serializedSize(self: VoteState) !usize {
        return sig.bincode.sizeOf(self, .{});
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/2b0966de426597399ed4570d4e6c0635db2f80bf/programs/vote/src/vote_processor.rs#L54
pub fn execute(
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
) InstructionError!void {
    // node must agree to accept this vote account
    if (!ic.isPubkeySigner(node_pubkey)) {
        try ic.tc.log("IntializeAccount: 'node' {} must sign", .{node_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    const rent = try ic.getSysvarWithAccountCheck(
        Rent,
        VoteProgramInstruction.InitializeAccountIndex.RentSysvar.index(),
    );

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        VoteProgramInstruction.InitializeAccountIndex.ClockSysvar.index(),
    );

    var vote_account = try ic.borrowInstructionAccount(
        VoteProgramInstruction.InitializeAccountIndex.Account.index(),
    );
    defer vote_account.release();

    // Apply all the checks to the account data.
    const min_balance = rent.minimumBalance(vote_account.getData().len);
    if (vote_account.account.lamports < min_balance) {
        return InstructionError.InsufficientFunds;
    }

    if (vote_account.getData().len != VoteState.sizeOf()) {
        return InstructionError.InvalidAccountData;
    }

    const versioned = try vote_account.deserializeFromAccountData(allocator, VoteState);

    if (!versioned.isUninitialized()) {
        return (InstructionError.AccountAlreadyInitialized);
    }

    var authority = try ic.borrowInstructionAccount(
        VoteProgramInstruction.InitializeAccountIndex.Signer.index(),
    );
    defer authority.release();

    try intializeAccount(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        &vote_account,
        clock,
    );
}

fn intializeAccount(
    allocator: std.mem.Allocator,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    vote_account: *BorrowedAccount,
    clock: Clock,
) InstructionError!void {
    const vote_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer vote_state.deinit();
    try vote_account.serializeIntoAccountData(vote_state);
}

test "executeIntializeAccount" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

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
    const final_vote_state = try VoteState.init(
        allocator,
        node_publey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    defer final_vote_state.deinit();

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try expectProgramExecuteResult(
        std.testing.allocator,
        vote_program,
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
                .{ .pubkey = vote_program.ID },
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
                .{ .pubkey = vote_program.ID },
            },
            .compute_meter = 0,
            .sysvar_cache = .{
                .rent = rent,
                .clock = clock,
            },
        },
    );
}
