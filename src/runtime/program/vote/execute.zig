const std = @import("std");
const sig = @import("../../../sig.zig");

const vote_program = sig.runtime.program.vote_program;
const pubkey_utils = sig.runtime.pubkey_utils;
const vote_instruction = vote_program.vote_instruction;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const VoteState = vote_program.state.VoteState;
const VoteStateVersions = vote_program.state.VoteStateVersions;
const VoteAuthorize = vote_program.state.VoteAuthorize;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const Rent = sig.runtime.sysvar.Rent;
const Clock = sig.runtime.sysvar.Clock;

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
        @intFromEnum(vote_instruction.IntializeAccount.AccountIndex.account),
    );
    defer vote_account.release();

    if (!vote_account.account.owner.equals(&vote_program.ID)) {
        return InstructionError.InvalidAccountOwner;
    }

    const instruction = try ic.info.deserializeInstruction(allocator, VoteProgramInstruction);
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
        .update_validator_identity => executeUpdateValidatorIdentity(allocator, ic, &vote_account),
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/vote/src/vote_processor.rs#L68-L76
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
        @intFromEnum(vote_instruction.IntializeAccount.AccountIndex.rent_sysvar),
    );

    const min_balance = rent.minimumBalance(vote_account.constAccountData().len);
    if (vote_account.account.lamports < min_balance) {
        return InstructionError.InsufficientFunds;
    }

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.IntializeAccount.AccountIndex.clock_sysvar),
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

    const deserialized_state = try vote_account.deserializeFromAccountData(allocator, VoteState);

    if (!deserialized_state.isUninitialized()) {
        return (InstructionError.AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    if (!ic.info.isPubkeySigner(node_pubkey)) {
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
    try vote_account.serializeIntoAccountData(VoteStateVersions{ .current = vote_state });
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

    const signers = try ic.info.getSigners();

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
            const current_epoch = clock.epoch;

            const authorized_withdrawer_signer = !std.meta.isError(validateIsSigner(
                vote_state.authorized_withdrawer,
                signers,
            ));

            // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/vote/src/vote_state/mod.rs#L697-L701
            const target_epoch = std.math.add(u64, current_epoch, 1) catch {
                return InstructionError.InvalidAccountData;
            };

            // [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L872
            const epoch_authorized_voter = try vote_state.getAndUpdateAuthorizedVoter(
                allocator,
                current_epoch,
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
                vote_state.authorized_withdrawer,
                signers,
            ));

            if (!authorized_withdrawer_signer) {
                return InstructionError.MissingRequiredSignature;
            }
            vote_state.authorized_withdrawer = authorized;
        },
    }
    try vote_account.serializeIntoAccountData(VoteStateVersions{ .current = vote_state });
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
    try ic.info.checkNumberOfAccounts(3);

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

/// Analogous to [process_authorize_with_seed_instruction] https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L19
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

    const signer_meta = ic.info.getAccountMetaAtIndex(signer_index) orelse
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
    try ic.info.checkNumberOfAccounts(4);

    // Safe since there are at least 4 accounts, and the new_authority index is 3.
    const new_authority_meta = &ic.info.account_metas.buffer[
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
    try ic.info.checkNumberOfAccounts(4);

    // Safe since there are at least 4 accounts, and the new_authority index is 3.
    const new_authority_meta = &ic.info.account_metas.buffer[
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

    const signers = try ic.info.getSigners();

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
    try ic.info.checkNumberOfAccounts(2);

    var new_identity = try ic.borrowInstructionAccount(
        @intFromEnum(vote_instruction.UpdateVoteIdentity.AccountIndex.new_identity),
    );
    defer new_identity.release();

    try updateValidatorIdentity(
        allocator,
        ic,
        vote_account,
        new_identity.pubkey,
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

    const is_withdrawer_signed = ic.info.isPubkeySigner(vote_state.authorized_withdrawer);
    const is_new_identity_signed = ic.info.isPubkeySigner(new_identity);
    // Both the current authorized withdrawer and new identity must sign.
    const has_required_signatures = is_withdrawer_signed and is_new_identity_signed;
    if (!has_required_signatures) {
        return InstructionError.MissingRequiredSignature;
    }

    vote_state.node_pubkey = new_identity;
    try vote_account.serializeIntoAccountData(VoteStateVersions{ .current = vote_state });
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
        {},
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
        {},
        vote_program,
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
    );
}

test "vote_program: executeAuthorize voter signed by current withdrawer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const PriorVote = sig.runtime.program.vote_program.state.PriorVote;

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

    var final_vote_state_ = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        clock,
    );
    try final_vote_state_.authorized_voters.insert(1, new_authorized_voter);
    final_vote_state_.prior_voters.append(PriorVote{
        .key = authorized_voter,
        .start = 0,
        .end = 1,
    });

    var final_vote_state = VoteStateVersions{ .current = final_vote_state_ };
    defer final_vote_state.deinit();

    var initial_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(initial_vote_state_bytes[0..], initial_vote_state, .{});

    var final_vote_state_bytes = ([_]u8{0} ** 3762);
    _ = try sig.bincode.writeToSlice(final_vote_state_bytes[0..], final_vote_state, .{});

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        {},
        vote_program,
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
        {},
        vote_program,
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
        {},
        vote_program,
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
        {},
        vote_program,
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
        {},
        vote_program,
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
        {},
        vote_program,
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
        {},
        vote_program,
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
    );

    try std.testing.expectError(InstructionError.MissingRequiredSignature, result);
}
