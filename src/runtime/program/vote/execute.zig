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
) InstructionError!void {
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

    const instruction = try ic.deserializeInstruction(allocator, VoteProgramInstruction);
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
            args.pubkey,
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
) InstructionError!void {
    const rent = try ic.getSysvarWithAccountCheck(
        Rent,
        @intFromEnum(vote_instruction.IntializeAccount.AccountIndex.rent_sysvar),
    );

    const min_balance = rent.minimumBalance(vote_account.getData().len);
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

/// Agave https://github.com/anza-xyz/agave/blob/ddec7bdbcf308a853d464f865ae4962acbc2b9cd/programs/vote/src/vote_state/mod.rs#L884-L903
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
) InstructionError!void {
    if (vote_account.getData().len != VoteState.sizeOf()) {
        return InstructionError.InvalidAccountData;
    }

    const deserialized_state = try vote_account.deserializeFromAccountData(allocator, VoteState);

    if (!deserialized_state.isUninitialized()) {
        return (InstructionError.AccountAlreadyInitialized);
    }

    // node must agree to accept this vote account
    if (!ic.isPubkeySigner(node_pubkey)) {
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
    try vote_account.serializeIntoAccountData(vote_state);
}

/// Agave https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L77-L79
fn executeAuthorize(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    pubkey: Pubkey,
    vote_authorize: VoteAuthorize,
) InstructionError!void {
    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.Authorize.AccountIndex.clock_sysvar),
    );

    try authorize(
        allocator,
        ic,
        vote_account,
        pubkey,
        vote_authorize,
        clock,
        null,
    );
}

/// Agave https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_state/mod.rs#L678
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
    signers: ?std.AutoHashMap(Pubkey, void),
) InstructionError!void {
    const versioned_state = try vote_account.deserializeFromAccountData(
        allocator,
        VoteStateVersions,
    );
    var vote_state = versioned_state.convertToCurrent(allocator) catch {
        // TODO okay to convert out of memory to custom error?
        return InstructionError.Custom;
    };

    switch (vote_authorize) {
        .voter => {
            const authorized_withdrawer_signer = if (signers) |signers_|
                try verifyAuthorizedSigner(authorized, signers_)
            else
                ic.isPubkeySigner(vote_state.authorized_withdrawer);

            try vote_state.setNewAuthorizedVoter(
                allocator,
                authorized,
                clock.epoch,
                (clock.leader_schedule_epoch +| 1),
                authorized_withdrawer_signer,
                ic,
            );
        },
        .withdrawer => {
            // current authorized withdrawer must say "yay".
            if (!ic.isPubkeySigner(vote_state.authorized_withdrawer)) {
                return InstructionError.MissingRequiredSignature;
            }
            vote_state.authorized_withdrawer = authorized;
        },
    }
    try vote_account.serializeIntoAccountData(vote_state);
}

/// Agave https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L82-L92
fn executeAuthorizeWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    new_account: Pubkey,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
) InstructionError!void {
    try ic.checkNumberOfAccounts(3);

    try authorizeWithSeed(
        allocator,
        ic,
        vote_account,
        new_account,
        authorization_type,
        current_authority_derived_key_owner,
        current_authority_derived_key_seed,
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
) InstructionError!void {
    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.VoteAuthorizeWithSeedArgs.AccountIndex.clock_sysvar),
    );

    var expected_authority_keys = std.AutoHashMap(Pubkey, void).init(allocator);
    defer expected_authority_keys.deinit();
    if (try ic.isIndexSigner(
        @intFromEnum(vote_instruction.VoteAuthorizeWithSeedArgs.AccountIndex.signer),
    )) {
        const signer_account = try ic.borrowInstructionAccount(
            @intFromEnum(vote_instruction.IntializeAccount.AccountIndex.signer),
        );
        const created = pubkey_utils.createWithSeed(
            signer_account.pubkey,
            seed,
            owner,
        ) catch |err| {
            ic.tc.custom_error = @intFromError(err);
            return InstructionError.Custom;
        };
        expected_authority_keys.put(created, {}) catch {
            // TODO okay to convert out of memory to custom error?
            return InstructionError.Custom;
        };
    }

    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority,
        authorization_type,
        clock,
        if (expected_authority_keys.count() > 0)
            expected_authority_keys
        else
            null,
    );
}

/// Agave https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L96-L102
fn executeAuthorizeCheckedWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
) InstructionError!void {
    try ic.checkNumberOfAccounts(4);

    const new_authority = try ic.borrowInstructionAccount(
        @intFromEnum(vote_instruction.VoteAuthorizeCheckedWithSeedArgs.AccountIndex.new_authority),
    );

    if (!ic.isPubkeySigner(new_authority.pubkey)) {
        return InstructionError.MissingRequiredSignature;
    }

    try authorizeWithSeed(
        allocator,
        ic,
        vote_account,
        new_authority.pubkey,
        authorization_type,
        current_authority_derived_key_owner,
        current_authority_derived_key_seed,
    );
}

/// Agave https://github.com/anza-xyz/agave/blob/0603d1cbc3ac6737df8c9e587c1b7a5c870e90f4/programs/vote/src/vote_processor.rs#L239-L248
fn executeAuthorizeChecked(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    vote_account: *BorrowedAccount,
    vote_authorize: vote_instruction.VoteAuthorize,
) InstructionError!void {
    try ic.checkNumberOfAccounts(4);

    const new_authority = try ic.borrowInstructionAccount(
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.new_signer),
    );

    if (!ic.isPubkeySigner(new_authority.pubkey)) {
        return InstructionError.MissingRequiredSignature;
    }

    const clock = try ic.getSysvarWithAccountCheck(
        Clock,
        @intFromEnum(vote_instruction.VoteAuthorize.AccountIndex.clock_sysvar),
    );

    const autorize = switch (vote_authorize) {
        .Voter => VoteAuthorize.voter,
        .Withdrawer => VoteAuthorize.withdrawer,
    };

    try authorize(
        allocator,
        ic,
        vote_account,
        new_authority.pubkey,
        autorize,
        clock,
        null,
    );
}

// TODO: Move this to instruction_context.zig
fn verifyAuthorizedSigner(
    authorized: Pubkey,
    signers: std.AutoHashMap(Pubkey, void),
) InstructionError!bool {
    if (signers.contains(authorized)) {
        return true;
    } else {
        return InstructionError.MissingRequiredSignature;
    }
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

//test "serde" {
// const MaleData = struct {
//     age: u8,
//     salary: u8,
//     name: []const u8,
// };

// const FemaleData = struct {
//     age: u8,
//     married: bool,
//     name: []const u8,
// };

// const Gender = union(enum) {
//     male: MaleData,
//     female: FemaleData,
// };

// // const data: Gender = Gender{ .male = MaleData{ .age = 11, .salary = 10, .name = "hello" } };
// const data: Gender = Gender{ .female = FemaleData{ .age = 11, .married = false, .name = "hello" } };

// const buffer = try std.testing.allocator.alloc(u8, sig.bincode.sizeOf(data, .{}));
// errdefer std.testing.allocator.free(buffer);
// defer std.testing.allocator.free(buffer);

// _ = try sig.bincode.writeToSlice(buffer, data, .{});

// std.debug.print("bufferr: {any}\n", .{buffer});

// const deserialized_data = try sig.bincode.readFromSlice(std.testing.allocator, Gender, buffer, .{});
// switch (deserialized_data) {
//     .female => |data_| {
//         defer std.testing.allocator.free(data_.name);
//         std.debug.print("data: {any}\n", .{data_});
//     },
//     .male => |data_| {
//         defer std.testing.allocator.free(data_.name);
//         std.debug.print("deserialized_data: {any}\n", .{data_});
//     },
// }

// const clock = Clock{
//     .slot = 0,
//     .epoch_start_timestamp = 0,
//     .epoch = 0,
//     .leader_schedule_epoch = 0,
//     .unix_timestamp = 0,
// };

// const VoteStateVersions = vote_program.state.VoteStateVersions;
// const vote_state = try VoteState.init(
//     std.testing.allocator,
//     Pubkey.ZEROES,
//     Pubkey.ZEROES,
//     Pubkey.ZEROES,
//     10,
//     clock,
// );
// defer vote_state.deinit();
// const version: VoteStateVersions = VoteStateVersions{ .current = vote_state };
// //const version: VoteState = vote_state;
// const buffer = try std.testing.allocator.alloc(u8, sig.bincode.sizeOf(version, .{}));
// // errdefer std.testing.allocator.free(buffer);
// defer std.testing.allocator.free(buffer);
// std.debug.print("buffer: {any}\n", .{buffer});
// _ = try sig.bincode.writeToSlice(buffer, version, .{});

// const deserialized_data = try sig.bincode.readFromSlice(std.testing.allocator, VoteStateVersions, buffer, .{});
// switch (deserialized_data) {
//     .v0_23_5 => |data_| {
//         // defer std.testing.allocator.free(data_.name);
//         std.debug.print("data: {any}\n", .{data_});
//     },
//     .v1_14_11 => |data_| {
//         // defer std.testing.allocator.free(data_.name);
//         std.debug.print("deserialized_data: {any}\n", .{data_});
//     },
//     .current => |data_| {
//         // defer std.testing.allocator.free(data_.name);
//         std.debug.print("deserialized_data: {any}\n", .{data_});
//     },
// }
//}
