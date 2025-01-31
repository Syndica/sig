const std = @import("std");
const sig = @import("../../sig.zig");

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;
const system_program = sig.runtime.program.system_program;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const BorrowedAccount = sig.runtime.BorrowedAccount;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const ExecuteInstructionAccount = sig.runtime.ExecuteInstructionContext.AccountInfo;
const FeatureSet = sig.runtime.FeatureSet;

const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;

const SystemError = system_program.SystemProgramError;
const SystemProgramInstruction = system_program.SystemProgramInstruction;

const MAX_PERMITTED_DATA_LENGTH = system_program.MAX_PERMITTED_DATA_LENGTH;

// TODO: Handle allocator errors with .Custom and return InstructionError

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn executeSystemProgramInstruction(allocator: std.mem.Allocator, eic: *ExecuteInstructionContext) !void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    try eic.etc.consumeCompute(150);

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try sig.bincode.readFromSlice(
        allocator,
        SystemProgramInstruction,
        eic.instruction_data,
        .{},
    );
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .create_account => |args| try executeCreateAccount(
            allocator,
            eic,
            args.lamports,
            args.space,
            args.owner,
        ),
        .assign => |args| try executeAssign(
            eic,
            args.owner,
        ),
        .transfer => |args| try executeTransfer(
            eic,
            args.lamports,
        ),
        .create_account_with_seed => |args| try executeCreateAccountWithSeed(
            allocator,
            eic,
            args.base,
            args.seed,
            args.lamports,
            args.space,
            args.owner,
        ),
        .advance_nonce_account => try executeAdvanceNonceAccount(
            allocator,
            eic,
        ),
        .withdraw_nonce_account => |arg| try executeWithdrawNonceAccount(
            allocator,
            eic,
            arg,
        ),
        .initialize_nonce_account => |arg| try executeInitializeNonceAccount(
            allocator,
            eic,
            arg,
        ),
        .authorize_nonce_account => |arg| try executeAuthorizeNonceAccount(
            allocator,
            eic,
            arg,
        ),
        .allocate => |args| try executeAllocate(
            allocator,
            eic,
            args.space,
        ),
        .allocate_with_seed => |args| try executeAllocateWithSeed(
            allocator,
            eic,
            args.base,
            args.seed,
            args.space,
            args.owner,
        ),
        .assign_with_seed => |args| try executeAssignWithSeed(
            eic,
            args.base,
            args.seed,
            args.owner,
        ),
        .transfer_with_seed => |args| try executeTransferWithSeed(
            eic,
            args.lamports,
            args.from_seed,
            args.from_owner,
        ),
        .upgrade_nonce_account => try executeUpgradeNonceAccount(
            allocator,
            eic,
        ),
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L315-L334
fn executeCreateAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(2);
    try createAccount(allocator, eic, 0, 1, lamports, space, owner, try eic.getAccountPubkey(1));
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L365-L375
fn executeAssign(
    eic: *ExecuteInstructionContext,
    owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    try assign(eic, account, owner, account.getPubkey());
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L378-L386
fn executeTransfer(
    eic: *ExecuteInstructionContext,
    lamports: u64,
) !void {
    try eic.checkNumberOfAccounts(2);
    try transfer(eic, 0, 1, lamports);
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L343-L362
fn executeCreateAccountWithSeed(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(2);
    try checkSeedAddress(
        eic,
        try eic.getAccountPubkey(1),
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try createAccount(allocator, eic, 0, 1, lamports, space, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L407-L423
fn executeAdvanceNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();

    const recent_blockhashes = try eic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        eic.etc.log("Advance nonce account: recent blockhash list is empty", .{});
        eic.etc.setCustomError(@intFromError(SystemError.NonceNoRecentBlockhashes));
        return InstructionError.Custom;
    }

    try advanceNonceAccount(allocator, eic, account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    lamports: u64,
) !void {
    try eic.checkNumberOfAccounts(2);

    // TODO: Is this sysvar call required for consensus despite being unused?
    _ = try eic.getSysvarWithAccountCheck(RecentBlockhashes, 2);

    const rent = try eic.getSysvarWithAccountCheck(Rent, 3);

    return withdrawNonceAccount(allocator, eic, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    authority: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();

    const recent_blockhashes = try eic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        eic.etc.log("Initialize nonce account: recent blockhash list is empty", .{});
        eic.etc.setCustomError(@intFromError(SystemError.NonceNoRecentBlockhashes));
        return InstructionError.Custom;
    }

    const rent = try eic.getSysvarWithAccountCheck(Rent, 2);

    try initializeNonceAccount(
        allocator,
        eic,
        account,
        authority,
        rent,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L466-L469
fn executeAuthorizeNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    authority: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    return authorizeNonceAccount(
        allocator,
        eic,
        account,
        authority,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L488-L498
fn executeAllocate(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    space: u64,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    try allocate(allocator, eic, account, space, account.getPubkey());
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L506-L523
fn executeAllocateWithSeed(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    try checkSeedAddress(
        eic,
        account.getPubkey(),
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try allocate(allocator, eic, account, space, base);
    try assign(eic, account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L526-L536
fn executeAssignWithSeed(
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    try checkSeedAddress(
        eic,
        account.getPubkey(),
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try assign(eic, account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L393-L404
fn executeTransferWithSeed(
    eic: *ExecuteInstructionContext,
    lamports: u64,
    from_seed: []const u8,
    from_owner: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(3);

    const from_index = 0;
    const from_base_index = 1;
    const to_index = 2;

    const from_base_pubkey = try eic.getAccountPubkey(from_base_index);
    const from_pubkey = try eic.getAccountPubkey(from_index);

    eic.checkIsSigner(u16, from_base_index) catch |err| {
        eic.etc.log("Transfer: `from` account {} must sign", .{from_base_pubkey});
        return err;
    };

    try checkSeedAddress(
        eic,
        from_pubkey,
        from_base_pubkey,
        from_owner,
        from_seed,
        "Transfer: 'from' address {} does not match derived address {}",
    );

    try transferVerified(
        eic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L472-L485
fn executeUpgradeNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.release();
    if (!account.getOwner().equals(&system_program.id())) return InstructionError.InvalidAccountOwner;
    if (!account.isWritable()) return InstructionError.InvalidArgument;
    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce) {
        .legacy => |state| {
            if (state == nonce.State.initialized) {
                var data = state.initialized;
                data.durable_nonce = nonce.createDurableNonce(data.getDurableNonce());
                try account.setState(nonce.Versions, nonce.Versions{ .current = state });
            }
        },
        .current => |_| return InstructionError.InvalidArgument,
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#70
fn allocate(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    space: u64,
    authority: Pubkey,
) !void {
    eic.checkIsSigner(Pubkey, authority) catch |err| {
        eic.etc.log("Allocate: 'base' account {} must sign", .{account.getPubkey()});
        return err;
    };

    if (account.hasData() or !system_program.id().equals(&account.getOwner())) {
        eic.etc.log("Allocate: account {} already in use", .{account.getPubkey()});
        eic.etc.setCustomError(@intFromError(SystemError.AccountAlreadyInUse));
        return InstructionError.Custom;
    }

    if (space > MAX_PERMITTED_DATA_LENGTH) {
        eic.etc.log("Allocate: requested {}, max allowed {}", .{ space, MAX_PERMITTED_DATA_LENGTH });
        eic.etc.setCustomError(@intFromError(SystemError.InvalidAccountDataLength));
        return InstructionError.Custom;
    }

    try account.setDataLength(allocator, @intCast(space));
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L112
fn assign(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    owner: Pubkey,
    authority: Pubkey,
) !void {
    if (account.getOwner().equals(&owner)) return;

    eic.checkIsSigner(Pubkey, authority) catch |err| {
        eic.etc.log("Assign: 'base' account {} must sign", .{account.getPubkey()});
        return err;
    };

    return account.setOwner(owner);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L145
fn createAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
    space: u64,
    owner: Pubkey,
    authority: Pubkey,
) !void {
    {
        var account = try eic.getBorrowedAccount(to_index);
        defer account.release();

        if (account.getLamports() > 0) {
            eic.etc.log("Create Account: account {} already in use", .{account.getPubkey()});
            eic.etc.setCustomError(@intFromError(SystemError.AccountAlreadyInUse));
            return InstructionError.Custom;
        }

        try allocate(allocator, eic, account, space, authority);
        try assign(eic, account, owner, authority);
    }

    return transfer(
        eic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L214
fn transfer(
    eic: *ExecuteInstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) !void {
    eic.checkIsSigner(u16, from_index) catch |err| {
        eic.etc.log("Transfer: `from` account {} must sign", .{try eic.getAccountPubkey(from_index)});
        return err;
    };

    return transferVerified(
        eic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L182
fn transferVerified(
    eic: *ExecuteInstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) !void {
    {
        var account = try eic.getBorrowedAccount(from_index);
        defer account.release();

        if (account.hasData()) {
            eic.etc.log("Transfer: `from` must not carry data", .{});
            return InstructionError.InvalidArgument;
        }

        if (lamports > account.getLamports()) {
            eic.etc.log("Transfer: insufficient lamports {}, need {}", .{ account.getLamports(), lamports });
            eic.etc.setCustomError(@intFromError(SystemError.ResultWithNegativeLamports));
            return InstructionError.Custom;
        }

        try account.subtractLamports(lamports);
    }

    var account = try eic.getBorrowedAccount(to_index);
    defer account.release();

    try account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
) !void {
    if (!account.isWritable()) {
        eic.etc.log("Advance nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.etc.log("Advance nonce account: Account {} state is invalid", .{account.getPubkey()});
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| {
            eic.checkIsSigner(Pubkey, data.authority) catch |err| {
                eic.etc.log("Advance nonce account: Account {} must be a signer", .{data.authority});
                return err;
            };

            const next_durable_nonce = nonce.createDurableNonce(eic.etc.getBlockhash());

            if (data.durable_nonce.eql(next_durable_nonce)) {
                eic.etc.log("Advance nonce account: nonce can only advance once per slot", .{});
                eic.etc.setCustomError(@intFromError(SystemError.NonceBlockhashNotExpired));
                return InstructionError.Custom;
            }

            try account.setState(
                nonce.Versions,
                nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    eic.etc.getLamportsPerSignature(),
                ) } },
            );
        },
    }
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L73-L74
fn withdrawNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    lamports: u64,
    rent: Rent,
) !void {
    const from_account_index = 0;
    const to_account_index = 1;

    {
        var from_account = try eic.getBorrowedAccount(from_account_index);
        defer from_account.release();

        if (!from_account.isWritable()) {
            eic.etc.log("Withdraw nonce account: Account {} must be writeable", .{from_account.getPubkey()});
            return InstructionError.InvalidArgument;
        }

        const versioned_nonce = try from_account.getState(allocator, nonce.Versions);
        const authority = switch (versioned_nonce.getState()) {
            .unintialized => blk: {
                if (lamports > from_account.getLamports()) {
                    eic.etc.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
                        from_account.getLamports(),
                        lamports,
                    });
                    return InstructionError.InsufficientFunds;
                }
                break :blk from_account.getPubkey();
            },
            .initialized => |data| blk: {
                if (lamports == from_account.getLamports()) {
                    const durable_nonce = nonce.createDurableNonce(eic.etc.getBlockhash());
                    if (durable_nonce.eql(data.durable_nonce)) {
                        eic.etc.log("Withdraw nonce account: nonce can only advance once per slot", .{});
                        eic.etc.setCustomError(@intFromError(SystemError.NonceBlockhashNotExpired));
                        return InstructionError.Custom;
                    }
                    try from_account.setState(nonce.Versions, nonce.Versions{ .current = nonce.State.unintialized });
                } else {
                    const min_balance = rent.minimumBalance(from_account.getData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch {
                        return InstructionError.InsufficientFunds;
                    };
                    if (amount > from_account.getLamports()) {
                        eic.etc.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
                            from_account.getLamports(),
                            amount,
                        });
                        return InstructionError.InsufficientFunds;
                    }
                }
                break :blk data.authority;
            },
        };

        eic.checkIsSigner(Pubkey, authority) catch |err| {
            eic.etc.log("Withdraw nonce account: Account {} must sign", .{authority});
            return err;
        };

        try from_account.subtractLamports(lamports);
    }

    var to_account = try eic.getBorrowedAccount(to_account_index);
    defer to_account.release();
    try to_account.addLamports(lamports);
}

fn initializeNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    authority: Pubkey,
    rent: Rent,
) !void {
    if (!account.isWritable()) {
        eic.etc.log("Initialize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            const min_balance = rent.minimumBalance(account.getData().len);
            if (min_balance > account.getLamports()) {
                eic.etc.log("Initialize nonce account: insufficient lamports {}, need {}", .{
                    account.getLamports(),
                    min_balance,
                });
                return InstructionError.InsufficientFunds;
            }
            try account.setState(nonce.Versions, nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                authority,
                nonce.createDurableNonce(eic.etc.getBlockhash()),
                eic.etc.getLamportsPerSignature(),
            ) } });
        },
        .initialized => |_| {
            eic.etc.log("Initialize nonce account: Account {} state is invalid", .{account.getPubkey()});
            return InstructionError.InvalidAccountData;
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L203
pub fn authorizeNonceAccount(
    allocator: std.mem.Allocator,
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    authority: Pubkey,
) !void {
    if (!account.isWritable()) {
        eic.etc.log("Authorize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.etc.log("Authorize nonce account: Account {} state is invalid", .{account.getPubkey()});
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| data,
    };

    eic.checkIsSigner(Pubkey, nonce_data.authority) catch |err| {
        eic.etc.log("Authorize nonce account: Account {} must sign", .{nonce_data.authority});
        return err;
    };

    const nonce_state = nonce.State{ .initialized = nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.getLamportsPerSignature(),
    ) };

    switch (versioned_nonce) {
        .legacy => try account.setState(nonce.Versions, nonce.Versions{ .legacy = nonce_state }),
        .current => try account.setState(nonce.Versions, nonce.Versions{ .current = nonce_state }),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L47-L58
fn checkSeedAddress(
    eic: *ExecuteInstructionContext,
    expected: Pubkey,
    base: Pubkey,
    owner: Pubkey,
    seed: []const u8,
    comptime log_err_fmt: []const u8,
) !void {
    const created = pubkey_utils.createWithSeed(base, seed, owner) catch |err| {
        eic.etc.setCustomError(@intFromError(err));
        return InstructionError.Custom;
    };
    if (!expected.equals(&created)) {
        eic.etc.log(log_err_fmt, .{ expected, created });
        eic.etc.setCustomError(@intFromError(SystemError.AddressWithSeedMismatch));
        return InstructionError.Custom;
    }
}

test "executeCreateAccount" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .create_account = .{
                .lamports = 1_000_000,
                .space = 0,
                .owner = system_program.id(),
            },
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 1,
            },
        },
        &.{
            .{
                .lamports = 2_000_000,
            },
            .{},
        },
        &.{
            .{ .lamports = 1_000_000 },
            .{ .lamports = 1_000_000, .owner = system_program.id(), .data = &.{} },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeAssign" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    const new_owner = Pubkey.initRandom(prng.random());
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .assign = .{
                .owner = new_owner,
            },
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        &.{
            .{},
        },
        &.{
            .{ .owner = new_owner },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeTransfer" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .transfer = .{
                .lamports = 1_000_000,
            },
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
        },
        &.{
            .{
                .lamports = 2_000_000,
            },
            .{
                .lamports = 0,
            },
        },
        &.{
            .{ .lamports = 1_000_000 },
            .{ .lamports = 1_000_000 },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeCreateAccountWithSeed" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .create_account_with_seed = .{
                .base = base,
                .seed = seed,
                .lamports = 1_000_000,
                .space = 0,
                .owner = system_program.id(),
            },
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = try pubkey_utils.createWithSeed(base, seed, system_program.id()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .pubkey = base,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        &.{
            .{
                .lamports = 2_000_000,
            },
            .{},
            .{},
        },
        &.{
            .{ .lamports = 1_000_000 },
            .{ .lamports = 1_000_000, .owner = system_program.id() },
            .{},
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeAdvanceNonceAccount" {
    const testing = sig.runtime.program.test_execute;

    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    // Last Blockhash is used to compute the next durable nonce
    const last_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const initial_durable_nonce = nonce.createDurableNonce(Hash.initRandom(prng.random()));
    const nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        initial_durable_nonce,
        0,
    ) } };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Final Nonce State
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{
            .initialized = nonce.Data.init(
                nonce_authority, // Unchanged
                nonce.createDurableNonce(last_blockhash), // Updated
                lamports_per_signature, // Updated
            ),
        },
    };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    // Create Sysvar Recent Blockhashes
    const recent_blockhashes = .{
        .entries = &.{.{
            .blockhash = Hash.initRandom(prng.random()),
            .fee_calculator = .{ .lamports_per_signature = 0 }, // Irrelevant
        }},
    };

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .advance_nonce_account = {},
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = RecentBlockhashes.id(),
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .pubkey = nonce_authority,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        &.{
            .{ .data = nonce_state_bytes },
            .{},
            .{},
        },
        &.{
            .{ .data = final_nonce_state_bytes },
            .{},
            .{},
        },
        .{
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .compute_meter = 150,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
            },
        },
    );
}

test "executeWithdrawNonceAccount" {
    const testing = sig.runtime.program.test_execute;

    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    // The amount to withdraw
    const withdraw_lamports = 1_000;

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const initial_durable_nonce = nonce.createDurableNonce(Hash.initRandom(prng.random()));
    const nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        initial_durable_nonce,
        0,
    ) } };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Sysvars
    const recent_blockhashes = RecentBlockhashes{ .entries = &.{} };
    const rent = Rent.default();
    const rent_minimum_balance = rent.minimumBalance(try nonce_state.serializedSize());

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .withdraw_nonce_account = 1_000,
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .pubkey = RecentBlockhashes.id(),
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 2,
            },
            .{
                .pubkey = Rent.id(),
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 3,
            },
            .{
                .pubkey = nonce_authority,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 4,
            },
        },
        &.{
            .{
                .lamports = 2 * withdraw_lamports + rent_minimum_balance,
                .data = nonce_state_bytes,
            },
            .{},
            .{},
            .{},
            .{},
        },
        &.{
            .{
                .lamports = withdraw_lamports + rent_minimum_balance,
                .data = nonce_state_bytes,
            },
            .{
                .lamports = withdraw_lamports,
            },
            .{},
            .{},
            .{},
        },
        .{
            .compute_meter = 150,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
            },
        },
    );
}

test "executeInitializeNonceAccount" {
    const testing = sig.runtime.program.test_execute;

    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    // Last Blockhash is used to compute the next durable nonce
    const last_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Final Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const final_nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        nonce.createDurableNonce(last_blockhash),
        lamports_per_signature,
    ) } };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    // Create Uninitialized Nonce State
    // The nonce state bytes must have sufficient space to store the final nonce state
    const nonce_state = nonce.Versions{ .current = .unintialized };
    const nonce_state_bytes = try allocator.alloc(u8, final_nonce_state_bytes.len);
    _ = try sig.bincode.writeToSlice(nonce_state_bytes, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Sysvar Recent Blockhashes
    const recent_blockhashes = .{
        .entries = &.{.{
            .blockhash = Hash.initRandom(prng.random()),
            .fee_calculator = .{ .lamports_per_signature = 0 }, // Irrelevant
        }},
    };
    const rent = Rent.default();

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .initialize_nonce_account = nonce_authority,
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = RecentBlockhashes.id(),
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 2,
            },
            .{
                .pubkey = Rent.id(),
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 3,
            },
        },
        &.{
            .{
                // Need rent to store final nonce state
                .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                .data = nonce_state_bytes,
            },
            .{},
            .{},
        },
        &.{
            .{
                .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                .data = final_nonce_state_bytes,
            },
            .{},
            .{},
        },
        .{
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .compute_meter = 150,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
            },
        },
    );
}

test "executeAuthorizeNonceAccount" {
    const testing = sig.runtime.program.test_execute;

    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    // Create Initial Nonce State
    const initial_nonce_authority = Pubkey.initRandom(prng.random());
    const durable_nonce = nonce.createDurableNonce(Hash.initRandom(prng.random()));
    const nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        initial_nonce_authority,
        durable_nonce,
        0,
    ) } };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Initial Nonce State
    const final_nonce_authority = Pubkey.initRandom(prng.random());
    const final_nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        final_nonce_authority,
        durable_nonce,
        0,
    ) } };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .authorize_nonce_account = final_nonce_authority,
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                // Signer must be the initial nonce authority
                .pubkey = initial_nonce_authority,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
        },
        &.{
            .{
                .data = nonce_state_bytes,
            },
            .{},
        },
        &.{
            .{
                .data = final_nonce_state_bytes,
            },
            .{},
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeAllocate" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .allocate = .{
                .space = 1024,
            },
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        &.{
            .{},
        },
        &.{
            .{ .data = &[_]u8{0} ** 1024 },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeAllocateWithSeed" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .allocate_with_seed = .{
                .base = base,
                .seed = seed,
                .space = 1024,
                .owner = system_program.id(),
            },
        },
        &.{
            .{
                .pubkey = try pubkey_utils.createWithSeed(base, seed, system_program.id()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = base,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 0,
            },
        },
        &.{
            .{},
            .{},
        },
        &.{
            .{ .data = &[_]u8{0} ** 1024 },
            .{},
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeAssignWithSeed" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    const new_owner = Pubkey.initRandom(prng.random());
    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .assign_with_seed = .{
                .base = base,
                .seed = seed,
                .owner = new_owner,
            },
        },
        &.{
            .{
                .pubkey = try pubkey_utils.createWithSeed(base, seed, new_owner),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = base,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 0,
            },
        },
        &.{
            .{},
        },
        &.{
            .{ .owner = new_owner },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeTransferWithSeed" {
    const testing = sig.runtime.program.test_execute;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const from_seed = &[_]u8{0x10} ** 32;
    const from_owner = Pubkey.initRandom(prng.random());
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .transfer_with_seed = .{
                .lamports = 1_000_000,
                .from_seed = from_seed,
                .from_owner = from_owner,
            },
        },
        &.{
            .{
                .pubkey = try pubkey_utils.createWithSeed(base, from_seed, from_owner),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .pubkey = base,
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 2,
            },
        },
        &.{
            .{
                .lamports = 2_000_000,
            },
            .{},
            .{
                .lamports = 0,
            },
        },
        &.{
            .{ .lamports = 1_000_000 },
            .{},
            .{ .lamports = 1_000_000 },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeUpgradeNonceAccount" {
    const testing = sig.runtime.program.test_execute;

    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const durable_nonce = nonce.createDurableNonce(Hash.initRandom(prng.random()));
    const lamports_per_signature = 5_000;
    const nonce_state = nonce.Versions{ .legacy = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        durable_nonce,
        lamports_per_signature,
    ) } };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Initial Nonce State
    const final_nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        durable_nonce,
        lamports_per_signature,
    ) } };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        executeSystemProgramInstruction,
        SystemProgramInstruction{
            .upgrade_nonce_account = {},
        },
        &.{
            .{
                .pubkey = Pubkey.initRandom(prng.random()),
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        &.{
            .{
                .data = nonce_state_bytes,
            },
        },
        &.{
            .{
                .data = final_nonce_state_bytes,
            },
        },
        .{
            .compute_meter = 150,
        },
    );
}
