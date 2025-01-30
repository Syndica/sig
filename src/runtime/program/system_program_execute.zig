const std = @import("std");
const sig = @import("../../sig.zig");

const sysvar = sig.runtime.sysvar;
const id = sig.runtime.id;
const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;

const Pubkey = sig.core.Pubkey;
const Rent = sig.runtime.sysvar.Rent;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionError = sig.core.instruction.InstructionError;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const ExecuteInstructionAccount = sig.runtime.ExecuteInstructionContext.AccountInfo;
const SystemError = sig.runtime.program.system_program.SystemProgramError;
const SystemProgramInstruction = sig.runtime.program.system_program.SystemProgramInstruction;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system_program.MAX_PERMITTED_DATA_LENGTH;

// TODO: Handle allocator errors with .Custom and return InstructionError

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn executeSystemProgramInstruction(allocator: std.mem.Allocator, eic: *ExecuteInstructionContext) !void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    try eic.consumeCompute(150);

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

    try eic.checkAccountAtIndex(1, id.SYSVAR_RECENT_BLOCKHASHES_ID);
    const recent_blockhashes = try eic.getSysvar(sysvar.RecentBlockhashes);

    if (recent_blockhashes.isEmpty()) {
        eic.log("Advance nonce account: recent blockhash list is empty", .{});
        eic.setCustomError(@intFromError(SystemError.NonceNoRecentBlockhashes));
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
    try eic.checkAccountAtIndex(2, id.SYSVAR_RECENT_BLOCKHASHES_ID);
    const recent_blockhashes = try eic.getSysvar(sysvar.RecentBlockhashes);
    _ = recent_blockhashes;

    try eic.checkAccountAtIndex(3, id.SYSVAR_RENT_ID);
    const rent = try eic.getSysvar(sysvar.Rent);

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

    try eic.checkAccountAtIndex(1, id.SYSVAR_RECENT_BLOCKHASHES_ID);
    const recent_blockhashes = try eic.getSysvar(sysvar.RecentBlockhashes);

    if (recent_blockhashes.isEmpty()) {
        eic.log("Initialize nonce account: recent blockhash list is empty", .{});
        eic.setCustomError(@intFromError(SystemError.NonceNoRecentBlockhashes));
        return InstructionError.Custom;
    }

    try eic.checkAccountAtIndex(3, id.SYSVAR_RENT_ID);
    const rent = try eic.getSysvar(sysvar.Rent);

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

    const from_base_index = 0;
    const from_index = 0;
    const to_index = 1;

    const from_base_pubkey = try eic.getAccountPubkey(from_base_index);
    const from_pubkey = try eic.getAccountPubkey(from_index);

    eic.checkIsSigner(u16, from_base_index) catch |err| {
        eic.log("Transfer: `from` account {} must sign", .{from_base_pubkey});
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
    if (!account.getOwner().equals(&id.SYSTEM_PROGRAM_ID)) return InstructionError.InvalidAccountOwner;
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
        eic.log("Allocate: 'base' account {} must sign", .{account.getPubkey()});
        return err;
    };

    if (account.hasData() or !id.SYSTEM_PROGRAM_ID.equals(&account.getOwner())) {
        eic.log("Allocate: account {} already in use", .{account.getPubkey()});
        eic.setCustomError(@intFromError(SystemError.AccountAlreadyInUse));
        return InstructionError.Custom;
    }

    if (space > MAX_PERMITTED_DATA_LENGTH) {
        eic.log("Allocate: requested {}, max allowed {}", .{ space, MAX_PERMITTED_DATA_LENGTH });
        eic.setCustomError(@intFromError(SystemError.InvalidAccountDataLength));
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
        eic.log("Assign: 'base' account {} must sign", .{account.getPubkey()});
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
            eic.log("Create Account: account {} already in use", .{account.getPubkey()});
            eic.setCustomError(@intFromError(SystemError.AccountAlreadyInUse));
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
        eic.log("Transfer: `from` account {} must sign", .{try eic.getAccountPubkey(from_index)});
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
            eic.log("Transfer: `from` must not carry data", .{});
            return InstructionError.InvalidArgument;
        }

        if (lamports > account.getLamports()) {
            eic.log("Transfer: insufficient lamports {}, need {}", .{ account.getLamports(), lamports });
            eic.setCustomError(@intFromError(SystemError.ResultWithNegativeLamports));
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
        eic.log("Advance nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.log("Advance nonce account: Account {} state is invalid", .{account.getPubkey()});
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| {
            eic.checkIsSigner(Pubkey, data.authority) catch |err| {
                eic.log("Advance nonce account: Account {} must be a signer", .{data.authority});
                return err;
            };

            const next_durable_nonce = nonce.createDurableNonce(eic.getBlockhash());

            if (data.durable_nonce.eql(next_durable_nonce)) {
                eic.log("Advance nonce account: nonce can only advance once per slot", .{});
                eic.setCustomError(@intFromError(SystemError.NonceBlockhashNotExpired));
                return InstructionError.Custom;
            }

            try account.setState(
                nonce.Versions,
                nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    eic.getLamportsPerSignature(),
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

        if (!from_account.isWritable()) {
            eic.log("Withdraw nonce account: Account {} must be writeable", .{from_account.getPubkey()});
            return InstructionError.InvalidArgument;
        }

        const versioned_nonce = try from_account.getState(allocator, nonce.Versions);
        const authority = switch (versioned_nonce.getState()) {
            .unintialized => blk: {
                if (lamports > from_account.getLamports()) {
                    eic.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
                        from_account.getLamports(),
                        lamports,
                    });
                    return InstructionError.InsufficientFunds;
                }
                break :blk from_account.getPubkey();
            },
            .initialized => |data| blk: {
                if (lamports == from_account.getLamports()) {
                    const durable_nonce = nonce.createDurableNonce(eic.getBlockhash());
                    if (durable_nonce.eql(data.durable_nonce)) {
                        eic.log("Withdraw nonce account: nonce can only advance once per slot", .{});
                        eic.setCustomError(@intFromError(SystemError.NonceBlockhashNotExpired));
                        return InstructionError.Custom;
                    }
                    try from_account.setState(nonce.Versions, nonce.Versions{ .current = nonce.State.unintialized });
                } else {
                    const min_balance = rent.mimimumBalance(from_account.getData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch {
                        return InstructionError.InsufficientFunds;
                    };
                    if (amount > from_account.getLamports()) {
                        eic.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
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
            eic.log("Withdraw nonce account: Account {} must sign", .{authority});
            return err;
        };

        try from_account.subtractLamports(lamports);
    }

    var to_account = try eic.getBorrowedAccount(to_account_index);
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
        eic.log("Initialize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            const min_balance = rent.mimimumBalance(account.getData().len);
            if (min_balance > account.getLamports()) {
                eic.log("Initialize nonce account: insufficient lamports {}, need {}", .{
                    account.getLamports(),
                    min_balance,
                });
                return InstructionError.InsufficientFunds;
            }
            try account.setState(nonce.Versions, nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                authority,
                nonce.createDurableNonce(eic.getBlockhash()),
                eic.getLamportsPerSignature(),
            ) } });
        },
        .initialized => |_| {
            eic.log("Initialize nonce account: Account {} state is invalid", .{account.getPubkey()});
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
        eic.log("Authorize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.log("Authorize nonce account: Account {} state is invalid", .{account.getPubkey()});
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| data,
    };

    eic.checkIsSigner(Pubkey, nonce_data.authority) catch |err| {
        eic.log("Authorize nonce account: Account {} must sign", .{nonce_data.authority});
        return err;
    };

    const nonce_stace = nonce.State{ .initialized = nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.getLamportsPerSignature(),
    ) };

    switch (versioned_nonce) {
        .legacy => try account.setState(nonce.Versions, nonce.Versions{ .legacy = nonce_stace }),
        .current => try account.setState(nonce.Versions, nonce.Versions{ .current = nonce_stace }),
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
        eic.setCustomError(@intFromError(err));
        return InstructionError.Custom;
    };
    if (!expected.equals(&created)) {
        eic.log(log_err_fmt, .{ expected, created });
        eic.setCustomError(@intFromError(SystemError.AddressWithSeedMismatch));
        return InstructionError.Custom;
    }
}

pub const testing = struct {
    const RwMux = sig.sync.RwMux;
    const Epoch = sig.core.Epoch;
    const Hash = sig.core.Hash;
    const Transaction = sig.core.Transaction;
    const AccountSharedData = sig.runtime.AccountSharedData;
    const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
    const ExecuteTransactionAccount = sig.runtime.ExecuteTransactionContext.AccountInfo;
    const SysvarCache = sig.runtime.SysvarCache;
    const MAX_INSTRUCTION_ACCOUNTS = sig.runtime.MAX_INSTRUCTION_ACCOUNTS;

    const AccountSharedDataParams = struct {
        lamports: u64 = 0,
        data: []const u8 = &.{},
        owner: Pubkey = Pubkey.ZEROES,
        executable: bool = false,
        rent_epoch: u64 = 0,
    };

    pub fn createAccountSharedData(
        allocator: std.mem.Allocator,
        params: AccountSharedDataParams,
    ) !AccountSharedData {
        const data = try allocator.create(std.ArrayListUnmanaged(u8));
        data.* = std.ArrayListUnmanaged(u8){
            .capacity = params.data.len,
            .items = try allocator.dupe(u8, params.data),
        };
        return .{
            .lamports = params.lamports,
            .data = data,
            .owner = params.owner,
            .executable = params.executable,
            .rent_epoch = params.rent_epoch,
        };
    }

    pub fn createAccountSharedDatas(
        allocator: std.mem.Allocator,
        params: []const AccountSharedDataParams,
    ) ![]AccountSharedData {
        var account_shared_datas = std.ArrayList(AccountSharedData).init(allocator);

        for (params) |param|
            try account_shared_datas.append(try createAccountSharedData(allocator, param));

        return account_shared_datas.toOwnedSlice();
    }

    const ExecuteTransactionContextParams = struct {
        accounts_resize_delta: i64 = 0,
        compute_meter: u64 = 0,
        maybe_custom_error: ?u32 = null,
        sysvar_cache: SysvarCache = SysvarCache.EMPTY,
        lamports_per_signature: u64 = 0,
        last_blockhash: Hash = Hash.ZEROES,
    };

    pub fn createExecuteTransactionContext(
        accounts: []const AccountSharedData,
        params: ExecuteTransactionContextParams,
    ) !ExecuteTransactionContext {
        var etc_accounts = std.BoundedArray(
            RwMux(ExecuteTransactionAccount),
            Transaction.MAX_ACCOUNTS,
        ){};

        for (accounts) |account_shared_data|
            try etc_accounts.append(RwMux(ExecuteTransactionAccount).init(.{
                .touched = false,
                .account = account_shared_data,
            }));

        return .{
            .accounts = etc_accounts,
            .accounts_resize_delta = params.accounts_resize_delta,
            .compute_meter = params.compute_meter,
            .maybe_custom_error = params.maybe_custom_error,
            .maybe_log_collector = null,
            .sysvar_cache = params.sysvar_cache,
            .lamports_per_signature = params.lamports_per_signature,
            .last_blockhash = params.last_blockhash,
        };
    }

    pub fn createExecuteInstructionContext(
        etc: *ExecuteTransactionContext,
        program_id: Pubkey,
        accounts: []const ExecuteInstructionAccount,
        instruction_data: []const u8,
    ) !ExecuteInstructionContext {
        const eic_accounts = try std.BoundedArray(
            ExecuteInstructionAccount,
            MAX_INSTRUCTION_ACCOUNTS,
        ).fromSlice(accounts);

        return .{
            .etc = etc,
            .program_id = program_id,
            .accounts = eic_accounts,
            .instruction_data = instruction_data,
        };
    }

    /// TODO: Add Context Pre / Post Checks
    pub fn expectInstructionExecutionResult(
        allocator: std.mem.Allocator,
        instruction: anytype,
        instruction_accounts: []const ExecuteInstructionAccount,
        pre_transaction_accounts: []const AccountSharedDataParams,
        post_transaction_accounts: []const AccountSharedDataParams,
        execute_transaction_context: ExecuteTransactionContextParams,
    ) !void {
        const instruction_data = try sig.bincode.writeAlloc(allocator, instruction, .{});
        defer allocator.free(instruction_data);

        const transaction_accounts = try createAccountSharedDatas(allocator, pre_transaction_accounts);
        defer {
            for (transaction_accounts) |account| {
                account.data.deinit(allocator);
                allocator.destroy(account.data);
            }
            allocator.free(transaction_accounts);
        }

        var etc = try createExecuteTransactionContext(
            transaction_accounts,
            execute_transaction_context,
        );

        var eic = try createExecuteInstructionContext(
            &etc,
            instruction.program_id(),
            instruction_accounts,
            instruction_data,
        );

        try executeSystemProgramInstruction(allocator, &eic);

        const expected_transaction_accounts = try createAccountSharedDatas(allocator, post_transaction_accounts);
        defer {
            for (expected_transaction_accounts) |account| {
                account.data.deinit(allocator);
                allocator.destroy(account.data);
            }
            allocator.free(expected_transaction_accounts);
        }

        try std.testing.expectEqual(expected_transaction_accounts.len, etc.accounts.len);
        for (expected_transaction_accounts, 0..) |expected_account, index|
            std.testing.expect(expected_account.equals(etc.getAccountSharedData(index))) catch |err| {
                std.debug.print("Mismatch in account at index {}\n", .{index});
                std.debug.print("\tExpected: {}\n", .{expected_account});
                std.debug.print("\tActual:   {}\n", .{etc.getAccountSharedData(index)});
                return err;
            };
    }
};

test "executeAllocate" {
    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
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

test "executeAssign" {
    var prng = std.Random.DefaultPrng.init(5083);

    const new_owner = Pubkey.initRandom(prng.random());
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
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

test "executeCreateAccount" {
    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        SystemProgramInstruction{
            .create_account = .{
                .lamports = 1_000_000,
                .space = 0,
                .owner = id.SYSTEM_PROGRAM_ID,
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
            .{ .lamports = 1_000_000, .owner = id.SYSTEM_PROGRAM_ID },
        },
        .{
            .compute_meter = 150,
        },
    );
}

test "executeTransfer" {
    var prng = std.Random.DefaultPrng.init(5083);

    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
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
    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    try testing.expectInstructionExecutionResult(
        std.testing.allocator,
        SystemProgramInstruction{
            .create_account_with_seed = .{
                .base = base,
                .seed = seed,
                .lamports = 1_000_000,
                .space = 0,
                .owner = id.SYSTEM_PROGRAM_ID,
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
                .pubkey = try pubkey_utils.createWithSeed(base, seed, id.SYSTEM_PROGRAM_ID),
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
            .{ .lamports = 1_000_000, .owner = id.SYSTEM_PROGRAM_ID },
            .{},
        },
        .{
            .compute_meter = 150,
        },
    );
}
