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
const SystemError = sig.runtime.program.system_program.SystemProgramError;
const SystemInstruction = sig.runtime.program.system_program.SystemProgramInstruction;

const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system_program.MAX_PERMITTED_DATA_LENGTH;

// TODO: Handle allocator errors with .Custom and return InstructionError

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn executeSystemProgramInstruction(allocator: std.mem.Allocator, eic: *ExecuteInstructionContext) !void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    eic.consumeCompute(150);

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try SystemInstruction.deserialize(eic.instruction_data);
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
            eic,
        ),
        .withdraw_nonce_account => |arg| try executeWithdrawNonceAccount(
            eic,
            arg,
        ),
        .initialize_nonce_account => |arg| try executeInitializeNonceAccount(
            eic,
            arg,
        ),
        .authorize_nonce_account => |arg| try executeAuthorizeNonceAccount(
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
            args.seed,
            args.program_id,
        ),
        .upgrade_nonce_account => try executeUpgradeNonceAccount(
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
    defer account.deinit();
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
        eic.getAccountPubkey(1),
        base,
        seed,
        owner,
        "Create: address {} does not match derived address {}",
    );
    try createAccount(allocator, eic, 0, 1, lamports, space, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L407-L423
fn executeAdvanceNonceAccount(
    eic: *ExecuteInstructionContext,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.deinit();

    try eic.checkAccountAtIndex(1, id.SYSVAR_RECENT_BLOCKHASHES_ID);
    const recent_blockhashes = try eic.getSysvar(sysvar.RecentBlockhashes);

    if (recent_blockhashes.isEmpty()) {
        eic.log("Advance nonce account: recent blockhash list is empty", .{});
        eic.setCustomError(SystemError.NonceNoRecentBlockhashes);
        return error.Custom;
    }

    try advanceNonceAccount(eic, account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
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

    return withdrawNonceAccount(eic, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    eic: *ExecuteInstructionContext,
    authority: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.deinit();

    try eic.checkAccountAtIndex(1, id.SYSVAR_RECENT_BLOCKHASHES_ID);
    const recent_blockhashes = try eic.getSysvar(sysvar.RecentBlockhashes);

    if (recent_blockhashes.isEmpty()) {
        eic.log("Initialize nonce account: recent blockhash list is empty", .{});
        eic.setCustomError(SystemError.NonceNoRecentBlockhashes);
        return error.Custom;
    }

    try eic.checkAccountAtIndex(3, id.SYSVAR_RENT_ID);
    const rent = try eic.getSysvar(sysvar.Rent);

    try initializeNonceAccount(
        eic,
        account,
        authority,
        rent,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L466-L469
fn executeAuthorizeNonceAccount(
    eic: *ExecuteInstructionContext,
    authority: Pubkey,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    return authorizeNonceAccount(
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
    defer account.deinit();
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
    defer account.deinit();
    try checkSeedAddress(
        eic,
        account.getPubkey(),
        base,
        seed,
        owner,
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
    defer account.deinit();
    try checkSeedAddress(
        eic,
        account.getPubkey(),
        base,
        seed,
        owner,
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
        from_seed,
        from_owner,
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
    eic: *ExecuteInstructionContext,
) !void {
    try eic.checkNumberOfAccounts(1);
    var account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    if (!account.getOwner().equals(id.SYSTEM_PROGRAM_ID)) return .InvalidAccountOwner;
    if (!account.isWritable()) return .InvalidArgument;
    switch (try account.getState(nonce.Versions)) {
        .legacy => |*state| {
            switch (state) {
                .unintialized => {},
                .initialized => |*data| {
                    data.durable_nonce = nonce.createDurableNonce(data.getDurableNonce());
                    account.setState(nonce.Versions.current(state.*));
                },
            }
        },
        .current => |_| return .InvalidArgument,
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

    const has_data = account.hasData();
    const prog_id_correct = !id.SYSTEM_PROGRAM_ID.equals(&account.getOwner());

    std.debug.print("\naccount.hasData()={}\n", .{has_data});
    std.debug.print("!id.SYSTEM_PROGRAM_ID.equals(&account.getOwner())={}\n", .{prog_id_correct});
    std.debug.print("account.hasData() or !id.SYSTEM_PROGRAM_ID.equals(&account.getOwner())={}\n", .{has_data or prog_id_correct});

    if (account.hasData() or !id.SYSTEM_PROGRAM_ID.equals(&account.getOwner())) {
        eic.log("Allocate: account {} already in use", .{account.getPubkey()});
        eic.setCustomError(@intFromError(SystemError.AccountAlreadyInUse));
        return error.Custom;
    }

    if (space > MAX_PERMITTED_DATA_LENGTH) {
        eic.log("Allocate: requested {}, max allowed {}", .{ space, MAX_PERMITTED_DATA_LENGTH });
        eic.setCustomError(@intFromError(SystemError.InvalidAccountDataLength));
        return error.Custom;
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
    if (account.getOwner().equals(owner)) return null;

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
        defer account.deinit();

        if (account.getLamports() > 0) {
            eic.log("Create Account: account {} already in use", .{account.getPubkey()});
            eic.setCustomError(SystemError.AccountAlreadyInUse);
            return error.Custom;
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
        eic.log("Transfer: `from` account {} must sign", .{eic.getAccountPubkey(from_index)});
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
        defer account.deinit();

        if (account.hasData()) {
            eic.log("Transfer: `from` must not carry data", .{});
            return .InvalidArgument;
        }

        if (lamports > account.getLamports()) {
            eic.log("Transfer: insufficient lamports {}, need {}", .{});
            eic.setCustomError(SystemError.ResultWithNegativeLamports);
            return error.Custom;
        }

        account.subtractLamports(lamports);
    }

    var account = try eic.getBorrowedAccount(to_index);
    defer account.deinit();
    account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
) !void {
    if (!account.isWritable()) {
        eic.log("Advance nonce account: Account {} must be writeable", .{account.getPubkey()});
        return .InvalidArgument;
    }

    const versioned_nonce = try account.getState(nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.log("Advance nonce account: Account {} state is invalid", .{account.getPubkey()});
            return .InvalidAccountData;
        },
        .initialized => |data| {
            eic.checkIsSigner(Pubkey, data.authority) catch |err| {
                eic.log("Advance nonce account: Account {} must be a signer", .{data.authority});
                return err;
            };

            const next_durable_nonce = nonce.createDurableNonce(eic.getBlockhash());

            if (data.durable_nonce.eql(next_durable_nonce)) {
                eic.log("Advance nonce account: nonce can only advance once per slot");
                eic.setCustomError(SystemError.NonceBlockhashNotExpired);
                return error.Custom;
            }

            account.setState(
                nonce.Versions.current(nonce.State.initialized(nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    eic.getLamportsPerSignature(),
                ))),
            );
        },
    }
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L73-L74
fn withdrawNonceAccount(
    eic: *ExecuteInstructionContext,
    lamports: u64,
    rent: Rent,
) !void {
    const from_account_index = 0;
    const to_account_index = 1;

    {
        const from_account = try eic.getBorrowedAccount(from_account_index);

        if (!from_account.isWritable()) {
            eic.log("Withdraw nonce account: Account {} must be writeable", .{from_account.getPubkey()});
            return .InvalidArgument;
        }

        const versioned_nonce = try from_account.getState(nonce.Versions);
        const authority = switch (versioned_nonce.getState()) {
            .unintialized => blk: {
                if (lamports > from_account.getLamports()) {
                    eic.log("Withdraw nonce account: insufficient lamports {}, need {}", .{});
                    return .InsufficientFunds;
                }
                break :blk from_account.getPubkey();
            },
            .initialized => |data| blk: {
                if (lamports == from_account.getLamports()) {
                    const durable_nonce = nonce.createDurableNonce(eic.getBlockhash());
                    if (durable_nonce.eql(data.durable_nonce)) {
                        eic.log("Withdraw nonce account: nonce can only advance once per slot");
                        eic.setCustomError(SystemError.NonceBlockhashNotExpired);
                        return error.Custom;
                    }
                    from_account.setState(nonce.Versions.current(nonce.State.unintialized));
                } else {
                    const min_balance = rent.mimimumBalance(from_account.getData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch {
                        return .InsufficientFunds;
                    };
                    if (amount > from_account.getLamports()) {
                        eic.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
                            from_account.getLamports(),
                            amount,
                        });
                        return .InsufficientFunds;
                    }
                }
                break :blk data.authority;
            },
        };

        eic.checkIsSigner(Pubkey, authority) catch |err| {
            eic.log("Withdraw nonce account: Account {} must sign", .{authority});
            return err;
        };

        from_account.subtractLamports(lamports);
    }

    const to_account = try eic.getBorrowedAccount(to_account_index);
    to_account.addLamports(lamports);
}

fn initializeNonceAccount(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    authority: Pubkey,
    rent: Rent,
) !void {
    if (!account.isWritable()) {
        eic.log("Initialize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return .InvalidArgument;
    }

    const versioned_nonce = try account.getState(nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            const min_balance = rent.mimimumBalance(account.getData().len);
            if (min_balance > account.getLamports()) {
                eic.log("Initialize nonce account: insufficient lamports {}, need {}", .{
                    account.getLamports(),
                    min_balance,
                });
                return .InsufficientFunds;
            }
            account.setState(nonce.Versions.current(nonce.State.initialized(nonce.Data.init(
                authority,
                nonce.createDurableNonce(eic.getBlockhash()),
                eic.getLamportsPerSignature(),
            ))));
        },
        .initialized => |_| {
            eic.log("Initialize nonce account: Account {} state is invalid", .{account.getPubkey()});
            return .InvalidAccountData;
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L203
pub fn authorizeNonceAccount(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    authority: Pubkey,
) !void {
    if (!account.isWritable()) {
        eic.log("Authorize nonce account: Account {} must be writeable", .{account.getPubkey()});
        return .InvalidArgument;
    }

    const versioned_nonce = try account.getState(nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .unintialized => {
            eic.log("Authorize nonce account: Account {} state is invalid", .{account.getPubkey()});
            return .InvalidAccountData;
        },
        .initialized => |data| data,
    };

    eic.checkIsSigner(Pubkey, nonce_data.authority) catch |err| {
        eic.log("Authorize nonce account: Account {} must sign", .{nonce_data.authority});
        return err;
    };

    const nonce_stace = nonce.State.initialized(nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.getLamportsPerSignature(),
    ));

    switch (versioned_nonce) {
        .legacy => account.setState(nonce.Versions.legacy(nonce_stace)),
        .current => account.setState(nonce.Versions.current(nonce_stace)),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L47-L58
fn checkSeedAddress(
    eic: *ExecuteInstructionContext,
    expected: Pubkey,
    base: Pubkey,
    owner: Pubkey,
    seed: []const u8,
    log_err_fmt: []const u8,
) !void {
    const created = try pubkey_utils.createWithSeed(eic, base, seed, owner);
    if (!expected.equals(created)) {
        eic.log(log_err_fmt, .{ expected, created });
        eic.setCustomError(SystemError.AddressWithSeedMismatch);
        return error.Custom;
    }
}

test "executeAllocate" {
    const Hash = sig.core.Hash;
    const SysvarCache = sig.runtime.SysvarCache;
    const Transaction = sig.core.Transaction;
    const RwMux = sig.sync.RwMux;
    const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;

    const MAX_INSTRUCTION_ACCOUNTS = sig.runtime.MAX_INSTRUCTION_ACCOUNTS;

    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(5083);

    const etc_account_info: ExecuteTransactionContext.AccountInfo = .{
        .touched = false,
        .account = .{
            .lamports = 0,
            .data = .{},
            .owner = id.SYSTEM_PROGRAM_ID,
            .executable = false,
            .rent_epoch = 0,
        },
    };

    var etc_accounts = try std.BoundedArray(
        RwMux(ExecuteTransactionContext.AccountInfo),
        Transaction.MAX_ACCOUNTS,
    ).init(0);
    try etc_accounts.append(RwMux(ExecuteTransactionContext.AccountInfo).init(etc_account_info));

    var etc: ExecuteTransactionContext = .{
        .accounts = etc_accounts,
        .accounts_resize_delta = 0,
        .compute_meter = 0,
        .maybe_custom_error = null,
        .maybe_log_collector = null,
        .sysvar_cache = SysvarCache.default(),
        .lamports_per_signature = 5000,
        .last_blockhash = Hash.ZEROES,
    };

    var eic_accounts = try std.BoundedArray(
        ExecuteInstructionContext.AccountInfo,
        MAX_INSTRUCTION_ACCOUNTS,
    ).init(0);
    try eic_accounts.append(.{
        .pubkey = Pubkey.initRandom(prng.random()),
        .is_signer = true,
        .is_writable = true,
        .index_in_transaction = 0,
    });

    var eic: ExecuteInstructionContext = .{
        .etc = &etc,
        .program_id = id.SYSTEM_PROGRAM_ID,
        .accounts = eic_accounts,
    };

    try executeAllocate(allocator, &eic, 1024);
}
