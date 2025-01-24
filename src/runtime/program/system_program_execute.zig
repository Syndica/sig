const std = @import("std");
const sig = @import("../../sig.zig");

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;

const Pubkey = sig.core.Pubkey;
const Rent = sig.runtime.sysvar.Rent;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const InstructionError = sig.core.instruction.InstructionError;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const SystemError = sig.runtime.program.system_program.SystemProgramError;
const SystemInstruction = sig.runtime.program.system_program.SystemProgramInstruction;

const SYSTEM_PROGRAM_ID = sig.runtime.id.SYSTEM_PROGRAM_ID;
const MAX_PERMITTED_DATA_LENGTH = sig.runtime.program.system_program.MAX_PERMITTED_DATA_LENGTH;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn executeSystemProgramInstruction(eic: *ExecuteInstructionContext) InstructionError!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    eic.consumeCompute(150);

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try SystemInstruction.deserialize(eic.instruction_data);
    return switch (instruction) {
        .create_account => |args| try executeCreateAccount(
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
            eic,
            args.space,
        ),
        .allocate_with_seed => |args| try executeAllocateWithSeed(
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
    eic: *ExecuteInstructionContext,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(2);
    try createAccount(eic, 0, 1, lamports, space, owner, try eic.getAccountPubkey(1));
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L365-L375
fn executeAssign(
    eic: *ExecuteInstructionContext,
    owner: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    try assign(eic, account, owner, account.getPubkey());
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L378-L386
fn executeTransfer(
    eic: *ExecuteInstructionContext,
    lamports: u64,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(2);
    try transfer(eic, 0, 1, lamports);
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L343-L362
fn executeCreateAccountWithSeed(
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(2);
    try checkSeedAddress(
        eic,
        eic.getAccountPubkey(1),
        base,
        seed,
        owner,
        "Create: address {} does not match derived address {}",
    );
    try createAccount(eic, 0, 1, lamports, space, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L407-L423
fn executeAdvanceNonceAccount(
    eic: *ExecuteInstructionContext,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    // TODO: Implement recent blockhashes sysvar
    // const recent_blockhashes = try get_sysvar_with_account_check.recent_blockhashes(
    //     eic.execute_transaction_context,
    //     eic,
    //     1,
    // );
    // if (recent_blockhashes.isEmpty()) {
    //     eic.log("Advance nonce account: recent blockhash list is empty", .{});
    //     eic.setCustomError(SystemError.NonceNoRecentBlockhashes);
    //     return .Custom;
    // }
    try advanceNonceAccount(eic, account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
    eic: *ExecuteInstructionContext,
    lamports: u64,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(2);
    // TODO: Implement recent blockhashes sysvar
    // const recent_blockhashes = try get_sysvar_with_account_check.recent_blockhashes(
    //     eic.execute_transaction_context,
    //     eic,
    //     2,
    // );
    // TODO: Implement rent sysvar
    // const rent = try get_sysvar_with_account_check.rent(
    //     eic.execute_transaction_context,
    //     eic,
    //     3,
    // );
    const rent = Rent{
        .lamports_per_byte_year = 0,
        .exemption_threshold = 0,
        .burn_percent = 0,
    };
    return withdrawNonceAccount(eic, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    eic: *ExecuteInstructionContext,
    authority: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    // TODO: Implement recent blockhashes sysvar
    // const recent_blockhashes = try get_sysvar_with_account_check.recent_blockhashes(
    //     eic.execute_transaction_context,
    //     eic,
    //     1,
    // );
    // TODO: Implement rent sysvar
    // if (recent_blockhashes.isEmpty()) {
    //     eic.log("Initialize nonce account: recent blockhash list is empty", .{});
    //     eic.setCustomError(SystemError.NonceNoRecentBlockhashes);
    //     return .Custom;
    // }
    const rent = Rent{
        .lamports_per_byte_year = 0,
        .exemption_threshold = 0,
        .burn_percent = 0,
    };
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
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    return authorizeNonceAccount(
        eic,
        account,
        authority,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L488-L498
fn executeAllocate(
    eic: *ExecuteInstructionContext,
    space: u64,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    try allocate(eic, account, space, account.getPubkey());
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L506-L523
fn executeAllocateWithSeed(
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    try checkSeedAddress(
        eic,
        account.getPubkey(),
        base,
        seed,
        owner,
        "Create: address {} does not match derived address {}",
    );
    try allocate(eic, account, space, base);
    try assign(eic, account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L526-L536
fn executeAssignWithSeed(
    eic: *ExecuteInstructionContext,
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
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
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(3);

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
) InstructionError!void {
    try eic.checkNumberOfInstructionAccounts(1);
    const account = try eic.getBorrowedAccount(0);
    defer account.deinit();
    if (!account.getOwner().equals(SYSTEM_PROGRAM_ID)) return .InvalidAccountOwner;
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
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    space: u64,
    authority: Pubkey,
) InstructionError!void {
    eic.checkIsSigner(Pubkey, authority) catch |err| {
        eic.log("Allocate: 'base' account {} must sign", .{account.getPubkey()});
        return err;
    };

    if (account.hasData() || !SYSTEM_PROGRAM_ID.equals(account.getOwner())) {
        eic.log("Allocate: account {} already in use", .{account.getPubkey()});
        eic.setCustomError(SystemError.AccountAlreadyInUse);
        return .Custom;
    }

    if (space > MAX_PERMITTED_DATA_LENGTH) {
        eic.log("Allocate: requested {}, max allowed {}", .{ space, MAX_PERMITTED_DATA_LENGTH });
        eic.setCustomError(SystemError.InvalidAccountDataLength);
        return .Custom;
    }

    try account.setDataLength(@intCast(space));
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L112
fn assign(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
    owner: Pubkey,
    authority: Pubkey,
) InstructionError!void {
    if (account.getOwner().equals(owner)) return null;

    eic.checkIsSigner(Pubkey, authority) catch |err| {
        eic.log("Assign: 'base' account {} must sign", .{account.getPubkey()});
        return err;
    };

    return account.setOwner(owner);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L145
fn createAccount(
    eic: *ExecuteInstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
    space: u64,
    owner: Pubkey,
    authority: Pubkey,
) InstructionError!void {
    {
        const account = try eic.getBorrowedAccount(to_index);
        defer account.deinit();

        if (account.getLamports() > 0) {
            eic.log("Create Account: account {} already in use", .{account.getPubkey()});
            eic.setCustomError(SystemError.AccountAlreadyInUse);
            return .Custom;
        }

        try allocate(eic, account, space, authority);
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
) InstructionError!void {
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
) InstructionError!void {
    {
        const account = try eic.getBorrowedAccount(from_index);
        defer account.deinit();

        if (account.hasData()) {
            eic.log("Transfer: `from` must not carry data", .{});
            return .InvalidArgument;
        }

        if (lamports > account.getLamports()) {
            eic.log("Transfer: insufficient lamports {}, need {}", .{});
            eic.setCustomError(SystemError.ResultWithNegativeLamports);
            return .Custom;
        }

        account.subtractLamports(lamports);
    }

    const account = try eic.getBorrowedAccount(to_index);
    defer account.deinit();
    account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    eic: *ExecuteInstructionContext,
    account: BorrowedAccount,
) InstructionError!void {
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
                return .Custom;
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
) InstructionError!void {
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
                        return .Custom;
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
) InstructionError!void {
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
) InstructionError!void {
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
) InstructionError!void {
    const created = try pubkey_utils.createWithSeed(eic, base, seed, owner);
    if (!expected.equals(created)) {
        eic.log(log_err_fmt, .{ expected, created });
        eic.setCustomError(SystemError.AddressWithSeedMismatch);
        return .Custom;
    }
}
