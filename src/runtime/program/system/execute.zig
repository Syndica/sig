const std = @import("std");
const sig = @import("../../../sig.zig");

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;
const system_program = sig.runtime.program.system_program;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const SystemProgramInstruction = system_program.Instruction;
const SystemProgramError = system_program.Error;

const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn execute(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    try ixn_ctx.txn_ctx.consumeCompute(system_program.COMPUTE_UNITS);

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try ixn_ctx.ixn_info.deserializeInstruction(
        allocator,
        SystemProgramInstruction,
    );
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .create_account => |args| try executeCreateAccount(
            allocator,
            ixn_ctx,
            args.lamports,
            args.space,
            args.owner,
        ),
        .assign => |args| try executeAssign(
            ixn_ctx,
            args.owner,
        ),
        .transfer => |args| try executeTransfer(
            ixn_ctx,
            args.lamports,
        ),
        .create_account_with_seed => |args| try executeCreateAccountWithSeed(
            allocator,
            ixn_ctx,
            args.base,
            args.seed,
            args.lamports,
            args.space,
            args.owner,
        ),
        .advance_nonce_account => try executeAdvanceNonceAccount(
            allocator,
            ixn_ctx,
        ),
        .withdraw_nonce_account => |arg| try executeWithdrawNonceAccount(
            allocator,
            ixn_ctx,
            arg,
        ),
        .initialize_nonce_account => |arg| try executeInitializeNonceAccount(
            allocator,
            ixn_ctx,
            arg,
        ),
        .authorize_nonce_account => |arg| try executeAuthorizeNonceAccount(
            allocator,
            ixn_ctx,
            arg,
        ),
        .allocate => |args| try executeAllocate(
            allocator,
            ixn_ctx,
            args.space,
        ),
        .allocate_with_seed => |args| try executeAllocateWithSeed(
            allocator,
            ixn_ctx,
            args.base,
            args.seed,
            args.space,
            args.owner,
        ),
        .assign_with_seed => |args| try executeAssignWithSeed(
            ixn_ctx,
            args.base,
            args.seed,
            args.owner,
        ),
        .transfer_with_seed => |args| try executeTransferWithSeed(
            ixn_ctx,
            args.lamports,
            args.from_seed,
            args.from_owner,
        ),
        .upgrade_nonce_account => try executeUpgradeNonceAccount(
            allocator,
            ixn_ctx,
        ),
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L315-L334
fn executeCreateAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(2);
    try createAccount(
        allocator,
        ixn_ctx,
        0,
        1,
        lamports,
        space,
        owner,
        ixn_ctx.ixn_info.account_metas.buffer[1].pubkey,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L365-L375
fn executeAssign(
    ixn_ctx: *InstructionContext,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);
    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();
    try assign(
        ixn_ctx,
        &account,
        owner,
        account.pubkey,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L378-L386
fn executeTransfer(
    ixn_ctx: *InstructionContext,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(2);
    try transfer(
        ixn_ctx,
        0,
        1,
        lamports,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L343-L362
fn executeCreateAccountWithSeed(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(2);
    try checkSeedAddress(
        ixn_ctx,
        ixn_ctx.ixn_info.account_metas.buffer[1].pubkey,
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try createAccount(
        allocator,
        ixn_ctx,
        0,
        1,
        lamports,
        space,
        owner,
        base,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L407-L423
fn executeAdvanceNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ixn_ctx.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ixn_ctx.txn_ctx.log("Advance nonce account: recent blockhash list is empty", .{});
        ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.NonceNoRecentBlockhashes);
        return InstructionError.Custom;
    }

    try advanceNonceAccount(allocator, ixn_ctx, &account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(2);

    // TODO: Is this sysvar call required for consensus despite being unused?
    _ = try ixn_ctx.getSysvarWithAccountCheck(RecentBlockhashes, 2);

    const rent = try ixn_ctx.getSysvarWithAccountCheck(Rent, 3);

    return withdrawNonceAccount(allocator, ixn_ctx, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ixn_ctx.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ixn_ctx.txn_ctx.log("Initialize nonce account: recent blockhash list is empty", .{});
        ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.NonceNoRecentBlockhashes);
        return InstructionError.Custom;
    }

    const rent = try ixn_ctx.getSysvarWithAccountCheck(Rent, 2);

    try initializeNonceAccount(
        allocator,
        ixn_ctx,
        &account,
        authority,
        rent,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L466-L469
fn executeAuthorizeNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    return authorizeNonceAccount(
        allocator,
        ixn_ctx,
        &account,
        authority,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L488-L498
fn executeAllocate(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    space: u64,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    try allocate(allocator, ixn_ctx, &account, space, account.pubkey);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L506-L523
fn executeAllocateWithSeed(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    try checkSeedAddress(
        ixn_ctx,
        account.pubkey,
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );

    try allocate(allocator, ixn_ctx, &account, space, base);
    try assign(ixn_ctx, &account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L526-L536
fn executeAssignWithSeed(
    ixn_ctx: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    try checkSeedAddress(
        ixn_ctx,
        account.pubkey,
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );

    try assign(ixn_ctx, &account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L393-L404
fn executeTransferWithSeed(
    ixn_ctx: *InstructionContext,
    lamports: u64,
    from_seed: []const u8,
    from_owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(3);

    const from_index = 0;
    const from_base_index = 1;
    const to_index = 2;

    const from_base_pubkey = ixn_ctx.ixn_info.account_metas.buffer[from_base_index].pubkey;
    const from_pubkey = ixn_ctx.ixn_info.account_metas.buffer[from_index].pubkey;

    if (!try ixn_ctx.ixn_info.isIndexSigner(from_base_index)) {
        try ixn_ctx.txn_ctx.log("Transfer: `from` account {} must sign", .{from_base_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    try checkSeedAddress(
        ixn_ctx,
        from_pubkey,
        from_base_pubkey,
        from_owner,
        from_seed,
        "Transfer: 'from' address {} does not match derived address {}",
    );

    try transferVerified(
        ixn_ctx,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L472-L485
fn executeUpgradeNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    try ixn_ctx.ixn_info.checkNumberOfAccounts(1);

    var account = try ixn_ctx.borrowInstructionAccount(0);
    defer account.release();

    if (!account.account.owner.equals(&system_program.ID))
        return InstructionError.InvalidAccountOwner;

    if (!account.context.is_writable) return InstructionError.InvalidArgument;

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);
    switch (versioned_nonce) {
        .legacy => |state| {
            if (state == nonce.State.initialized) {
                var data = state.initialized;
                data.durable_nonce = nonce.createDurableNonce(data.durable_nonce);
                try account.serializeIntoAccountData(nonce.Versions{ .current = state });
            }
        },
        .current => |_| return InstructionError.InvalidArgument,
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#70
fn allocate(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    account: *BorrowedAccount,
    space: u64,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ixn_ctx.ixn_info.isPubkeySigner(authority)) {
        try ixn_ctx.txn_ctx.log("Allocate: 'base' account {} must sign", .{account.pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    if (account.constAccountData().len > 0 or !account.account.owner.equals(&system_program.ID)) {
        try ixn_ctx.txn_ctx.log("Allocate: account {} already in use", .{account.pubkey});
        ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.AccountAlreadyInUse);
        return InstructionError.Custom;
    }

    if (space > system_program.MAX_PERMITTED_DATA_LENGTH) {
        try ixn_ctx.txn_ctx.log(
            "Allocate: requested {}, max allowed {}",
            .{ space, system_program.MAX_PERMITTED_DATA_LENGTH },
        );
        ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.InvalidAccountDataLength);
        return InstructionError.Custom;
    }

    try account.setDataLength(allocator, &ixn_ctx.txn_ctx.accounts_resize_delta, @intCast(space));
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L112
fn assign(
    ixn_ctx: *InstructionContext,
    account: *BorrowedAccount,
    owner: Pubkey,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (account.account.owner.equals(&owner)) return;

    if (!ixn_ctx.ixn_info.isPubkeySigner(authority)) {
        try ixn_ctx.txn_ctx.log("Assign: 'base' account {} must sign", .{account.pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    try account.setOwner(owner);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L145
fn createAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
    space: u64,
    owner: Pubkey,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    {
        var account = try ixn_ctx.borrowInstructionAccount(to_index);
        defer account.release();

        if (account.account.lamports > 0) {
            try ixn_ctx.txn_ctx.log(
                "Create Account: account {} already in use",
                .{account.pubkey},
            );
            ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.AccountAlreadyInUse);
            return InstructionError.Custom;
        }

        try allocate(allocator, ixn_ctx, &account, space, authority);
        try assign(ixn_ctx, &account, owner, authority);
    }

    return transfer(
        ixn_ctx,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L214
fn transfer(
    ixn_ctx: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    if (!try ixn_ctx.ixn_info.isIndexSigner(from_index)) {
        try ixn_ctx.txn_ctx.log(
            "Transfer: `from` account {} must sign",
            .{ixn_ctx.ixn_info.account_metas.buffer[from_index].pubkey},
        );
        return InstructionError.MissingRequiredSignature;
    }

    return transferVerified(
        ixn_ctx,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L182
fn transferVerified(
    ixn_ctx: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    {
        var account = try ixn_ctx.borrowInstructionAccount(from_index);
        defer account.release();

        if (account.constAccountData().len > 0) {
            try ixn_ctx.txn_ctx.log("Transfer: `from` must not carry data", .{});
            return InstructionError.InvalidArgument;
        }

        if (lamports > account.account.lamports) {
            try ixn_ctx.txn_ctx.log(
                "Transfer: insufficient lamports {}, need {}",
                .{ account.account.lamports, lamports },
            );
            ixn_ctx.txn_ctx.custom_error =
                @intFromEnum(SystemProgramError.ResultWithNegativeLamports);
            return InstructionError.Custom;
        }

        try account.subtractLamports(lamports);
    }

    var account = try ixn_ctx.borrowInstructionAccount(to_index);
    defer account.release();

    try account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    account: *BorrowedAccount,
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ixn_ctx.txn_ctx.log(
            "Advance nonce account: Account {} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            try ixn_ctx.txn_ctx.log(
                "Advance nonce account: Account {} state is invalid",
                .{account.pubkey},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| {
            if (!ixn_ctx.ixn_info.isPubkeySigner(data.authority)) {
                try ixn_ctx.txn_ctx.log(
                    "Advance nonce account: Account {} must be a signer",
                    .{data.authority},
                );
                return InstructionError.MissingRequiredSignature;
            }

            const next_durable_nonce = nonce.createDurableNonce(ixn_ctx.txn_ctx.prev_blockhash);

            if (data.durable_nonce.eql(next_durable_nonce)) {
                try ixn_ctx.txn_ctx.log(
                    "Advance nonce account: nonce can only advance once per slot",
                    .{},
                );
                ixn_ctx.txn_ctx.custom_error =
                    @intFromEnum(SystemProgramError.NonceBlockhashNotExpired);
                return InstructionError.Custom;
            }

            try account.serializeIntoAccountData(
                nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    ixn_ctx.txn_ctx.prev_lamports_per_signature,
                ) } },
            );
        },
    }
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L73-L74
fn withdrawNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    lamports: u64,
    rent: Rent,
) (error{OutOfMemory} || InstructionError)!void {
    const from_account_index = 0;
    const to_account_index = 1;

    {
        var from_account = try ixn_ctx.borrowInstructionAccount(from_account_index);
        defer from_account.release();

        if (!from_account.context.is_writable) {
            try ixn_ctx.txn_ctx.log(
                "Withdraw nonce account: Account {} must be writeable",
                .{from_account.pubkey},
            );
            return InstructionError.InvalidArgument;
        }

        const versioned_nonce = try from_account.deserializeFromAccountData(
            allocator,
            nonce.Versions,
        );
        const authority = switch (versioned_nonce.getState()) {
            .unintialized => blk: {
                if (lamports > from_account.account.lamports) {
                    try ixn_ctx.txn_ctx.log(
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        .{ from_account.account.lamports, lamports },
                    );
                    return InstructionError.InsufficientFunds;
                }
                break :blk from_account.pubkey;
            },
            .initialized => |data| blk: {
                if (lamports == from_account.account.lamports) {
                    const durable_nonce =
                        nonce.createDurableNonce(ixn_ctx.txn_ctx.prev_blockhash);
                    if (durable_nonce.eql(data.durable_nonce)) {
                        try ixn_ctx.txn_ctx.log(
                            "Withdraw nonce account: nonce can only advance once per slot",
                            .{},
                        );
                        ixn_ctx.txn_ctx.custom_error =
                            @intFromEnum(SystemProgramError.NonceBlockhashNotExpired);
                        return InstructionError.Custom;
                    }
                    try from_account.serializeIntoAccountData(
                        nonce.Versions{ .current = nonce.State.unintialized },
                    );
                } else {
                    const min_balance = rent.minimumBalance(from_account.constAccountData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch
                        return InstructionError.InsufficientFunds;
                    if (amount > from_account.account.lamports) {
                        try ixn_ctx.txn_ctx.log(
                            "Withdraw nonce account: insufficient lamports {}, need {}",
                            .{
                                from_account.account.lamports,
                                amount,
                            },
                        );
                        return InstructionError.InsufficientFunds;
                    }
                }
                break :blk data.authority;
            },
        };

        if (!ixn_ctx.ixn_info.isPubkeySigner(authority)) {
            try ixn_ctx.txn_ctx.log("Withdraw nonce account: Account {} must sign", .{authority});
            return InstructionError.MissingRequiredSignature;
        }

        try from_account.subtractLamports(lamports);
    }

    var to_account = try ixn_ctx.borrowInstructionAccount(to_account_index);
    defer to_account.release();
    try to_account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L155
fn initializeNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    account: *BorrowedAccount,
    authority: Pubkey,
    rent: Rent,
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ixn_ctx.txn_ctx.log(
            "Initialize nonce account: Account {} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            const min_balance = rent.minimumBalance(account.constAccountData().len);
            if (min_balance > account.account.lamports) {
                try ixn_ctx.txn_ctx.log(
                    "Initialize nonce account: insufficient lamports {}, need {}",
                    .{
                        account.account.lamports,
                        min_balance,
                    },
                );
                return InstructionError.InsufficientFunds;
            }
            try account.serializeIntoAccountData(nonce.Versions{
                .current = nonce.State{ .initialized = nonce.Data.init(
                    authority,
                    nonce.createDurableNonce(ixn_ctx.txn_ctx.prev_blockhash),
                    ixn_ctx.txn_ctx.prev_lamports_per_signature,
                ) },
            });
        },
        .initialized => |_| {
            try ixn_ctx.txn_ctx.log(
                "Initialize nonce account: Account {} state is invalid",
                .{account.pubkey},
            );
            return InstructionError.InvalidAccountData;
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L203
pub fn authorizeNonceAccount(
    allocator: std.mem.Allocator,
    ixn_ctx: *InstructionContext,
    account: *BorrowedAccount,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ixn_ctx.txn_ctx.log(
            "Authorize nonce account: Account {} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .unintialized => {
            try ixn_ctx.txn_ctx.log(
                "Authorize nonce account: Account {} state is invalid",
                .{account.pubkey},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| data,
    };

    if (!ixn_ctx.ixn_info.isPubkeySigner(nonce_data.authority)) {
        try ixn_ctx.txn_ctx.log(
            "Authorize nonce account: Account {} must sign",
            .{nonce_data.authority},
        );
        return InstructionError.MissingRequiredSignature;
    }

    const nonce_state = nonce.State{ .initialized = nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.fee_calculator.lamports_per_signature,
    ) };

    switch (versioned_nonce) {
        .legacy => try account.serializeIntoAccountData(nonce.Versions{ .legacy = nonce_state }),
        .current => try account.serializeIntoAccountData(nonce.Versions{ .current = nonce_state }),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L47-L58
fn checkSeedAddress(
    ixn_ctx: *InstructionContext,
    expected: Pubkey,
    base: Pubkey,
    owner: Pubkey,
    seed: []const u8,
    comptime log_err_fmt: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    const created = pubkey_utils.createWithSeed(base, seed, owner) catch |err| {
        ixn_ctx.txn_ctx.custom_error = pubkey_utils.mapError(err);
        return InstructionError.Custom;
    };
    if (!expected.equals(&created)) {
        try ixn_ctx.txn_ctx.log(log_err_fmt, .{ expected, created });
        ixn_ctx.txn_ctx.custom_error = @intFromEnum(SystemProgramError.AddressWithSeedMismatch);
        return InstructionError.Custom;
    }
}

test "executeCreateAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .create_account = .{
                .lamports = 1_000_000,
                .space = 2,
                .owner = system_program.ID,
            },
        },
        &.{
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key, .owner = system_program.ID },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 150,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{
                    .pubkey = account_1_key,
                    .owner = system_program.ID,
                    .lamports = 1_000_000,
                    .data = &[_]u8{ 0, 0 },
                },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .accounts_resize_delta = 2,
        },
        .{},
    );
}

test "executeAssign" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const new_owner = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .assign = .{
                .owner = new_owner,
            },
        },
        &.{
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = system_program.ID },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = new_owner },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeTransfer" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .transfer = .{
                .lamports = 1_000_000,
            },
        },
        &.{
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = account_1_key, .lamports = 1_000_000 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeCreateAccountWithSeed" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = try pubkey_utils.createWithSeed(base, seed, system_program.ID);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .create_account_with_seed = .{
                .base = base,
                .seed = seed,
                .lamports = 1_000_000,
                .space = 0,
                .owner = system_program.ID,
            },
        },
        &.{
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key, .owner = system_program.ID },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = account_1_key, .owner = system_program.ID, .lamports = 1_000_000 },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeAdvanceNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    // Last Blockhash is used to compute the next durable nonce
    const prev_blockhash = Hash.initRandom(prng.random());

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
                nonce.createDurableNonce(prev_blockhash), // Updated
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

    const account_0_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        allocator,
        system_program.ID,
        SystemProgramInstruction{
            .advance_nonce_account = {},
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
            .prev_blockhash = prev_blockhash,
            .prev_lamports_per_signature = lamports_per_signature,
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = final_nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .prev_blockhash = prev_blockhash,
            .prev_lamports_per_signature = lamports_per_signature,
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
            },
        },
        .{},
    );
}

test "executeWithdrawNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
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
    const rent = Rent.DEFAULT;
    const rent_minimum_balance = rent.minimumBalance(sig.bincode.sizeOf(nonce_state, .{}));

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        allocator,
        system_program.ID,
        SystemProgramInstruction{
            .withdraw_nonce_account = 1_000,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 4 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .lamports = 2 * withdraw_lamports + rent_minimum_balance,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = account_1_key },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .lamports = withdraw_lamports + rent_minimum_balance,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = account_1_key, .lamports = withdraw_lamports },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
                .rent = rent,
            },
        },
        .{},
    );
}

test "executeInitializeNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    // Last Blockhash is used to compute the next durable nonce
    const prev_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Final Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{ .initialized = nonce.Data.init(
            nonce_authority,
            nonce.createDurableNonce(prev_blockhash),
            lamports_per_signature,
        ) },
    };
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
    const rent = Rent.DEFAULT;

    const account_0_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        allocator,
        system_program.ID,
        SystemProgramInstruction{
            .initialize_nonce_account = nonce_authority,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
            .prev_lamports_per_signature = lamports_per_signature,
            .prev_blockhash = prev_blockhash,
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
                .rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                    .data = final_nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .prev_lamports_per_signature = lamports_per_signature,
            .prev_blockhash = prev_blockhash,
            .sysvar_cache = .{
                .recent_blockhashes = recent_blockhashes,
                .rent = rent,
            },
        },
        .{},
    );
}

test "executeAuthorizeNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
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
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{ .initialized = nonce.Data.init(
            final_nonce_authority,
            durable_nonce,
            0,
        ) },
    };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    const account_0_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        allocator,
        system_program.ID,
        SystemProgramInstruction{
            .authorize_nonce_account = final_nonce_authority,
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = initial_nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = final_nonce_state_bytes,
                },
                .{ .pubkey = initial_nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeAllocate" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const allocation_size = 1024;

    const account_0_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .allocate = .{
                .space = allocation_size,
            },
        },
        &.{
            .{ .is_signer = true, .is_writable = true, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = &[_]u8{0} ** allocation_size,
                },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .accounts_resize_delta = allocation_size,
        },
        .{},
    );
}

test "executeAllocateWithSeed" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const allocation_size = 1024;

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, system_program.ID);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .allocate_with_seed = .{
                .base = base,
                .seed = seed,
                .space = allocation_size,
                .owner = system_program.ID,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = &[_]u8{0} ** 1024,
                },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .accounts_resize_delta = allocation_size,
        },
        .{},
    );
}

test "executeAssignWithSeed" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const owner = Pubkey.initRandom(prng.random());

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, owner);

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .assign_with_seed = .{
                .base = base,
                .seed = seed,
                .owner = owner,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = system_program.ID },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = owner },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeTransferWithSeed" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const owner = Pubkey.initRandom(prng.random());

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, owner);
    const account_2_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        std.testing.allocator,
        system_program.ID,
        SystemProgramInstruction{
            .transfer_with_seed = .{
                .lamports = 1_000_000,
                .from_seed = seed,
                .from_owner = owner,
            },
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
            .{ .is_signer = true, .is_writable = false, .index_in_transaction = 1 },
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 2 },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = base },
                .{ .pubkey = account_2_key, .lamports = 0 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = base },
                .{ .pubkey = account_2_key, .lamports = 1_000_000 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}

test "executeUpgradeNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const durable_nonce = nonce.createDurableNonce(Hash.initRandom(prng.random()));
    const lamports_per_signature = 5_000;
    const nonce_state = nonce.Versions{
        .legacy = nonce.State{ .initialized = nonce.Data.init(
            nonce_authority,
            durable_nonce,
            lamports_per_signature,
        ) },
    };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Initial Nonce State
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{ .initialized = nonce.Data.init(
            nonce_authority,
            durable_nonce,
            lamports_per_signature,
        ) },
    };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    const account_0_key = Pubkey.initRandom(prng.random());

    try testing.expectProgramExecuteResult(
        allocator,
        system_program.ID,
        SystemProgramInstruction{
            .upgrade_nonce_account = {},
        },
        &.{
            .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .owner = system_program.ID,
                    .data = final_nonce_state_bytes,
                },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
        },
        .{},
    );
}
