const std = @import("std");
const sig = @import("../../sig.zig");

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;
const system_program = sig.runtime.program.system_program;

const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;

const InstructionContext = sig.runtime.InstructionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

const SystemProgramInstruction = system_program.SystemProgramInstruction;
const SystemProgramError = system_program.SystemProgramError;

const RecentBlockhashes = sig.runtime.sysvar.RecentBlockhashes;
const Rent = sig.runtime.sysvar.Rent;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L300
pub fn systemProgramExecute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) InstructionError!void {
    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    try ic.tc.consumeCompute(system_program.computeUnits());

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try ic.deserializeInstruction(allocator, SystemProgramInstruction);
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .create_account => |args| try executeCreateAccount(
            allocator,
            ic,
            args.lamports,
            args.space,
            args.owner,
        ),
        .assign => |args| try executeAssign(
            ic,
            args.owner,
        ),
        .transfer => |args| try executeTransfer(
            ic,
            args.lamports,
        ),
        .create_account_with_seed => |args| try executeCreateAccountWithSeed(
            allocator,
            ic,
            args.base,
            args.seed,
            args.lamports,
            args.space,
            args.owner,
        ),
        .advance_nonce_account => try executeAdvanceNonceAccount(
            allocator,
            ic,
        ),
        .withdraw_nonce_account => |arg| try executeWithdrawNonceAccount(
            allocator,
            ic,
            arg,
        ),
        .initialize_nonce_account => |arg| try executeInitializeNonceAccount(
            allocator,
            ic,
            arg,
        ),
        .authorize_nonce_account => |arg| try executeAuthorizeNonceAccount(
            allocator,
            ic,
            arg,
        ),
        .allocate => |args| try executeAllocate(
            allocator,
            ic,
            args.space,
        ),
        .allocate_with_seed => |args| try executeAllocateWithSeed(
            allocator,
            ic,
            args.base,
            args.seed,
            args.space,
            args.owner,
        ),
        .assign_with_seed => |args| try executeAssignWithSeed(
            ic,
            args.base,
            args.seed,
            args.owner,
        ),
        .transfer_with_seed => |args| try executeTransferWithSeed(
            ic,
            args.lamports,
            args.from_seed,
            args.from_owner,
        ),
        .upgrade_nonce_account => try executeUpgradeNonceAccount(
            allocator,
            ic,
        ),
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L315-L334
fn executeCreateAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(2);
    try createAccount(
        allocator,
        ic,
        0,
        1,
        lamports,
        space,
        owner,
        ic.accounts[1].pubkey,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L365-L375
fn executeAssign(
    ic: *InstructionContext,
    owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    try assign(
        ic,
        &account,
        owner,
        account.getPubkey(),
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L378-L386
fn executeTransfer(
    ic: *InstructionContext,
    lamports: u64,
) !void {
    try ic.checkNumberOfAccounts(2);
    try transfer(
        ic,
        0,
        1,
        lamports,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L343-L362
fn executeCreateAccountWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(2);
    try checkSeedAddress(
        ic,
        ic.accounts[1].pubkey,
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try createAccount(
        allocator,
        ic,
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
    ic: *InstructionContext,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ic.tc.log("Advance nonce account: recent blockhash list is empty", .{});
        ic.tc.maybe_custom_error = @intFromError(SystemProgramError.NonceNoRecentBlockhashes);
        return InstructionError.Custom;
    }

    try advanceNonceAccount(allocator, ic, &account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    lamports: u64,
) !void {
    try ic.checkNumberOfAccounts(2);

    // TODO: Is this sysvar call required for consensus despite being unused?
    _ = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 2);

    const rent = try ic.getSysvarWithAccountCheck(Rent, 3);

    return withdrawNonceAccount(allocator, ic, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    authority: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ic.tc.log("Initialize nonce account: recent blockhash list is empty", .{});
        ic.tc.maybe_custom_error = @intFromError(SystemProgramError.NonceNoRecentBlockhashes);
        return InstructionError.Custom;
    }

    const rent = try ic.getSysvarWithAccountCheck(Rent, 2);

    try initializeNonceAccount(
        allocator,
        ic,
        &account,
        authority,
        rent,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L466-L469
fn executeAuthorizeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    authority: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    return authorizeNonceAccount(
        allocator,
        ic,
        &account,
        authority,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L488-L498
fn executeAllocate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    space: u64,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    try allocate(allocator, ic, &account, space, account.getPubkey());
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L506-L523
fn executeAllocateWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    try checkSeedAddress(
        ic,
        account.getPubkey(),
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try allocate(allocator, ic, &account, space, base);
    try assign(ic, &account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L526-L536
fn executeAssignWithSeed(
    ic: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    try checkSeedAddress(
        ic,
        account.getPubkey(),
        base,
        owner,
        seed,
        "Create: address {} does not match derived address {}",
    );
    try assign(ic, &account, owner, base);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L393-L404
fn executeTransferWithSeed(
    ic: *InstructionContext,
    lamports: u64,
    from_seed: []const u8,
    from_owner: Pubkey,
) !void {
    try ic.checkNumberOfAccounts(3);

    const from_index = 0;
    const from_base_index = 1;
    const to_index = 2;

    const from_base_pubkey = ic.accounts[from_base_index].pubkey;
    const from_pubkey = ic.accounts[from_index].pubkey;

    if (!try ic.isIndexSigner(from_base_index)) {
        try ic.tc.log("Transfer: `from` account {} must sign", .{from_base_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    try checkSeedAddress(
        ic,
        from_pubkey,
        from_base_pubkey,
        from_owner,
        from_seed,
        "Transfer: 'from' address {} does not match derived address {}",
    );

    try transferVerified(
        ic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L472-L485
fn executeUpgradeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) !void {
    try ic.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    if (!account.getOwner().equals(&system_program.id()))
        return InstructionError.InvalidAccountOwner;

    if (!account.isWritable()) return InstructionError.InvalidArgument;

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce) {
        .legacy => |state| {
            if (state == nonce.State.initialized) {
                var data = state.initialized;
                data.durable_nonce = nonce.createDurableNonce(data.getDurableNonce());
                try account.setState(nonce.Versions{ .current = state });
            }
        },
        .current => |_| return InstructionError.InvalidArgument,
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#70
fn allocate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
    space: u64,
    authority: Pubkey,
) InstructionError!void {
    if (!ic.isPubkeySigner(authority)) {
        try ic.tc.log("Allocate: 'base' account {} must sign", .{account.getPubkey()});
        return InstructionError.MissingRequiredSignature;
    }

    if (account.getData().len > 0 or !account.getOwner().equals(&system_program.id())) {
        try ic.tc.log("Allocate: account {} already in use", .{account.getPubkey()});
        ic.tc.maybe_custom_error = @intFromError(SystemProgramError.AccountAlreadyInUse);
        return InstructionError.Custom;
    }

    if (space > system_program.MAX_PERMITTED_DATA_LENGTH) {
        try ic.tc.log(
            "Allocate: requested {}, max allowed {}",
            .{ space, system_program.MAX_PERMITTED_DATA_LENGTH },
        );
        ic.tc.maybe_custom_error = @intFromError(SystemProgramError.InvalidAccountDataLength);
        return InstructionError.Custom;
    }

    try account.setDataLength(allocator, ic.tc, @intCast(space));
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L112
fn assign(
    ic: *InstructionContext,
    account: *BorrowedAccount,
    owner: Pubkey,
    authority: Pubkey,
) InstructionError!void {
    if (account.getOwner().equals(&owner)) return;

    if (!ic.isPubkeySigner(authority)) {
        try ic.tc.log("Assign: 'base' account {} must sign", .{account.getPubkey()});
        return InstructionError.MissingRequiredSignature;
    }

    try account.setOwner(owner);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L145
fn createAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
    space: u64,
    owner: Pubkey,
    authority: Pubkey,
) InstructionError!void {
    {
        var account = try ic.borrowInstructionAccount(to_index);
        defer account.release();

        if (account.getLamports() > 0) {
            try ic.tc.log("Create Account: account {} already in use", .{account.getPubkey()});
            ic.tc.maybe_custom_error = @intFromError(SystemProgramError.AccountAlreadyInUse);
            return InstructionError.Custom;
        }

        try allocate(allocator, ic, &account, space, authority);
        try assign(ic, &account, owner, authority);
    }

    return transfer(
        ic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L214
fn transfer(
    ic: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) !void {
    if (!try ic.isIndexSigner(from_index)) {
        try ic.tc.log(
            "Transfer: `from` account {} must sign",
            .{ic.accounts[from_index].pubkey},
        );
        return InstructionError.MissingRequiredSignature;
    }

    return transferVerified(
        ic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L182
fn transferVerified(
    ic: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) !void {
    {
        var account = try ic.borrowInstructionAccount(from_index);
        defer account.release();

        if (account.getData().len > 0) {
            try ic.tc.log("Transfer: `from` must not carry data", .{});
            return InstructionError.InvalidArgument;
        }

        if (lamports > account.getLamports()) {
            try ic.tc.log(
                "Transfer: insufficient lamports {}, need {}",
                .{ account.getLamports(), lamports },
            );
            ic.tc.maybe_custom_error =
                @intFromError(SystemProgramError.ResultWithNegativeLamports);
            return InstructionError.Custom;
        }

        try account.subtractLamports(lamports);
    }

    var account = try ic.borrowInstructionAccount(to_index);
    defer account.release();

    try account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
) !void {
    if (!account.isWritable()) {
        try ic.tc.log(
            "Advance nonce account: Account {} must be writeable",
            .{account.getPubkey()},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            try ic.tc.log(
                "Advance nonce account: Account {} state is invalid",
                .{account.getPubkey()},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| {
            if (!ic.isPubkeySigner(data.authority)) {
                try ic.tc.log(
                    "Advance nonce account: Account {} must be a signer",
                    .{data.authority},
                );
                return InstructionError.MissingRequiredSignature;
            }

            const next_durable_nonce = nonce.createDurableNonce(ic.tc.last_blockhash);

            if (data.durable_nonce.eql(next_durable_nonce)) {
                try ic.tc.log("Advance nonce account: nonce can only advance once per slot", .{});
                ic.tc.maybe_custom_error =
                    @intFromError(SystemProgramError.NonceBlockhashNotExpired);
                return InstructionError.Custom;
            }

            try account.setState(
                nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    ic.tc.lamports_per_signature,
                ) } },
            );
        },
    }
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L73-L74
fn withdrawNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    lamports: u64,
    rent: Rent,
) !void {
    const from_account_index = 0;
    const to_account_index = 1;

    {
        var from_account = try ic.borrowInstructionAccount(from_account_index);
        defer from_account.release();

        if (!from_account.isWritable()) {
            try ic.tc.log(
                "Withdraw nonce account: Account {} must be writeable",
                .{from_account.getPubkey()},
            );
            return InstructionError.InvalidArgument;
        }

        const versioned_nonce = try from_account.getState(allocator, nonce.Versions);
        const authority = switch (versioned_nonce.getState()) {
            .unintialized => blk: {
                if (lamports > from_account.getLamports()) {
                    try ic.tc.log("Withdraw nonce account: insufficient lamports {}, need {}", .{
                        from_account.getLamports(),
                        lamports,
                    });
                    return InstructionError.InsufficientFunds;
                }
                break :blk from_account.getPubkey();
            },
            .initialized => |data| blk: {
                if (lamports == from_account.getLamports()) {
                    const durable_nonce = nonce.createDurableNonce(ic.tc.last_blockhash);
                    if (durable_nonce.eql(data.durable_nonce)) {
                        try ic.tc.log(
                            "Withdraw nonce account: nonce can only advance once per slot",
                            .{},
                        );
                        ic.tc.maybe_custom_error =
                            @intFromError(SystemProgramError.NonceBlockhashNotExpired);
                        return InstructionError.Custom;
                    }
                    try from_account.setState(
                        nonce.Versions{ .current = nonce.State.unintialized },
                    );
                } else {
                    const min_balance = rent.minimumBalance(from_account.getData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch
                        return InstructionError.InsufficientFunds;
                    if (amount > from_account.getLamports()) {
                        try ic.tc.log(
                            "Withdraw nonce account: insufficient lamports {}, need {}",
                            .{
                                from_account.getLamports(),
                                amount,
                            },
                        );
                        return InstructionError.InsufficientFunds;
                    }
                }
                break :blk data.authority;
            },
        };

        if (!ic.isPubkeySigner(authority)) {
            try ic.tc.log("Withdraw nonce account: Account {} must sign", .{authority});
            return InstructionError.MissingRequiredSignature;
        }

        try from_account.subtractLamports(lamports);
    }

    var to_account = try ic.borrowInstructionAccount(to_account_index);
    defer to_account.release();
    try to_account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L155
fn initializeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
    authority: Pubkey,
    rent: Rent,
) !void {
    if (!account.isWritable()) {
        try ic.tc.log(
            "Initialize nonce account: Account {} must be writeable",
            .{account.getPubkey()},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .unintialized => {
            const min_balance = rent.minimumBalance(account.getData().len);
            if (min_balance > account.getLamports()) {
                try ic.tc.log("Initialize nonce account: insufficient lamports {}, need {}", .{
                    account.getLamports(),
                    min_balance,
                });
                return InstructionError.InsufficientFunds;
            }
            try account.setState(nonce.Versions{
                .current = nonce.State{ .initialized = nonce.Data.init(
                    authority,
                    nonce.createDurableNonce(ic.tc.last_blockhash),
                    ic.tc.lamports_per_signature,
                ) },
            });
        },
        .initialized => |_| {
            try ic.tc.log(
                "Initialize nonce account: Account {} state is invalid",
                .{account.getPubkey()},
            );
            return InstructionError.InvalidAccountData;
        },
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L203
pub fn authorizeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
    authority: Pubkey,
) !void {
    if (!account.isWritable()) {
        try ic.tc.log(
            "Authorize nonce account: Account {} must be writeable",
            .{account.getPubkey()},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.getState(allocator, nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .unintialized => {
            try ic.tc.log(
                "Authorize nonce account: Account {} state is invalid",
                .{account.getPubkey()},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| data,
    };

    if (!ic.isPubkeySigner(nonce_data.authority)) {
        try ic.tc.log("Authorize nonce account: Account {} must sign", .{nonce_data.authority});
        return InstructionError.MissingRequiredSignature;
    }

    const nonce_state = nonce.State{ .initialized = nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.fee_calculator.lamports_per_signature,
    ) };

    switch (versioned_nonce) {
        .legacy => try account.setState(nonce.Versions{ .legacy = nonce_state }),
        .current => try account.setState(nonce.Versions{ .current = nonce_state }),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L47-L58
fn checkSeedAddress(
    ic: *InstructionContext,
    expected: Pubkey,
    base: Pubkey,
    owner: Pubkey,
    seed: []const u8,
    comptime log_err_fmt: []const u8,
) !void {
    const created = pubkey_utils.createWithSeed(base, seed, owner) catch |err| {
        ic.tc.maybe_custom_error = @intFromError(err);
        return InstructionError.Custom;
    };
    if (!expected.equals(&created)) {
        try ic.tc.log(log_err_fmt, .{ expected, created });
        ic.tc.maybe_custom_error = @intFromError(SystemProgramError.AddressWithSeedMismatch);
        return InstructionError.Custom;
    }
}

test "executeCreateAccount" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .create_account = .{
                .lamports = 1_000_000,
                .space = 0,
                .owner = system_program.id(),
            },
        },
        &.{
            .{
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 1,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = 150,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{
                    .pubkey = account_1_key,
                    .lamports = 1_000_000,
                    .owner = system_program.id(),
                    .data = &.{},
                },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeAssign" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const new_owner = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .assign = .{
                .owner = new_owner,
            },
        },
        &.{
            .{
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = new_owner },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeTransfer" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .transfer = .{
                .lamports = 1_000_000,
            },
        },
        &.{
            .{
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key, .lamports = 0 },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = account_1_key, .lamports = 1_000_000 },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeCreateAccountWithSeed" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = try pubkey_utils.createWithSeed(base, seed, system_program.id());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
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
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = account_1_key },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = account_1_key, .lamports = 1_000_000, .owner = system_program.id() },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeAdvanceNonceAccount" {
    const Hash = sig.core.Hash;
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

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

    const account_0_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        allocator,
        system_program,
        SystemProgramInstruction{
            .advance_nonce_account = {},
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = nonce_state_bytes },
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = final_nonce_state_bytes },
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.id() },
            },
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
            },
        },
    );
}

test "executeWithdrawNonceAccount" {
    const Hash = sig.core.Hash;
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

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

    const account_0_key = Pubkey.initRandom(prng.random());
    const account_1_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        allocator,
        system_program,
        SystemProgramInstruction{
            .withdraw_nonce_account = 1_000,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 2,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 3,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 4,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .lamports = 2 * withdraw_lamports + rent_minimum_balance,
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = account_1_key },
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = Rent.id() },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
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
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = Rent.id() },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.id() },
            },
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
            },
        },
    );
}

test "executeInitializeNonceAccount" {
    const Hash = sig.core.Hash;
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);

    // Last Blockhash is used to compute the next durable nonce
    const last_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Final Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{ .initialized = nonce.Data.init(
            nonce_authority,
            nonce.createDurableNonce(last_blockhash),
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
    const rent = Rent.default();

    const account_0_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .initialize_nonce_account = nonce_authority,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = false,
                .is_writable = false,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                    .data = nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = Rent.id() },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
            },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = account_0_key,
                    .lamports = rent.minimumBalance(final_nonce_state_bytes.len),
                    .data = final_nonce_state_bytes,
                },
                .{ .pubkey = RecentBlockhashes.id() },
                .{ .pubkey = Rent.id() },
                .{ .pubkey = system_program.id() },
            },
            .lamports_per_signature = lamports_per_signature,
            .last_blockhash = last_blockhash,
            .sysvar_cache = .{
                .maybe_recent_blockhashes = recent_blockhashes,
                .maybe_rent = rent,
            },
        },
    );
}

test "executeAuthorizeNonceAccount" {
    const Hash = sig.core.Hash;
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

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

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .authorize_nonce_account = final_nonce_authority,
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = nonce_state_bytes },
                .{ .pubkey = initial_nonce_authority },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = final_nonce_state_bytes },
                .{ .pubkey = initial_nonce_authority },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeAllocate" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const allocation_size = 1024;

    const account_0_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .allocate = .{
                .space = allocation_size,
            },
        },
        &.{
            .{
                .is_signer = true,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = &[_]u8{0} ** allocation_size },
                .{ .pubkey = system_program.id() },
            },
            .accounts_resize_delta = allocation_size,
        },
    );
}

test "executeAllocateWithSeed" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const allocation_size = 1024;

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, system_program.id());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .allocate_with_seed = .{
                .base = base,
                .seed = seed,
                .space = allocation_size,
                .owner = system_program.id(),
            },
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = &[_]u8{0} ** 1024 },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
            .accounts_resize_delta = allocation_size,
        },
    );
}

test "executeAssignWithSeed" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const owner = Pubkey.initRandom(prng.random());

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, owner);

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .assign_with_seed = .{
                .base = base,
                .seed = seed,
                .owner = owner,
            },
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .owner = owner },
                .{ .pubkey = base },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeTransferWithSeed" {
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

    var prng = std.Random.DefaultPrng.init(5083);

    const base = Pubkey.initRandom(prng.random());
    const seed = &[_]u8{0x10} ** 32;
    const owner = Pubkey.initRandom(prng.random());

    const account_0_key = try pubkey_utils.createWithSeed(base, seed, owner);
    const account_2_key = Pubkey.initRandom(prng.random());

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .transfer_with_seed = .{
                .lamports = 1_000_000,
                .from_seed = seed,
                .from_owner = owner,
            },
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
            .{
                .is_signer = true,
                .is_writable = false,
                .index_in_transaction = 1,
            },
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 2,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 2_000_000 },
                .{ .pubkey = base },
                .{ .pubkey = account_2_key, .lamports = 0 },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000 },
                .{ .pubkey = base },
                .{ .pubkey = account_2_key, .lamports = 1_000_000 },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}

test "executeUpgradeNonceAccount" {
    const Hash = sig.core.Hash;
    const expectProgramExecuteResult =
        sig.runtime.program.test_program_execute.expectProgramExecuteResult;

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

    try expectProgramExecuteResult(
        std.testing.allocator,
        system_program,
        SystemProgramInstruction{
            .upgrade_nonce_account = {},
        },
        &.{
            .{
                .is_signer = false,
                .is_writable = true,
                .index_in_transaction = 0,
            },
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = nonce_state_bytes },
                .{ .pubkey = system_program.id() },
            },
            .compute_meter = system_program.computeUnits(),
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .data = final_nonce_state_bytes },
                .{ .pubkey = system_program.id() },
            },
        },
    );
}
