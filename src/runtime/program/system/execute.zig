const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../sig.zig");

const nonce = sig.runtime.nonce;
const pubkey_utils = sig.runtime.pubkey_utils;
const system_program = sig.runtime.program.system;

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
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "system: execute" });
    defer zone.deinit();

    // Default compute units for the system program are applied via the declare_process_instruction macro
    // [agave] https://github.com/anza-xyz/agave/blob/v2.0.22/programs/system/src/system_processor.rs#L298
    try ic.tc.consumeCompute(system_program.COMPUTE_UNITS);

    // Deserialize the instruction and dispatch to the appropriate handler
    // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L304-L308
    const instruction = try ic.ixn_info.deserializeInstruction(
        allocator,
        SystemProgramInstruction,
    );
    defer sig.bincode.free(allocator, instruction);

    return switch (instruction) {
        .create_account => |args| try executeCreateAccount(
            allocator,
            ic,
            args.lamports,
            args.space,
            args.owner,
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
        .assign => |args| try executeAssign(
            ic,
            args.owner,
        ),
        .transfer => |args| try executeTransfer(
            ic,
            args.lamports,
        ),
        .transfer_with_seed => |args| try executeTransferWithSeed(
            ic,
            args.lamports,
            args.from_seed,
            args.from_owner,
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
        .upgrade_nonce_account => try executeUpgradeNonceAccount(
            allocator,
            ic,
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
    };
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L315-L334
fn executeCreateAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    lamports: u64,
    space: u64,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeCreateAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(2);
    try createAccount(
        allocator,
        ic,
        0,
        1,
        lamports,
        space,
        owner,
        ic.ixn_info.account_metas.items[1].pubkey,
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
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeCreateAccountWithSeed" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(2);
    try checkSeedAddress(
        ic,
        ic.ixn_info.account_metas.items[1].pubkey,
        base,
        owner,
        seed,
        "Create: address {f} does not match derived address {f}",
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

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L365-L375
fn executeAssign(
    ic: *InstructionContext,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAssign" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);
    var account = try ic.borrowInstructionAccount(0);
    defer account.release();
    try assign(
        ic,
        &account,
        owner,
        account.pubkey,
    );
}

//// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L378-L386
fn executeTransfer(
    ic: *InstructionContext,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeTransfer" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(2);
    try transfer(
        ic,
        0,
        1,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L393-L404
fn executeTransferWithSeed(
    ic: *InstructionContext,
    lamports: u64,
    from_seed: []const u8,
    from_owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeTransferWithSeed" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(3);

    const from_index = 0;
    const from_base_index = 1;
    const to_index = 2;

    const from_base_pubkey = ic.ixn_info.account_metas.items[from_base_index].pubkey;
    const from_pubkey = ic.ixn_info.account_metas.items[from_index].pubkey;

    if (!try ic.ixn_info.isIndexSigner(from_base_index)) {
        try ic.tc.log("Transfer: `from` account {f} must sign", .{from_base_pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    try checkSeedAddress(
        ic,
        from_pubkey,
        from_base_pubkey,
        from_owner,
        from_seed,
        "Transfer: 'from' address {f} does not match derived address {f}",
    );

    try transferVerified(
        ic,
        from_index,
        to_index,
        lamports,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L407-L423
fn executeAdvanceNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAdvanceNonceAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ic.tc.log("Advance nonce account: recent blockhash list is empty", .{});
        ic.tc.custom_error = @intFromEnum(SystemProgramError.NonceNoRecentBlockhashes);
        return InstructionError.Custom;
    }

    try advanceNonceAccount(allocator, ic, &account);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L426-L443
fn executeWithdrawNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeWithdrawNonceAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(2);

    _ = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 2);

    const rent = try ic.getSysvarWithAccountCheck(Rent, 3);

    return withdrawNonceAccount(allocator, ic, lamports, rent);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L446-L463
fn executeInitializeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeInitializeNonceAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    const recent_blockhashes = try ic.getSysvarWithAccountCheck(RecentBlockhashes, 1);
    if (recent_blockhashes.isEmpty()) {
        try ic.tc.log("Initialize nonce account: recent blockhash list is empty", .{});
        ic.tc.custom_error = @intFromEnum(SystemProgramError.NonceNoRecentBlockhashes);
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
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAuthorizeNonceAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    return authorizeNonceAccount(
        allocator,
        ic,
        &account,
        authority,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L472-L485
fn executeUpgradeNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeUpgradeNonceAccount" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    if (!account.account.owner.equals(&system_program.ID))
        return InstructionError.InvalidAccountOwner;

    if (!account.context.is_writable) return InstructionError.InvalidArgument;

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);

    try account.serializeIntoAccountData(
        versioned_nonce.upgrade() orelse return InstructionError.InvalidArgument,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L488-L498
fn executeAllocate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    space: u64,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAllocate" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    try allocate(allocator, ic, &account, space, account.pubkey);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L506-L523
fn executeAllocateWithSeed(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    base: Pubkey,
    seed: []const u8,
    space: u64,
    owner: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAllocateWithSeed" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    try checkSeedAddress(
        ic,
        account.pubkey,
        base,
        owner,
        seed,
        "Create: address {f} does not match derived address {f}",
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
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "executeAssignWithSeed" });
    defer zone.deinit();

    try ic.ixn_info.checkNumberOfAccounts(1);

    var account = try ic.borrowInstructionAccount(0);
    defer account.release();

    try checkSeedAddress(
        ic,
        account.pubkey,
        base,
        owner,
        seed,
        "Create: address {f} does not match derived address {f}",
    );

    try assign(ic, &account, owner, base);
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
) (error{OutOfMemory} || InstructionError)!void {
    var zone = tracy.Zone.init(@src(), .{ .name = "createAccount" });
    defer zone.deinit();

    {
        var account = try ic.borrowInstructionAccount(to_index);
        defer account.release();

        if (account.account.lamports > 0) {
            try ic.tc.log(
                "Create Account: account {f} already in use",
                .{account.pubkey},
            );
            ic.tc.custom_error = @intFromEnum(SystemProgramError.AccountAlreadyInUse);
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

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L112
fn assign(
    ic: *InstructionContext,
    account: *BorrowedAccount,
    owner: Pubkey,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "assign" });
    defer zone.deinit();

    if (account.account.owner.equals(&owner)) return;

    if (!ic.ixn_info.isPubkeySigner(authority)) {
        try ic.tc.log("Assign: 'base' account {f} must sign", .{account.pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    try account.setOwner(owner);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L214
fn transfer(
    ic: *InstructionContext,
    from_index: u16,
    to_index: u16,
    lamports: u64,
) (error{OutOfMemory} || InstructionError)!void {
    if (!try ic.ixn_info.isIndexSigner(from_index)) {
        try ic.tc.log(
            "Transfer: `from` account {f} must sign",
            .{ic.ixn_info.account_metas.items[from_index].pubkey},
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
) (error{OutOfMemory} || InstructionError)!void {
    {
        var from_account = try ic.borrowInstructionAccount(from_index);
        defer from_account.release();

        if (from_account.constAccountData().len > 0) {
            try ic.tc.log("Transfer: `from` must not carry data", .{});
            return InstructionError.InvalidArgument;
        }

        if (lamports > from_account.account.lamports) {
            try ic.tc.log(
                "Transfer: insufficient lamports {}, need {}",
                .{ from_account.account.lamports, lamports },
            );
            ic.tc.custom_error =
                @intFromEnum(SystemProgramError.ResultWithNegativeLamports);
            return InstructionError.Custom;
        }

        try from_account.subtractLamports(lamports);
    }

    var to_account = try ic.borrowInstructionAccount(to_index);
    defer to_account.release();

    try to_account.addLamports(lamports);
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_instruction.rs#L20
fn advanceNonceAccount(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ic.tc.log(
            "Advance nonce account: Account {f} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .uninitialized => {
            try ic.tc.log(
                "Advance nonce account: Account {f} state is invalid",
                .{account.pubkey},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| {
            if (!ic.ixn_info.isPubkeySigner(data.authority)) {
                try ic.tc.log(
                    "Advance nonce account: Account {f} must be a signer",
                    .{data.authority},
                );
                return InstructionError.MissingRequiredSignature;
            }

            const next_durable_nonce = nonce.initDurableNonceFromHash(ic.tc.prev_blockhash);

            if (data.durable_nonce.eql(next_durable_nonce)) {
                try ic.tc.log(
                    "Advance nonce account: nonce can only advance once per slot",
                    .{},
                );
                ic.tc.custom_error =
                    @intFromEnum(SystemProgramError.NonceBlockhashNotExpired);
                return InstructionError.Custom;
            }

            try account.serializeIntoAccountData(
                nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
                    data.authority,
                    next_durable_nonce,
                    ic.tc.prev_lamports_per_signature,
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
) (error{OutOfMemory} || InstructionError)!void {
    const from_account_index = 0;
    const to_account_index = 1;

    {
        var from_account = try ic.borrowInstructionAccount(from_account_index);
        defer from_account.release();

        if (!from_account.context.is_writable) {
            try ic.tc.log(
                "Withdraw nonce account: Account {f} must be writeable",
                .{from_account.pubkey},
            );
            return InstructionError.InvalidArgument;
        }

        const versioned_nonce = try from_account.deserializeFromAccountData(
            allocator,
            nonce.Versions,
        );
        const authority = switch (versioned_nonce.getState()) {
            .uninitialized => blk: {
                if (lamports > from_account.account.lamports) {
                    try ic.tc.log(
                        "Withdraw nonce account: insufficient lamports {}, need {}",
                        .{ from_account.account.lamports, lamports },
                    );
                    return InstructionError.InsufficientFunds;
                }
                break :blk from_account.pubkey;
            },
            .initialized => |data| blk: {
                if (lamports == from_account.account.lamports) {
                    const durable_nonce = nonce.initDurableNonceFromHash(ic.tc.prev_blockhash);
                    if (durable_nonce.eql(data.durable_nonce)) {
                        try ic.tc.log(
                            "Withdraw nonce account: nonce can only advance once per slot",
                            .{},
                        );
                        ic.tc.custom_error =
                            @intFromEnum(SystemProgramError.NonceBlockhashNotExpired);
                        return InstructionError.Custom;
                    }
                    try from_account.serializeIntoAccountData(
                        nonce.Versions{ .current = nonce.State.uninitialized },
                    );
                } else {
                    const min_balance = rent.minimumBalance(from_account.constAccountData().len);
                    const amount = std.math.add(u64, lamports, min_balance) catch
                        return InstructionError.InsufficientFunds;
                    if (amount > from_account.account.lamports) {
                        try ic.tc.log(
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

        if (!ic.ixn_info.isPubkeySigner(authority)) {
            try ic.tc.log("Withdraw nonce account: Account {f} must sign", .{authority});
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
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ic.tc.log(
            "Initialize nonce account: Account {f} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);
    switch (versioned_nonce.getState()) {
        .uninitialized => {
            const min_balance = rent.minimumBalance(account.constAccountData().len);
            if (min_balance > account.account.lamports) {
                try ic.tc.log(
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
                    nonce.initDurableNonceFromHash(ic.tc.prev_blockhash),
                    ic.tc.prev_lamports_per_signature,
                ) },
            });
        },
        .initialized => |_| {
            try ic.tc.log(
                "Initialize nonce account: Account {f} state is invalid",
                .{account.pubkey},
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
) (error{OutOfMemory} || InstructionError)!void {
    if (!account.context.is_writable) {
        try ic.tc.log(
            "Authorize nonce account: Account {f} must be writeable",
            .{account.pubkey},
        );
        return InstructionError.InvalidArgument;
    }

    const versioned_nonce = try account.deserializeFromAccountData(allocator, nonce.Versions);

    const nonce_data = switch (versioned_nonce.getState()) {
        .uninitialized => {
            try ic.tc.log(
                "Authorize nonce account: Account {f} state is invalid",
                .{account.pubkey},
            );
            return InstructionError.InvalidAccountData;
        },
        .initialized => |data| data,
    };

    if (!ic.ixn_info.isPubkeySigner(nonce_data.authority)) {
        try ic.tc.log(
            "Authorize nonce account: Account {f} must sign",
            .{nonce_data.authority},
        );
        return InstructionError.MissingRequiredSignature;
    }

    const nonce_state = nonce.State{ .initialized = nonce.Data.init(
        authority,
        nonce_data.durable_nonce,
        nonce_data.lamports_per_signature,
    ) };

    switch (versioned_nonce) {
        .legacy => try account.serializeIntoAccountData(nonce.Versions{ .legacy = nonce_state }),
        .current => try account.serializeIntoAccountData(nonce.Versions{ .current = nonce_state }),
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#70
fn allocate(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    account: *BorrowedAccount,
    space: u64,
    authority: Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    if (!ic.ixn_info.isPubkeySigner(authority)) {
        try ic.tc.log("Allocate: 'base' account {f} must sign", .{account.pubkey});
        return InstructionError.MissingRequiredSignature;
    }

    if (account.constAccountData().len > 0 or !account.account.owner.equals(&system_program.ID)) {
        try ic.tc.log("Allocate: account {f} already in use", .{account.pubkey});
        ic.tc.custom_error = @intFromEnum(SystemProgramError.AccountAlreadyInUse);
        return InstructionError.Custom;
    }

    if (space > system_program.MAX_PERMITTED_DATA_LENGTH) {
        try ic.tc.log(
            "Allocate: requested {}, max allowed {}",
            .{ space, system_program.MAX_PERMITTED_DATA_LENGTH },
        );
        ic.tc.custom_error = @intFromEnum(SystemProgramError.InvalidAccountDataLength);
        return InstructionError.Custom;
    }

    try account.setDataLength(allocator, &ic.tc.accounts_resize_delta, @intCast(space));
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/system/src/system_processor.rs#L47-L58
fn checkSeedAddress(
    ic: *InstructionContext,
    expected: Pubkey,
    base: Pubkey,
    owner: Pubkey,
    seed: []const u8,
    comptime log_err_fmt: []const u8,
) (error{OutOfMemory} || InstructionError)!void {
    const created = pubkey_utils.createWithSeed(base, seed, owner) catch |err| {
        ic.tc.custom_error = pubkey_utils.mapError(err);
        return InstructionError.Custom;
    };
    if (!expected.equals(&created)) {
        try ic.tc.log(log_err_fmt, .{ expected, created });
        ic.tc.custom_error = @intFromEnum(SystemProgramError.AddressWithSeedMismatch);
        return InstructionError.Custom;
    }
}

test "executeCreateAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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
                .{ .pubkey = account_0_key, .lamports = 2_000_000, .owner = system_program.ID },
                .{ .pubkey = account_1_key, .owner = system_program.ID },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = 150,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000, .owner = system_program.ID },
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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
                .{ .pubkey = account_0_key, .lamports = 2_000_000, .owner = system_program.ID },
                .{ .pubkey = account_1_key },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000, .owner = system_program.ID },
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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
                .{ .pubkey = account_0_key, .lamports = 2_000_000, .owner = system_program.ID },
                .{ .pubkey = account_1_key, .owner = system_program.ID },
                .{ .pubkey = base },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000, .owner = system_program.ID },
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    // Last Blockhash is used to compute the next durable nonce
    const prev_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const initial_durable_nonce = nonce.initDurableNonceFromHash(Hash.initRandom(prng.random()));
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
                nonce.initDurableNonceFromHash(prev_blockhash), // Updated
                lamports_per_signature, // Updated
            ),
        },
    };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    // Create Sysvar Recent Blockhashes
    // Deinitialized by the syvar cache in the created transaction context
    const recent_blockhashes: RecentBlockhashes = .initWithEntries(&.{.{
        .blockhash = Hash.initRandom(prng.random()),
        .lamports_per_signature = 0,
    }});

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
        },
        .{},
    );
}

test "executeWithdrawNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    // The amount to withdraw
    const withdraw_lamports = 1_000;

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const initial_durable_nonce = nonce.initDurableNonceFromHash(Hash.initRandom(prng.random()));
    const nonce_state = nonce.Versions{ .current = nonce.State{ .initialized = nonce.Data.init(
        nonce_authority,
        initial_durable_nonce,
        0,
    ) } };
    const nonce_state_bytes = try sig.bincode.writeAlloc(allocator, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Sysvars
    const recent_blockhashes: RecentBlockhashes = .INIT;

    const rent = Rent.INIT;
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
                    .owner = system_program.ID,
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
                    .owner = system_program.ID,
                },
                .{ .pubkey = account_1_key, .lamports = withdraw_lamports },
                .{ .pubkey = RecentBlockhashes.ID },
                .{ .pubkey = Rent.ID },
                .{ .pubkey = nonce_authority },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    // Last Blockhash is used to compute the next durable nonce
    const prev_blockhash = Hash.initRandom(prng.random());

    // Lamports per signature is set when the nonce is advanced
    const lamports_per_signature = 5_000;

    // Create Final Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const final_nonce_state = nonce.Versions{
        .current = nonce.State{ .initialized = nonce.Data.init(
            nonce_authority,
            nonce.initDurableNonceFromHash(prev_blockhash),
            lamports_per_signature,
        ) },
    };
    const final_nonce_state_bytes = try sig.bincode.writeAlloc(allocator, final_nonce_state, .{});
    defer allocator.free(final_nonce_state_bytes);

    // Create Uninitialized Nonce State
    // The nonce state bytes must have sufficient space to store the final nonce state
    const nonce_state = nonce.Versions{ .current = .uninitialized };
    const nonce_state_bytes = try allocator.alloc(u8, final_nonce_state_bytes.len);
    _ = try sig.bincode.writeToSlice(nonce_state_bytes, nonce_state, .{});
    defer allocator.free(nonce_state_bytes);

    // Create Sysvar Recent Blockhashes
    const recent_blockhashes: RecentBlockhashes = .initWithEntries(&.{.{
        .blockhash = Hash.initRandom(prng.random()),
        .lamports_per_signature = 0,
    }});
    const rent = Rent.INIT;

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
        },
        .{},
    );
}

test "executeAuthorizeNonceAccount" {
    const ids = sig.runtime.ids;
    const testing = sig.runtime.program.testing;
    const Hash = sig.core.Hash;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    // Create Initial Nonce State
    const initial_nonce_authority = Pubkey.initRandom(prng.random());
    const durable_nonce = nonce.initDurableNonceFromHash(Hash.initRandom(prng.random()));
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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
                .{ .pubkey = account_0_key, .lamports = 2_000_000, .owner = system_program.ID },
                .{ .pubkey = base },
                .{ .pubkey = account_2_key, .lamports = 0 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
        .{
            .accounts = &.{
                .{ .pubkey = account_0_key, .lamports = 1_000_000, .owner = system_program.ID },
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    // Create Initial Nonce State
    const nonce_authority = Pubkey.initRandom(prng.random());
    const durable_nonce = nonce.initDurableNonceFromHash(Hash.initRandom(prng.random()));
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
            nonce.initDurableNonceFromHash(durable_nonce),
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
