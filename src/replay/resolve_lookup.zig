const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;
const compute_budget_program = sig.runtime.program.compute_budget;

const Allocator = std.mem.Allocator;

const Hash = core.Hash;
const Ancestors = core.Ancestors;
const InstructionAccount = core.instruction.InstructionAccount;
const Pubkey = core.Pubkey;
const ReservedAccounts = core.ReservedAccounts;
const Slot = core.Slot;
const Transaction = core.Transaction;
const TransactionAddressLookup = core.transaction.AddressLookup;

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const AddressLookupTable = sig.runtime.program.address_lookup_table.AddressLookupTable;
const ComputeBudgetInstructionDetails = compute_budget_program.ComputeBudgetInstructionDetails;
const InstructionInfo = sig.runtime.InstructionInfo;
const ProgramMeta = sig.runtime.InstructionInfo.ProgramMeta;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const SlotHashes = sig.runtime.sysvar.SlotHashes;

const LockableAccount = sig.replay.account_locks.LockableAccount;

const Logger = sig.trace.Logger("replay-resolve");

pub const ResolvedBatch = struct {
    transactions: []const ResolvedTransaction,
    accounts: []const LockableAccount,

    pub fn deinit(self: ResolvedBatch, allocator: Allocator) void {
        for (self.transactions) |tx| tx.deinit(allocator);
        allocator.free(self.transactions);
        allocator.free(self.accounts);
    }
};

/// This is a transaction plus the following additions:
/// - The lookup table addresses have been resolved from accountsdb.
/// - The instructions have been expanded out to a more useful form for the SVM.
///
/// This struct contains some redundancies for ease of access by the SVM.
pub const ResolvedTransaction = struct {
    transaction: Transaction,
    accounts: std.MultiArrayList(InstructionAccount),
    instructions: []const InstructionInfo,

    /// The transaction is not deinitialized since it is borrowed.
    pub fn deinit(self: ResolvedTransaction, allocator: Allocator) void {
        var acc = self.accounts;
        acc.deinit(allocator);
        allocator.free(self.instructions);
    }

    pub fn toRuntimeTransaction(
        self: ResolvedTransaction,
        message_hash: Hash,
        compute_budget_instruction_details: ComputeBudgetInstructionDetails,
    ) RuntimeTransaction {
        return .{
            .signature_count = self.transaction.signatures.len,
            .fee_payer = self.transaction.msg.account_keys[0],
            .msg_hash = message_hash,
            .recent_blockhash = self.transaction.msg.recent_blockhash,
            .instructions = self.instructions,
            .accounts = self.accounts,
            .compute_budget_instruction_details = compute_budget_instruction_details,
            .num_lookup_tables = self.transaction.msg.address_lookups.len,
        };
    }
};

/// Data sources needed to resolve arbitrary transactions from a particular slot
pub const SlotResolver = struct {
    slot: Slot,
    account_reader: SlotAccountReader,
    /// borrowed
    reserved_accounts: *const ReservedAccounts,
    slot_hashes: SlotHashes,
};

pub fn resolveBatch(
    allocator: Allocator,
    batch: []const Transaction,
    params: SlotResolver,
) !ResolvedBatch {
    var accounts = try std.ArrayListUnmanaged(LockableAccount)
        .initCapacity(allocator, Transaction.numAccounts(batch));
    errdefer accounts.deinit(allocator);

    const resolved_txns = try allocator.alloc(ResolvedTransaction, batch.len);
    errdefer allocator.free(resolved_txns);

    for (batch, resolved_txns) |transaction, *resolved| {
        resolved.* = try resolveTransaction(allocator, transaction, params);
        for (
            resolved.accounts.items(.pubkey),
            resolved.accounts.items(.is_writable),
        ) |pubkey, is_writable| {
            accounts.appendAssumeCapacity(.{
                .address = pubkey,
                .writable = is_writable,
            });
        }
    }

    return .{
        .transactions = resolved_txns,
        .accounts = try accounts.toOwnedSlice(allocator),
    };
}

/// Returned data is partially borrowed and partially owned.
/// - Ensure `transaction` exceeds the lifetime of this struct.
/// - Use `deinit` to free this struct
pub fn resolveTransaction(
    allocator: Allocator,
    transaction: Transaction,
    params: SlotResolver,
) !ResolvedTransaction {
    const message = transaction.msg;

    const lookups = try resolveLookupTableAccounts(
        allocator,
        params.account_reader,
        message.address_lookups,
        params.slot,
        params.slot_hashes,
    );
    defer {
        allocator.free(lookups.writable);
        allocator.free(lookups.readonly);
    }

    // calculate bounds based on the concatenation of normal ++ writable ++ readonly accounts
    const lookups_start = message.account_keys.len;
    const readable_lookups_start = lookups.writable.len + lookups_start;
    const lookups_end = lookups.readonly.len + readable_lookups_start;

    // construct accounts
    var accounts = std.MultiArrayList(InstructionAccount){};
    try accounts.ensureTotalCapacity(allocator, lookups_end);
    errdefer accounts.deinit(allocator);
    for (message.account_keys, 0..) |pubkey, i| accounts.appendAssumeCapacity(.{
        .pubkey = pubkey,
        .is_signer = message.isSigner(i),
        .is_writable = message.isWritable(i, lookups, params.reserved_accounts),
    });
    for (lookups.writable, 0..) |pubkey, i| accounts.appendAssumeCapacity(.{
        .pubkey = pubkey,
        .is_signer = false,
        .is_writable = message.isWritable(
            message.account_keys.len + i,
            lookups,
            params.reserved_accounts,
        ),
    });
    for (lookups.readonly) |pubkey| accounts.appendAssumeCapacity(.{
        .pubkey = pubkey,
        .is_signer = false,
        .is_writable = false,
    });

    // construct instructions
    const instructions = try allocator.alloc(InstructionInfo, message.instructions.len);
    errdefer allocator.free(instructions);
    for (message.instructions, instructions) |input_ix, *output_ix| {
        var account_metas = InstructionInfo.AccountMetas{};
        var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
        for (input_ix.account_indexes, 0..) |index_in_transaction, i| {
            // find first usage of this account in this instruction
            if (dedupe_map[index_in_transaction] == 0xff)
                dedupe_map[index_in_transaction] = @intCast(i);

            // expand the account metadata
            if (index_in_transaction >= accounts.len) return error.InvalidAccountIndex;
            const account = accounts.get(index_in_transaction);
            (account_metas.addOne() catch break).* = .{
                .pubkey = account.pubkey,
                .is_signer = account.is_signer,
                .is_writable = account.is_writable,
                .index_in_transaction = index_in_transaction,
            };
        }

        if (input_ix.program_index >= message.account_keys.len) {
            return error.InvalidAddressLookupTableIndex;
        }
        output_ix.* = .{
            .program_meta = .{
                .pubkey = message.account_keys[input_ix.program_index],
                .index_in_transaction = input_ix.program_index,
            },
            .account_metas = account_metas,
            .dedupe_map = dedupe_map,
            .instruction_data = input_ix.data,
        };
    }
    return .{
        .transaction = transaction,
        .instructions = instructions,
        .accounts = accounts,
    };
}

pub const LookupTableAccounts = struct {
    writable: []const Pubkey,
    readonly: []const Pubkey,
};

fn resolveLookupTableAccounts(
    allocator: Allocator,
    account_reader: SlotAccountReader,
    address_lookups: []const TransactionAddressLookup,
    slot: Slot,
    slot_hashes: SlotHashes,
) !LookupTableAccounts {
    // count number of accounts
    var total_writable: usize = 0;
    var total_readonly: usize = 0;
    for (address_lookups) |lookup| {
        total_writable += lookup.writable_indexes.len;
        total_readonly += lookup.readonly_indexes.len;
    }

    var writable_accounts = try std.ArrayListUnmanaged(Pubkey)
        .initCapacity(allocator, total_writable);
    errdefer writable_accounts.deinit(allocator);

    var readonly_accounts = try std.ArrayListUnmanaged(Pubkey)
        .initCapacity(allocator, total_readonly);
    errdefer readonly_accounts.deinit(allocator);

    // handle lookup table accounts
    for (address_lookups) |lookup| {
        const table = try getLookupTable(allocator, account_reader, lookup.table_address);
        defer allocator.free(table.addresses);

        if (table.meta.status(slot, slot_hashes) == .Deactivated) {
            return error.AddressLookupTableNotFound;
        }

        const active_addresses_len = if (slot > table.meta.last_extended_slot)
            table.addresses.len
        else
            table.meta.last_extended_slot_start_index;

        // resolve writable addresses
        for (lookup.writable_indexes) |index| {
            if (active_addresses_len < index + 1) {
                return error.InvalidAddressLookupTableIndex;
            }
            writable_accounts.appendAssumeCapacity(table.addresses[index]);
        }

        // resolve readonly addresses
        for (lookup.readonly_indexes) |index| {
            if (active_addresses_len < index + 1) {
                return error.InvalidAddressLookupTableIndex;
            }
            readonly_accounts.appendAssumeCapacity(table.addresses[index]);
        }
    }

    return .{
        .writable = try writable_accounts.toOwnedSlice(allocator),
        .readonly = try readonly_accounts.toOwnedSlice(allocator),
    };
}

fn getLookupTable(
    allocator: std.mem.Allocator,
    account_reader: SlotAccountReader,
    table_address: Pubkey,
) !AddressLookupTable {
    // TODO: Ensure the account comes from a valid slot by checking
    // it against the current slot's ancestors. This won't be usable
    // until consensus is implemented in replay, so it's not
    // implemented yet.
    const account = try account_reader.get(allocator, table_address) orelse
        return error.AddressLookupTableNotFound;
    defer account.deinit(allocator);

    if (!account.owner.equals(&sig.runtime.program.address_lookup_table.ID)) {
        return error.InvalidAddressLookupTableOwner;
    }

    if (account.data.len() > AddressLookupTable.MAX_SERIALIZED_SIZE) {
        return error.InvalidAddressLookupTableData;
    }

    var buf: [AddressLookupTable.MAX_SERIALIZED_SIZE]u8 = undefined;
    const account_bytes = buf[0..account.data.len()];
    account.data.readAll(account_bytes);

    const table = AddressLookupTable.deserializeOwned(allocator, account_bytes) catch |err| {
        if (err == error.OutOfMemory) return err;
        return error.InvalidAddressLookupTableData;
    };

    // NOTE: deactivated lookup tables are allowed to be used,
    // according to agave's implementation. see here, where agave
    // discards the value:
    // https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank/address_lookup_table.rs#L36
    return table;
}

test resolveBatch {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    // concisely represents all the expected account metas within an InstructionInfo
    const ExpectedAccountMetas = struct {
        index_in_transaction: []const u8,
        is_signer: []const u8,
        is_writable: []const u8,
    };

    // concisely represents all the expected lockable accounts within a ResolvedTransaction
    const ExpectedAccounts = struct {
        pubkey: []const Pubkey,
        is_writable: []const u8,
    };

    var pubkeys: [9]Pubkey = undefined;
    for (&pubkeys) |*pubkey| {
        pubkey.* = Pubkey.initRandom(random);
    }

    const lookup_table_addresses = .{
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
    };

    const lookup_tables: [2]AddressLookupTable = .{
        .{
            .meta = .{},
            .addresses = &.{
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
            },
        },
        .{
            .meta = .{},
            .addresses = &.{
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
                Pubkey.initRandom(random),
            },
        },
    };

    var map = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
    defer map.deinit();
    try put(&map, lookup_table_addresses[0], lookup_tables[0]);
    try put(&map, lookup_table_addresses[1], lookup_tables[1]);

    const tx = Transaction{
        .signatures = &.{},
        .version = .v0,
        .msg = .{
            .signature_count = 5,
            .readonly_signed_count = 2,
            .readonly_unsigned_count = 2,
            .account_keys = &pubkeys,
            .recent_blockhash = sig.core.Hash.ZEROES,
            .instructions = &.{
                .{
                    .program_index = 7,
                    .account_indexes = &.{ 1, 2, 3, 4, 5, 6, 11, 13 },
                    .data = &.{123},
                },
                .{
                    .program_index = 8,
                    .account_indexes = &.{ 3, 7, 3, 8, 9, 11, 12, 14 },
                    .data = &.{234},
                },
            },
            .address_lookups = &.{
                .{
                    .table_address = lookup_table_addresses[0],
                    .writable_indexes = &.{2},
                    .readonly_indexes = &.{1},
                },
                .{
                    .table_address = lookup_table_addresses[1],
                    .writable_indexes = &.{0},
                    .readonly_indexes = &.{ 1, 2, 3 },
                },
            },
        },
    };

    // layout:
    //  0-2: writable signers
    //  3-4: readonly signer
    //  5-6: writable non-signers
    //  7-8: readonly non-signers (programs 1 and 2)
    //  9-10: writable lookups 0.2, 1.0
    //  11-14: readonly lookups 0.1, 1.1-1.3
    // lookup table 1:
    //  2 - writable
    //  1 - readonly
    // lookup table 2:
    //  0 - writable
    //  1,2,3 - readonly
    // .account_indexes = &.{ 1, 2, 3, 4, 5, 6, 11, 13 },
    // .account_indexes = &.{ 3, 7, 3, 8, 9, 11, 12, 14 },

    const lt = .{ lookup_tables[0].addresses, lookup_tables[1].addresses };
    const expected_accounts = ExpectedAccounts{
        .pubkey = &(pubkeys ++ .{ lt[0][2], lt[1][0], lt[0][1], lt[1][1], lt[1][2], lt[1][3] }),
        .is_writable = &.{ 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0 },
    };

    const expected_account_metas = [2]ExpectedAccountMetas{
        .{
            .index_in_transaction = tx.msg.instructions[0].account_indexes,
            .is_signer = &.{ 1, 1, 1, 1, 0, 0, 0, 0 },
            .is_writable = &.{ 1, 1, 0, 0, 1, 1, 0, 0 },
        },
        .{
            .index_in_transaction = tx.msg.instructions[1].account_indexes,
            .is_signer = &.{ 1, 0, 1, 0, 0, 0, 0, 0 },
            .is_writable = &.{ 0, 0, 0, 0, 1, 0, 0, 0 },
        },
    };

    var ancestors = Ancestors{ .ancestors = .empty };
    defer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, 0, {});

    const slot_hashes: SlotHashes = .DEFAULT;

    const resolved = try resolveBatch(
        allocator,
        &.{tx},
        .{
            .slot = 1, // Greater than lookup tables' last_extended_slot
            .slot_hashes = slot_hashes,
            .reserved_accounts = &.empty,
            .account_reader = map.accountReader().forSlot(&ancestors),
        },
    );
    defer resolved.deinit(allocator);

    for (
        resolved.accounts,
        expected_accounts.pubkey,
        expected_accounts.is_writable,
        0..,
    ) |acc, pubkey, is_writable, i| {
        std.debug.print("pubkey: {}\n", .{pubkey});
        std.debug.print("acc: {}\n", .{acc.address});
        std.debug.print("same: {}\n", .{std.mem.eql(u8, &pubkey.data, &acc.address.data)});

        const tx_account = resolved.transactions[0].accounts.get(i);
        try std.testing.expectEqual(pubkey, acc.address);
        try std.testing.expectEqual(pubkey, tx_account.pubkey);
        try std.testing.expectEqual(is_writable != 0, acc.writable);
        try std.testing.expectEqual(is_writable != 0, tx_account.is_writable);
        try std.testing.expectEqual(i < 5, tx_account.is_signer);
    }

    const ix0 = resolved.transactions[0].instructions[0];
    try std.testing.expectEqual(pubkeys[7], ix0.program_meta.pubkey);
    try std.testing.expectEqual(7, ix0.program_meta.index_in_transaction);
    try std.testing.expectEqual(tx.msg.instructions[0].data, ix0.instruction_data);

    const ix1 = resolved.transactions[0].instructions[1];
    try std.testing.expectEqual(pubkeys[8], ix1.program_meta.pubkey);
    try std.testing.expectEqual(8, ix1.program_meta.index_in_transaction);
    try std.testing.expectEqual(tx.msg.instructions[1].data, ix1.instruction_data);

    for (
        tx.msg.instructions,
        resolved.transactions[0].instructions,
        expected_account_metas,
    ) |input_ix, output_ix, expect| {
        for (
            input_ix.account_indexes,
            output_ix.account_metas.slice(),
            expect.index_in_transaction,
            expect.is_signer,
            expect.is_writable,
        ) |
            input_index,
            output_meta,
            index_in_transaction,
            is_signer,
            is_writable,
        | {
            const address = resolved.accounts[input_index].address;
            try std.testing.expectEqual(address, output_meta.pubkey);
            try std.testing.expectEqual(index_in_transaction, output_meta.index_in_transaction);
            try std.testing.expectEqual(is_signer != 0, output_meta.is_signer);
            try std.testing.expectEqual(is_writable != 0, output_meta.is_writable);
        }
    }
}

fn put(
    map: *sig.accounts_db.ThreadSafeAccountMap,
    address: Pubkey,
    lookup_table: AddressLookupTable,
) !void {
    var buf: [AddressLookupTable.MAX_SERIALIZED_SIZE]u8 = undefined;

    try AddressLookupTable.overwriteMetaData(&buf, lookup_table.meta);

    const src = std.mem.sliceAsBytes(lookup_table.addresses);
    const dst = buf[sig.runtime.program.address_lookup_table.state.LOOKUP_TABLE_META_SIZE..];
    @memcpy(dst[0..src.len], src);

    try map.put(0, address, .{
        .lamports = 1,
        .data = &buf,
        .owner = sig.runtime.program.address_lookup_table.ID,
        .executable = false,
        .rent_epoch = 0,
    });
}

test getLookupTable {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var map = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
    defer map.deinit();

    var ancestors = sig.core.Ancestors{};
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    const account_reader = map.accountReader().forSlot(&ancestors);

    { // Invalid owner
        const pubkey = Pubkey.initRandom(random);

        try map.put(0, pubkey, .{
            .lamports = 1,
            .data = &.{},
            .owner = Pubkey.initRandom(random),
            .executable = false,
            .rent_epoch = 0,
        });

        try std.testing.expectError(
            error.InvalidAddressLookupTableOwner,
            getLookupTable(allocator, account_reader, pubkey),
        );
    }

    { // Size too large
        const pubkey = Pubkey.initRandom(random);
        const data = try allocator.alloc(u8, AddressLookupTable.MAX_SERIALIZED_SIZE + 1);
        defer allocator.free(data);

        try map.put(0, pubkey, .{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.program.address_lookup_table.ID,
            .executable = false,
            .rent_epoch = 0,
        });

        try std.testing.expectError(
            error.InvalidAddressLookupTableData,
            getLookupTable(allocator, account_reader, pubkey),
        );
    }

    { // Data invalid
        const pubkey = Pubkey.initRandom(random);
        const data = try allocator.alloc(u8, AddressLookupTable.MAX_SERIALIZED_SIZE);
        defer allocator.free(data);

        try map.put(0, pubkey, .{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.program.address_lookup_table.ID,
            .executable = false,
            .rent_epoch = 0,
        });

        try std.testing.expectError(
            error.InvalidAddressLookupTableData,
            getLookupTable(allocator, account_reader, pubkey),
        );
    }

    {
        const pubkey = Pubkey.initRandom(random);
        const lookup_table = AddressLookupTable{
            .meta = .{},
            .addresses = &.{Pubkey.initRandom(random)},
        };

        try put(&map, pubkey, lookup_table);

        const loaded_lookup_table = try getLookupTable(allocator, account_reader, pubkey);
        defer allocator.free(loaded_lookup_table.addresses);

        try std.testing.expectEqual(lookup_table.meta, loaded_lookup_table.meta);
        try std.testing.expect(lookup_table.addresses[0].equals(&loaded_lookup_table.addresses[0]));
    }
}
