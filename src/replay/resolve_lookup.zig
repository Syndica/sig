const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const InstructionAccount = core.instruction.InstructionAccount;
const Pubkey = core.Pubkey;
const Transaction = core.Transaction;
const TransactionAddressLookup = core.transaction.AddressLookup;

const AccountsDB = sig.accounts_db.AccountsDB;

const AddressLookupTable = sig.runtime.program.address_lookup_table.AddressLookupTable;
const InstructionInfo = sig.runtime.InstructionInfo;
const AccountMeta = sig.runtime.InstructionInfo.AccountMeta;
const ProgramMeta = sig.runtime.InstructionInfo.ProgramMeta;

const LockableAccount = sig.replay.account_locks.LockableAccount;

const ScopedLogger = sig.trace.ScopedLogger("replay-resolve");

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

    pub fn deinit(self: ResolvedTransaction, allocator: Allocator) void {
        var acc = self.accounts;
        acc.deinit(allocator);
        allocator.free(self.instructions);
        // transaction is not freed because it is borrowed.
    }
};

pub fn resolveBatch(
    allocator: Allocator,
    accounts_db: *AccountsDB,
    batch: []const Transaction,
) !ResolvedBatch {
    return resolveBatchGeneric(allocator, .accounts_db, accounts_db, batch);
}

fn resolveBatchGeneric(
    allocator: Allocator,
    comptime provider_tag: lookup_table_provider.Tag,
    table_provider: provider_tag.T(),
    batch: []const Transaction,
) !ResolvedBatch {
    var accounts = try std.ArrayListUnmanaged(LockableAccount)
        .initCapacity(allocator, Transaction.numAccounts(batch));
    errdefer accounts.deinit(allocator);

    const resolved_txns = try allocator.alloc(ResolvedTransaction, batch.len);
    errdefer allocator.free(resolved_txns);

    for (batch, resolved_txns) |transaction, *resolved| {
        resolved.* = try resolveTransaction(allocator, provider_tag, table_provider, transaction);
        for (
            resolved.accounts.items(.pubkey),
            resolved.accounts.items(.is_writable),
        ) |pubkey, is_writable| {
            accounts.appendAssumeCapacity(.{ .address = pubkey, .writable = is_writable });
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
fn resolveTransaction(
    allocator: Allocator,
    comptime provider_tag: lookup_table_provider.Tag,
    table_provider: provider_tag.T(),
    transaction: Transaction,
) !ResolvedTransaction {
    const message = transaction.msg;

    const lookups = try resolveLookupTableAccounts(
        allocator,
        provider_tag,
        table_provider,
        message.address_lookups,
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
        .is_writable = message.isWritable(i),
    });
    for (lookups.writable) |pubkey| accounts.appendAssumeCapacity(.{
        .pubkey = pubkey,
        .is_signer = false,
        .is_writable = true,
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
        var account_metas =
            std.BoundedArray(AccountMeta, InstructionInfo.MAX_ACCOUNT_METAS){};
        var seen = std.bit_set.ArrayBitSet(usize, 256).initEmpty();
        for (input_ix.account_indexes, 0..) |index, i| {
            // find first usage of this account in this instruction
            const index_in_callee = if (seen.isSet(index))
                for (input_ix.account_indexes[0..i], 0..) |prior_index, j| {
                    if (prior_index == index) break j;
                } else unreachable
            else
                i;
            seen.set(index);

            // expand the account metadata
            (try account_metas.addOne()).* = if (index < lookups_start) .{
                .pubkey = message.account_keys[index],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = @intCast(index_in_callee),
                .is_signer = message.isSigner(index),
                .is_writable = message.isWritable(index),
            } else if (index < readable_lookups_start) .{
                .pubkey = lookups.writable[index - lookups_start],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = @intCast(index_in_callee),
                .is_signer = false,
                .is_writable = true,
            } else if (index < lookups_end) .{
                .pubkey = lookups.readonly[index - readable_lookups_start],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = @intCast(index_in_callee),
                .is_signer = false,
                .is_writable = false,
            } else {
                return error.InvalidAccountIndex;
            };
        }

        if (input_ix.program_index >= message.account_keys.len) {
            return error.InvalidAccountIndex;
        }
        output_ix.* = .{
            .program_meta = ProgramMeta{
                .pubkey = message.account_keys[input_ix.program_index],
                .index_in_transaction = input_ix.program_index,
            },
            .account_metas = account_metas,
            .instruction_data = input_ix.data,
        };
    }
    return .{
        .transaction = transaction,
        .instructions = instructions,
        .accounts = accounts,
    };
}

fn resolveLookupTableAccounts(
    allocator: Allocator,
    comptime provider_tag: lookup_table_provider.Tag,
    table_provider: provider_tag.T(),
    address_lookups: []const TransactionAddressLookup,
) !struct { writable: []const Pubkey, readonly: []const Pubkey } {
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
        const table = try lookup_table_provider
            .get(provider_tag, table_provider, &lookup.table_address);

        // resolve writable addresses
        for (lookup.writable_indexes) |index| {
            if (table.addresses.len < index + 1) {
                return error.LookupTableAccountTooSmall;
            }
            writable_accounts.appendAssumeCapacity(table.addresses[index]);
        }

        // resolve readonly addresses
        for (lookup.readonly_indexes) |index| {
            if (table.addresses.len < index + 1) {
                return error.LookupTableAccountTooSmall;
            }
            readonly_accounts.appendAssumeCapacity(table.addresses[index]);
        }
    }

    return .{
        .writable = try writable_accounts.toOwnedSlice(allocator),
        .readonly = try readonly_accounts.toOwnedSlice(allocator),
    };
}

const lookup_table_provider = struct {
    pub const Tag = enum {
        accounts_db,
        map,

        fn T(self: Tag) type {
            return switch (self) {
                .accounts_db => *AccountsDB,
                .map => *const std.AutoArrayHashMapUnmanaged(Pubkey, AddressLookupTable),
            };
        }
    };

    fn get(
        comptime tag: Tag,
        table_provider: tag.T(),
        table_address: *const Pubkey,
    ) !AddressLookupTable {
        switch (tag) {
            .accounts_db => {
                const accounts_db: *AccountsDB = table_provider;
                // TODO: Ensure the account comes from a valid slot by checking
                // it against the current slot's ancestors. This won't be usable
                // until consensus is implemented in replay, so it's not
                // implemented yet.
                const account = try accounts_db.getAccount(table_address);
                if (account.data.len() > AddressLookupTable.MAX_SERIALIZED_SIZE) {
                    return error.LookupTableAccountOverflow;
                }
                var buf: [AddressLookupTable.MAX_SERIALIZED_SIZE]u8 = undefined;
                const account_bytes = buf[0..account.data.len()];
                account.data.readAll(account_bytes);
                return try AddressLookupTable.deserialize(account_bytes);
                // NOTE: deactivated lookup tables are allowed to be used,
                // according to agave's implementation. see here, where agave
                // discards the value:
                // https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank/address_lookup_table.rs#L36
            },
            .map => {
                const map: *const std.AutoArrayHashMapUnmanaged(Pubkey, AddressLookupTable) =
                    table_provider;
                return map.get(table_address.*) orelse return error.PubkeyNotInIndex;
            },
        }
    }
};

test resolveBatchGeneric {
    var rng = std.Random.DefaultPrng.init(0);

    // concisely represents all the expected account metas within an InstructionInfo
    const ExpectedAccountMetas = struct {
        index_in_transaction: []const u8,
        index_in_caller: []const u8,
        index_in_callee: []const u16,
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
        pubkey.* = Pubkey.initRandom(rng.random());
    }

    const lookup_table_addresses = .{
        Pubkey.initRandom(rng.random()),
        Pubkey.initRandom(rng.random()),
    };

    const lookup_tables: [2]AddressLookupTable = .{
        .{
            .meta = .{},
            .addresses = &.{
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
            },
        },
        .{
            .meta = .{},
            .addresses = &.{
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
                Pubkey.initRandom(rng.random()),
            },
        },
    };

    var map = std.AutoArrayHashMapUnmanaged(Pubkey, AddressLookupTable){};
    defer map.deinit(std.testing.allocator);
    try map.put(std.testing.allocator, lookup_table_addresses[0], lookup_tables[0]);
    try map.put(std.testing.allocator, lookup_table_addresses[1], lookup_tables[1]);

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
            .index_in_caller = tx.msg.instructions[0].account_indexes,
            .index_in_callee = &.{ 0, 1, 2, 3, 4, 5, 6, 7 },
            .is_signer = &.{ 1, 1, 1, 1, 0, 0, 0, 0 },
            .is_writable = &.{ 1, 1, 0, 0, 1, 1, 0, 0 },
        },
        .{
            .index_in_transaction = tx.msg.instructions[1].account_indexes,
            .index_in_caller = tx.msg.instructions[1].account_indexes,
            .index_in_callee = &.{ 0, 1, 0, 3, 4, 5, 6, 7 },
            .is_signer = &.{ 1, 0, 1, 0, 0, 0, 0, 0 },
            .is_writable = &.{ 0, 0, 0, 0, 1, 0, 0, 0 },
        },
    };

    const resolved = try resolveBatchGeneric(std.testing.allocator, .map, &map, &.{tx});
    defer resolved.deinit(std.testing.allocator);

    for (
        resolved.accounts,
        expected_accounts.pubkey,
        expected_accounts.is_writable,
        0..,
    ) |acc, pubkey, is_writable, i| {
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
            expect.index_in_caller,
            expect.index_in_callee,
            expect.is_signer,
            expect.is_writable,
        ) |
            input_index,
            output_meta,
            index_in_transaction,
            index_in_caller,
            index_in_callee,
            is_signer,
            is_writable,
        | {
            const address = resolved.accounts[input_index].address;
            try std.testing.expectEqual(address, output_meta.pubkey);
            try std.testing.expectEqual(index_in_transaction, output_meta.index_in_transaction);
            try std.testing.expectEqual(index_in_caller, output_meta.index_in_caller);
            try std.testing.expectEqual(index_in_callee, output_meta.index_in_callee);
            try std.testing.expectEqual(is_signer != 0, output_meta.is_signer);
            try std.testing.expectEqual(is_writable != 0, output_meta.is_writable);
        }
    }
}
