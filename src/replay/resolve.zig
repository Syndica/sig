const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const InstructionAccount = core.instruction.InstructionAccount;
const Pubkey = core.Pubkey;
const Transaction = core.Transaction;
const TransactionAddressLookup = core.transaction.TransactionAddressLookup;

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
        allocator.free(self.accounts);
        allocator.free(self.instructions);
        // transaction is not freed because it is borrowed.
    }
};

pub fn resolveBatch(
    allocator: Allocator,
    accounts_db: *AccountsDB,
    batch: []const Transaction,
) !ResolvedBatch {
    var accounts = try std.ArrayListUnmanaged(LockableAccount)
        .initCapacity(allocator, Transaction.numAccounts(batch));
    errdefer accounts.deinit(allocator);

    const resolved_txns = try allocator.alloc(ResolvedTransaction, batch.len);
    errdefer allocator.free(resolved_txns);

    for (batch, resolved_txns) |transaction, *resolved| {
        resolved.* = try resolveTransaction(allocator, accounts_db, transaction);
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
    accounts_db: *AccountsDB,
    transaction: Transaction,
) !ResolvedTransaction {
    const message = transaction.msg;

    const lookups = try resolveLookupTableAccounts(allocator, accounts_db, message.address_lookups);
    defer {
        allocator.free(lookups.writable);
        allocator.free(lookups.readonly);
    }

    // calculate bounds based on the concatenation of normal ++ writable ++ readable accounts
    const normal_end = message.account_keys.len;
    const writable_end = lookups.writable.len + normal_end;
    const readonly_end = lookups.readonly.len + writable_end;

    // construct accounts
    var accounts = std.MultiArrayList(InstructionAccount){};
    try accounts.ensureTotalCapacity(allocator, readonly_end + lookups.readonly.len);
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
            (try account_metas.addOne()).* = if (index <= normal_end) .{
                .pubkey = message.account_keys[index],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = @intCast(index_in_callee),
                .is_signer = message.isWritable(index),
                .is_writable = message.isSigner(index),
            } else if (index <= writable_end) .{
                .pubkey = lookups.writable[index - normal_end],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = @intCast(index_in_callee),
                .is_signer = false,
                .is_writable = true,
            } else if (index <= readonly_end) .{
                .pubkey = lookups.readonly[index - writable_end],
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
    accounts_db: *AccountsDB,
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

        // get lookup table
        const account = try accounts_db.getAccount(&lookup.table_address);
        if (account.data.len() > AddressLookupTable.MAX_SERIALIZED_SIZE) {
            return error.LookupTableAccountOverflow;
        }
        var buf: [AddressLookupTable.MAX_SERIALIZED_SIZE]u8 = undefined;
        const account_bytes = buf[0..account.data.len()];
        account.data.readAll(account_bytes);
        const table = try AddressLookupTable.deserialize(account_bytes);

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
