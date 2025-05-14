const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const Entry = core.Entry;
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
    accounts_to_lock: []const LockableAccount,

    pub fn deinit(self: ResolvedBatch, allocator: Allocator) void {
        for (self.transactions) |tx| tx.deinit(allocator);
        allocator.free(self.transactions);
        allocator.free(self.accounts_to_lock);
    }
};

/// This is a transaction plus the following additions:
/// - The lookup table addresses have been resolved from accountsdb.
/// - The instructions have been expanded out to a more useful form for the SVM.
pub const ResolvedTransaction = struct {
    transaction: Transaction,
    // writable_lookups: []const Pubkey,
    // readonly_lookups: []const Pubkey,
    instructions: []const InstructionInfo,
    accounts: []const TxAccount,

    pub const TxAccount = struct {
        address: Pubkey,
        writable: bool,
    };

    pub fn deinit(self: ResolvedTransaction, allocator: Allocator) void {
        allocator.free(self.instructions);
        allocator.free(self.accounts);
        // allocator.free(self.writable_lookups);
        // allocator.free(self.readonly_lookups);
        // transaction and instruction_data are not freed because they are borrowed.
    }
};

pub fn resolveBatch(
    allocator: Allocator,
    accounts_db: *AccountsDB,
    batch: []const Transaction,
) !ResolvedBatch {
    var accounts_to_lock = try std.ArrayListUnmanaged(struct { Pubkey, bool })
        .initCapacity(allocator, Transaction.numAccounts(batch));
    errdefer accounts_to_lock.deinit(allocator);

    const resolved_txns = try allocator.alloc(ResolvedTransaction, batch.len);
    errdefer allocator.free(resolved_txns);

    for (batch.items, resolved_txns) |transaction, *resolved| {
        resolved.* = try ResolvedTransaction
            .init(allocator, accounts_db, transaction, &accounts_to_lock);
    }

    return .{
        .transactions = resolved_txns,
        .accounts_to_lock = accounts_to_lock.toOwnedSlice(allocator),
    };
}

/// Returned data is partially borrowed and partially owned.
/// - Ensure `transaction` exceeds the lifetime of this struct.
/// - Use `deinit` to free this struct
fn resolveTransaction(
    allocator: Allocator,
    accounts_db: *AccountsDB,
    transaction: Transaction,
    batch_accounts: *std.ArrayListUnmanaged(struct { Pubkey, bool }),
) !ResolvedTransaction {
    _ = batch_accounts; // autofix // TODO: maybe just split out the lookup table stuff
    const message = transaction.msg;
    const instructions = allocator.alloc(InstructionInfo, message.instructions.len);
    const lookups = try resolveLookupTableAccounts(allocator, accounts_db, message);
    defer {
        allocator.free(lookups.writable);
        allocator.free(lookups.readonly);
    }
    const normal_bound = message.account_keys.len;
    const writable_bound = lookups.writable.len + normal_bound;
    const readonly_bound = lookups.readonly.len + writable_bound;
    for (message.instructions, instructions) |input_ix, *output_ix| {
        const account_metas = try allocator.alloc(AccountMeta, input_ix.account_indexes);
        const seen = std.bit_set.ArrayBitSet(256).initEmpty();
        for (input_ix.account_indexes, account_metas, 0..) |index, *account_meta, i| {
            // find first usage of this account in this instruction
            const index_in_callee = if (seen.isSet(index))
                for (input_ix.account_indexes[0..i], 0..) |prior_index, j| {
                    if (prior_index == index) break j;
                } else unreachable
            else
                i;
            seen.set(index);

            // expand the account metadata
            account_meta.* = if (index <= normal_bound) AccountMeta{
                .pubkey = message.account_keys[index],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = index_in_callee,
                .is_signer = index < message.signature_count,
                .is_writable = index < message.signature_count and
                    index > message.readonly_signed_count or
                    index >= message.signature_count + message.readonly_unsigned_count,
            } else if (index <= writable_bound) AccountMeta{
                .pubkey = lookups.writable[index - normal_bound],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = index_in_callee,
                .is_signer = false,
                .is_writable = true,
            } else if (index <= readonly_bound) AccountMeta{
                .pubkey = lookups.readonly[index - writable_bound],
                .index_in_transaction = index,
                .index_in_caller = index,
                .index_in_callee = index_in_callee,
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
        .writable_lookups = lookups.writable,
        .readonly_lookups = lookups.readonly,
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

    const writable_accounts = try allocator.alloc(ResolvedTransaction.Account, total_writable);
    errdefer allocator.free(writable_accounts);
    const readonly_accounts = try allocator.alloc(ResolvedTransaction.Account, total_readonly);
    errdefer allocator.free(readonly_accounts);

    // handle lookup table accounts
    for (address_lookups) |lookup| {

        // get lookup table
        const account = try accounts_db.getAccount(&lookup.table_address);
        var buf: [AddressLookupTable.MAX_SERIALIZED_SIZE]u8 = undefined;
        const bytes_read = account.data.read(&buf);
        const table = try AddressLookupTable.deserialize(buf[0..bytes_read]);

        // resolve writable addresses
        for (writable_accounts, lookup.writable_indexes) |*acc, index| {
            if (table.addresses.len < index + 1) {
                return error.LookupTableAccountTooSmall;
            }
            acc.* = Pubkey{ .data = table.addresses[index].* };
        }

        // resolve readonly addresses
        for (readonly_accounts, lookup.readonly_indexes) |*acc, index| {
            if (table.addresses.len < index + 1) {
                return error.LookupTableAccountTooSmall;
            }
            acc.* = Pubkey{ .data = table.addresses[index].* };
        }
    }

    return .{
        .writable = writable_accounts,
        .readable = readonly_accounts,
    };
}
