const std = @import("std");
const std14 = @import("std14");

const AccountSharedData = @import("AccountSharedData.zig");
const Pubkey = @import("../core/lib.zig").Pubkey;

pub const MAX_TX_ACCOUNT_LOCKS = 128;

pub const RentDebit = struct { rent_collected: u64, rent_balance: u64 };

pub const LoadedTransactionAccounts = struct {
    accounts: Accounts,
    rent_debits: std14.BoundedArray(RentDebit, MAX_TX_ACCOUNT_LOCKS),
    rent_collected: u64,
    loaded_accounts_data_size: u32,

    pub const Accounts = std14.BoundedArray(LoadedAccount, MAX_TX_ACCOUNT_LOCKS);

    pub const DEFAULT: LoadedTransactionAccounts = .{
        .accounts = .{},
        .rent_debits = .{},
        .rent_collected = 0,
        .loaded_accounts_data_size = 0,
    };

    pub fn deinit(self: *const LoadedTransactionAccounts, allocator: std.mem.Allocator) void {
        for (self.accounts.slice()) |account| account.deinit(allocator);
    }

    pub fn increase(
        self: *LoadedTransactionAccounts,
        account_data_size: usize,
        requested_loaded_accounts_data_size_limit: u32,
    ) error{MaxLoadedAccountsDataSizeExceeded}!void {
        const account_data_sz = std.math.cast(u32, account_data_size) orelse
            return error.MaxLoadedAccountsDataSizeExceeded;

        self.loaded_accounts_data_size +|= account_data_sz;

        if (self.loaded_accounts_data_size > requested_loaded_accounts_data_size_limit) {
            return error.MaxLoadedAccountsDataSizeExceeded;
        }
    }
};

pub const LoadedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,

    pub fn deinit(self: LoadedAccount, allocator: std.mem.Allocator) void {
        self.account.deinit(allocator);
    }
};

pub const AccountLoadError = error{ OutOfMemory, AccountsDBError };

pub fn wrapDB(item: anytype) AccountLoadError!@typeInfo(@TypeOf(item)).error_union.payload {
    const ItemError = @typeInfo(@TypeOf(item)).error_union.error_set;
    return item catch |err| switch (@as(AccountLoadError || ItemError, err)) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.AccountsDBError,
    };
}
