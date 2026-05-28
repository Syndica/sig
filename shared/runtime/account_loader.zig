const std = @import("std");
const std14 = @import("../std14.zig");
const sig = @import("../lib.zig");

const AccountSharedData = @import("AccountSharedData.zig");
const execution_interfaces = @import("execution_interfaces.zig");

const Allocator = std.mem.Allocator;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const RENT_EXEMPT_RENT_EPOCH = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
const CollectedInfo = sig.core.rent_collector.CollectedInfo;

pub const AccountLoadError = execution_interfaces.AccountLoadError;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
pub const MAX_TX_ACCOUNT_LOCKS = 128;

// [agave] https://github.com/anza-xyz/agave/blob/7b0e13bc6fb4bfd84eb3cd0ace4bd86a451f1913/svm/src/account_loader.rs#L43
/// Storage cost of the transaction account metadata.
pub const TRANSACTION_ACCOUNT_BASE_SIZE = 64;
// [agave] https://github.com/anza-xyz/agave/blob/7b0e13bc6fb4bfd84eb3cd0ace4bd86a451f1913/svm/src/account_loader.rs#L47
/// Per SIMD-0186, resolved address lookup tables are assigned a base size of 8248
/// bytes: 8192 bytes for the maximum table size plus 56 bytes for metadata.
pub const ADDRESS_LOOKUP_TABLE_BASE_SIZE = 8248;

pub const RentDebit = struct { rent_collected: u64, rent_balance: u64 };

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L417
/// agave's LoadedTransactionAccounts contains a field "program indices". This has been omitted as
/// it's a Vec<Vec<u8>> whose elements are either [program_id] or [] (when program_id is the native
/// loader), which seems pointless.
pub const LoadedTransactionAccounts = struct {
    /// data owned by AccountMap
    accounts: Accounts,
    /// equal len to .accounts
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

    pub fn deinit(self: *const LoadedTransactionAccounts, allocator: Allocator) void {
        for (self.accounts.slice()) |account| account.deinit(allocator);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L618
    pub fn increase(
        self: *LoadedTransactionAccounts,
        account_data_size: usize,
        /// non-zero
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

// An account that was loaded to execute a transaction. The data slice is owned.
pub const LoadedAccount = struct {
    pubkey: Pubkey,
    account: AccountSharedData,

    pub fn deinit(self: LoadedAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }
};

/// An account loaded and prepared for transaction execution, with its
/// contribution to the loaded data size and any rent that was collected.
pub const PreparedAccount = struct {
    account: AccountSharedData,
    loaded_size: usize,
    rent_collected: u64,
};

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L293
pub fn collectRentFromAccount(
    account: *AccountSharedData,
    account_key: *const Pubkey,
    feature_set: *const sig.core.FeatureSet,
    slot: sig.core.Slot,
    rent_collector: *const RentCollector,
) CollectedInfo {
    if (!feature_set.active(.disable_rent_fees_collection, slot)) {
        @branchHint(.unlikely);
        return rent_collector.collectFromExistingAccount(account_key, account);
    }

    if (account.rent_epoch != RENT_EXEMPT_RENT_EPOCH and
        rent_collector.getRentDue(
            account.lamports,
            account.data.len,
            account.rent_epoch,
        ) == .Exempt)
    {
        account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;
    }

    return CollectedInfo.NoneCollected;
}
