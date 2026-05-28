const shared = @import("shared");

const account_loader = shared.runtime.account_loader;

pub const MAX_TX_ACCOUNT_LOCKS = account_loader.MAX_TX_ACCOUNT_LOCKS;
pub const TRANSACTION_ACCOUNT_BASE_SIZE = account_loader.TRANSACTION_ACCOUNT_BASE_SIZE;
pub const ADDRESS_LOOKUP_TABLE_BASE_SIZE = account_loader.ADDRESS_LOOKUP_TABLE_BASE_SIZE;
pub const RentDebit = account_loader.RentDebit;
pub const LoadedTransactionAccounts = account_loader.LoadedTransactionAccounts;
pub const LoadedAccount = account_loader.LoadedAccount;
pub const PreparedAccount = account_loader.PreparedAccount;
pub const AccountLoadError = account_loader.AccountLoadError;
pub const loadTransactionAccounts = account_loader.loadTransactionAccounts;
pub const collectRentFromAccount = account_loader.collectRentFromAccount;
