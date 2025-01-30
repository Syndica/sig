pub const id = @import("id.zig");
pub const nonce = @import("nonce.zig");
pub const program = @import("program/lib.zig");
pub const sysvar = @import("sysvar/lib.zig");
pub const pubkey_utils = @import("pubkey_utils.zig");
pub const tmp_utils = @import("tmp_utils.zig");

pub const ExecuteTransactionContext = @import("execute_transaction_context.zig").ExecuteTransactionContext;
pub const ExecuteInstructionContext = @import("execute_instruction_context.zig").ExecuteInstructionContext;
pub const SysvarCache = @import("sysvar_cache.zig").SysvarCache;

pub const BorrowedAccount = @import("borrowed_account.zig").BorrowedAccount;
pub const LogCollector = @import("log_collector.zig").LogCollector;

// TODO: move to accounts db
pub const AccountSharedData = @import("account_shared_data.zig").AccountSharedData;

// TODO: Find better place for these constants

/// Maximum permitted size of account data (10 MiB).
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/system_instruction.rs#L85
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

/// Maximum permitted size of new allocations per transaction, in bytes.
///
/// The value was chosen such that at least one max sized account could be created,
/// plus some additional resize allocations.
/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/system_instruction.rs#L91
pub const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 = @intCast(2 * MAX_PERMITTED_DATA_LENGTH);

// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/info/fd_instr_info.h#L12
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 256;
