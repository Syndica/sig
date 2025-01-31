pub const ids = @import("ids.zig");
pub const nonce = @import("nonce.zig");
pub const program = @import("program/lib.zig");
pub const sysvar = @import("sysvar/lib.zig");
pub const pubkey_utils = @import("pubkey_utils.zig");
pub const tmp_utils = @import("tmp_utils.zig");

pub const ExecuteTransactionContext =
    @import("execute_transaction_context.zig").ExecuteTransactionContext;
pub const ExecuteInstructionContext =
    @import("execute_instruction_context.zig").ExecuteInstructionContext;
pub const FeatureSet = @import("feature_set.zig").FeatureSet;
pub const SysvarCache = @import("sysvar_cache.zig").SysvarCache;

pub const BorrowedAccount = @import("borrowed_account.zig").BorrowedAccount;
pub const LogCollector = @import("log_collector.zig").LogCollector;

// TODO: move to accounts db
pub const AccountSharedData = @import("account_shared_data.zig").AccountSharedData;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/serialization.rs#L26
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 256;

/// TODO: Why do I need to define this here for the tests to run?
pub const system_program_execute = @import("program/system_program_execute.zig");
