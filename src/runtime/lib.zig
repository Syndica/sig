pub const borrowed_account = @import("borrowed_account.zig");
pub const feature_set = @import("feature_set.zig");
pub const ids = @import("ids.zig");
pub const instruction_context = @import("instruction_context.zig");
pub const log_collector = @import("log_collector.zig");
pub const nonce = @import("nonce.zig");
pub const program = @import("program/lib.zig");
pub const pubkey_utils = @import("pubkey_utils.zig");
pub const sysvar = @import("sysvar/lib.zig");
pub const sysvar_cache = @import("sysvar_cache.zig");
pub const tmp_utils = @import("tmp_utils.zig");
pub const transaction_context = @import("transaction_context.zig");

pub const BorrowedAccount = borrowed_account.BorrowedAccount;
pub const FeatureSet = feature_set.FeatureSet;
pub const InstructionContext = instruction_context.InstructionContext;
pub const InstructionAccountInfo = instruction_context.InstructionAccountInfo;
pub const LogCollector = log_collector.LogCollector;
pub const SysvarCache = sysvar_cache.SysvarCache;
pub const TransactionContext = transaction_context.TransactionContext;
pub const TransactionAccount = transaction_context.TransactionAccount;

// TODO: move to accounts db
pub const AccountSharedData = @import("account_shared_data.zig").AccountSharedData;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/serialization.rs#L26
pub const MAX_INSTRUCTION_ACCOUNTS: usize = 256;

/// TODO: Why do I need to define this here for the tests to run?
pub const system_program_execute = @import("program/system_program/execute.zig");
