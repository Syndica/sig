const sig = @import("../../../sig.zig");

const InstructionInfo = sig.runtime.InstructionInfo;

pub const ID = sig.runtime.ids.COMPUTE_BUDGET_PROGRAM_ID;

pub const Error = error{ InvalidLoadedAccountsDataSizeLimit, InvalidInstructionData };

pub fn execute(transaction: []const InstructionInfo) Error!ComputeBudgetLimits {
    _ = transaction;
    return ComputeBudgetLimits.DEFAULT;
}

pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;
const HEAP_LENGTH = 32 * 1024;
const MIN_HEAP_FRAME_BYTES = HEAP_LENGTH;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

// [agave] https://github.com/anza-xyz/agave/blob/3e9af14f3a145070773c719ad104b6a02aefd718/compute-budget/src/compute_budget_limits.rs#L28
pub const ComputeBudgetLimits = struct {
    updated_heap_bytes: u32,
    compute_unit_limit: u32,
    compute_unit_price: u64,
    /// non-zero
    loaded_accounts_bytes: u32,

    pub const DEFAULT: ComputeBudgetLimits = .{
        .updated_heap_bytes = MIN_HEAP_FRAME_BYTES,
        .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
        .compute_unit_price = 0,
        .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    };

    pub fn intoComputeBudget(self: ComputeBudgetLimits) sig.runtime.ComputeBudget {
        var default = sig.runtime.ComputeBudget.default(self.compute_unit_limit);
        default.heap_size = self.updated_heap_bytes;
        return default;
    }
};
