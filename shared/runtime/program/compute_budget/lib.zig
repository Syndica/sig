const std = @import("std");

const core = @import("../../../core/lib.zig");
const RuntimeComputeBudget = @import("../../ComputeBudget.zig");

pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
pub const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
pub const HEAP_LENGTH: usize = 32 * 1024;
pub const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
pub const MIN_HEAP_FRAME_BYTES: u32 = HEAP_LENGTH;
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

pub const ID: core.Pubkey = .parse("ComputeBudget111111111111111111111111111111");

pub const COMPUTE_UNITS = 150;

pub const ComputeBudgetInstructionDetails = struct {
    // compute-budget instruction details:
    // the first field in tuple is instruction index, second field is the unsanitized value set by user
    requested_compute_unit_limit: ?struct { u8, u32 } = null,
    requested_compute_unit_price: ?struct { u8, u64 } = null,
    requested_heap_size: ?struct { u8, u32 } = null,
    requested_loaded_accounts_data_size_limit: ?struct { u8, u32 } = null,
    num_non_compute_budget_instructions: u16 = 0,
    // Additional builtin program counters
    num_non_migratable_builtin_instructions: u16 = 0,
    num_non_builtin_instructions: u16 = 0,
    migrating_builtin_feature_counters: [3]u16 = @splat(0),
};

// [agave] https://github.com/anza-xyz/agave/blob/3e9af14f3a145070773c719ad104b6a02aefd718/compute-budget/src/compute_budget_limits.rs#L28
pub const ComputeBudgetLimits = struct {
    heap_size: u32,
    compute_unit_limit: u32,
    compute_unit_price: u64,
    /// non-zero
    loaded_accounts_bytes: u32,

    pub const DEFAULT: ComputeBudgetLimits = .{
        .heap_size = MIN_HEAP_FRAME_BYTES,
        .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
        .compute_unit_price = 0,
        .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    };

    pub fn intoComputeBudget(
        self: ComputeBudgetLimits,
        feature_set: *const core.FeatureSet,
        slot: core.Slot,
    ) RuntimeComputeBudget {
        const simd_0339_active = feature_set.active(.increase_cpi_account_info_limit, slot);
        var default = RuntimeComputeBudget.init(self.compute_unit_limit, simd_0339_active);
        default.heap_size = self.heap_size;
        return default;
    }
};
