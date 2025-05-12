const sig = @import("../../../sig.zig");

const InstructionInfo = sig.runtime.InstructionInfo;

pub const ID = sig.runtime.ids.COMPUTE_BUDGET_PROGRAM_ID;

pub const Error = error{ InvalidLoadedAccountsDataSizeLimit, InvalidInstructionData };

pub fn execute(tx: []const InstructionInfo) Error!ComputeBudgetLimits {
    const instr_details = try ComputeBudgetInstructionDetails.fromInstructions(tx);
    const budget_limits = try instr_details.sanitizeAndConvertToComputeBudgetLimits();
    return budget_limits;
}

// TODO: do we really need this type? I think we could just make a ComputeBudget type directly.
// This code is a bit hairy in Agave. Same goes for ComputeBudgetLimits.
// [agave] https://github.com/anza-xyz/agave/blob/b70cac38827e499d34c3a521eac17c68fb1b5b1f/compute-budget-instruction/src/compute_budget_instruction_details.rs#L39
const ComputeBudgetInstructionDetails = struct {
    /// unimpl
    const MigrationBuiltinFeatureCounter = struct {};

    const Value32 = struct { instr_idx: u8, value: u32 };
    const Value64 = struct { instr_idx: u8, value: u32 };

    // compute-budget instruction details:
    // the first field in tuple is instruction index, second field is the unsanitized value set by user
    requested_compute_unit_limit: ?Value32,
    requested_compute_unit_price: ?Value64,
    requested_heap_size: ?Value32,
    requested_loaded_accounts_data_size_limit: ?Value32,
    num_non_compute_budget_instructions: u16,
    // Additional builtin program counters
    num_non_migratable_builtin_instructions: u16,
    num_non_builtin_instructions: u16,
    migrating_builtin_feature_counters: MigrationBuiltinFeatureCounter,

    const DEFAULT: ComputeBudgetInstructionDetails = .{
        .requested_compute_unit_limit = null,
        .requested_compute_unit_price = null,
        .requested_heap_size = null,
        .requested_loaded_accounts_data_size_limit = null,
        .num_non_compute_budget_instructions = 0,
        .num_non_migratable_builtin_instructions = 0,
        .num_non_builtin_instructions = 0,
        .migrating_builtin_feature_counters = .{},
    };

    // This impl is a bit of a stub
    // [agave] https://github.com/anza-xyz/agave/blob/b70cac38827e499d34c3a521eac17c68fb1b5b1f/compute-budget-instruction/src/compute_budget_instruction_details.rs#L54
    fn fromInstructions(
        instructions: []const InstructionInfo,
    ) !ComputeBudgetInstructionDetails {
        const details = DEFAULT;

        for (instructions) |instr| {
            if (instr.program_meta.pubkey.equals(&ID)) {
                @panic("TODO: compute budget program unsupported");
            }
        }

        return details;
    }

    const HEAP_LENGTH = 32 * 1024;
    const MIN_HEAP_FRAME_BYTES = HEAP_LENGTH;
    const MAX_HEAP_FRAME_BYTES = 256 * 1024;
    const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT = 200_000;
    const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

    fn sanitizeRequestedHeapSize(bytes: u32) bool {
        return bytes % 1024 == 0 and
            bytes >= MIN_HEAP_FRAME_BYTES and bytes <= MAX_HEAP_FRAME_BYTES;
    }

    fn sanitizeAndConvertToComputeBudgetLimits(
        self: ComputeBudgetInstructionDetails,
    ) error{ InvalidLoadedAccountsDataSizeLimit, InvalidInstructionData }!ComputeBudgetLimits {
        const updated_heap_bytes = @min(
            MAX_HEAP_FRAME_BYTES,
            if (self.requested_heap_size) |requested_heap_size| blk: {
                if (sanitizeRequestedHeapSize(requested_heap_size.value)) {
                    break :blk requested_heap_size.value;
                } else {
                    return error.InvalidInstructionData;
                }
            } else MIN_HEAP_FRAME_BYTES,
        );

        // TODO: the real impl for this one is more complicated
        const compute_unit_limit = if (self.requested_compute_unit_limit) |limit|
            limit.value
        else
            DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;

        const compute_unit_price = if (self.requested_compute_unit_price) |price|
            price.value
        else
            0;

        const loaded_bytes = if (self.requested_loaded_accounts_data_size_limit) |size_limit| blk: {
            if (size_limit.value == 0) return error.InvalidLoadedAccountsDataSizeLimit;
            break :blk @min(MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, size_limit.value);
        } else MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;

        return .{
            .updated_heap_bytes = updated_heap_bytes,
            .compute_unit_limit = compute_unit_limit,
            .compute_unit_price = compute_unit_price,
            .loaded_accounts_bytes = loaded_bytes,
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/3e9af14f3a145070773c719ad104b6a02aefd718/compute-budget/src/compute_budget_limits.rs#L28
pub const ComputeBudgetLimits = struct {
    updated_heap_bytes: u32,
    compute_unit_limit: u32,
    compute_unit_price: u64,
    /// non-zero
    loaded_accounts_bytes: u32,

    pub fn intoComputeBudget(self: ComputeBudgetLimits) sig.runtime.ComputeBudget {
        var default = sig.runtime.ComputeBudget.default(self.compute_unit_limit);
        default.heap_size = self.updated_heap_bytes;
        return default;
    }
};
