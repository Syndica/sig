/// Cost model for calculating transaction costs for block scheduling and packing.
/// This is different from compute_units_consumed which measures actual CUs used during execution.
/// cost_units is used for block capacity planning and fee calculations.
///
/// See Agave's cost model:
/// - https://github.com/anza-xyz/agave/blob/main/cost-model/src/block_cost_limits.rs
/// - https://github.com/anza-xyz/agave/blob/main/cost-model/src/cost_model.rs
const std = @import("std");
const sig = @import("../sig.zig");

const FeatureSet = sig.core.FeatureSet;
const Slot = sig.core.Slot;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const ComputeBudgetLimits = sig.runtime.program.compute_budget.ComputeBudgetLimits;

// Block cost limit constants from Agave's block_cost_limits.rs
// https://github.com/anza-xyz/agave/blob/main/cost-model/src/block_cost_limits.rs

/// Number of compute units for one signature verification.
pub const SIGNATURE_COST: u64 = 720;

/// Number of compute units for one write lock.
pub const WRITE_LOCK_UNITS: u64 = 300;

/// Cluster averaged compute unit to micro-sec conversion rate.
pub const COMPUTE_UNIT_TO_US_RATIO: u64 = 30;

/// Number of data bytes per compute unit.
/// From Agave: INSTRUCTION_DATA_BYTES_COST = 140 bytes/us / 30 CU/us = 4 bytes/CU
/// This means 1 CU per 4 bytes of instruction data.
pub const INSTRUCTION_DATA_BYTES_PER_UNIT: u64 = 140 / COMPUTE_UNIT_TO_US_RATIO;

/// Default instruction compute unit limit when not specified via SetComputeUnitLimit.
pub const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;

/// Cost per 32KB of loaded account data.
/// Based on Agave's ACCOUNT_DATA_COST_PAGE_SIZE = 32KB
pub const LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K: u64 = 8;

/// Page size for loaded accounts data cost calculation (32KB).
pub const ACCOUNT_DATA_COST_PAGE_SIZE: u64 = 32 * 1024;

/// Static cost for simple vote transactions (when feature is inactive).
/// Breakdown: 2100 (vote CUs) + 720 (1 sig) + 600 (2 write locks) + 8 (loaded data)
pub const SIMPLE_VOTE_USAGE_COST: u64 = sig.runtime.program.vote.COMPUTE_UNITS +
    SIGNATURE_COST +
    2 * WRITE_LOCK_UNITS +
    LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K;
comptime {
    if (SIMPLE_VOTE_USAGE_COST != 3428) @compileError(
        "SIMPLE_VOTE_USAGE_COST must be 3428 to match Agave's cost model",
    );
}

/// Represents the calculated cost units for a transaction.
/// Can be either a static simple vote cost or dynamically calculated.
pub const TransactionCost = union(enum) {
    /// Static cost for simple vote transactions (feature inactive)
    simple_vote: void,
    /// Dynamic cost calculation
    transaction: UsageCostDetails,

    /// Returns the total cost units for this transaction.
    pub fn total(self: TransactionCost) u64 {
        return switch (self) {
            .simple_vote => SIMPLE_VOTE_USAGE_COST,
            .transaction => |details| details.total(),
        };
    }

    pub fn programsExecutionCost(self: TransactionCost) u64 {
        return switch (self) {
            .simple_vote => sig.runtime.program.vote.COMPUTE_UNITS,
            .transaction => |details| details.programs_execution_cost,
        };
    }
};

/// Detailed cost breakdown for dynamically calculated transactions.
pub const UsageCostDetails = struct {
    /// Cost for verifying signatures.
    signature_cost: u64,
    /// Cost for acquiring write locks.
    write_lock_cost: u64,
    /// Cost for instruction data bytes.
    data_bytes_cost: u64,
    /// Cost for program execution (compute units).
    programs_execution_cost: u64,
    /// Cost for loaded account data size.
    loaded_accounts_data_size_cost: u64,

    /// Returns the total cost units for this transaction.
    pub fn total(self: UsageCostDetails) u64 {
        return self.signature_cost +
            self.write_lock_cost +
            self.data_bytes_cost +
            self.programs_execution_cost +
            self.loaded_accounts_data_size_cost;
    }
};

/// Calculate the cost units for a transaction before execution (estimation).
///
/// This follows Agave's cost model which calculates costs based on:
/// 1. Number of signatures (720 CU per signature)
/// 2. Number of write locks (300 CU per write lock)
/// 3. Instruction data bytes (1 CU per 4 bytes)
/// 4. Compute unit limit (from compute budget or default)
/// 5. Loaded accounts data size (8 CU per 32KB page)
///
/// When the `stop_use_static_simple_vote_tx_cost` feature is inactive,
/// simple vote transactions use a static cost of 3428 CU.
///
/// See: https://github.com/anza-xyz/agave/blob/main/cost-model/src/cost_model.rs
pub fn calculateTransactionCost(
    transaction: *const RuntimeTransaction,
    compute_budget_limits: *const ComputeBudgetLimits,
    loaded_accounts_data_size: u32,
    // feature_set: *const FeatureSet,
    // slot: Slot,
) TransactionCost {
    return calculateTransactionCostInternal(
        transaction,
        compute_budget_limits.compute_unit_limit,
        loaded_accounts_data_size,
    );
}

/// Calculate the cost units for an executed transaction using actual consumed CUs.
///
/// This should be used for calculating costs after execution, where we know
/// the actual compute units consumed rather than using the budget limit.
/// This matches Agave's `calculate_cost_for_executed_transaction`.
///
/// See: https://github.com/anza-xyz/agave/blob/main/cost-model/src/cost_model.rs#L66
pub fn calculateCostForExecutedTransaction(
    transaction: *const RuntimeTransaction,
    actual_programs_execution_cost: u64,
    loaded_accounts_data_size: u32,
) TransactionCost {
    return calculateTransactionCostInternal(
        transaction,
        actual_programs_execution_cost,
        loaded_accounts_data_size,
    );
}

/// Calculate the total signature verification cost for a transaction.
/// Includes transaction signatures AND precompile instruction signatures.
/// Mirrors Agave's `CostModel::get_signature_cost()`.
/// See: https://github.com/anza-xyz/agave/blob/eb30856ca804831f30d96f034a1cabd65c96184a/cost-model/src/cost_model.rs#L148
fn getSignatureCost(transaction: *const RuntimeTransaction) u64 {
    const precompiles = sig.runtime.program.precompiles;

    var n_secp256k1_instruction_signatures: u64 = 0;
    var n_ed25519_instruction_signatures: u64 = 0;
    // TODO: add secp256r1 when enable_secp256r1_precompile feature is active
    // var n_secp256r1_instruction_signatures: u64 = 0;

    for (transaction.instructions) |instruction| {
        if (instruction.instruction_data.len == 0) continue;

        const program_id = instruction.program_meta.pubkey;
        if (program_id.equals(&precompiles.secp256k1.ID)) {
            n_secp256k1_instruction_signatures +|= instruction.instruction_data[0];
        }
        if (program_id.equals(&precompiles.ed25519.ID)) {
            n_ed25519_instruction_signatures +|= instruction.instruction_data[0];
        }
        // TODO: uncomment when secp256r1 feature is active
        // if (program_id.equals(&precompiles.secp256r1.ID)) {
        //     n_secp256r1_instruction_signatures +|= instruction.instruction_data[0];
        // }
    }

    return transaction.signature_count *| precompiles.SIGNATURE_COST +|
        n_secp256k1_instruction_signatures *| precompiles.SECP256K1_VERIFY_COST +|
        n_ed25519_instruction_signatures *| precompiles.ED25519_VERIFY_COST;
    // TODO: +| n_secp256r1_instruction_signatures *| precompiles.SECP256R1_VERIFY_COST
}

/// Internal calculation function used by both pre-execution and post-execution cost calculation.
fn calculateTransactionCostInternal(
    transaction: *const RuntimeTransaction,
    programs_execution_cost: u64,
    loaded_accounts_data_size: u32,
    // feature_set: *const FeatureSet,
    // slot: Slot,
) TransactionCost {
    // _ = feature_set;
    // _ = slot;
    // Check if we should use static simple vote cost
    // TODO: implement this in the future
    // const use_static_vote_cost = !feature_set.active(.stop_use_static_simple_vote_tx_cost, slot);
    const use_static_vote_cost = true;

    if (transaction.isSimpleVoteTransaction() and use_static_vote_cost) {
        return .{ .simple_vote = {} };
    }

    // Dynamic calculation
    // 1. Signature cost: includes transaction sigs + precompile sigs (ed25519, secp256k1, secp256r1)
    const signature_cost = getSignatureCost(transaction);

    // 2. Write lock cost: 300 CU per writable account
    var write_lock_count: u64 = 0;
    for (transaction.accounts.items(.is_writable)) |is_writable| {
        if (is_writable) write_lock_count += 1;
    }
    const write_lock_cost = write_lock_count * WRITE_LOCK_UNITS;

    // 3. Instruction data bytes cost: 1 CU per INSTRUCTION_DATA_BYTES_PER_UNIT bytes (4 bytes)
    var total_instruction_data_len: u64 = 0;
    for (transaction.instructions) |instruction| {
        total_instruction_data_len += instruction.instruction_data.len;
    }
    // Truncating division (matches Agave)
    const data_bytes_cost = total_instruction_data_len / INSTRUCTION_DATA_BYTES_PER_UNIT;

    // 4. Programs execution cost: passed in (either limit for estimation, or actual consumed)

    // 5. Loaded accounts data size cost: 8 CU per 32KB page
    // This is calculated based on the actual loaded account data size
    const loaded_accounts_data_size_cost = calculateLoadedAccountsDataSizeCost(
        loaded_accounts_data_size,
    );

    return .{
        .transaction = .{
            .signature_cost = signature_cost,
            .write_lock_cost = write_lock_cost,
            .data_bytes_cost = data_bytes_cost,
            .programs_execution_cost = programs_execution_cost,
            .loaded_accounts_data_size_cost = loaded_accounts_data_size_cost,
        },
    };
}

/// Calculate the cost for loaded accounts data size.
/// Returns 8 CU per 32KB page (rounded up).
fn calculateLoadedAccountsDataSizeCost(loaded_accounts_data_size: u32) u64 {
    if (loaded_accounts_data_size == 0) return 0;

    // Round up to the next 32KB page
    const size: u64 = loaded_accounts_data_size;
    const pages = (size + ACCOUNT_DATA_COST_PAGE_SIZE - 1) / ACCOUNT_DATA_COST_PAGE_SIZE;
    return pages * LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K;
}

test "calculateLoadedAccountsDataSizeCost" {
    // 0 bytes = 0 cost
    try std.testing.expectEqual(@as(u64, 0), calculateLoadedAccountsDataSizeCost(0));

    // 1 byte = 1 page = 8 CU
    try std.testing.expectEqual(@as(u64, 8), calculateLoadedAccountsDataSizeCost(1));

    // 32KB exactly = 1 page = 8 CU
    try std.testing.expectEqual(@as(u64, 8), calculateLoadedAccountsDataSizeCost(32 * 1024));

    // 32KB + 1 = 2 pages = 16 CU
    try std.testing.expectEqual(@as(u64, 16), calculateLoadedAccountsDataSizeCost(32 * 1024 + 1));

    // 64KB = 2 pages = 16 CU
    try std.testing.expectEqual(@as(u64, 16), calculateLoadedAccountsDataSizeCost(64 * 1024));
}

test "UsageCostDetails.total" {
    const cost = UsageCostDetails{
        .signature_cost = SIGNATURE_COST,
        .write_lock_cost = 2 * WRITE_LOCK_UNITS,
        .data_bytes_cost = 10,
        .programs_execution_cost = 200_000,
        .loaded_accounts_data_size_cost = LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K,
    };
    try std.testing.expectEqual(@as(u64, 201_338), cost.total());
}

test "TransactionCost.total for simple_vote" {
    const cost = TransactionCost{ .simple_vote = {} };
    try std.testing.expectEqual(@as(u64, SIMPLE_VOTE_USAGE_COST), cost.total());
}

test "TransactionCost.total for transaction" {
    const cost = TransactionCost{
        .transaction = .{
            .signature_cost = SIGNATURE_COST,
            .write_lock_cost = 2 * WRITE_LOCK_UNITS,
            .data_bytes_cost = 10,
            .programs_execution_cost = 200_000,
            .loaded_accounts_data_size_cost = LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K,
        },
    };
    try std.testing.expectEqual(@as(u64, 201_338), cost.total());
}

test "TransactionCost.programsExecutionCost for simple_vote" {
    const cost = TransactionCost{ .simple_vote = {} };
    // Simple vote transactions use a static execution cost of 2100 CU (vote program default)
    try std.testing.expectEqual(
        @as(u64, sig.runtime.program.vote.COMPUTE_UNITS),
        cost.programsExecutionCost(),
    );
}

test "TransactionCost.programsExecutionCost for transaction" {
    const cost = TransactionCost{
        .transaction = .{
            .signature_cost = SIGNATURE_COST,
            .write_lock_cost = 2 * WRITE_LOCK_UNITS,
            .data_bytes_cost = 10,
            .programs_execution_cost = 150_000,
            .loaded_accounts_data_size_cost = LOADED_ACCOUNTS_DATA_SIZE_COST_PER_32K,
        },
    };
    // Should return the actual programs_execution_cost from the details
    try std.testing.expectEqual(@as(u64, 150_000), cost.programsExecutionCost());
}
