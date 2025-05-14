const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../../sig.zig");

const features = sig.runtime.features;
const builtin_costs = sig.runtime.program.builtin_costs;

const Pubkey = sig.core.Pubkey;
const Packet = sig.net.Packet;
const FeatureSet = sig.runtime.FeatureSet;
const InstructionInfo = sig.runtime.InstructionInfo;
const TransactionError = sig.runtime.transaction_error.TransactionError;
const TransactionResult = sig.runtime.transaction_error.TransactionResult;

const MIGRATING_BUILTIN_COSTS = builtin_costs.MIGRATING_BUILTIN_COSTS;
const MAX_TRANSACTION_ACCOUNTS = sig.core.Transaction.MAX_ACCOUNTS;
const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
const HEAP_LENGTH: usize = 32 * 1024;
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
const MIN_HEAP_FRAME_BYTES: u32 = HEAP_LENGTH;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

pub const ID =
    Pubkey.parseBase58String("ComputeBudget111111111111111111111111111111") catch unreachable;

pub const COMPUTE_UNITS = 150;

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

    pub fn intoComputeBudget(self: ComputeBudgetLimits) sig.runtime.ComputeBudget {
        var default = sig.runtime.ComputeBudget.default(self.compute_unit_limit);
        default.heap_size = self.heap_size;
        return default;
    }
};

const ComputeBudgetInstruction = union(enum(u32)) {
    /// Deprecated variant, reserved value.
    unused,

    /// Request a specific transaction-wide program heap region size in bytes.
    /// The value requested must be a multiple of 1024. This new heap region
    /// size applies to each program executed in the transaction, including all
    /// calls to CPIs.
    request_heap_frame: u32,

    /// Set a specific compute unit limit that the transaction is allowed to consume.
    set_compute_unit_limit: u32,

    /// Set a compute unit price in "micro-lamports" to pay a higher transaction
    /// fee for higher transaction prioritization.
    set_compute_unit_price: u64,

    /// Set a specific transaction-wide account data size limit, in bytes, is allowed to load.
    set_loaded_accounts_data_size_limit: u32,
};

pub fn execute(
    instructions: []const InstructionInfo,
    feature_set: *const FeatureSet,
) TransactionResult(ComputeBudgetLimits) {
    var requested_compute_unit_limit: ?struct { u8, u32 } = null;
    var requested_compute_unit_price: ?struct { u8, u64 } = null;
    var requested_heap_size: ?struct { u8, u32 } = null;
    var requested_loaded_accounts_data_size_limit: ?struct { u8, u32 } = null;
    var num_non_compute_budget_instructions: u16 = 0;
    var num_non_migratable_builtin_instructions: u16 = 0;
    var num_non_builtin_instructions: u16 = 0;
    var migrating_builtin_counts = [_]u16{0} ** MIGRATING_BUILTIN_COSTS.len;

    var is_compute_budget_cache = [_]?bool{null} ** MAX_TRANSACTION_ACCOUNTS;

    for (instructions, 0..) |instr, index| {
        const program_id = instr.program_meta.pubkey;
        const program_index = instr.program_meta.index_in_transaction;

        if (isComputeBudgetProgram(&is_compute_budget_cache, program_index, program_id)) {
            const invalid_instruction_data_error: TransactionResult(ComputeBudgetLimits) = .{
                .err = .{
                    .InstructionError = .{ @intCast(index), error.InvalidInstructionData },
                },
            };
            const duplicate_instruction_error: TransactionResult(ComputeBudgetLimits) = .{
                .err = .{
                    .DuplicateInstruction = @intCast(index),
                },
            };

            const instruction = instr.deserializeInstruction(
                std.testing.failing_allocator,
                ComputeBudgetInstruction,
            ) catch return invalid_instruction_data_error;

            switch (instruction) {
                .unused => return invalid_instruction_data_error,
                .request_heap_frame => |heap_size| {
                    if (requested_heap_size) |_|
                        return duplicate_instruction_error;

                    requested_heap_size = .{
                        @intCast(index),
                        heap_size,
                    };
                },
                .set_compute_unit_limit => |compute_unit_limit| {
                    if (requested_compute_unit_limit) |_|
                        return duplicate_instruction_error;

                    requested_compute_unit_limit = .{
                        @intCast(index),
                        compute_unit_limit,
                    };
                },
                .set_compute_unit_price => |compute_unit_price| {
                    if (requested_compute_unit_price) |_|
                        return duplicate_instruction_error;

                    requested_compute_unit_price = .{
                        @intCast(index),
                        compute_unit_price,
                    };
                },
                .set_loaded_accounts_data_size_limit => |loaded_accounts_data_size_limit| {
                    if (requested_loaded_accounts_data_size_limit) |_|
                        return duplicate_instruction_error;

                    requested_loaded_accounts_data_size_limit = .{
                        @intCast(index),
                        loaded_accounts_data_size_limit,
                    };
                },
            }
        } else num_non_compute_budget_instructions +|= 1;
    }

    if (requested_compute_unit_limit == null) {
        var kind_cache = [_]?ProgramKind{null} ** MAX_TRANSACTION_ACCOUNTS;
        for (instructions, 0..) |instr, index| {
            switch (getProgramKind(&kind_cache, index, instr.program_meta.pubkey)) {
                .not_builtin => num_non_builtin_instructions +|= 1,
                .builtin => num_non_migratable_builtin_instructions +|= 1,
                .migrating_builtin => |pos| migrating_builtin_counts[pos] += 1,
            }
        }
    }

    // Requested heap size outsize of range is a transaction error
    // Requested heap size is not a multiple of 1024 is an instruction error
    const heap_bytes = blk: {
        if (requested_heap_size) |heap_size| {
            const index, const size = heap_size;
            if (size >= MIN_HEAP_FRAME_BYTES and
                size <= MAX_HEAP_FRAME_BYTES and
                size % 1024 == 0)
                break :blk size
            else
                return .{
                    .err = .{
                        .InstructionError = .{ index, error.InvalidInstructionData },
                    },
                };
        }
        break :blk MIN_HEAP_FRAME_BYTES;
    };

    // Requested compute unit limit greater than max results in max compute unit limit
    const compute_unit_limit = if (requested_compute_unit_limit) |limit|
        limit[1]
    else
        defaultComputeUnitLimit(
            feature_set,
            num_non_compute_budget_instructions,
            num_non_builtin_instructions,
            num_non_migratable_builtin_instructions,
            &migrating_builtin_counts,
        );

    // Compute unit price is not bounded
    const compute_unit_price = if (requested_compute_unit_price) |price|
        price[1]
    else
        0;

    // Requested loaded accounts data size limit greater than max results in max loaded accounts data size limit
    const loaded_accounts_bytes = blk: {
        if (requested_loaded_accounts_data_size_limit) |max_size| {
            if (max_size[1] == 0) return .{ .err = .InvalidLoadedAccountsDataSizeLimit };
            break :blk max_size[1];
        }
        break :blk MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;
    };

    return .{ .ok = .{
        .heap_size = heap_bytes,
        .compute_unit_limit = @min(compute_unit_limit, MAX_COMPUTE_UNIT_LIMIT),
        .compute_unit_price = compute_unit_price,
        .loaded_accounts_bytes = @min(loaded_accounts_bytes, MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES),
    } };
}

fn isComputeBudgetProgram(cache: []?bool, index: usize, program_id: Pubkey) bool {
    if (cache[index] == null) {
        cache[index] = program_id.equals(&ID);
    }
    return cache[index].?;
}

fn defaultComputeUnitLimit(
    feature_set: *const FeatureSet,
    num_non_compute_budget_instructions: u32,
    num_non_builtin_instructions: u32,
    num_non_migratable_builtin_instructions: u32,
    migrating_builtin_counts: []u16,
) u32 {
    if (feature_set.active.contains(features.RESERVE_MINIMAL_CUS_FOR_BUILTIN_INSTRUCTIONS)) {
        var num_migrated: u32 = 0;
        var num_not_migrated: u32 = 0;
        for (migrating_builtin_counts, 0..) |count, index| {
            if (count > 0 and feature_set.active.contains(
                builtin_costs.getMigrationFeatureId(index),
            ))
                num_migrated += count
            else
                num_not_migrated += count;
        }

        const builtin_limit = (num_non_migratable_builtin_instructions +| num_not_migrated) *|
            MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT;

        const not_builtin_limit = (num_non_builtin_instructions +| num_migrated) *|
            DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;

        return builtin_limit +| not_builtin_limit;
    } else return num_non_compute_budget_instructions *| DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;
}

const ProgramKind = union(enum(u8)) {
    not_builtin,
    builtin,
    migrating_builtin: usize,
};

fn getProgramKind(
    cache: []?ProgramKind,
    index: usize,
    program_id: Pubkey,
) ProgramKind {
    if (cache[index] == null) {
        if (!builtin_costs.MAYBE_BUILTIN_KEY[program_id.data[0]])
            return .not_builtin;

        if (builtin_costs.BUILTIN_COSTS.get(&program_id.data)) |builtin_cost| {
            cache[index] = if (builtin_cost.position()) |pos| .{
                .migrating_builtin = pos,
            } else .builtin;
        } else cache[index] = .not_builtin;
    }
    return cache[index].?;
}

fn testComputeBudgetLimits(
    allocator: std.mem.Allocator,
    feature_set: FeatureSet,
    instructions: []const InstructionInfo,
    expected: struct {
        err: ?TransactionError = null,
        heap_size: u32 = MIN_HEAP_FRAME_BYTES,
        compute_unit_limit: u32 = MAX_COMPUTE_UNIT_LIMIT,
        compute_unit_price: u64 = 0,
        loaded_accounts_bytes: u32 = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    },
) !void {
    if (!builtin.is_test) @compileError("testComputeBudgetLimits is for testing only");
    defer {
        // Only the compute budget instruction infos have allocated instruction data
        for (instructions) |instr| {
            if (instr.program_meta.pubkey.equals(&ID))
                allocator.free(instr.instruction_data);
        }
        feature_set.deinit(allocator);
    }

    const indexed_instructions = try allocator.alloc(
        InstructionInfo,
        instructions.len,
    );
    defer allocator.free(indexed_instructions);

    for (instructions, 0..) |instr, index| {
        indexed_instructions[index] = instr;
        indexed_instructions[index].program_meta.index_in_transaction = @intCast(index);
    }

    const result = execute(indexed_instructions, &feature_set);

    switch (result) {
        .ok => |actual| {
            try std.testing.expect(expected.err == null);

            try std.testing.expectEqual(
                expected.heap_size,
                actual.heap_size,
            );
            try std.testing.expectEqual(
                expected.compute_unit_limit,
                actual.compute_unit_limit,
            );
            try std.testing.expectEqual(
                expected.compute_unit_price,
                actual.compute_unit_price,
            );
            try std.testing.expectEqual(
                expected.loaded_accounts_bytes,
                actual.loaded_accounts_bytes,
            );
        },
        .err => |actual_err| {
            try std.testing.expect(expected.err != null);
            try std.testing.expectEqual(
                expected.err.?,
                actual_err,
            );
        },
    }
}

fn computeBudgetInstructionInfo(
    allocator: std.mem.Allocator,
    instruction: ComputeBudgetInstruction,
) !InstructionInfo {
    if (!builtin.is_test) @compileError("computeBudgetInstructionInfo is for testing only");
    const instruction_data = try sig.bincode.writeAlloc(
        allocator,
        instruction,
        .{},
    );

    return InstructionInfo{
        .program_meta = .{ .pubkey = ID, .index_in_transaction = 0 },
        .account_metas = .{},
        .instruction_data = instruction_data,
        .initial_account_lamports = 0,
    };
}

fn emptyInstructionInfo(
    random: std.rand.Random,
) InstructionInfo {
    if (!builtin.is_test) @compileError("emptyInstructionInfo is for testing only");
    return InstructionInfo{
        .program_meta = .{ .pubkey = Pubkey.initRandom(random), .index_in_transaction = 0 },
        .account_metas = .{},
        .instruction_data = &.{},
        .initial_account_lamports = 0,
    };
}

test execute {
    const allocator = std.testing.allocator;

    var prng = std.rand.DefaultPrng.init(0);

    // Units
    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{},
        .{ .compute_unit_limit = 0 },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{ .compute_unit_limit = 1 },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT + 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{ .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
            ),
        },
        .{ .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = 1 },
            ),
        },
        .{ .compute_unit_limit = 1 },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = 1 },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_price = 42 },
            ),
        },
        .{ .compute_unit_limit = 1, .compute_unit_price = 42 },
    );

    // Heap Size
    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = 40 * 1024 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{
            .heap_size = 40 * 1024,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        try FeatureSet.allEnabled(allocator),
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = 40 * 1024 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{
            .heap_size = 40 * 1024,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = 40 * 1024 + 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{ .err = .{
            .InstructionError = .{ 0, error.InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = 31 * 1024 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{ .err = .{
            .InstructionError = .{ 0, error.InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES + 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{ .err = .{
            .InstructionError = .{ 0, error.InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES },
            ),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .compute_unit_price = 0,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        try FeatureSet.allEnabled(allocator),
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES },
            ),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            .compute_unit_price = 0,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = 1 },
            ),
        },
        .{ .err = .{
            .InstructionError = .{ 3, error.InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
            emptyInstructionInfo(prng.random()),
        },
        .{ .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT * 7 },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_price = std.math.maxInt(u64) },
            ),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
            .compute_unit_price = std.math.maxInt(u64),
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = 1 },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_price = std.math.maxInt(u64) },
            ),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = 1,
            .compute_unit_price = std.math.maxInt(u64),
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT - 1 },
            ),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MIN_HEAP_FRAME_BYTES },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .request_heap_frame = MAX_HEAP_FRAME_BYTES },
            ),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_price = 0 },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_compute_unit_price = std.math.maxInt(u64) },
            ),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    // Loaded Accounts Data Size Limit
    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_loaded_accounts_data_size_limit = 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = 1,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        try FeatureSet.allEnabled(allocator),
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_loaded_accounts_data_size_limit = 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = 1,
        },
    );

    try testComputeBudgetLimits(allocator, FeatureSet.EMPTY, &.{
        try computeBudgetInstructionInfo(
            allocator,
            .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + 1 },
        ),
        emptyInstructionInfo(prng.random()),
    }, .{
        .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
        .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
    });

    try testComputeBudgetLimits(
        allocator,
        try FeatureSet.allEnabled(allocator),
        &.{
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + 1 },
            ),
            emptyInstructionInfo(prng.random()),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        FeatureSet.EMPTY,
        &.{
            emptyInstructionInfo(prng.random()),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES },
            ),
            try computeBudgetInstructionInfo(
                allocator,
                .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES },
            ),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );
}
