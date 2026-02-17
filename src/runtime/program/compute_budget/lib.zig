const builtin = @import("builtin");
const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../../sig.zig");

const builtin_program_costs = sig.runtime.program.builtin_program_costs;

const Message = sig.core.transaction.Message;
const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const FeatureSet = sig.core.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionError = sig.ledger.transaction_status.TransactionError;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

const MIGRATING_BUILTIN_COSTS = builtin_program_costs.MIGRATING_BUILTIN_COSTS;
const MAX_TRANSACTION_ACCOUNTS = sig.core.Transaction.MAX_ACCOUNTS;
const DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT: u32 = 200_000;
const MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT: u32 = 3_000;
const HEAP_LENGTH: usize = 32 * 1024;
const MAX_HEAP_FRAME_BYTES: u32 = 256 * 1024;
const MIN_HEAP_FRAME_BYTES: u32 = HEAP_LENGTH;
const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;
pub const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

pub const ID: Pubkey = .parse("ComputeBudget111111111111111111111111111111");

pub const COMPUTE_UNITS = 150;

/// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/compute-budget/src/lib.rs#L5
pub fn entrypoint(
    _: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const zone = tracy.Zone.init(@src(), .{ .name = "compute_budget: entrypoint" });
    defer zone.deinit();

    try ic.tc.consumeCompute(COMPUTE_UNITS);
}

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
    migrating_builtin_feature_counters: [MIGRATING_BUILTIN_COSTS.len]u16 = @splat(0),
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

    pub fn intoComputeBudget(self: ComputeBudgetLimits, feature_set: *const sig.core.FeatureSet, slot: sig.core.Slot) sig.runtime.ComputeBudget {
        const simd_0339_active = feature_set.active(.increase_cpi_account_info_limit, slot);
        var default = sig.runtime.ComputeBudget.init(self.compute_unit_limit, simd_0339_active);
        default.heap_size = self.heap_size;
        return default;
    }
};

/// Analogous to [ComputeBudgetInstruction](https://github.com/anza-xyz/solana-sdk/blob/1c1d667f161666f12f5a43ebef8eda9470a8c6ee/compute-budget-interface/src/lib.rs#L18-L24).
/// NOTE: this type uses [BORSH](https://borsh.io/) encoding.
const ComputeBudgetInstruction = union(enum) {
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

    pub const Tag = @typeInfo(ComputeBudgetInstruction).@"union".tag_type.?;

    const borsh = BorshStaticTaggedUnionHelper(ComputeBudgetInstruction);

    pub const BorshDecodeError = error{
        /// The raw data did not match the expected representation.
        DecodeFailed,
        /// `src` was too short.
        TruncatedSrc,
    };

    /// Decodes the encoded ComputeBudgetInstruction, and the number of bytes it occupied in `src`.
    pub fn borshDecodeSlice(
        src: []const u8,
    ) BorshDecodeError!struct { ComputeBudgetInstruction, borsh.EncodedSizeInt } {
        if (src.len == 0) return error.TruncatedSrc;
        const tag = borsh.tagDecode(src[0]) orelse return error.DecodeFailed;
        const pl_size: borsh.EncodedSizeInt = borsh.payloadEncodedSize(tag);
        const pl_bytes = src[1..];
        if (pl_bytes.len < pl_size) return error.TruncatedSrc;
        const cbi = borsh.decodeFromTagAndPayload(tag, pl_bytes[0..pl_size]) orelse
            return error.DecodeFailed;
        return .{ cbi, @sizeOf(u8) + pl_size };
    }
};

// TODO: see https://github.com/Syndica/sig/issues/849
fn BorshStaticTaggedUnionHelper(comptime U: type) type {
    const u_info = @typeInfo(U).@"union";
    const Tag = u_info.tag_type.?;
    if (@sizeOf(Tag) > @sizeOf(u8)) @compileError("Tag type is too big");

    const pl_size_max = blk: {
        var max: usize = 0;
        for (@typeInfo(U).@"union".fields) |u_field| {
            max = @max(max, @sizeOf(u_field.type));
            switch (u_field.type) {
                u8, u16, u32, u64, u128 => {},
                i8, i16, i32, i64, i128 => {},
                f32, f64 => {},
                void => {},
                bool => {},
                else => |T| @compileError("Unsupported: " ++ @typeName(T)),
            }
        }
        break :blk max;
    };

    return struct {
        pub const ENCODED_SIZE_MAX = @sizeOf(u8) + pl_size_max;
        pub const EncodedSizeInt = std.math.IntFittingRange(0, ENCODED_SIZE_MAX);

        pub fn encode(
            tagged: U,
            buffer: *[ENCODED_SIZE_MAX]u8,
        ) EncodedSizeInt {
            var fbs = std.io.fixedBufferStream(buffer);
            const w = fbs.writer();

            w.writeByte(@intFromEnum(tagged)) catch unreachable;
            switch (tagged) {
                inline else => |payload| switch (@TypeOf(payload)) {
                    void => {},
                    bool => w.writeByte(@intFromBool(payload)) catch unreachable,

                    f32, f64 => |T| {
                        const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
                        w.writeInt(Int, @bitCast(payload), .little) catch unreachable;
                    },

                    // zig fmt: off
                    u8, u16, u32, u64, u128,
                    i8, i16, i32, i64, i128,
                    => |T| w.writeInt(T, payload, .little) catch unreachable,
                    // zig fmt: on

                    else => unreachable,
                },
            }

            return @intCast(fbs.pos);
        }

        /// Presumes byte is the first byte of the encoded buffer.
        pub fn tagDecode(tag_byte: u8) ?Tag {
            return std.meta.intToEnum(Tag, tag_byte) catch |err| switch (err) {
                error.InvalidEnumTag => null,
            };
        }

        /// Presumes `tag == tagDecode(byte)` where byte is the first byte of the encoded buffer.
        pub fn payloadEncodedSize(tag: Tag) EncodedSizeInt {
            return switch (tag) {
                inline else => |itag| @sizeOf(@FieldType(U, @tagName(itag))),
            };
        }

        pub fn fullEncodedSize(tag: Tag) EncodedSizeInt {
            return 1 + payloadEncodedSize(tag);
        }

        /// Presumes `tag == tagDecode(byte)` where byte is the first byte of the encoded buffer,
        /// and `payload_bytes` is a slice of bytes subsequent to that first byte.
        /// Returns null if the payload fails to decode.
        /// Asserts `payload_bytes.len == payloadEncodedSize(tag)`.
        pub fn decodeFromTagAndPayload(
            tag: Tag,
            payload_bytes: []const u8,
        ) ?ComputeBudgetInstruction {
            std.debug.assert(payload_bytes.len == payloadEncodedSize(tag));
            switch (tag) {
                inline else => |itag| {
                    const Payload = @FieldType(U, @tagName(itag));
                    comptime std.debug.assert(@sizeOf(Payload) == payloadEncodedSize(itag));
                    const payload: Payload = switch (Payload) {
                        void => {},
                        bool => switch (payload_bytes[0]) {
                            0 => false,
                            1 => true,
                            else => return null,
                        },
                        f32, f64 => |T| blk: {
                            const Int = std.meta.Int(.unsigned, @bitSizeOf(T));
                            const int = std.mem.readInt(Int, payload_bytes[0..@sizeOf(T)], .little);
                            break :blk @bitCast(int);
                        },

                        // zig fmt: off
                        u8, u16, u32, u64, u128,
                        i8, i16, i32, i64, i128,
                        => |T| std.mem.readInt(T, payload_bytes[0..@sizeOf(T)], .little),
                        // zig fmt: on

                        else => |T| @compileError(
                            "Unhandled `" ++ @tagName(itag) ++ ": " ++ @typeName(T) ++ "`",
                        ),
                    };
                    return @unionInit(ComputeBudgetInstruction, @tagName(itag), payload);
                },
            }
        }
    };
}

/// Compute budget instructions are executed during transaction sanitization.
/// Successful execution returns a `ComputeBudgetInstructionDetails` struct which is subsequently
/// sanitized into a `ComputeBudgetLimits` struct during transaction execution.
pub fn execute(msg: *const Message) TransactionResult(ComputeBudgetInstructionDetails) {
    var details = ComputeBudgetInstructionDetails{};
    var is_compute_budget_cache = [_]?bool{null} ** MAX_TRANSACTION_ACCOUNTS;

    for (msg.instructions, 0..) |instr, index| {
        const program_id = msg.account_keys[instr.program_index];
        const program_index = instr.program_index;

        if (!isComputeBudgetProgram(&is_compute_budget_cache, program_index, program_id)) {
            details.num_non_compute_budget_instructions +|= 1;
            continue;
        }

        const invalid_instruction_data_error: TransactionResult(ComputeBudgetInstructionDetails) = .{
            .err = .{ .InstructionError = .{ @intCast(index), .InvalidInstructionData } },
        };
        const duplicate_instruction_error: TransactionResult(ComputeBudgetInstructionDetails) = .{
            .err = .{ .DuplicateInstruction = @intCast(index) },
        };

        const instruction, _ = ComputeBudgetInstruction.borshDecodeSlice(instr.data) catch
            return invalid_instruction_data_error;

        switch (instruction) {
            .unused => return invalid_instruction_data_error,
            .request_heap_frame => |heap_size| {
                if (details.requested_heap_size) |_|
                    return duplicate_instruction_error;

                details.requested_heap_size = .{
                    @intCast(index),
                    heap_size,
                };
            },
            .set_compute_unit_limit => |compute_unit_limit| {
                if (details.requested_compute_unit_limit) |_|
                    return duplicate_instruction_error;

                details.requested_compute_unit_limit = .{
                    @intCast(index),
                    compute_unit_limit,
                };
            },
            .set_compute_unit_price => |compute_unit_price| {
                if (details.requested_compute_unit_price) |_|
                    return duplicate_instruction_error;

                details.requested_compute_unit_price = .{
                    @intCast(index),
                    compute_unit_price,
                };
            },
            .set_loaded_accounts_data_size_limit => |loaded_accounts_data_size_limit| {
                if (details.requested_loaded_accounts_data_size_limit) |_|
                    return duplicate_instruction_error;

                details.requested_loaded_accounts_data_size_limit = .{
                    @intCast(index),
                    loaded_accounts_data_size_limit,
                };
            },
        }
    }

    if (details.requested_compute_unit_limit == null) {
        var kind_cache = [_]?ProgramKind{null} ** MAX_TRANSACTION_ACCOUNTS;
        for (msg.instructions, 0..) |instr, index| {
            const program_id = msg.account_keys[instr.program_index];

            switch (getProgramKind(&kind_cache, index, program_id)) {
                .not_builtin => details.num_non_builtin_instructions +|= 1,
                .builtin => details.num_non_migratable_builtin_instructions +|= 1,
                .migrating_builtin => |pos| details.migrating_builtin_feature_counters[pos] += 1,
            }
        }
    }

    return .{ .ok = details };
}

pub fn sanitize(
    details: ComputeBudgetInstructionDetails,
    feature_set: *const FeatureSet,
    slot: sig.core.Slot,
) TransactionResult(ComputeBudgetLimits) {
    // Requested heap size outsize of range is a transaction error
    // Requested heap size is not a multiple of 1024 is an instruction error
    const heap_bytes = blk: {
        if (details.requested_heap_size) |heap_size| {
            const index, const size = heap_size;
            if (size >= MIN_HEAP_FRAME_BYTES and
                size <= MAX_HEAP_FRAME_BYTES and
                size % 1024 == 0)
                break :blk size
            else
                return .{
                    .err = .{
                        .InstructionError = .{ index, .InvalidInstructionData },
                    },
                };
        }
        break :blk MIN_HEAP_FRAME_BYTES;
    };

    // Requested compute unit limit greater than max results in max compute unit limit
    const compute_unit_limit = if (details.requested_compute_unit_limit) |limit|
        limit[1]
    else
        defaultComputeUnitLimit(feature_set, slot, &details);

    // Compute unit price is not bounded
    const compute_unit_price = if (details.requested_compute_unit_price) |price|
        price[1]
    else
        0;

    // Requested loaded accounts data size limit greater than max results in max loaded accounts data size limit
    const loaded_accounts_bytes = blk: {
        if (details.requested_loaded_accounts_data_size_limit) |max_size| {
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
    slot: sig.core.Slot,
    details: *const ComputeBudgetInstructionDetails,
) u32 {
    if (!feature_set.active(.reserve_minimal_cus_for_builtin_instructions, slot)) {
        return details.num_non_compute_budget_instructions *| DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;
    }

    var num_migrated: u32 = 0;
    var num_not_migrated: u32 = 0;

    for (details.migrating_builtin_feature_counters, 0..) |count, index| {
        if (count > 0 and feature_set.active(
            builtin_program_costs.getMigrationFeatureId(index),
            slot,
        )) num_migrated += count else num_not_migrated += count;
    }

    const builtin_limit = (details.num_non_migratable_builtin_instructions +| num_not_migrated) *|
        MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT;

    const not_builtin_limit = (details.num_non_builtin_instructions +| num_migrated) *|
        DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT;

    return builtin_limit +| not_builtin_limit;
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
        if (!builtin_program_costs.MAYBE_BUILTIN_KEY[program_id.data[0]])
            return .not_builtin;

        if (builtin_program_costs.BUILTIN_COSTS.get(&program_id.data)) |builtin_cost| {
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
    account_keys: []const Pubkey,
    instructions: []const sig.core.transaction.Instruction,
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
            if (account_keys[instr.program_index].equals(&ID))
                allocator.free(instr.data);
        }
    }

    const msg = sig.core.transaction.Message{
        .signature_count = 0,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 0,
        .recent_blockhash = sig.core.Hash.ZEROES,
        .account_keys = account_keys,
        .instructions = instructions,
        .address_lookups = &.{},
    };

    const execute_result = execute(&msg);

    const compute_budget_instruction_details = switch (execute_result) {
        .ok => |res| res,
        .err => |actual_err| {
            try std.testing.expect(expected.err != null);
            try std.testing.expectEqual(
                expected.err.?,
                actual_err,
            );
            return;
        },
    };

    const sanitize_result = sanitize(compute_budget_instruction_details, &feature_set, 0);

    switch (sanitize_result) {
        .ok => |actual| {
            try std.testing.expect(expected.err == null);
            try std.testing.expectEqual(expected.heap_size, actual.heap_size);
            try std.testing.expectEqual(expected.compute_unit_limit, actual.compute_unit_limit);
            try std.testing.expectEqual(expected.compute_unit_price, actual.compute_unit_price);
            try std.testing.expectEqual(
                expected.loaded_accounts_bytes,
                actual.loaded_accounts_bytes,
            );
        },
        .err => |actual_err| {
            try std.testing.expect(expected.err != null);
            try std.testing.expectEqual(expected.err.?, actual_err);
        },
    }
}

fn testCreateComputeBudgetInstructionData(
    allocator: std.mem.Allocator,
    instruction: ComputeBudgetInstruction,
) ![]const u8 {
    if (!builtin.is_test) @compileError("computeBudgetInstructionData is for testing only");

    const instruction_data: []const u8 = blk: {
        const cbi_borsh = ComputeBudgetInstruction.borsh;

        var buffer: [cbi_borsh.ENCODED_SIZE_MAX]u8 = @splat(undefined);
        const encoded_len = cbi_borsh.encode(instruction, &buffer);
        const encoded_bytes = buffer[0..encoded_len];

        break :blk try allocator.dupe(u8, encoded_bytes);
    };
    errdefer allocator.free(instruction_data);

    return instruction_data;
}

pub fn testCreateComputeBudgetInstruction(
    allocator: std.mem.Allocator,
    program_index: u8,
    instruction: ComputeBudgetInstruction,
) !sig.core.transaction.Instruction {
    if (!builtin.is_test) @compileError("computeBudgetInstructionData is for testing only");

    return .{
        .program_index = program_index,
        .account_indexes = &.{},
        .data = try testCreateComputeBudgetInstructionData(allocator, instruction),
    };
}

fn testCreateEmptyInstruction(program_index: u8) sig.core.transaction.Instruction {
    if (!builtin.is_test) @compileError("testCreateEmptyInstruction is for testing only");
    return .{
        .program_index = program_index,
        .account_indexes = &.{},
        .data = &.{},
    };
}

test "compute_budget Instruction" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var tx = try sig.runtime.testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{
                    .pubkey = ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = COMPUTE_UNITS,
        },
    );
    const tc = &tx[1];
    defer {
        sig.runtime.testing.deinitTransactionContext(allocator, tc);
        tx[0].deinit(allocator);
    }

    try sig.runtime.executor.executeInstruction(allocator, tc, .{
        .account_metas = .{},
        .dedupe_map = @splat(0xff),
        .instruction_data = &.{},
        .owned_instruction_data = false,
        .program_meta = .{ .index_in_transaction = 0, .pubkey = ID },
    });

    try std.testing.expectEqual(tc.compute_meter, 0);
}

test execute {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // Units
    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{},
        &.{},
        .{ .compute_unit_limit = 0 },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{ .compute_unit_limit = 1 },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT + 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{ .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
            }),
        },
        .{ .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = 1,
            }),
        },
        .{ .compute_unit_limit = 1 },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = 1,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_price = 42,
            }),
        },
        .{ .compute_unit_limit = 1, .compute_unit_price = 42 },
    );

    // Heap Size
    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = 40 * 1024,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .heap_size = 40 * 1024,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_ENABLED_AT_GENESIS,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = 40 * 1024,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .heap_size = 40 * 1024,
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = 40 * 1024 + 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{ .err = .{
            .InstructionError = .{ 0, .InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = 31 * 1024,
            }),
            testCreateEmptyInstruction(0),
        },
        .{ .err = .{
            .InstructionError = .{ 0, .InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES + 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{ .err = .{
            .InstructionError = .{ 0, .InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES,
            }),
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
        .ALL_ENABLED_AT_GENESIS,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES,
            }),
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
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = 1,
            }),
        },
        .{ .err = .{
            .InstructionError = .{ 3, .InvalidInstructionData },
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
            testCreateEmptyInstruction(0),
        },
        .{ .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT * 7 },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_price = std.math.maxInt(u64),
            }),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
            .compute_unit_price = std.math.maxInt(u64),
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = 1,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_price = std.math.maxInt(u64),
            }),
        },
        .{
            .heap_size = MAX_HEAP_FRAME_BYTES,
            .compute_unit_limit = 1,
            .compute_unit_price = std.math.maxInt(u64),
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_limit = MAX_COMPUTE_UNIT_LIMIT - 1,
            }),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MIN_HEAP_FRAME_BYTES,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .request_heap_frame = MAX_HEAP_FRAME_BYTES,
            }),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_price = 0,
            }),
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_compute_unit_price = std.math.maxInt(u64),
            }),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );

    // Loaded Accounts Data Size Limit
    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_loaded_accounts_data_size_limit = 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = 1,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_ENABLED_AT_GENESIS,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_loaded_accounts_data_size_limit = 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = 1,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_ENABLED_AT_GENESIS,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            try testCreateComputeBudgetInstruction(allocator, 1, .{
                .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES + 1,
            }),
            testCreateEmptyInstruction(0),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT +
                MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
        },
        .{
            .compute_unit_limit = DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
            .loaded_accounts_bytes = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
        },
    );

    try testComputeBudgetLimits(
        allocator,
        .ALL_DISABLED,
        &.{ Pubkey.initRandom(random), ID },
        &.{
            testCreateEmptyInstruction(0),
            try testCreateComputeBudgetInstruction(
                allocator,
                1,
                .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES },
            ),
            try testCreateComputeBudgetInstruction(
                allocator,
                1,
                .{ .set_loaded_accounts_data_size_limit = MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES },
            ),
        },
        .{ .err = .{
            .DuplicateInstruction = 2,
        } },
    );
}
