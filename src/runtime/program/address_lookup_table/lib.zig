const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const Instruction = @import("instruction.zig").Instruction;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

pub const execute = @import("execute.zig").execute;

pub const entrypoint = @import("execute.zig").entrypoint;
pub const ProgramState = @import("execute.zig").ProgramState;
pub const LookupTableMeta = @import("execute.zig").LookupTableMeta;
pub const AddressLookupTable = @import("execute.zig").AddressLookupTable;

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

//https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
// note - this is actually the size of ProgramState?
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;

pub const relax_authority_signer_check_for_lookup_table_creation = Pubkey.parseBase58String(
    "FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap",
) catch unreachable;

pub fn createLookupTableSigned(
    allocator: std.mem.Allocator,
    authority_address: Pubkey,
    payer_address: Pubkey,
    recent_slot: Slot,
) error{OutOfMemory}!struct { sig.core.Instruction, Pubkey } {
    return try createLookupTableCommon(
        allocator,
        authority_address,
        payer_address,
        recent_slot,
        true,
    );
}

fn createLookupTableCommon(
    allocator: std.mem.Allocator,
    authority_address: Pubkey,
    payer_address: Pubkey,
    recent_slot: Slot,
    authority_is_signer: bool,
) error{OutOfMemory}!struct { sig.core.Instruction, Pubkey } {
    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        authority_address,
        recent_slot,
    );

    const accounts: []const sig.core.instruction.InstructionAccount = &.{
        .{ .pubkey = lookup_table_address, .is_signer = false, .is_writable = true },
        .{ .pubkey = authority_address, .is_signer = authority_is_signer, .is_writable = false },
        .{ .pubkey = payer_address, .is_signer = true, .is_writable = true },
        .{ .pubkey = ID, .is_signer = false, .is_writable = false },
    };

    const instruction = try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        accounts,
        &.{ .CreateLookupTable = .{ .recent_slot = recent_slot, .bump_seed = bump_seed } },
    );

    return .{ instruction, lookup_table_address };
}

pub fn deriveLookupTableAddress(
    authority_address: Pubkey,
    recent_block_slot: Slot,
) struct { Pubkey, u8 } {
    return sig.runtime.pubkey_utils.findProgramAddress(
        &.{
            std.mem.asBytes(&authority_address),
            std.mem.asBytes(&std.mem.nativeToLittle(Slot, recent_block_slot)),
        },
        ID,
    ).?;
}

test "bad execute" {
    _ = sig.runtime.program.testing.expectProgramExecuteResult(
        std.testing.allocator,
        {},
        @This(),
        Instruction{
            .CreateLookupTable = .{ .bump_seed = 0, .recent_slot = 0 },
        },
        &.{},
        .{ .accounts = &.{} },
        .{ .accounts = &.{} },
    ) catch {};
}

test "address-lookup-table create" {
    const testing = sig.runtime.program.testing;

    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const payer = Pubkey.initRandom(prng.random());
    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );

    const before_lamports = 9999999999999;
    // table meta (56 bytes) stored for a year. cross-verified with real instructions
    const required_lamports = 1280640;
    const after_lamports = before_lamports - required_lamports;

    const before_compute_meter = 9999999;
    const expected_used_compute = COMPUTE_UNITS +
        sig.runtime.program.system_program.COMPUTE_UNITS + // transfer
        sig.runtime.program.system_program.COMPUTE_UNITS + // allocate
        sig.runtime.program.system_program.COMPUTE_UNITS; //  assign

    // cross-verified with real instructions
    // note: real instructions also call SetComputeUnitLimit and SetComputeUnitPrice,
    // which cost 150 each, for a total of 1500.
    try std.testing.expectEqual(expected_used_compute, 1200);
    const after_compute_meter = before_compute_meter - expected_used_compute;

    const new_state: ProgramState = .{
        .LookupTable = LookupTableMeta.new(unsigned_authority_address),
    };
    const expected_state = try sig.bincode.writeAlloc(std.testing.allocator, new_state, .{});
    defer std.testing.allocator.free(expected_state);

    const accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = sig.runtime.program.system_program.ID,
            .lamports = 0,
            .data = &.{},
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = before_lamports },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const accounts_after: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = required_lamports,
            .data = expected_state,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = after_lamports },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const testing.InstructionContextAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
    };

    const sysvar_cache = sig.runtime.SysvarCache{
        .clock = sig.runtime.sysvar.Clock.DEFAULT,
        .slot_hashes = sig.runtime.sysvar.SlotHashes{
            .entries = &.{.{ std.math.maxInt(Slot), sig.core.Hash.ZEROES }},
        },
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };

    var log_out = std.ArrayList(u8).init(std.testing.allocator);
    defer log_out.deinit();
    errdefer std.debug.print("{s}", .{log_out.items});

    try testing.expectProgramExecuteResult(
        allocator,
        log_out.writer(),
        @This(),
        Instruction{ .CreateLookupTable = .{ .bump_seed = bump_seed, .recent_slot = recent_slot } },
        meta,
        .{
            .log_collector = sig.runtime.LogCollector.default(std.testing.allocator),
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = accounts_after,
            .accounts_resize_delta = 56,
            .compute_meter = after_compute_meter,
        },
    );
}

test "address-lookup-table freeze" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: ProgramState = .{
        .LookupTable = LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const after_lookup_table = try allocator.dupe(u8, before_lookup_table);
    defer allocator.free(after_lookup_table);
    // set authority to null
    @memset(after_lookup_table[21..][0 .. @sizeOf(Pubkey) + 1], 0);

    const accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 0,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 0,
            .data = after_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const testing.InstructionContextAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
    };

    const sysvar_cache = sig.runtime.SysvarCache{
        .clock = sig.runtime.sysvar.Clock.DEFAULT,
        .slot_hashes = sig.runtime.sysvar.SlotHashes{
            .entries = &.{.{ std.math.maxInt(Slot), sig.core.Hash.ZEROES }},
        },
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };

    const expected_used_compute = COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try testing.expectProgramExecuteResult(
        allocator,
        {},
        @This(),
        Instruction.FreezeLookupTable,
        meta,
        .{
            .log_collector = sig.runtime.LogCollector.default(std.testing.allocator),
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = 0,
            .compute_meter = after_compute_meter,
        },
    );
}

test "address-lookup-table close" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());
    const payer = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: ProgramState = .{
        .LookupTable = LookupTableMeta{
            .authority = unsigned_authority_address,
            .deactivation_slot = 1,
        },
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 100,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 0 },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 0,
            .data = &.{},
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 100 },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const testing.InstructionContextAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
    };

    const sysvar_cache = sig.runtime.SysvarCache{
        .clock = sig.runtime.sysvar.Clock.DEFAULT,
        .slot_hashes = sig.runtime.sysvar.SlotHashes{
            .entries = &.{.{ std.math.maxInt(Slot), sig.core.Hash.ZEROES }},
        },
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };

    const expected_used_compute = COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try testing.expectProgramExecuteResult(
        allocator,
        {},
        @This(),
        Instruction.CloseLookupTable,
        meta,
        .{
            .log_collector = sig.runtime.LogCollector.default(std.testing.allocator),
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = -@as(i64, @intCast(before_lookup_table.len)),
            .compute_meter = after_compute_meter,
        },
    );
}

test "address-lookup-table deactivate" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: ProgramState = .{
        .LookupTable = LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );
    @memcpy(before_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    const after_lookup_table = try allocator.dupe(u8, before_lookup_table);
    defer allocator.free(after_lookup_table);
    // set deactivation slot to zero (same as clock)
    @memset(after_lookup_table[4..][0..8], 0);

    const accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 0,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = 0,
            .data = after_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const testing.InstructionContextAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
    };

    const sysvar_cache = sig.runtime.SysvarCache{
        .clock = sig.runtime.sysvar.Clock.DEFAULT,
        .slot_hashes = sig.runtime.sysvar.SlotHashes{
            .entries = &.{.{ std.math.maxInt(Slot), sig.core.Hash.ZEROES }},
        },
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };

    const expected_used_compute = COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try testing.expectProgramExecuteResult(
        allocator,
        {},
        @This(),
        Instruction.DeactivateLookupTable,
        meta,
        .{
            .log_collector = sig.runtime.LogCollector.default(std.testing.allocator),
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = 0,
            .compute_meter = after_compute_meter,
        },
    );
}

test "address-lookup-table extend" {
    const testing = sig.runtime.program.testing;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const unsigned_authority_address = Pubkey.initRandom(prng.random());
    const first_address = Pubkey.initRandom(prng.random());
    const payer = Pubkey.initRandom(prng.random());

    const recent_slot = std.math.maxInt(Slot);
    const authority_is_signer = true;

    const lookup_table_address, const bump_seed = deriveLookupTableAddress(
        unsigned_authority_address,
        recent_slot,
    );
    _ = bump_seed;

    const new_state: ProgramState = .{
        .LookupTable = LookupTableMeta.new(unsigned_authority_address),
    };

    const before_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE);
    defer allocator.free(before_lookup_table);
    _ = try sig.bincode.writeToSlice(
        before_lookup_table[0..LOOKUP_TABLE_META_SIZE],
        new_state,
        .{},
    );

    const after_lookup_table = try allocator.alloc(u8, LOOKUP_TABLE_META_SIZE + @sizeOf(Pubkey));
    defer allocator.free(after_lookup_table);
    @memcpy(after_lookup_table[0..LOOKUP_TABLE_META_SIZE], before_lookup_table);
    @memcpy(after_lookup_table[LOOKUP_TABLE_META_SIZE..], &first_address.data);

    // can be derived from required_lamports for create (1280640) (128 = account overhead)
    // (1280640/(128+56))*(128+56+32) = 1503360
    const required_lamports = 1503360;

    const accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = required_lamports,
            .data = before_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 0 },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const expected_accounts: []const testing.TransactionContextAccountParams = &.{
        .{
            .pubkey = lookup_table_address,
            .owner = ID,
            .lamports = required_lamports,
            .data = after_lookup_table,
        },
        .{ .pubkey = unsigned_authority_address },
        .{ .pubkey = payer, .lamports = 0 },
        .{ .pubkey = ID, .owner = sig.runtime.ids.NATIVE_LOADER_ID, .executable = true },
        .{
            .pubkey = sig.runtime.program.system_program.ID,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .executable = true,
        },
    };

    const meta: []const testing.InstructionContextAccountMetaParams = &.{
        .{ .is_signer = false, .is_writable = true, .index_in_transaction = 0 },
        .{ .is_signer = authority_is_signer, .is_writable = false, .index_in_transaction = 1 },
        .{ .is_signer = true, .is_writable = true, .index_in_transaction = 2 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 3 },
        .{ .is_signer = false, .is_writable = false, .index_in_transaction = 4 },
    };

    const sysvar_cache = sig.runtime.SysvarCache{
        .clock = sig.runtime.sysvar.Clock.DEFAULT,
        .slot_hashes = sig.runtime.sysvar.SlotHashes{
            .entries = &.{.{ std.math.maxInt(Slot), sig.core.Hash.ZEROES }},
        },
        .rent = sig.runtime.sysvar.Rent.DEFAULT,
    };

    const expected_used_compute = COMPUTE_UNITS;
    const before_compute_meter = 9999999;
    const after_compute_meter = before_compute_meter - expected_used_compute;

    try testing.expectProgramExecuteResult(
        allocator,
        {},
        @This(),
        Instruction{ .ExtendLookupTable = .{ .new_addresses = &.{first_address} } },
        meta,
        .{
            .log_collector = sig.runtime.LogCollector.default(std.testing.allocator),
            .accounts = accounts,
            .compute_meter = before_compute_meter,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = expected_accounts,
            .accounts_resize_delta = 32,
            .compute_meter = after_compute_meter,
        },
    );
}
