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

// https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L30
/// The maximum number of addresses that a lookup table can hold
pub const LOOKUP_TABLE_MAX_ADDRESSES: usize = 256;

//https://github.com/anza-xyz/agave/blob/d300f3733f45d64a3b6b9fdb5a1157f378e181c2/sdk/program/src/address_lookup_table/state.rs#L33
/// The serialized size of lookup table metadata
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
            .compute_meter = 9999999,
            .sysvar_cache = sysvar_cache,
        },
        .{
            .accounts = accounts_after,
            .accounts_resize_delta = 56,
            .compute_meter = after_compute_meter,
        },
    );
}
