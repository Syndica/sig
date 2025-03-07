const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Instruction = @import("instruction.zig").Instruction;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

pub const execute = @import("execute.zig").execute;

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
    return try createLookupTableCommon(allocator, authority_address, payer_address, recent_slot, true);
}

fn createLookupTableCommon(
    allocator: std.mem.Allocator,
    authority_address: Pubkey,
    payer_address: Pubkey,
    recent_slot: Slot,
    authority_is_signer: bool,
) error{OutOfMemory}!struct { sig.core.Instruction, Pubkey } {
    const lookup_table_address, const bump_seed = deriveLookupTableAddress(authority_address, recent_slot);

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
        @This(),
        Instruction{
            .CreateLookupTable = .{ .bump_seed = 0, .recent_slot = 0 },
        },
        &.{},
        .{ .accounts = &.{} },
        .{ .accounts = &.{} },
    ) catch {};
}
