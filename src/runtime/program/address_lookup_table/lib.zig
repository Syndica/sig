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
