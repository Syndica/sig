const sig = @import("../../../sig.zig");

pub const Instruction = @import("instruction.zig").Instruction;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

pub const execute = @import("execute.zig").execute;

pub const ProgramState = @import("state.zig").ProgramState;
pub const LookupTableMeta = @import("state.zig").LookupTableMeta;
pub const AddressLookupTable = @import("state.zig").AddressLookupTable;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;
