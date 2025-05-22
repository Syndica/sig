const sig = @import("../../../sig.zig");

pub const program = @import("lib.zig");
pub const state = @import("state.zig");
pub const instruction = @import("instruction.zig");

pub const Instruction = instruction.Instruction;

pub const ID = sig.runtime.ids.ADDRESS_LOOKUP_TABLE_PROGRAM_ID;

pub const execute = @import("execute.zig").execute;

pub const ProgramState = state.ProgramState;
pub const LookupTableMeta = state.LookupTableMeta;
pub const AddressLookupTable = state.AddressLookupTable;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;
