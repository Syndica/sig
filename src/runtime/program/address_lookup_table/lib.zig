const sig = @import("../../../sig.zig");

pub const program = @import("lib.zig");
pub const state = @import("state.zig");
pub const instruction = @import("instruction.zig");

pub const Instruction = instruction.Instruction;
pub const AddressLookupTable = state.AddressLookupTable;
pub const LookupTableMeta = state.LookupTableMeta;
pub const ProgramState = state.ProgramState;

const Pubkey = sig.core.Pubkey;

pub const ID: Pubkey = .parse("AddressLookupTab1e1111111111111111111111111");

pub const execute = @import("execute.zig").execute;

// https://github.com/anza-xyz/agave/blob/8116c10021f09c806159852f65d37ffe6d5a118e/programs/address-lookup-table/src/processor.rs#L23
pub const COMPUTE_UNITS = 750;
