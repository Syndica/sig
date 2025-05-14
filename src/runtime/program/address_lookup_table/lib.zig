const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const ID =
    Pubkey.parseBase58String("AddressLookupTab1e1111111111111111111111111") catch unreachable;

pub const COMPUTE_UNITS = 750;

pub const execute = @import("execute.zig").execute;

pub const Instruction = @import("instruction.zig").Instruction;
pub const ProgramState = @import("state.zig").ProgramState;
pub const LookupTableMeta = @import("state.zig").LookupTableMeta;
pub const AddressLookupTable = @import("state.zig").AddressLookupTable;
