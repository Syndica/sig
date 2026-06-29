const sig = @import("../../../lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("instruction.zig");
        _ = @import("state.zig");
    }
}

pub const program = @import("lib.zig");
pub const state = @import("state.zig");
pub const instruction = @import("instruction.zig");

pub const Instruction = instruction.Instruction;
pub const AddressLookupTable = state.AddressLookupTable;
pub const LookupTableMeta = state.LookupTableMeta;
pub const ProgramState = state.ProgramState;

const Pubkey = sig.core.Pubkey;

pub const ID: Pubkey = .parse("AddressLookupTab1e1111111111111111111111111");
