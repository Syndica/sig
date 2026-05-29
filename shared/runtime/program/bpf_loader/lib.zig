const shared_bpf_loader = @import("base.zig");

pub const v1 = shared_bpf_loader.v1;
pub const v2 = shared_bpf_loader.v2;

pub const v3 = struct {
    pub const ID = shared_bpf_loader.v3.ID;
    pub const COMPUTE_UNITS = shared_bpf_loader.v3.COMPUTE_UNITS;
    pub const State = shared_bpf_loader.v3.State;

    pub const instruction = @import("v3_instruction.zig");
    pub const Instruction = instruction.Instruction;
};

pub const v4 = struct {
    pub const ID = shared_bpf_loader.v4.ID;
    pub const COMPUTE_UNITS = shared_bpf_loader.v4.COMPUTE_UNITS;
    pub const State = shared_bpf_loader.v4.State;

    pub const instruction = @import("v4_instruction.zig");
    pub const Instruction = instruction.Instruction;
};

pub const execute = @import("execute.zig").execute;
pub const verifyProgram = @import("execute.zig").verifyProgram;
