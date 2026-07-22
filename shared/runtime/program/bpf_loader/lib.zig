const sig = @import("../../../lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("execute.zig");
        _ = @import("v3_instruction.zig");
        _ = @import("v3_state.zig");
        _ = @import("v4_instruction.zig");
        _ = @import("v4_state.zig");
    }
}

const Pubkey = sig.core.Pubkey;

pub const v1 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed166/sdk/sdk-ids/src/lib.rs#L11
    pub const ID: Pubkey = .parse("BPFLoader1111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f/programs/bpf_loader/src/lib.rs#L56
    pub const COMPUTE_UNITS = 1_140;
};

pub const v2 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed166/sdk/sdk-ids/src/lib.rs#L7
    pub const ID: Pubkey = .parse("BPFLoader2111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f/programs/bpf_loader/src/lib.rs#L55
    pub const COMPUTE_UNITS = 570;
};

pub const v3 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed166/sdk/sdk-ids/src/lib.rs#L15-L16
    pub const ID: Pubkey = .parse("BPFLoaderUpgradeab1e11111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f/programs/bpf_loader/src/lib.rs#L57
    pub const COMPUTE_UNITS = 2_370;

    pub const instruction = @import("v3_instruction.zig");
    pub const Instruction = instruction.Instruction;
    pub const State = @import("v3_state.zig").State;
};

pub const v4 = struct {
    /// [agave] https://docs.rs/solana-sdk-ids/latest/src/solana_sdk_ids/lib.rs.html#43
    pub const ID: Pubkey = .parse("LoaderV411111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/a11b42a/programs/loader-v4/src/lib.rs#L30
    pub const COMPUTE_UNITS = 2000;

    pub const instruction = @import("v4_instruction.zig");
    pub const Instruction = instruction.Instruction;
    pub const State = @import("v4_state.zig").State;
};

pub const execute = @import("execute.zig").execute;
pub const verifyProgram = @import("execute.zig").verifyProgram;
pub const AccessViolationHandlerCtx = @import("execute.zig").AccessViolationHandlerCtx;
