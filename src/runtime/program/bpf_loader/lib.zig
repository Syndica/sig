const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const v1 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L11
    pub const ID: Pubkey = .parse("BPFLoader1111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L56
    pub const COMPUTE_UNITS = 1_140;
};

pub const v2 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L7
    pub const ID: Pubkey = .parse("BPFLoader2111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L55
    pub const COMPUTE_UNITS = 570;
};

pub const v3 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L15-L16
    pub const ID: Pubkey = .parse("BPFLoaderUpgradeab1e11111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L57
    pub const COMPUTE_UNITS = 2_370;

    pub const instruction = @import("v3_instruction.zig");
    pub const Instruction = instruction.Instruction;
    pub const State = @import("v3_state.zig").State;
};

pub const v4 = struct {
    /// [agave] https://docs.rs/solana-sdk-ids/latest/src/solana_sdk_ids/lib.rs.html#43
    pub const ID: Pubkey = .parse("LoaderV411111111111111111111111111111111111");

    /// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/loader-v4/src/lib.rs#L30
    pub const COMPUTE_UNITS = 2000;

    pub const instruction = @import("v4_instruction.zig");
    pub const Instruction = instruction.Instruction;
    pub const State = @import("v4_state.zig").State;
};

pub const execute = @import("execute.zig").execute;
pub const verifyProgram = @import("execute.zig").verifyProgram;
