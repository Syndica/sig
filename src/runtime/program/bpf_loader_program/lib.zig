const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const v1 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L11
    pub const ID =
        Pubkey.parseBase58String("BPFLoader1111111111111111111111111111111111") catch unreachable;

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L56
    pub const COMPUTE_UNITS = 1_140;

    pub const execute = @import("execute.zig").execute;
};

pub const v2 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L7
    pub const ID =
        Pubkey.parseBase58String("BPFLoader2111111111111111111111111111111111") catch unreachable;

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L55
    pub const COMPUTE_UNITS = 570;

    pub const execute = @import("execute.zig").execute;
};

pub const v3 = struct {
    /// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/sdk-ids/src/lib.rs#L15-L16
    pub const ID =
        Pubkey.parseBase58String("BPFLoaderUpgradeab1e11111111111111111111111") catch unreachable;

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L57
    pub const COMPUTE_UNITS = 2_370;

    pub const Instruction = @import("v3_instruction.zig").Instruction;
    pub const State = @import("v3_state.zig").State;

    pub const execute = @import("execute.zig").execute;
};

pub const execute = @import("execute.zig").execute;
