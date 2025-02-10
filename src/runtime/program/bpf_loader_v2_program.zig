const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const ID =
    Pubkey.parseBase58String("BPFLoader2111111111111111111111111111111111") catch unreachable;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L55
pub const COMPUTE_UNITS = 570;
