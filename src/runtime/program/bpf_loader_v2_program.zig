const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub fn id() Pubkey {
    sig.runtime.ids.BPF_LOADER_V2_PROGRAM_ID;
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L55
pub fn compute_units() u64 {
    return 570;
}
