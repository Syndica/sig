const sig = @import("../../../sig.zig");

const precompile_programs = sig.runtime.program.precompiles;

const Pubkey = sig.core.Pubkey;
const FeatureSet = sig.runtime.FeatureSet;
const PrecompileProgramError = precompile_programs.PrecompileProgramError;

pub const ID =
    Pubkey.parseBase58String("Secp256r1SigVerify1111111111111111111111111") catch unreachable;

// Part of SIMD-0075, which is accepted.
// Firedancer puts this one behind an ifdef. Maybe we don't need it yet?
// https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0075-precompile-for-secp256r1-sigverify.md
// https://github.com/firedancer-io/firedancer/blob/49056135a4c7ba024cb75a45925439239904238b/src/flamenco/runtime/program/fd_precompiles.c#L376pub fn verify(
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
    _: *const FeatureSet,
) PrecompileProgramError!void {
    _ = current_instruction_data;
    _ = all_instruction_datas;
    @panic("TODO");
}
