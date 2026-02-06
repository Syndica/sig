const std = @import("std");
const sig = @import("../sig.zig");

const ComputeBudget = @This();

/// Number of compute units that a transaction or individual instruction is
/// allowed to consume. Compute units are consumed by program execution,
/// resources they use, etc...
///
/// TODO: we should remove this from the ComputeBudget and combine it with the compute budget native program's types
compute_unit_limit: u64,
/// Number of compute units consumed by a log_u64 call
log_64_units: u64,
/// Number of compute units consumed by a create_program_address call
create_program_address_units: u64,
/// Maximum SBF to BPF call depth
max_call_depth: usize,
/// Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend
stack_frame_size: usize,
/// Number of compute units consumed by logging a `Pubkey`
log_pubkey_units: u64,
/// Number of compute units consumed to do a syscall without any work
syscall_base_cost: u64,
/// Base number of compute units consumed to get a sysvar
sysvar_base_cost: u64,
/// program heap region size, default: solana_sdk::entrypoint::HEAP_LENGTH
heap_size: u32,
/// Number of compute units per additional 32k heap above the default (~.5
/// us per 32k at 15 units/us rounded up)
heap_cost: u64,
/// Memory operation syscall base cost
mem_op_base_cost: u64,
/// Coefficient `a` of the quadratic function which determines the number
/// of compute units consumed to call poseidon syscall for a given number
/// of inputs.
poseidon_cost_coefficient_a: u64,
/// Coefficient `c` of the quadratic function which determines the number
/// of compute units consumed to call poseidon syscall for a given number
/// of inputs.
poseidon_cost_coefficient_c: u64,
/// Number of account data bytes per compute unit charged during a cross-program invocation
cpi_bytes_per_unit: u64,
/// Maximum cross-program invocation instruction size
max_cpi_instruction_size: usize,
/// Number of compute units consumed by an invoke call (not including the cost incurred by
/// the called program)
invoke_units: u64,
/// Base number of compute units consumed to call SHA256
sha256_base_cost: u64,
/// Incremental number of units consumed by SHA256 (based on bytes)
sha256_byte_cost: u64,
/// Maximum number of slices hashed per syscall
sha256_max_slices: u64,
/// Number of compute units consumed to validate a curve25519 edwards point
curve25519_edwards_validate_point_cost: u64,
/// Number of compute units consumed to add two curve25519 edwards points
curve25519_edwards_add_cost: u64,
/// Number of compute units consumed to subtract two curve25519 edwards points
curve25519_edwards_subtract_cost: u64,
/// Number of compute units consumed to multiply a curve25519 edwards point
curve25519_edwards_multiply_cost: u64,
/// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
/// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
curve25519_edwards_msm_base_cost: u64,
/// Number of compute units consumed for a multiscalar multiplication (msm) of edwards points.
/// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
curve25519_edwards_msm_incremental_cost: u64,
/// Number of compute units consumed to validate a curve25519 ristretto point
curve25519_ristretto_validate_point_cost: u64,
/// Number of compute units consumed to add two curve25519 ristretto points
curve25519_ristretto_add_cost: u64,
/// Number of compute units consumed to subtract two curve25519 ristretto points
curve25519_ristretto_subtract_cost: u64,
/// Number of compute units consumed to multiply a curve25519 ristretto point
curve25519_ristretto_multiply_cost: u64,
/// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
/// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
curve25519_ristretto_msm_base_cost: u64,
/// Number of compute units consumed for a multiscalar multiplication (msm) of ristretto points.
/// The total cost is calculated as `msm_base_cost + (length - 1) * msm_incremental_cost`.
curve25519_ristretto_msm_incremental_cost: u64,
/// Number of compute units consumed to call alt_bn128_addition
alt_bn128_addition_cost: u64,
/// Number of compute units consumed to call alt_bn128_multiplication.
alt_bn128_multiplication_cost: u64,
/// Total cost will be alt_bn128_pairing_one_pair_cost_first
/// + alt_bn128_pairing_one_pair_cost_other * (num_elems - 1)
alt_bn128_pairing_one_pair_cost_first: u64,
alt_bn128_pairing_one_pair_cost_other: u64,
/// Number of compute units consumed to call alt_bn128_g1_compress.
alt_bn128_g1_compress: u64,
/// Number of compute units consumed to call alt_bn128_g1_decompress.
alt_bn128_g1_decompress: u64,
/// Number of compute units consumed to call alt_bn128_g2_compress.
alt_bn128_g2_compress: u64,
/// Number of compute units consumed to call alt_bn128_g2_decompress.
alt_bn128_g2_decompress: u64,
/// Number of compute units consumed to call secp256k1_recover
secp256k1_recover_cost: u64,

pub const DEFAULT: ComputeBudget = ComputeBudget.init(1_400_000, false);

/// [agave] https://github.com/anza-xyz/agave/blob/8363752bd5e41aaf8eaf9137711e8d8b11d84be6/program-runtime/src/execution_budget.rs#L162
pub fn init(compute_unit_limit: u64, simd_0339_active: bool) ComputeBudget {
    return .{
        .compute_unit_limit = compute_unit_limit,
        .create_program_address_units = 1500,
        .log_64_units = 100,
        .max_call_depth = 64,
        .stack_frame_size = 4096,
        .log_pubkey_units = 100,
        .syscall_base_cost = 100,
        .sysvar_base_cost = 100,
        .cpi_bytes_per_unit = 250, // ~50MB at 200,000 units
        .heap_size = 32 * 1024,
        .heap_cost = 8,
        .mem_op_base_cost = 10,
        .poseidon_cost_coefficient_a = 61,
        .poseidon_cost_coefficient_c = 542,
        .max_cpi_instruction_size = 1280, // IPv6 Min MTU size
        // [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/execution_budget.rs#L25-L31
        .invoke_units = if (simd_0339_active)
            946
        else
            1000,
        .sha256_base_cost = 85,
        .sha256_byte_cost = 1,
        .sha256_max_slices = 20_000,
        .curve25519_edwards_validate_point_cost = 159,
        .curve25519_edwards_add_cost = 473,
        .curve25519_edwards_subtract_cost = 475,
        .curve25519_edwards_multiply_cost = 2_177,
        .curve25519_edwards_msm_base_cost = 2_273,
        .curve25519_edwards_msm_incremental_cost = 758,
        .curve25519_ristretto_validate_point_cost = 169,
        .curve25519_ristretto_add_cost = 521,
        .curve25519_ristretto_subtract_cost = 519,
        .curve25519_ristretto_multiply_cost = 2_208,
        .curve25519_ristretto_msm_base_cost = 2303,
        .curve25519_ristretto_msm_incremental_cost = 788,
        .alt_bn128_addition_cost = 334,
        .alt_bn128_multiplication_cost = 3_840,
        .alt_bn128_pairing_one_pair_cost_first = 36_364,
        .alt_bn128_pairing_one_pair_cost_other = 12_121,
        .alt_bn128_g1_compress = 30,
        .alt_bn128_g1_decompress = 398,
        .alt_bn128_g2_compress = 86,
        .alt_bn128_g2_decompress = 13610,
        .secp256k1_recover_cost = 25_000,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.4/program-runtime/src/execution_budget.rs#L239-L266
/// [fd] https://github.com/firedancer-io/firedancer/blob/211dfccc1d84a50191a487a6abffd962f7954179/src/flamenco/vm/syscall/fd_vm_syscall_crypto.c#L238-L245
///
/// Returns the cost of a Poseidon hash syscall for a given input length.
pub fn poseidonCost(self: ComputeBudget, len: std.math.IntFittingRange(0, 12)) u64 {
    const squared_inputs = std.math.powi(u64, len, 2) catch unreachable;
    const mul = squared_inputs * self.poseidon_cost_coefficient_a;
    return mul + self.poseidon_cost_coefficient_c;
}

pub fn curveGroupOperationCost(
    self: ComputeBudget,
    curve_id: sig.vm.syscalls.ecc.CurveId,
    group_op: sig.vm.syscalls.ecc.GroupOp,
) u64 {
    switch (curve_id) {
        inline else => |id| switch (group_op) {
            inline else => |op| {
                const name = "curve25519_" ++ @tagName(id) ++ "_" ++ @tagName(op) ++ "_cost";
                return @field(self, name);
            },
        },
    }
}
