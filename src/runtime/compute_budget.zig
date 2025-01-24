/// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L1-L228
/// Max instruction stack depth. This is the maximum nesting of instructions that can happen during
/// a transaction.
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

/// Max call depth. This is the maximum nesting of SBF to SBF call that can happen within a program.
pub const MAX_CALL_DEPTH: usize = 64;

/// The size of one SBF stack frame.
pub const STACK_FRAME_SIZE: usize = 4096;

pub const DEFAULT_HEAP_COST: u64 = 8;
pub const MAX_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

pub const ComputeBudget = struct {
    /// Number of compute units that a transaction or individual instruction is
    /// allowed to consume. Compute units are consumed by program execution,
    /// resources they use, etc...
    compute_unit_limit: u64,
    /// Number of compute units consumed by a log_u64 call
    log_64_units: u64,
    /// Number of compute units consumed by a create_program_address call
    create_program_address_units: u64,
    /// Number of compute units consumed by an invoke call (not including the cost incurred by
    /// the called program)
    invoke_units: u64,
    /// Maximum program instruction invocation stack depth. Invocation stack
    /// depth starts at 1 for transaction instructions and the stack depth is
    /// incremented each time a program invokes an instruction and decremented
    /// when a program returns.
    max_instruction_stack_depth: usize,
    /// Maximum cross-program invocation and instructions per transaction
    max_instruction_trace_length: usize,
    /// Base number of compute units consumed to call SHA256
    sha256_base_cost: u64,
    /// Incremental number of units consumed by SHA256 (based on bytes)
    sha256_byte_cost: u64,
    /// Maximum number of slices hashed per syscall
    sha256_max_slices: u64,
    /// Maximum SBF to BPF call depth
    max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend
    stack_frame_size: usize,
    /// Number of compute units consumed by logging a `Pubkey`
    log_pubkey_units: u64,
    /// Maximum cross-program invocation instruction size
    max_cpi_instruction_size: usize,
    /// Number of account data bytes per compute unit charged during a cross-program invocation
    cpi_bytes_per_unit: u64,
    /// Base number of compute units consumed to get a sysvar
    sysvar_base_cost: u64,
    /// Number of compute units consumed to call secp256k1_recover
    secp256k1_recover_cost: u64,
    /// Number of compute units consumed to do a syscall without any work
    syscall_base_cost: u64,
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
    /// program heap region size, default: solana_sdk::entrypoint::HEAP_LENGTH
    heap_size: u32,
    /// Number of compute units per additional 32k heap above the default (~.5
    /// us per 32k at 15 units/us rounded up)
    heap_cost: u64,
    /// Memory operation syscall base cost
    mem_op_base_cost: u64,
    /// Number of compute units consumed to call alt_bn128_addition
    alt_bn128_addition_cost: u64,
    /// Number of compute units consumed to call alt_bn128_multiplication.
    alt_bn128_multiplication_cost: u64,
    /// Total cost will be alt_bn128_pairing_one_pair_cost_first
    /// + alt_bn128_pairing_one_pair_cost_other * (num_elems - 1)
    alt_bn128_pairing_one_pair_cost_first: u64,
    alt_bn128_pairing_one_pair_cost_other: u64,
    /// Big integer modular exponentiation base cost
    big_modular_exponentiation_base_cost: u64,
    /// Big integer moduler exponentiation cost divisor
    /// The modular exponentiation cost is computed as
    /// `input_length`/`big_modular_exponentiation_cost_divisor` + `big_modular_exponentiation_base_cost`
    big_modular_exponentiation_cost_divisor: u64,
    /// Coefficient `a` of the quadratic function which determines the number
    /// of compute units consumed to call poseidon syscall for a given number
    /// of inputs.
    poseidon_cost_coefficient_a: u64,
    /// Coefficient `c` of the quadratic function which determines the number
    /// of compute units consumed to call poseidon syscall for a given number
    /// of inputs.
    poseidon_cost_coefficient_c: u64,
    /// Number of compute units consumed for accessing the remaining compute units.
    get_remaining_compute_units_cost: u64,
    /// Number of compute units consumed to call alt_bn128_g1_compress.
    alt_bn128_g1_compress: u64,
    /// Number of compute units consumed to call alt_bn128_g1_decompress.
    alt_bn128_g1_decompress: u64,
    /// Number of compute units consumed to call alt_bn128_g2_compress.
    alt_bn128_g2_compress: u64,
    /// Number of compute units consumed to call alt_bn128_g2_decompress.
    alt_bn128_g2_decompress: u64,

    pub fn default() ComputeBudget {
        return ComputeBudget.new(@intCast(MAX_COMPUTE_UNIT_LIMIT));
    }

    pub fn new(compute_unit_limit: u64) ComputeBudget {
        return .{
            .compute_unit_limit = compute_unit_limit,
            .log_64_units = 100,
            .create_program_address_units = 1500,
            .invoke_units = 1000,
            .max_instruction_stack_depth = MAX_INSTRUCTION_STACK_DEPTH,
            .max_instruction_trace_length = 64,
            .sha256_base_cost = 85,
            .sha256_byte_cost = 1,
            .sha256_max_slices = 20_000,
            .max_call_depth = MAX_CALL_DEPTH,
            .stack_frame_size = STACK_FRAME_SIZE,
            .log_pubkey_units = 100,
            .max_cpi_instruction_size = 1280, // IPv6 Min MTU size
            .cpi_bytes_per_unit = 250, // ~50MB at 200,000 units
            .sysvar_base_cost = 100,
            .secp256k1_recover_cost = 25_000,
            .syscall_base_cost = 100,
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
            .heap_size = 32 * 1024, // solana_program_entrypoint::HEAP_LENGTH
            .heap_cost = DEFAULT_HEAP_COST,
            .mem_op_base_cost = 10,
            .alt_bn128_addition_cost = 334,
            .alt_bn128_multiplication_cost = 3_840,
            .alt_bn128_pairing_one_pair_cost_first = 36_364,
            .alt_bn128_pairing_one_pair_cost_other = 12_121,
            .big_modular_exponentiation_base_cost = 190,
            .big_modular_exponentiation_cost_divisor = 2,
            .poseidon_cost_coefficient_a = 61,
            .poseidon_cost_coefficient_c = 542,
            .get_remaining_compute_units_cost = 100,
            .alt_bn128_g1_compress = 30,
            .alt_bn128_g1_decompress = 398,
            .alt_bn128_g2_compress = 86,
            .alt_bn128_g2_decompress = 13610,
        };
    }

    /// Returns cost of the Poseidon hash function for the given number of
    /// inputs is determined by the following quadratic function:
    ///
    /// 61*n^2 + 542
    ///
    /// Which aproximates the results of benchmarks of light-posiedon
    /// library[0]. These results assume 1 CU per 33 ns. Examples:
    ///
    /// * 1 input
    ///   * light-poseidon benchmark: `18,303 / 33 ≈ 555`
    ///   * function: `61*1^2 + 542 = 603`
    /// * 2 inputs
    ///   * light-poseidon benchmark: `25,866 / 33 ≈ 784`
    ///   * function: `61*2^2 + 542 = 786`
    /// * 3 inputs
    ///   * light-poseidon benchmark: `37,549 / 33 ≈ 1,138`
    ///   * function; `61*3^2 + 542 = 1091`
    ///
    /// [0] https://github.com/Lightprotocol/light-poseidon#performance
    pub fn poseidon_cost(self: ComputeBudget, nr_inputs: u64) ?u64 {
        // TODO: Implement
        _ = self;
        _ = nr_inputs;
        // let squared_inputs = nr_inputs.checked_pow(2)?;
        // let mul_result = self
        //     .poseidon_cost_coefficient_a
        //     .checked_mul(squared_inputs)?;
        // let final_result = mul_result.checked_add(self.poseidon_cost_coefficient_c)?;

        // Some(final_result)
    }
};
