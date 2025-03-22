const std = @import("std");

/// [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/compute-budget/src/compute_budget.rs#L11-L119
pub const ComputeBudget = struct {
    /// Number of compute units that a transaction or individual instruction is
    /// allowed to consume. Compute units are consumed by program execution,
    /// resources they use, etc...
    compute_unit_limit: u64,
    /// Number of compute units consumed by a log_u64 call
    log_64_units: u64,
    /// Maximum SBF to BPF call depth
    max_call_depth: usize,
    /// Size of a stack frame in bytes, must match the size specified in the LLVM SBF backend
    stack_frame_size: usize,
    /// Number of compute units consumed by logging a `Pubkey`
    log_pubkey_units: u64,
    /// Number of compute units consumed to do a syscall without any work
    syscall_base_cost: u64,
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

    pub fn default(compute_unit_limit: u64) ComputeBudget {
        return .{
            .compute_unit_limit = compute_unit_limit,
            .log_64_units = 100,
            .max_call_depth = 64,
            .stack_frame_size = 4096,
            .log_pubkey_units = 100,
            .syscall_base_cost = 100,
            .cpi_bytes_per_unit = 250, // ~50MB at 200,000 units
            .heap_size = 32 * 1024,
            .heap_cost = 8,
            .mem_op_base_cost = 10,
            .poseidon_cost_coefficient_a = 61,
            .poseidon_cost_coefficient_c = 542,
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/9fddc352aa300a194e5364298d445f3555cd5132/program-runtime/src/execution_budget.rs#L205-L232
    /// [fd] https://github.com/firedancer-io/firedancer/blob/211dfccc1d84a50191a487a6abffd962f7954179/src/flamenco/vm/syscall/fd_vm_syscall_crypto.c#L238-L245
    ///
    /// Returns the cost of a Poseidon hash syscall for a given input length.
    pub fn poseidonCost(self: ComputeBudget, len: u64) !u64 {
        const squared_inputs = try std.math.powi(u64, len, 2);
        const mul_result = try std.math.mul(
            u64,
            squared_inputs,
            self.poseidon_cost_coefficient_a,
        );
        return try std.math.add(
            u64,
            mul_result,
            self.poseidon_cost_coefficient_c,
        );
    }
};
