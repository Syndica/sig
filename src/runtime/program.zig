const std = @import("std");
const sig = @import("../sig.zig");

const shared_program = sig.shared.runtime.program;

pub const address_lookup_table = shared_program.address_lookup_table;
pub const bpf = shared_program.bpf;
pub const bpf_loader = shared_program.bpf_loader;
pub const builtin_program_costs = shared_program.builtin_program_costs;
pub const builtin_programs = shared_program.builtin_programs;
pub const compute_budget = shared_program.compute_budget;
pub const config = shared_program.config;
pub const precompiles = shared_program.precompiles;
pub const system = shared_program.system;
pub const testing = shared_program.testing;
pub const vote = shared_program.vote;
pub const zk_elgamal = shared_program.zk_elgamal;

pub const NATIVE = shared_program.NATIVE;
pub const PRECOMPILE = shared_program.PRECOMPILE;
pub const SEED_FIELD_CONFIG = shared_program.SEED_FIELD_CONFIG;

pub const stake = struct {
    const shared_stake = shared_program.stake;

    pub const state = shared_stake.state;
    pub const Instruction = shared_stake.Instruction;
    pub const LockupArgs = shared_stake.LockupArgs;
    pub const StakeStateV2 = shared_stake.StakeStateV2;
    pub const ID = shared_stake.ID;
    pub const SOURCE_ID = shared_stake.SOURCE_ID;
    pub const COMPUTE_UNITS = shared_stake.COMPUTE_UNITS;
    pub const StakeError = shared_stake.StakeError;

    pub const execute = shared_stake.execute;
    pub const getMinimumDelegation = shared_stake.getMinimumDelegation;

    pub fn stakeStateFromAccount(
        allocator: std.mem.Allocator,
        account: sig.core.Account,
    ) !StakeStateV2 {
        const buffer = try allocator.alloc(u8, account.data.len());
        defer allocator.free(buffer);
        account.data.readAll(buffer);
        return sig.bincode.readFromSlice(
            sig.utils.allocators.failing.allocator(.{}),
            StakeStateV2,
            buffer,
            .{},
        );
    }
};

pub const state = stake;
