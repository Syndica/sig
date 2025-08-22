const std = @import("std");
const sig = @import("../sig.zig");

const syscalls = sig.vm.syscalls;

const FeatureSet = sig.core.FeatureSet;
const ComputeBudget = sig.runtime.ComputeBudget;
const Config = sig.vm.Config;
const SbpfVersion = sig.vm.sbpf.Version;
const Syscall = sig.vm.Syscall;
const Registry = sig.vm.Registry;

pub const Environment = struct {
    loader: Registry(Syscall) = .{},
    config: Config = .{},

    pub fn deinit(self: Environment, allocator: std.mem.Allocator) void {
        var loader = self.loader;
        loader.deinit(allocator);
    }

    pub fn initV1(
        allocator: std.mem.Allocator,
        feature_set: *const FeatureSet,
        compute_budget: *const ComputeBudget,
        slot: sig.core.Slot,
        debugging_features: bool,
        reject_deployment_of_broken_elfs: bool,
    ) !Environment {
        return .{
            .loader = try initV1Loader(
                allocator,
                feature_set,
                slot,
                reject_deployment_of_broken_elfs,
            ),
            .config = initV1Config(
                feature_set,
                compute_budget,
                slot,
                debugging_features,
                reject_deployment_of_broken_elfs,
            ),
        };
    }

    pub fn initV1Config(
        feature_set: *const FeatureSet,
        compute_budget: *const ComputeBudget,
        slot: sig.core.Slot,
        debugging_features: bool,
        reject_deployment_of_broken_elfs: bool,
    ) Config {
        const min_sbpf_version: SbpfVersion = if (!feature_set.active(
            .disable_sbpf_v0_execution,
            slot,
        ) or feature_set.active(.reenable_sbpf_v0_execution, slot)) .v0 else .v3;

        const max_sbpf_version: SbpfVersion = if (feature_set.active(
            .enable_sbpf_v3_deployment_and_execution,
            slot,
        )) .v3 else if (feature_set.active(
            .enable_sbpf_v2_deployment_and_execution,
            slot,
        )) .v2 else if (feature_set.active(
            .enable_sbpf_v1_deployment_and_execution,
            slot,
        )) .v1 else .v0;

        return .{
            .max_call_depth = compute_budget.max_call_depth,
            .stack_frame_size = compute_budget.stack_frame_size,
            .enable_address_translation = true,
            .enable_stack_frame_gaps = !feature_set.active(
                .bpf_account_data_direct_mapping,
                slot,
            ),
            .instruction_meter_checkpoint_distance = 10000,
            .enable_instruction_meter = true,
            .enable_instruction_tracing = debugging_features,
            .enable_symbol_and_section_labels = debugging_features,
            .reject_broken_elfs = reject_deployment_of_broken_elfs,
            .noop_instruction_rate = 256,
            .sanitize_user_provided_values = true,
            .optimize_rodata = false,
            .aligned_memory_mapping = !feature_set.active(
                .bpf_account_data_direct_mapping,
                slot,
            ),
            .minimum_version = min_sbpf_version,
            .maximum_version = max_sbpf_version,
        };
    }

    pub fn initV1Loader(
        allocator: std.mem.Allocator,
        feature_set: *const FeatureSet,
        slot: sig.core.Slot,
        reject_deployment_of_broken_elfs: bool,
    ) !Registry(Syscall) {
        // Register syscalls
        var loader = Registry(Syscall){};
        errdefer loader.deinit(allocator);

        // Abort
        _ = try loader.registerHashed(
            allocator,
            "abort",
            syscalls.abort,
        );

        // Panic
        _ = try loader.registerHashed(
            allocator,
            "sol_panic_",
            syscalls.panic,
        );

        // Alloc Free
        const disable_alloc_free = reject_deployment_of_broken_elfs and
            feature_set.active(.disable_deploy_of_alloc_free_syscall, slot);

        if (!disable_alloc_free) {
            _ = try loader.registerHashed(
                allocator,
                "sol_alloc_free_",
                syscalls.allocFree,
            );
        }

        // Logging
        _ = try loader.registerHashed(
            allocator,
            "sol_log_",
            syscalls.log,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_log_64_",
            syscalls.log64,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_log_pubkey",
            syscalls.logPubkey,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_log_compute_units_",
            syscalls.logComputeUnits,
        );

        // Log Data
        _ = try loader.registerHashed(
            allocator,
            "sol_log_data",
            syscalls.logData,
        );

        // Program derived addresses
        _ = try loader.registerHashed(
            allocator,
            "sol_create_program_address",
            syscalls.createProgramAddress,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_try_find_program_address",
            syscalls.findProgramAddress,
        );

        // Sha256, Keccak256, Secp256k1Recover
        _ = try loader.registerHashed(
            allocator,
            "sol_sha256",
            syscalls.hash.sha256,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_keccak256",
            syscalls.hash.keccak256,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_secp256k1_recover",
            syscalls.ecc.secp256k1Recover,
        );

        // Blake3
        if (feature_set.active(.blake3_syscall_enabled, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_blake3",
                syscalls.hash.blake3,
            );
        }

        // Elliptic Curve
        if (feature_set.active(.curve25519_syscall_enabled, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_curve_validate_point",
                syscalls.ecc.curvePointValidation,
            );
            _ = try loader.registerHashed(
                allocator,
                "sol_curve_group_op",
                syscalls.ecc.curveGroupOp,
            );
            _ = try loader.registerHashed(
                allocator,
                "sol_curve_multiscalar_mul",
                syscalls.ecc.curveMultiscalarMul,
            );
        }

        // Sysvars
        _ = try loader.registerHashed(
            allocator,
            "sol_get_clock_sysvar",
            syscalls.sysvar.getClock,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_get_epoch_schedule_sysvar",
            syscalls.sysvar.getEpochSchedule,
        );
        if (!feature_set.active(.disable_fees_sysvar, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_get_fees_sysvar",
                syscalls.sysvar.getFees,
            );
        }
        _ = try loader.registerHashed(
            allocator,
            "sol_get_rent_sysvar",
            syscalls.sysvar.getRent,
        );
        if (feature_set.active(.last_restart_slot_sysvar, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_get_last_restart_slot",
                syscalls.sysvar.getLastRestartSlot,
            );
        }

        _ = try loader.registerHashed(
            allocator,
            "sol_get_epoch_rewards_sysvar",
            syscalls.sysvar.getEpochRewards,
        );

        // Memory
        _ = try loader.registerHashed(
            allocator,
            "sol_memcpy_",
            syscalls.memops.memcpy,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_memmove_",
            syscalls.memops.memmove,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_memset_",
            syscalls.memops.memset,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_memcmp_",
            syscalls.memops.memcmp,
        );

        _ = try loader.registerHashed(
            allocator,
            "sol_get_processed_sibling_instruction",
            syscalls.getProcessedSiblingInstruction,
        );

        // Stack Height
        _ = try loader.registerHashed(
            allocator,
            "sol_get_stack_height",
            syscalls.getStackHeight,
        );

        // Return Data
        _ = try loader.registerHashed(
            allocator,
            "sol_set_return_data",
            syscalls.setReturnData,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_get_return_data",
            syscalls.getReturnData,
        );

        // Cross Program Invocation
        _ = try loader.registerHashed(
            allocator,
            "sol_invoke_signed_c",
            syscalls.cpi.invokeSignedC,
        );
        _ = try loader.registerHashed(
            allocator,
            "sol_invoke_signed_rust",
            syscalls.cpi.invokeSignedRust,
        );

        // Memory Allocator
        if (!feature_set.active(.disable_deploy_of_alloc_free_syscall, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_alloc_free_",
                syscalls.allocFree,
            );
        }

        // Alt-bn128
        if (feature_set.active(.enable_alt_bn128_syscall, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_alt_bn128_group_op",
                syscalls.ecc.altBn128GroupOp,
            );
        }
        if (feature_set.active(.enable_alt_bn128_compression_syscall, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_alt_bn128_compression",
                syscalls.ecc.altBn128Compression,
            );
        }

        // Big_mod_exp
        // if (feature_set.active(feature_set.ENABLE_BIG_MOD_EXP_SYSCALL, slot)) {
        //     _ = try syscalls.registerHashed(allocator, "sol_big_mod_exp", bigModExp,);
        // }

        if (feature_set.active(.enable_poseidon_syscall, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_poseidon",
                syscalls.hash.poseidon,
            );
        }

        if (feature_set.active(.remaining_compute_units_syscall_enabled, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_remaining_compute_units",
                syscalls.remainingComputeUnits,
            );
        }

        // Sysvar Getter
        if (feature_set.active(.get_sysvar_syscall_enabled, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_get_sysvar",
                syscalls.sysvar.getSysvar,
            );
        }

        if (feature_set.active(.enable_get_epoch_stake_syscall, slot)) {
            _ = try loader.registerHashed(
                allocator,
                "sol_get_epoch_stake",
                syscalls.getEpochStake,
            );
        }

        return loader;
    }
};
