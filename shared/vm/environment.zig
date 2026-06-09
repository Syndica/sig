const std = @import("std");
const sig = @import("../lib.zig");
const tracy = @import("tracy");

const syscalls = sig.vm.syscalls;

const FeatureSet = sig.core.FeatureSet;
const ComputeBudget = sig.runtime.ComputeBudget;
const Config = sig.vm.Config;
const SbpfVersion = sig.vm.sbpf.Version;
const SyscallMap = sig.vm.SyscallMap;

pub const Environment = struct {
    loader: SyscallMap,
    config: Config,

    pub const ALL_ENABLED: Environment = .{
        .loader = .ALL_ENABLED,
        .config = .{},
    };

    pub fn initV1(
        feature_set: *const FeatureSet,
        compute_budget: *const ComputeBudget,
        slot: sig.core.Slot,
        reject_deployment_of_broken_elfs: bool,
    ) Environment {
        const zone = tracy.Zone.init(@src(), .{ .name = "Environment.initV1" });
        defer zone.deinit();

        return .{
            .loader = initV1Loader(
                feature_set,
                slot,
                reject_deployment_of_broken_elfs,
            ),
            .config = initV1Config(
                feature_set,
                compute_budget,
                slot,
                reject_deployment_of_broken_elfs,
            ),
        };
    }

    pub fn initV1Config(
        feature_set: *const FeatureSet,
        compute_budget: *const ComputeBudget,
        slot: sig.core.Slot,
        reject_deployment_of_broken_elfs: bool,
    ) Config {
        const min_sbpf_version: SbpfVersion =
            if (!feature_set.active(.disable_sbpf_v0_execution, slot) or
            feature_set.active(.reenable_sbpf_v0_execution, slot))
                .v0
            else
                .v3;

        const max_sbpf_version: SbpfVersion =
            if (feature_set.active(.enable_sbpf_v3_deployment_and_execution, slot))
                .v3
            else if (feature_set.active(.enable_sbpf_v2_deployment_and_execution, slot))
                .v2
            else if (feature_set.active(.enable_sbpf_v1_deployment_and_execution, slot))
                .v1
            else
                .v0;
        std.debug.assert(@intFromEnum(min_sbpf_version) <= @intFromEnum(max_sbpf_version));

        // SIMD-0460: stack frame gaps are deactivated globally (including SBPFv0).
        // For SBPFv0 this also has the side effect of lowering the per-call stack
        // bump from `stack_frame_size * 2` (8 KiB) to `stack_frame_size` (4 KiB),
        // see Interpreter.pushFrame in interpreter.zig.
        // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-beta.6/syscalls/src/lib.rs#L319
        const virtual_address_space_adjustments = feature_set.active(
            .virtual_address_space_adjustments,
            slot,
        );

        const enable_sbpf_v3_deployment_and_execution = feature_set.active(
            .enable_sbpf_v3_deployment_and_execution,
            slot,
        );

        // [agave] https://github.com/anza-xyz/agave/blob/v4.0/syscalls/src/lib.rs#L331
        return .{
            .max_call_depth = compute_budget.max_call_depth,
            .stack_frame_size = compute_budget.stack_frame_size,
            // SIMD-0460: Disable stack frame gaps with virtual_address_space_adjustments.
            .enable_stack_frame_gaps = !virtual_address_space_adjustments,
            .enable_instruction_meter = true,
            .reject_broken_elfs = reject_deployment_of_broken_elfs,
            .optimize_rodata = false,
            .aligned_memory_mapping = !virtual_address_space_adjustments,
            .allow_memory_region_zero = enable_sbpf_v3_deployment_and_execution,
            .virtual_address_space_adjustments = virtual_address_space_adjustments,
            .minimum_version = min_sbpf_version,
            .maximum_version = max_sbpf_version,
        };
    }

    pub fn initV1Loader(
        feature_set: *const FeatureSet,
        slot: sig.core.Slot,
        reject_deployment_of_broken_elfs: bool,
    ) SyscallMap {
        var loader: SyscallMap = .ALL_ENABLED;

        // we want to compute what are the requirments for keeping the syscall *enabled*.
        // it is much faster to construct the map from a negative side instead of enabling
        // all except for a few syscalls.

        // TODO: shouldn't need a copy/mutable map, improve stdlib here
        var gates = syscalls.Syscall.gates;
        var iter = gates.iterator();
        while (iter.next()) |entry| {
            const gate = entry.value.* orelse continue; // always enabled syscall
            const should = feature_set.active(gate.feature, slot);
            if (gate.invert == should) loader.map.set(entry.key, null);
        }

        // disable_deploy_of_alloc_free_syscall is hardcoded (always active), so
        // sol_alloc_free_ is always disabled when reject_deployment_of_broken_elfs is set.
        if (reject_deployment_of_broken_elfs) {
            loader.map.set(.sol_alloc_free_, null);
        }

        // disable_fees_sysvar is hardcoded (always active), so
        // sol_get_fees_sysvar is always disabled.
        loader.map.set(.sol_get_fees_sysvar, null);

        return loader;
    }
};
