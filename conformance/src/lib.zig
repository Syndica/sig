const std = @import("std");
const sig = @import("sig");

comptime {
    _ = @import("elf_loader.zig");
    _ = @import("instruction_execute.zig");
    _ = @import("vm_interp.zig");
    _ = @import("vm_syscall.zig");
    _ = @import("txn_execute.zig");
}

pub const std_options: std.Options = .{
    .log_level = .warn,
};

export fn sol_compat_init(log_level: i32) void {
    _ = log_level;
}
export fn sol_compat_fini() void {}

const SolCompatFeatures = extern struct {
    struct_size: u64,
    hardcoded_features: ?[*]const u64,
    hardcoded_features_len: u64,
    supported_features: ?[*]const u64,
    supported_features_len: u64,
};

const FEATURES: SolCompatFeatures = f: {
    @setEvalBranchQuota(sig.core.features.all_features.len * 1_000);
    var hardcoded_features: []const u64 = &.{};
    var supported_features: []const u64 = &.{};

    for (sig.core.features.features) |feature| {
        const hardcoded_for_fuzzing = switch (feature.status) {
            .reverted, .unsupported => continue,
            .supported => false,
            .hardcoded_for_fuzzing, .hardcoded => true,
        };
        if (hardcoded_for_fuzzing)
            hardcoded_features = hardcoded_features ++ .{feature.id()}
        else
            supported_features = supported_features ++ .{feature.id()};
    }

    break :f .{
        .struct_size = @sizeOf(SolCompatFeatures),
        .hardcoded_features = hardcoded_features.ptr,
        .hardcoded_features_len = hardcoded_features.len,
        .supported_features = supported_features.ptr,
        .supported_features_len = supported_features.len,
    };
};

export fn sol_compat_get_features_v1() *const SolCompatFeatures {
    return &FEATURES;
}

// sig fmt: off
pub const entrypoints: std.StaticStringMap(*const fn (
    out: [*]u8,
    out_sz: *u64,
    input: [*]const u8,
    in_sz: u64,
) callconv(.c) i32) = .initComptime(.{
    .{ "sol_compat_instr_execute_v1", @import("instruction_execute.zig").sol_compat_instr_execute_v1 },
    .{ "sol_compat_vm_interp_v1", @import("vm_interp.zig").sol_compat_vm_interp_v1 },
    .{ "sol_compat_vm_cpi_syscall_v1", @import("vm_syscall.zig").sol_compat_vm_cpi_syscall_v1 },
    .{ "sol_compat_vm_syscall_execute_v1", @import("vm_syscall.zig").sol_compat_vm_syscall_execute_v1 },
    .{ "sol_compat_elf_loader_v1", @import("elf_loader.zig").sol_compat_elf_loader_v1 },
    .{ "sol_compat_txn_execute_v1", @import("txn_execute.zig").sol_compat_txn_execute_v1 },
});
// sig fmt: on
