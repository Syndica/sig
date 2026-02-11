const std = @import("std");
const sig = @import("sig");

comptime {
    _ = @import("elf_loader.zig");
    _ = @import("shred_parse.zig");
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
    var hardcoded_features: []const u64 = &.{};
    var supported_features: []const u64 = &.{};

    for (sig.core.features.map.values) |feature| {
        if (feature.reverted) continue; // skip reverted features

        if (feature.hardcoded_for_fuzzing) {
            hardcoded_features = hardcoded_features ++ .{feature.id()};
        } else {
            supported_features = supported_features ++ .{feature.id()};
        }
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
