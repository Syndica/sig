const std = @import("std");

const package_name = "sig";
const package_path = "src/lib.zig";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const opts = .{ .target = target, .optimize = optimize };
    const base58_module = b.dependency("base58-zig", opts).module("base58-zig");
    const zig_network_module = b.dependency("zig-network", opts).module("network");
    const zig_cli_module = b.dependency("zig-cli", opts).module("zig-cli");
    const getty_mod = b.dependency("getty", opts).module("getty");
    const httpz_mod = b.dependency("httpz", opts).module("httpz");
    const zigdig_mod = b.dependency("zigdig", opts).module("dns");

    const zstd_dep = b.dependency("zstd", opts);
    const zstd_mod = zstd_dep.module("zstd");
    const zstd_c_lib = zstd_dep.artifact("zstd");

    // expose Sig as a module
    _ = b.addModule(package_name, .{
        .source_file = .{ .path = package_path },
        .dependencies = &.{
            .{
                .name = "zig-network",
                .module = zig_network_module,
            },
            .{
                .name = "base58-zig",
                .module = base58_module,
            },
            .{
                .name = "zig-cli",
                .module = zig_cli_module,
            },
            .{
                .name = "getty",
                .module = getty_mod,
            },
            .{
                .name = "httpz",
                .module = httpz_mod,
            },
            .{
                .name = "zigdig",
                .module = zigdig_mod,
            },
            .{
                .name = "zstd",
                .module = zstd_mod,
            },
        },
    });

    // unit tests
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/tests.zig" },
        .target = target,
        .optimize = optimize,
        .filter = if (b.args) |args| args[0] else null, // filter tests like so: zig build test -- "<FILTER>"
    });
    tests.addModule("zig-network", zig_network_module);
    tests.addModule("base58-zig", base58_module);
    tests.addModule("zig-cli", zig_cli_module);
    tests.addModule("getty", getty_mod);
    tests.addModule("httpz", httpz_mod);
    tests.addModule("zigdig", zigdig_mod);
    tests.addModule("zstd", zstd_mod);
    tests.linkLibrary(zstd_c_lib);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_tests.step);

    const exe = b.addExecutable(.{
        .name = "sig",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("base58-zig", base58_module);
    exe.addModule("zig-network", zig_network_module);
    exe.addModule("zig-cli", zig_cli_module);
    exe.addModule("getty", getty_mod);
    exe.addModule("httpz", httpz_mod);
    exe.addModule("zigdig", zigdig_mod);
    exe.addModule("zstd", zstd_mod);
    exe.linkLibrary(zstd_c_lib);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const ExecCommand = struct {
        name: []const u8,
        path: []const u8,
        description: []const u8 = "",
    };

    const exec_commands = [_]ExecCommand{
        ExecCommand{
            .name = "fuzz",
            .path = "src/gossip/fuzz.zig",
            .description = "gossip fuzz testing",
        },
        ExecCommand{
            .name = "benchmark",
            .path = "src/benchmarks.zig",
            .description = "benchmark client",
            // note: we dont want this in ReleaseSafe always because its harder to debug
        },
    };

    for (exec_commands) |command_info| {
        const exec = b.addExecutable(.{
            .name = command_info.name,
            .root_source_file = .{ .path = command_info.path },
            .target = target,
            .optimize = optimize,
            .main_pkg_path = .{ .path = "src" },
        });

        // TODO: maybe we dont need all these for all bins
        exec.addModule("base58-zig", base58_module);
        exec.addModule("zig-network", zig_network_module);
        exec.addModule("zig-cli", zig_cli_module);
        exec.addModule("getty", getty_mod);
        exec.addModule("httpz", httpz_mod);
        exec.addModule("zigdig", zigdig_mod);
        exec.addModule("zstd", zstd_mod);
        exec.linkLibrary(zstd_c_lib);

        // this lets us run it as an exec
        b.installArtifact(exec);

        const cmd = b.addRunArtifact(exec);
        if (b.args) |args| cmd.addArgs(args);
        b
            .step(command_info.name, command_info.description)
            .dependOn(&cmd.step);
    }
}
