const std = @import("std");

const package_name = "sig";
const package_path = "src/lib.zig";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const opts = .{ .target = target, .optimize = optimize };
    const base58 = b.dependency("base58-zig", opts);
    const base58_module = base58.module("base58-zig");

    const zig_network = b.dependency("zig-network", opts);
    const zig_network_module = zig_network.module("network");

    const zig_cli = b.dependency("zig-cli", opts);
    const zig_cli_module = zig_cli.module("zig-cli");

    const getty = b.dependency("getty", opts);
    const getty_mod = getty.module("getty");

    const httpz = b.dependency("httpz", opts);
    const httpz_mod = httpz.module("httpz");

    const zigdig = b.dependency("zigdig", opts);
    const zigdig_mod = zigdig.module("dns");

    const zstd_dep = b.dependency("zstd", opts);
    const zstd_mod = zstd_dep.module("zstd");
    const zstd_c_lib = zstd_dep.artifact("zstd");

    const curl_dep = b.dependency("curl", opts);
    const curl_mod = curl_dep.module("curl");
    const curl_c_lib = curl_dep.artifact("curl");

    // expose Sig as a module
    _ = b.addModule(package_name, .{
        .root_source_file = .{ .path = package_path },
        .imports = &.{
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
            .{
                .name = "curl",
                .module = curl_mod,
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
    tests.root_module.addImport("zig-network", zig_network_module);
    tests.root_module.addImport("base58-zig", base58_module);
    tests.root_module.addImport("zig-cli", zig_cli_module);
    tests.root_module.addImport("getty", getty_mod);
    tests.root_module.addImport("httpz", httpz_mod);
    tests.root_module.addImport("zigdig", zigdig_mod);
    tests.root_module.addImport("zstd", zstd_mod);
    tests.root_module.addImport("curl", curl_mod);
    tests.linkLibrary(curl_c_lib);
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

    exe.root_module.addImport("zig-cli", zig_cli_module);
    exe.root_module.addImport("base58-zig", base58_module);
    exe.root_module.addImport("zig-network", zig_network_module);
    exe.root_module.addImport("zig-cli", zig_cli_module);
    exe.root_module.addImport("getty", getty_mod);
    exe.root_module.addImport("httpz", httpz_mod);
    exe.root_module.addImport("zigdig", zigdig_mod);
    exe.root_module.addImport("zstd", zstd_mod);
    exe.root_module.addImport("curl", curl_mod);
    exe.linkLibrary(curl_c_lib);
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
            .path = "src/fuzz.zig",
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
            // .main_pkg_path = .{ .path = "src" },
        });

        // TODO: maybe we dont need all these for all bins
        exec.root_module.addImport("base58-zig", base58_module);
        exec.root_module.addImport("zig-network", zig_network_module);
        exec.root_module.addImport("zig-cli", zig_cli_module);
        exec.root_module.addImport("getty", getty_mod);
        exec.root_module.addImport("httpz", httpz_mod);
        exec.root_module.addImport("zigdig", zigdig_mod);
        exec.root_module.addImport("zstd", zstd_mod);
        exec.root_module.addImport("curl", curl_mod);
        exec.linkLibrary(curl_c_lib);
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
