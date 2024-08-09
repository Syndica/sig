const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    defer makeZlsNotInstallAnythingDuringBuildOnSave(b);

    // CLI options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "filter", "List of filters, used for example to filter unit tests by name"); // specified as a series like `-Dfilter="filter1" -Dfilter="filter2"`

    // CLI build steps
    const run_step = b.step("run", "Run the sig executable");
    const test_step = b.step("test", "Run library tests");
    const fuzz_step = b.step("fuzz", "Gossip fuzz testing");
    const benchmark_step = b.step("benchmark", "Benchmark client");

    // Dependencies
    const dep_opts = .{ .target = target, .optimize = optimize };

    const base58_dep = b.dependency("base58-zig", dep_opts);
    const base58_module = base58_dep.module("base58-zig");

    const zig_network_dep = b.dependency("zig-network", dep_opts);
    const zig_network_module = zig_network_dep.module("network");

    const zig_cli_dep = b.dependency("zig-cli", dep_opts);
    const zig_cli_module = zig_cli_dep.module("zig-cli");

    const httpz_dep = b.dependency("httpz", dep_opts);
    const httpz_mod = httpz_dep.module("httpz");

    const zstd_dep = b.dependency("zstd", dep_opts);
    const zstd_mod = zstd_dep.module("zstd");

    const curl_dep = b.dependency("curl", dep_opts);
    const curl_mod = curl_dep.module("curl");

    const rocksdb_dep = b.dependency("rocksdb", dep_opts);
    const rocksdb_mod = rocksdb_dep.module("rocksdb-bindings");

    // expose Sig as a module
    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/lib.zig"),
    });
    sig_mod.addImport("zig-network", zig_network_module);
    sig_mod.addImport("base58-zig", base58_module);
    sig_mod.addImport("zig-cli", zig_cli_module);
    sig_mod.addImport("httpz", httpz_mod);
    sig_mod.addImport("zstd", zstd_mod);
    sig_mod.addImport("curl", curl_mod);
    sig_mod.addImport("rocksdb", rocksdb_mod);

    // main executable
    const sig_exe = b.addExecutable(.{
        .name = "sig",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(sig_exe);
    sig_exe.root_module.addImport("base58-zig", base58_module);
    sig_exe.root_module.addImport("curl", curl_mod);
    sig_exe.root_module.addImport("httpz", httpz_mod);
    sig_exe.root_module.addImport("zig-cli", zig_cli_module);
    sig_exe.root_module.addImport("zig-network", zig_network_module);
    sig_exe.root_module.addImport("zstd", zstd_mod);
    sig_exe.root_module.addImport("rocksdb", rocksdb_mod);

    const main_exe_run = b.addRunArtifact(sig_exe);
    main_exe_run.addArgs(b.args orelse &.{});
    run_step.dependOn(&main_exe_run.step);

    // unit tests
    const unit_tests_exe = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .filters = filters orelse &.{},
    });
    b.installArtifact(unit_tests_exe);
    unit_tests_exe.root_module.addImport("base58-zig", base58_module);
    unit_tests_exe.root_module.addImport("curl", curl_mod);
    unit_tests_exe.root_module.addImport("httpz", httpz_mod);
    unit_tests_exe.root_module.addImport("zig-network", zig_network_module);
    unit_tests_exe.root_module.addImport("zstd", zstd_mod);
    unit_tests_exe.root_module.addImport("rocksdb", rocksdb_mod);

    const unit_tests_exe_run = b.addRunArtifact(unit_tests_exe);
    test_step.dependOn(&unit_tests_exe_run.step);

    // fuzz test
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(fuzz_exe);
    fuzz_exe.root_module.addImport("base58-zig", base58_module);
    fuzz_exe.root_module.addImport("zig-network", zig_network_module);
    fuzz_exe.root_module.addImport("httpz", httpz_mod);
    fuzz_exe.root_module.addImport("zstd", zstd_mod);

    const fuzz_exe_run = b.addRunArtifact(fuzz_exe);
    fuzz_exe_run.addArgs(b.args orelse &.{});
    fuzz_step.dependOn(&fuzz_exe_run.step);

    // benchmarks
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("src/benchmarks.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(benchmark_exe);
    benchmark_exe.root_module.addImport("base58-zig", base58_module);
    benchmark_exe.root_module.addImport("zig-network", zig_network_module);
    benchmark_exe.root_module.addImport("httpz", httpz_mod);
    benchmark_exe.root_module.addImport("zstd", zstd_mod);

    const benchmark_exe_run = b.addRunArtifact(benchmark_exe);
    benchmark_exe_run.addArgs(b.args orelse &.{});
    benchmark_step.dependOn(&benchmark_exe_run.step);
}

/// Reference/inspiration: https://kristoff.it/blog/improving-your-zls-experience/
fn makeZlsNotInstallAnythingDuringBuildOnSave(b: *Build) void {
    const zls_is_build_runner = b.option(bool, "zls-is-build-runner", "" ++
        "Option passed by zls to indicate that it's the one running this build script (configured in the local zls.json). " ++
        "This should not be specified on the command line nor as a dependency argument.") orelse false;
    if (!zls_is_build_runner) return;

    for (b.install_tls.step.dependencies.items) |*install_step_dep| {
        const install_artifact = install_step_dep.*.cast(Build.Step.InstallArtifact) orelse continue;
        const artifact = install_artifact.artifact;
        install_step_dep.* = &artifact.step;
        // this will make it so `-fno-emit-bin` is passed, meaning
        // that the compiler will only go as far as semantically
        // analyzing the code, without sending it to any backend,
        // namely the slow-to-compile LLVM.
        artifact.generated_bin = null;
    }
}
