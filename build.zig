const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    defer makeZlsNotInstallAnythingDuringBuildOnSave(b);

    // CLI options
    const target = b.standardTargetOptions(.{
        .default_target = defaultTargetDetectM3() orelse .{},
    });
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "filter", "List of filters, used for example to filter unit tests by name"); // specified as a series like `-Dfilter="filter1" -Dfilter="filter2"`
    const enable_tsan = b.option(bool, "enable-tsan", "Enable TSan for the test suite");
    const blockstore_db = b.option(BlockstoreDB, "blockstore", "Blockstore database backend") orelse .rocksdb;
    const no_run = b.option(bool, "no-run",
        \\Don't run any of the executables implied by the specified steps, only install them.
        \\Use in conjunction with 'no-bin' to avoid installation as well.
    ) orelse false;
    const no_bin = b.option(bool, "no-bin",
        \\Don't install any of the binaries implied by the specified steps, only run them.
        \\Use in conjunction with 'no-run' to avoid running as well.
    ) orelse false;
    const no_network_tests = b.option(bool, "no-network-tests", "Do not run any tests that depend on the network.") orelse false;

    // Build options
    const build_options = b.addOptions();
    build_options.addOption(BlockstoreDB, "blockstore_db", blockstore_db);
    build_options.addOption(bool, "no_network_tests", no_network_tests);

    // CLI build steps
    const install_step = b.getInstallStep();
    const sig_step = b.step("sig", "Run the sig executable");
    const test_step = b.step("test", "Run library tests");
    const fuzz_step = b.step("fuzz", "Gossip fuzz testing");
    const benchmark_step = b.step("benchmark", "Benchmark client");
    const geyser_reader_step = b.step("geyser_reader", "Read data from geyser");
    const svm_step = b.step("svm", "Run the SVM client");
    const docs_step = b.step("docs", "Generate and install documentation for the Sig Library");

    // Dependencies
    const dep_opts = .{ .target = target, .optimize = optimize };

    const base58_dep = b.dependency("base58", dep_opts);
    const base58_mod = base58_dep.module("base58");

    const zig_network_dep = b.dependency("zig-network", dep_opts);
    const zig_network_mod = zig_network_dep.module("network");

    const zig_cli_dep = b.dependency("zig-cli", dep_opts);
    const zig_cli_mod = zig_cli_dep.module("zig-cli");

    const zstd_dep = b.dependency("zstd", dep_opts);
    const zstd_mod = zstd_dep.module("zstd");

    const rocksdb_dep = b.dependency("rocksdb", dep_opts);
    const rocksdb_mod = rocksdb_dep.module("rocksdb-bindings");

    const lsquic_dep = b.dependency("lsquic", dep_opts);
    const lsquic_mod = lsquic_dep.module("lsquic");

    const ssl_dep = lsquic_dep.builder.dependency("boringssl", dep_opts);
    const ssl_mod = ssl_dep.module("ssl");

    const xev_dep = b.dependency("xev", dep_opts);
    const xev_mod = xev_dep.module("xev");

    const pretty_table_dep = b.dependency("prettytable", dep_opts);
    const pretty_table_mod = pretty_table_dep.module("prettytable");

    // expose Sig as a module
    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/sig.zig"),
    });

    sig_mod.addOptions("build-options", build_options);

    sig_mod.addImport("zig-network", zig_network_mod);
    sig_mod.addImport("base58", base58_mod);
    sig_mod.addImport("zig-cli", zig_cli_mod);
    sig_mod.addImport("zstd", zstd_mod);
    switch (blockstore_db) {
        .rocksdb => sig_mod.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    // main executable
    const sig_exe = b.addExecutable(.{
        .name = "sig",
        .root_source_file = b.path("src/cmd.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
    });
    sig_step.dependOn(&sig_exe.step);
    install_step.dependOn(&sig_exe.step);

    // make sure pyroscope's got enough info to profile
    sig_exe.build_id = .fast;
    sig_exe.root_module.omit_frame_pointer = false;
    sig_exe.root_module.strip = false;

    sig_exe.linkLibC();
    sig_exe.root_module.addOptions("build-options", build_options);

    sig_exe.root_module.addImport("xev", xev_mod);
    sig_exe.root_module.addImport("base58", base58_mod);
    sig_exe.root_module.addImport("zig-cli", zig_cli_mod);
    sig_exe.root_module.addImport("zig-network", zig_network_mod);
    sig_exe.root_module.addImport("zstd", zstd_mod);
    sig_exe.root_module.addImport("lsquic", lsquic_mod);
    sig_exe.root_module.addImport("ssl", ssl_mod);
    sig_exe.root_module.addImport("xev", xev_mod);
    switch (blockstore_db) {
        .rocksdb => sig_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    if (!no_bin) {
        const sig_install = b.addInstallArtifact(sig_exe, .{});
        sig_step.dependOn(&sig_install.step);
        install_step.dependOn(&sig_install.step);
    }

    if (!no_run) {
        const sig_run = b.addRunArtifact(sig_exe);
        sig_step.dependOn(&sig_run.step);
        sig_run.addArgs(b.args orelse &.{});
    }

    // unit tests
    const unit_tests_exe = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
        .filters = filters orelse &.{},
    });
    test_step.dependOn(&unit_tests_exe.step);
    install_step.dependOn(&unit_tests_exe.step);

    unit_tests_exe.linkLibC();
    unit_tests_exe.root_module.addOptions("build-options", build_options);

    unit_tests_exe.root_module.addImport("xev", xev_mod);
    unit_tests_exe.root_module.addImport("base58", base58_mod);
    unit_tests_exe.root_module.addImport("zig-network", zig_network_mod);
    unit_tests_exe.root_module.addImport("zstd", zstd_mod);
    switch (blockstore_db) {
        .rocksdb => unit_tests_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    if (!no_bin) {
        const unit_tests_install = b.addInstallArtifact(unit_tests_exe, .{});
        test_step.dependOn(&unit_tests_install.step);
        install_step.dependOn(&unit_tests_install.step);
    }

    if (!no_run) {
        const unit_tests_run = b.addRunArtifact(unit_tests_exe);
        test_step.dependOn(&unit_tests_run.step);
    }

    // fuzz test
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
    });
    fuzz_step.dependOn(&fuzz_exe.step);
    install_step.dependOn(&fuzz_exe.step);

    fuzz_exe.linkLibC();
    fuzz_exe.root_module.addOptions("build-options", build_options);

    fuzz_exe.root_module.addImport("xev", xev_mod);
    fuzz_exe.root_module.addImport("base58", base58_mod);
    fuzz_exe.root_module.addImport("zig-network", zig_network_mod);
    fuzz_exe.root_module.addImport("zstd", zstd_mod);
    switch (blockstore_db) {
        .rocksdb => fuzz_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    if (!no_bin) {
        const fuzz_install = b.addInstallArtifact(fuzz_exe, .{});
        fuzz_step.dependOn(&fuzz_install.step);
        install_step.dependOn(&fuzz_install.step);
    }

    if (!no_run) {
        const fuzz_run = b.addRunArtifact(fuzz_exe);
        fuzz_step.dependOn(&fuzz_run.step);
        fuzz_run.addArgs(b.args orelse &.{});
    }

    // benchmarks
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("src/benchmarks.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
    });
    benchmark_step.dependOn(&benchmark_exe.step);
    install_step.dependOn(&benchmark_exe.step);

    benchmark_exe.linkLibC();
    benchmark_exe.root_module.addOptions("build-options", build_options);

    benchmark_exe.root_module.addImport("xev", xev_mod);
    benchmark_exe.root_module.addImport("base58", base58_mod);
    benchmark_exe.root_module.addImport("zig-network", zig_network_mod);
    benchmark_exe.root_module.addImport("zstd", zstd_mod);
    benchmark_exe.root_module.addImport("prettytable", pretty_table_mod);
    switch (blockstore_db) {
        .rocksdb => benchmark_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    if (!no_bin) {
        const benchmark_install = b.addInstallArtifact(benchmark_exe, .{});
        benchmark_step.dependOn(&benchmark_install.step);
        install_step.dependOn(&benchmark_install.step);
    }

    if (!no_run) {
        const benchmark_run = b.addRunArtifact(benchmark_exe);
        benchmark_step.dependOn(&benchmark_run.step);
        benchmark_run.addArgs(b.args orelse &.{});
    }

    // geyser reader
    const geyser_reader_exe = b.addExecutable(.{
        .name = "geyser",
        .root_source_file = b.path("src/geyser/main.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
    });
    geyser_reader_step.dependOn(&geyser_reader_exe.step);
    install_step.dependOn(&geyser_reader_exe.step);

    geyser_reader_exe.root_module.addImport("sig", sig_mod);
    geyser_reader_exe.root_module.addImport("zig-cli", zig_cli_mod);

    if (!no_bin) {
        const geyser_reader_install = b.addInstallArtifact(geyser_reader_exe, .{});
        geyser_reader_step.dependOn(&geyser_reader_install.step);
        install_step.dependOn(&geyser_reader_install.step);
    }

    if (!no_run) {
        const geyser_reader_run = b.addRunArtifact(geyser_reader_exe);
        geyser_reader_step.dependOn(&geyser_reader_run.step);
        geyser_reader_run.addArgs(b.args orelse &.{});
    }

    const svm_exe = b.addExecutable(.{
        .name = "svm",
        .root_source_file = b.path("src/svm/main.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = enable_tsan,
    });
    svm_step.dependOn(&svm_exe.step);
    install_step.dependOn(&svm_exe.step);

    svm_exe.root_module.addImport("sig", sig_mod);

    if (!no_bin) {
        const svm_install = b.addInstallArtifact(svm_exe, .{});
        svm_step.dependOn(&svm_install.step);
        install_step.dependOn(&svm_install.step);
    }

    if (!no_run) {
        const svm_run = b.addRunArtifact(svm_exe);
        svm_step.dependOn(&svm_run.step);
        svm_run.addArgs(b.args orelse &.{});
    }

    // docs for the Sig library
    const install_sig_docs = b.addInstallDirectory(.{
        .source_dir = sig_exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_sig_docs.step);
}

const BlockstoreDB = enum {
    rocksdb,
    hashmap,
};

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

/// TODO: remove after updating to 0.14, where M3/M4 feature detection is fixed.
/// Ref: https://github.com/ziglang/zig/pull/21116
fn defaultTargetDetectM3() ?std.Target.Query {
    const builtin = @import("builtin");
    if (builtin.os.tag != .macos) return null;
    switch (builtin.cpu.arch) {
        .aarch64, .aarch64_be => {},
        else => return null,
    }
    var cpu_family: std.c.CPUFAMILY = undefined;
    var len: usize = @sizeOf(std.c.CPUFAMILY);
    std.posix.sysctlbynameZ("hw.cpufamily", &cpu_family, &len, null, 0) catch unreachable;

    // Detects M4 as M3 to get around missing C flag translations when passing the target to dependencies.
    // https://github.com/Homebrew/brew/blob/64edbe6b7905c47b113c1af9cb1a2009ed57a5c7/Library/Homebrew/extend/os/mac/hardware/cpu.rb#L106
    const model: *const std.Target.Cpu.Model = switch (@intFromEnum(cpu_family)) {
        else => return null,
        0x2876f5b5 => &std.Target.aarch64.cpu.apple_a17, // ARM_COLL
        0xfa33415e => &std.Target.aarch64.cpu.apple_m3, // ARM_IBIZA
        0x5f4dea93 => &std.Target.aarch64.cpu.apple_m3, // ARM_LOBOS
        0x72015832 => &std.Target.aarch64.cpu.apple_m3, // ARM_PALMA
        0x6f5129ac => &std.Target.aarch64.cpu.apple_m3, // ARM_DONAN (M4)
        0x17d5b93a => &std.Target.aarch64.cpu.apple_m3, // ARM_BRAVA (M4)
    };

    return .{
        .cpu_arch = builtin.cpu.arch,
        .cpu_model = .{ .explicit = model },
    };
}
