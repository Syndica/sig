const std = @import("std");

const Allocator = std.mem.Allocator;
const Build = std.Build;

pub const Config = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    filters: ?[]const []const u8,
    enable_tsan: ?bool,
    blockstore_db: BlockstoreDB,
    run: bool,
    install: bool,
    ssh_host: ?[]const u8,
    ssh_install_dir: []const u8,
    ssh_workdir: []const u8,
    no_network_tests: bool,

    pub fn fromBuild(b: *Build) !Config {
        var self = Config{
            .target = b.standardTargetOptions(.{
                .default_target = defaultTargetDetectM3() orelse .{},
            }),
            .optimize = b.standardOptimizeOption(.{}),
            .filters = b.option([]const []const u8, "filter", "List of filters, used for example" ++
                " to filter unit tests by name. specified as a series like `-Dfilter='filter1' " ++
                "-Dfilter='filter2'`"),
            .enable_tsan = b.option(bool, "enable-tsan", "Enable TSan for the test suite"),
            .blockstore_db = b.option(BlockstoreDB, "blockstore", "Blockstore database backend") orelse
                .rocksdb,
            .run = !(b.option(bool, "no-run",
                \\Don't run any of the executables implied by the specified steps, only install them.
                \\Use in conjunction with 'no-bin' to avoid installation as well.
            ) orelse false),
            .install = !(b.option(bool, "no-bin",
                \\Don't install any of the binaries implied by the specified steps, only run them.
                \\Use in conjunction with 'no-run' to avoid running as well.
            ) orelse false),
            .ssh_host = b.option([]const u8, "ssh-host", "Builds will target this remote host," ++
                " binaries will be installed there, and executables will run there."),
            .ssh_install_dir = b.option([]const u8, "ssh-installdir", "When using ssh-host, this" ++
                " configures the directory to install binaries (relative to ssh-workdir)" ++
                " (default: zig-out/bin).") orelse "zig-out/bin/",
            .ssh_workdir = b.option([]const u8, "ssh-workdir", "When using ssh-host, this " ++
                "configures the working directory where executables will run (default: sig).") orelse
                "sig",
            .no_network_tests = b.option(bool, "no-network-tests", "Do not run any tests that " ++
                "depend on the network.") orelse false,
        };

        if (self.ssh_host) |host| {
            self.target = try ssh.getHostTarget(b, host);
        }

        return self;
    }
};

pub fn build(b: *Build) !void {
    defer makeZlsNotInstallAnythingDuringBuildOnSave(b);

    // CLI options
    const config = try Config.fromBuild(b);

    // Build options
    const build_options = b.addOptions();
    build_options.addOption(BlockstoreDB, "blockstore_db", config.blockstore_db);
    build_options.addOption(bool, "no_network_tests", config.no_network_tests);

    // CLI build steps
    const install_step = b.getInstallStep();
    const sig_step = b.step("sig", "Run the sig executable");
    const test_step = b.step("test", "Run library tests");
    const fuzz_step = b.step("fuzz", "Gossip fuzz testing");
    const benchmark_step = b.step("benchmark", "Benchmark client");
    const geyser_reader_step = b.step("geyser_reader", "Read data from geyser");
    const vm_step = b.step("vm", "Run the VM client");
    const docs_step = b.step("docs", "Generate and install documentation for the Sig Library");

    // Dependencies
    const dep_opts = .{ .target = config.target, .optimize = config.optimize };

    const base58_dep = b.dependency("base58", dep_opts);
    const base58_mod = base58_dep.module("base58");

    const zig_network_dep = b.dependency("zig-network", dep_opts);
    const zig_network_mod = zig_network_dep.module("network");

    const httpz_dep = b.dependency("httpz", dep_opts);
    const httpz_mod = httpz_dep.module("httpz");

    const zstd_dep = b.dependency("zstd", dep_opts);
    const zstd_mod = zstd_dep.module("zstd");

    const poseidon_dep = b.dependency("poseidon", dep_opts);
    const poseidon_mod = poseidon_dep.module("poseidon");

    const rocksdb_dep = b.dependency("rocksdb", dep_opts);
    const rocksdb_mod = rocksdb_dep.module("rocksdb-bindings");

    const secp256k1_dep = b.dependency("secp256k1", dep_opts);
    const secp256k1_mod = secp256k1_dep.module("secp256k1");

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
    sig_mod.addImport("secp256k1", secp256k1_mod);
    sig_mod.addImport("httpz", httpz_mod);
    sig_mod.addImport("zstd", zstd_mod);

    sig_mod.addImport("poseidon", poseidon_mod);

    switch (config.blockstore_db) {
        .rocksdb => sig_mod.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = config.target,
        .optimize = config.optimize,
    });

    // main executable
    const sig_exe = b.addExecutable(.{
        .name = "sig",
        .root_source_file = b.path("src/cmd.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
    });
    sig_step.dependOn(&sig_exe.step);
    install_step.dependOn(&sig_exe.step);

    // make sure pyroscope's got enough info to profile
    sig_exe.build_id = .fast;
    sig_exe.root_module.omit_frame_pointer = false;
    sig_exe.root_module.strip = false;

    sig_exe.linkLibC();
    sig_exe.root_module.addOptions("build-options", build_options);

    sig_exe.root_module.addImport("cli", cli_mod);
    sig_exe.root_module.addImport("xev", xev_mod);
    sig_exe.root_module.addImport("base58", base58_mod);
    sig_exe.root_module.addImport("httpz", httpz_mod);
    sig_exe.root_module.addImport("zig-network", zig_network_mod);
    sig_exe.root_module.addImport("zstd", zstd_mod);
    sig_exe.root_module.addImport("lsquic", lsquic_mod);
    sig_exe.root_module.addImport("secp256k1", secp256k1_mod);
    sig_exe.root_module.addImport("ssl", ssl_mod);
    sig_exe.root_module.addImport("xev", xev_mod);
    switch (config.blockstore_db) {
        .rocksdb => sig_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    try addInstallAndRun(b, sig_step, sig_exe, config);

    // unit tests
    const unit_tests_exe = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
        .filters = config.filters orelse &.{},
    });
    b.installArtifact(unit_tests_exe);
    test_step.dependOn(&unit_tests_exe.step);
    install_step.dependOn(&unit_tests_exe.step);

    unit_tests_exe.linkLibC();
    unit_tests_exe.root_module.addOptions("build-options", build_options);

    unit_tests_exe.root_module.addImport("xev", xev_mod);
    unit_tests_exe.root_module.addImport("base58", base58_mod);
    unit_tests_exe.root_module.addImport("httpz", httpz_mod);
    unit_tests_exe.root_module.addImport("zig-network", zig_network_mod);
    unit_tests_exe.root_module.addImport("zstd", zstd_mod);
    unit_tests_exe.root_module.addImport("poseidon", poseidon_mod);
    unit_tests_exe.root_module.addImport("secp256k1", secp256k1_mod);

    switch (config.blockstore_db) {
        .rocksdb => unit_tests_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    try addInstallAndRun(b, test_step, unit_tests_exe, config);

    // fuzz test
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_source_file = b.path("src/fuzz.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
    });
    fuzz_step.dependOn(&fuzz_exe.step);
    install_step.dependOn(&fuzz_exe.step);

    fuzz_exe.linkLibC();
    fuzz_exe.root_module.addOptions("build-options", build_options);

    fuzz_exe.root_module.addImport("xev", xev_mod);
    fuzz_exe.root_module.addImport("base58", base58_mod);
    fuzz_exe.root_module.addImport("secp256k1", secp256k1_mod);
    fuzz_exe.root_module.addImport("zig-network", zig_network_mod);
    fuzz_exe.root_module.addImport("httpz", httpz_mod);
    fuzz_exe.root_module.addImport("zstd", zstd_mod);
    switch (config.blockstore_db) {
        .rocksdb => fuzz_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    try addInstallAndRun(b, fuzz_step, fuzz_exe, config);

    // benchmarks
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("src/benchmarks.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
    });
    benchmark_step.dependOn(&benchmark_exe.step);
    install_step.dependOn(&benchmark_exe.step);

    benchmark_exe.linkLibC();
    benchmark_exe.root_module.addOptions("build-options", build_options);

    // make sure pyroscope's got enough info to profile
    benchmark_exe.build_id = .fast;
    benchmark_exe.root_module.omit_frame_pointer = false;
    benchmark_exe.root_module.strip = false;

    b.installArtifact(benchmark_exe);

    benchmark_exe.root_module.addImport("secp256k1", secp256k1_mod);
    benchmark_exe.root_module.addImport("base58", base58_mod);
    benchmark_exe.root_module.addImport("zig-network", zig_network_mod);
    benchmark_exe.root_module.addImport("httpz", httpz_mod);
    benchmark_exe.root_module.addImport("zstd", zstd_mod);
    benchmark_exe.root_module.addImport("prettytable", pretty_table_mod);
    switch (config.blockstore_db) {
        .rocksdb => benchmark_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    try addInstallAndRun(b, benchmark_step, benchmark_exe, config);

    // geyser reader
    const geyser_reader_exe = b.addExecutable(.{
        .name = "geyser",
        .root_source_file = b.path("src/geyser/main.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
    });
    geyser_reader_step.dependOn(&geyser_reader_exe.step);
    install_step.dependOn(&geyser_reader_exe.step);

    geyser_reader_exe.root_module.addImport("sig", sig_mod);
    geyser_reader_exe.root_module.addImport("cli", cli_mod);
    try addInstallAndRun(b, geyser_reader_step, geyser_reader_exe, config);

    const vm_exe = b.addExecutable(.{
        .name = "vm",
        .root_source_file = b.path("src/vm/main.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .sanitize_thread = config.enable_tsan,
    });
    vm_step.dependOn(&vm_exe.step);
    install_step.dependOn(&vm_exe.step);

    vm_exe.root_module.addImport("sig", sig_mod);
    vm_exe.root_module.addImport("cli", cli_mod);
    try addInstallAndRun(b, vm_step, vm_exe, config);

    // docs for the Sig library
    const install_sig_docs = b.addInstallDirectory(.{
        .source_dir = sig_exe.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_sig_docs.step);
}

/// the standard approach for installing and running the executables produced in
/// this build script.
fn addInstallAndRun(
    b: *Build,
    step: *Build.Step,
    exe: *Build.Step.Compile,
    config: Config,
) !void {
    var send_step: ?*Build.Step = null;

    if (config.install or (config.ssh_host != null and config.run)) {
        const install = b.addInstallArtifact(exe, .{});
        step.dependOn(&install.step);
        b.getInstallStep().dependOn(&install.step);

        if (config.ssh_host) |host| {
            const install_dir = if (config.ssh_install_dir[0] == '/')
                try b.allocator.dupe(u8, config.ssh_install_dir)
            else
                b.fmt("{s}/{s}", .{ config.ssh_workdir, config.ssh_install_dir });
            defer b.allocator.free(install_dir);

            const send = try ssh.addSendArtifact(b, install, host, install_dir);
            send.step.dependOn(&install.step);
            step.dependOn(&send.step);
            send_step = &send.step;
        }
    }

    if (config.run) {
        if (config.ssh_host) |host| {
            const exe_path = b.fmt("{s}/{s}", .{ config.ssh_install_dir, exe.name });
            defer b.allocator.free(exe_path);

            const run = try ssh.addRemoteCommand(b, host, config.ssh_workdir, exe_path);
            run.step.dependOn(send_step.?);
            step.dependOn(&run.step);
        } else {
            const run = b.addRunArtifact(exe);
            run.addArgs(b.args orelse &.{});
            step.dependOn(&run.step);
        }
    }
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

const ssh = struct {
    /// SSH into the host and call `zig targets` to determine the compilation
    /// target for that machine.
    ///
    /// This means the build script needs to spawn another process to run a
    /// system installed SSH binary. This is a temporary hack to get a remote
    /// target. This will stop working if build.zig is sandboxed.
    /// > See more: https://github.com/ziglang/zig/issues/14286
    ///
    /// Do not depend on this function for any critical build processes. This
    /// should only be used for optional ease-of-use features that are disabled
    /// by default.
    fn getHostTarget(b: *Build, remote_host: []const u8) !Build.ResolvedTarget {
        const run_result = try std.process.Child.run(.{
            .allocator = b.allocator,
            .argv = &.{ "ssh", remote_host, "bash", "--login", "-c", "'zig targets'" },
            .max_output_bytes = 2 << 20,
        });

        if (run_result.term != .Exited or run_result.term.Exited != 0) {
            std.debug.print(
                \\command completed unexpectedly with: {any}
                \\stdout: {s}
                \\stderr: {s}
            , .{ run_result.term, run_result.stdout, run_result.stderr });
            return error.CommandFailed;
        }

        const Targets = struct {
            native: struct {
                triple: []const u8,
                cpu: struct { name: []const u8 },
            },
        };

        const targets = try std.json.parseFromSlice(
            Targets,
            b.allocator,
            run_result.stdout,
            .{ .ignore_unknown_fields = true },
        );
        defer targets.deinit();

        const query = try Build.parseTargetQuery(.{
            .arch_os_abi = targets.value.native.triple,
            .cpu_features = targets.value.native.cpu.name,
        });

        return b.resolveTargetQuery(query);
    }

    /// add a build step to send the artifact to the remote host using send-file.zig
    fn addSendArtifact(
        b: *Build,
        install: *Build.Step.InstallArtifact,
        host: []const u8,
        remote_dir: []const u8,
    ) !*Build.Step.Run {
        const local_path = b.getInstallPath(install.dest_dir.?, install.dest_sub_path);
        const remote_path = b.fmt("{s}/{s}", .{ remote_dir, install.dest_sub_path });

        const exe = b.addExecutable(.{
            .name = "send-file",
            .root_source_file = b.path("scripts/send-file.zig"),
            .target = b.host,
            .link_libc = true,
        });

        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ local_path, host, remote_path });

        return run;
    }

    /// add a build step to run a command on a remote host using ssh.
    fn addRemoteCommand(
        b: *Build,
        host: []const u8,
        workdir: []const u8,
        executable_path: []const u8,
    ) !*Build.Step.Run {
        const cd_exe = b.fmt("cd {s}; {s}", .{ workdir, executable_path });
        defer b.allocator.free(cd_exe);

        const cmd_size = 4;
        const ssh_cd_exe = &[cmd_size][]const u8{ "ssh", "-t", host, cd_exe };

        const full_command = if (b.args) |args| cmd: {
            const cmd = try b.allocator.alloc([]const u8, cmd_size + args.len);
            @memcpy(cmd[0..cmd_size], ssh_cd_exe[0..cmd_size]);
            @memcpy(cmd[cmd_size..], args);
            break :cmd cmd;
        } else ssh_cd_exe;
        defer b.allocator.free(full_command);

        return b.addSystemCommand(full_command);
    }
};
