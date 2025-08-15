const std = @import("std");
const Build = std.Build;

pub const Config = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    filters: ?[]const []const u8,
    enable_tsan: bool,
    ledger_db: LedgerDB,
    run: bool,
    install: bool,
    ssh_host: ?[]const u8,
    ssh_install_dir: []const u8,
    ssh_workdir: []const u8,
    no_network_tests: bool,
    has_side_effects: bool,
    enable_tracy: bool,
    use_llvm: bool,
    force_pic: bool,
    error_tracing: ?bool,

    pub fn fromBuild(b: *Build) Config {
        var self: Config = .{
            .target = b.standardTargetOptions(.{}),
            .optimize = b.standardOptimizeOption(.{}),
            .filters = b.option(
                []const []const u8,
                "filter",
                "List of filters, used for example to filter unit tests by name. " ++
                    "Specified as a series like `-Dfilter='filter1' -Dfilter='filter2'`.",
            ),
            .enable_tsan = b.option(
                bool,
                "enable-tsan",
                "Enable TSan for the test suite",
            ) orelse false,
            .ledger_db = b.option(
                LedgerDB,
                "ledger",
                "Ledger database backend",
            ) orelse .rocksdb,
            .run = !(b.option(
                bool,
                "no-run",
                "Don't run any of the executables implied by the specified steps, only install " ++
                    "them. Use in conjunction with 'no-bin' to avoid installation as well.",
            ) orelse false),
            .install = !(b.option(
                bool,
                "no-bin",
                "Don't install any of the binaries implied by the specified steps, only run " ++
                    "them. Use in conjunction with 'no-run' to avoid running as well.",
            ) orelse false),
            .ssh_host = b.option(
                []const u8,
                "ssh-host",
                "Builds will target this remote host," ++
                    " binaries will be installed there, and executables will run there.",
            ),
            .ssh_install_dir = b.option(
                []const u8,
                "ssh-installdir",
                "When using ssh-host, this" ++
                    " configures the directory to install binaries (relative to ssh-workdir)" ++
                    " (default: zig-out/bin).",
            ) orelse "zig-out/bin/",
            .ssh_workdir = b.option(
                []const u8,
                "ssh-workdir",
                "When using ssh-host, this configures the working " ++
                    "directory where executables will run (default: sig).",
            ) orelse "sig",
            .no_network_tests = b.option(
                bool,
                "no-network-tests",
                "Do not run any tests that depend on the network.",
            ) orelse false,
            .has_side_effects = b.option(
                bool,
                "side-effects",
                "Disables caching of the run step",
            ) orelse false,
            .enable_tracy = b.option(
                bool,
                "enable-tracy",
                "Enables tracy",
            ) orelse false,
            .use_llvm = b.option(
                bool,
                "use-llvm",
                "If disabled, uses experimental self-hosted backend. Only works for x86_64-linux",
            ) orelse true,
            .force_pic = b.option(
                bool,
                "force_pic",
                "Builds linked dependencies with PIC enabled. If false, builds default PIC mode.",
            ) orelse false,
            .error_tracing = b.option(
                bool,
                "error-tracing",
                "Enable or disable error tracing. Default: Only for Debug builds.",
            ),
        };

        if (self.ssh_host) |host| {
            self.target = ssh.getHostTarget(b, host) catch |e| std.debug.panic("{}", .{e});
        }

        return self;
    }
};

pub fn build(b: *Build) void {
    defer makeZlsNotInstallAnythingDuringBuildOnSave(b);

    const config = Config.fromBuild(b);

    const build_options = b.addOptions();
    build_options.addOption(LedgerDB, "ledger_db", config.ledger_db);
    build_options.addOption(bool, "no_network_tests", config.no_network_tests);

    const sig_step = b.step("sig", "Run the sig executable");
    const test_step = b.step("test", "Run library tests");
    const fuzz_step = b.step("fuzz", "Gossip fuzz testing");
    const benchmark_step = b.step("benchmark", "Benchmark client");
    const geyser_reader_step = b.step("geyser_reader", "Read data from geyser");
    const vm_step = b.step("vm", "Run the VM client");
    const docs_step = b.step("docs", "Generate and install documentation for the Sig Library");

    // Dependencies
    const dep_opts = .{
        .target = config.target,
        .optimize = config.optimize,
    };

    const base58_mod = b.dependency("base58", dep_opts).module("base58");
    const zig_network_mod = b.dependency("zig-network", dep_opts).module("network");
    const httpz_mod = b.dependency("httpz", dep_opts).module("httpz");
    const poseidon_mod = b.dependency("poseidon", dep_opts).module("poseidon");
    const xev_mod = b.dependency("xev", dep_opts).module("xev");
    const pretty_table_mod = b.dependency("prettytable", dep_opts).module("prettytable");

    const lsquic_dep = b.dependency("lsquic", .{
        .target = config.target,
        .optimize = config.optimize,
        // TSan needs a PIE executable, so we need to build the deps with PIC.
        .force_pic = config.force_pic or config.enable_tsan,
    });
    const lsquic_mod = lsquic_dep.module("lsquic");

    const zstd_mod = b.dependency("zstd", .{
        .target = config.target,
        .optimize = config.optimize,
        .force_pic = config.force_pic or config.enable_tsan,
    }).module("zstd");

    const ssl_mod = lsquic_dep.builder.dependency("boringssl", .{
        .target = config.target,
        .optimize = config.optimize,
        .force_pic = config.force_pic or config.enable_tsan,
    }).module("ssl");

    const rocksdb_dep = b.dependency("rocksdb", .{
        .target = config.target,
        .optimize = config.optimize,
        .force_pic = config.force_pic or config.enable_tsan,
    });
    const rocksdb_mod = rocksdb_dep.module("bindings");
    // TODO: UB might be fixed by future RocksDB version upgrade.
    // reproducable via: zig build test -Dfilter="ledger"
    rocksdb_dep.artifact("rocksdb").root_module.sanitize_c = false;

    // the sig-fuzz target needs to be built as a shared library, which requires
    // the linked dependencies of sig to have been built with PIC.
    const secp256k1_mod = b.dependency("secp256k1", .{
        .target = config.target,
        .optimize = config.optimize,
        .force_pic = config.force_pic or config.enable_tsan,
    }).module("secp256k1");

    const tracy_mod = b.dependency("tracy", .{
        .target = config.target,
        .optimize = config.optimize,
        .tracy_enable = config.enable_tracy,
        .tracy_no_system_tracing = false,
        .tracy_callstack = 6,
    }).module("tracy");
    tracy_mod.sanitize_c = false; // Workaround UB in Tracy.

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = config.target,
        .optimize = config.optimize,
    });

    // G/H table for Bulletproofs
    const gh_table = b.createModule(.{
        .root_source_file = generateTable(b),
    });

    // zig fmt: off
    const imports: []const Build.Module.Import = &.{
        .{ .name = "base58",        .module = base58_mod },
        .{ .name = "build-options", .module = build_options.createModule() },
        .{ .name = "httpz",         .module = httpz_mod },
        .{ .name = "lsquic",        .module = lsquic_mod },
        .{ .name = "poseidon",      .module = poseidon_mod },
        .{ .name = "prettytable",   .module = pretty_table_mod },
        .{ .name = "secp256k1",     .module = secp256k1_mod },
        .{ .name = "ssl",           .module = ssl_mod },
        .{ .name = "tracy",         .module = tracy_mod },
        .{ .name = "xev",           .module = xev_mod },
        .{ .name = "zig-network",   .module = zig_network_mod },
        .{ .name = "zstd",          .module = zstd_mod },
        .{ .name = "table",         .module = gh_table },
    };
    // zig fmt: on

    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/sig.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .imports = imports,
    });

    switch (config.ledger_db) {
        .rocksdb => sig_mod.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }

    const sig_exe = b.addExecutable(.{
        .name = "sig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cmd.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports,
            // .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
            .stack_protector = true,
            .stack_check = true,
            .omit_frame_pointer = false,
            .error_tracing = true,
        }),
        .use_llvm = config.use_llvm,
    });
    sig_exe.root_module.addImport("cli", cli_mod);

    // make sure pyroscope's got enough info to profile
    sig_exe.build_id = .fast;

    switch (config.ledger_db) {
        .rocksdb => sig_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    addInstallAndRun(b, sig_step, sig_exe, config);

    const unit_tests_exe = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tests.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
        }),
        .filters = config.filters orelse &.{},
        .use_llvm = config.use_llvm,
    });
    switch (config.ledger_db) {
        .rocksdb => unit_tests_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    addInstallAndRun(b, test_step, unit_tests_exe, config);

    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
        }),
    });
    switch (config.ledger_db) {
        .rocksdb => fuzz_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    addInstallAndRun(b, fuzz_step, fuzz_exe, config);

    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/benchmarks.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
        }),
    });
    // make sure pyroscope's got enough info to profile
    benchmark_exe.build_id = .fast;

    switch (config.ledger_db) {
        .rocksdb => benchmark_exe.root_module.addImport("rocksdb", rocksdb_mod),
        .hashmap => {},
    }
    addInstallAndRun(b, benchmark_step, benchmark_exe, config);

    const geyser_reader_exe = b.addExecutable(.{
        .name = "geyser",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/geyser/main.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
        }),
    });
    geyser_reader_exe.root_module.addImport("sig", sig_mod);
    geyser_reader_exe.root_module.addImport("cli", cli_mod);
    addInstallAndRun(b, geyser_reader_step, geyser_reader_exe, config);

    const vm_exe = b.addExecutable(.{
        .name = "vm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm/main.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .sanitize_thread = config.enable_tsan,
            .error_tracing = config.error_tracing,
        }),
    });
    vm_exe.root_module.addImport("sig", sig_mod);
    vm_exe.root_module.addImport("cli", cli_mod);
    addInstallAndRun(b, vm_step, vm_exe, config);

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
) void {
    const install_step = b.getInstallStep();
    var send_step: ?*Build.Step = null;

    step.dependOn(&exe.step);
    install_step.dependOn(&exe.step);

    if (config.install or (config.ssh_host != null and config.run)) {
        const install = b.addInstallArtifact(exe, .{});
        step.dependOn(&install.step);
        install_step.dependOn(&install.step);

        if (config.ssh_host) |host| {
            const install_dir = if (config.ssh_install_dir[0] == '/')
                b.dupe(config.ssh_install_dir)
            else
                b.fmt("{s}/{s}", .{ config.ssh_workdir, config.ssh_install_dir });
            const send = ssh.addSendArtifact(b, install, host, install_dir);
            send.step.dependOn(&install.step);
            step.dependOn(&send.step);
            send_step = &send.step;
        }
    }

    if (config.run) {
        if (config.ssh_host) |host| {
            const exe_path = b.fmt("{s}/{s}", .{ config.ssh_install_dir, exe.name });
            const run = ssh.addRemoteCommand(b, host, config.ssh_workdir, exe_path);
            run.step.dependOn(send_step.?);
            step.dependOn(&run.step);
        } else {
            const run = b.addRunArtifact(exe);
            run.addArgs(b.args orelse &.{});
            run.has_side_effects = config.has_side_effects;
            step.dependOn(&run.step);
        }
    }
}

fn generateTable(b: *Build) Build.LazyPath {
    const gen = b.addExecutable(.{
        .name = "generator_chain",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            // Overall it takes less time to compile in debug mode than the perf gain from a release mode at runtime
            .optimize = .Debug,
            .root_source_file = b.path("scripts/generator_chain.zig"),
        }),
    });
    return b.addRunArtifact(gen).captureStdOut();
}

const LedgerDB = enum {
    rocksdb,
    hashmap,
};

/// Reference/inspiration: https://kristoff.it/blog/improving-your-zls-experience/
fn makeZlsNotInstallAnythingDuringBuildOnSave(b: *Build) void {
    const zls_is_build_runner = b.option(
        bool,
        "zls-is-build-runner",
        "Option passed by zls to indicate that it's the one running this build script " ++
            "(configured in the local zls.build.json). This should not be specified on the " ++
            "command line nor as a dependency argument.",
    ) orelse false;
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

        const stdoutz = try b.allocator.dupeZ(u8, run_result.stdout);
        defer b.allocator.free(stdoutz);
        const targets = try std.zon.parse.fromSlice(
            Targets,
            b.allocator,
            stdoutz,
            null,
            .{ .ignore_unknown_fields = true },
        );
        defer b.allocator.free(targets.native.triple);
        defer b.allocator.free(targets.native.cpu.name);

        const query = try Build.parseTargetQuery(.{
            .arch_os_abi = targets.native.triple,
            .cpu_features = targets.native.cpu.name,
        });

        return b.resolveTargetQuery(query);
    }

    /// add a build step to send the artifact to the remote host using send-file.zig
    fn addSendArtifact(
        b: *Build,
        install: *Build.Step.InstallArtifact,
        host: []const u8,
        remote_dir: []const u8,
    ) *Build.Step.Run {
        const local_path = b.getInstallPath(install.dest_dir.?, install.dest_sub_path);
        const remote_path = b.pathJoin(&.{ remote_dir, install.dest_sub_path });
        const exe = sendFileExe(b);
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ local_path, host, remote_path });
        return run;
    }

    /// Returns the executable for the `send-file` script, compiled
    /// exactly once regardless of how many times this is called.
    fn sendFileExe(b: *Build) *Build.Step.Compile {
        const static = struct {
            var exe: ?*Build.Step.Compile = null;
        };

        if (static.exe == null) {
            static.exe = b.addExecutable(.{
                .name = "send-file",
                .root_source_file = b.path("scripts/send-file.zig"),
                .target = b.graph.host,
                .link_libc = true,
            });
        }

        return static.exe.?;
    }

    /// add a build step to run a command on a remote host using ssh.
    fn addRemoteCommand(
        b: *Build,
        host: []const u8,
        workdir: []const u8,
        executable_path: []const u8,
    ) *Build.Step.Run {
        var ssh_cd_exe: std.ArrayListUnmanaged([]const u8) = .empty;

        ssh_cd_exe.appendSlice(
            b.graph.arena,
            &.{ "ssh", "-t", host, b.fmt("cd {s}; {s}", .{ workdir, executable_path }) },
        ) catch |e| std.debug.panic("{}", .{e});

        if (b.args) |args| ssh_cd_exe.appendSlice(
            b.graph.arena,
            args,
        ) catch |e| std.debug.panic("{}", .{e});

        return b.addSystemCommand(ssh_cd_exe.items);
    }
};
