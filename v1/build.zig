const std = @import("std");
const Build = std.Build;
const zig_zon = @import("build.zig.zon");

const sig_version = std.SemanticVersion.parse(zig_zon.version) catch unreachable;

const LedgerDB = enum {
    rocksdb,
    hashmap,
};

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
    tracy_on_demand: bool,
    tracy_no_exit: bool,
    use_llvm: bool,
    error_tracing: ?bool,
    long_tests: bool,
    allow_no_sha: bool,
    allow_no_avx512: bool,
    /// Forwarded to the sig_v2 dependency.
    debug_skip_shred_sig_verify: bool,
    debug_skip_shred_version_check: bool,
    version: std.SemanticVersion,

    pub fn fromBuild(b: *Build) !Config {
        const filters = b.option(
            []const []const u8,
            "filter",
            "List of filters, used for example to filter unit tests by name. " ++
                "Specified as a series like `-Dfilter='filter1' -Dfilter='filter2'`.",
        );

        const zls_is_build_runner = b.option(
            bool,
            "zls-is-build-runner",
            "Option passed by zls to indicate that it's the one running this build script " ++
                "(configured in the local zls.build.json). This should not be specified on the " ++
                "command line nor as a dependency argument.",
        ) orelse false;

        const optimize = b.standardOptimizeOption(.{});

        var self: Config = .{
            .target = b.standardTargetOptions(.{}),
            .optimize = optimize,
            .filters = filters,
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
            ) orelse false or zls_is_build_runner),
            .install = !(b.option(
                bool,
                "no-bin",
                "Don't install any of the binaries implied by the specified steps, only run " ++
                    "them. Use in conjunction with 'no-run' to avoid running as well.",
            ) orelse false or zls_is_build_runner),
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
            .tracy_on_demand = b.option(
                bool,
                "tracy-on-demand",
                "Enables tracy on-demand mode (allows reconnecting). Only has an effect if tracy is enabled via enable-tracy.",
            ) orelse false,
            .tracy_no_exit = b.option(
                bool,
                "tracy-no-exit",
                "Delays process exit until Tracy has received data. Only has an effect if tracy is enabled via enable-tracy.",
            ) orelse false,
            .use_llvm = b.option(
                bool,
                "use-llvm",
                "If disabled, uses experimental self-hosted backend. Only works for x86_64-linux",
            ) orelse true,
            .error_tracing = b.option(
                bool,
                "error-tracing",
                "Enable or disable error tracing. Default: Only for Debug builds.",
            ),
            .long_tests = b.option(
                bool,
                "long-tests",
                "Run extra tests that take a long time, for more exhaustive coverage.",
            ) orelse (filters != null),
            .allow_no_sha = b.option(
                bool,
                "allow-no-sha",
                "Opt in to a slower software fallback when the target lacks the x86 SHA " ++
                    "extension. Without this flag, building for a target without SHA-NI is a " ++
                    "compile-time error so the performance hit is not silently accepted.",
            ) orelse (optimize == .Debug),
            .allow_no_avx512 = b.option(
                bool,
                "allow-no-avx512",
                "Opt in to a slower generic ed25519 path when the target lacks AVX-512 " ++
                    "(avx512ifma + avx512vl). Without this flag, building for an x86_64 target " ++
                    "without these features is a compile-time error so the performance hit is " ++
                    "not silently accepted.",
            ) orelse (optimize == .Debug),
            .debug_skip_shred_sig_verify = b.option(
                bool,
                "debug-skip-shred-sig-verify",
                "Forwarded to sig_v2. See sig_v2's build.zig for details.",
            ) orelse false,
            .debug_skip_shred_version_check = b.option(
                bool,
                "debug-skip-shred-version-check",
                "Forwarded to sig_v2. See sig_v2's build.zig for details.",
            ) orelse false,
            .version = s: {
                const maybe_version_string = b.option(
                    []const u8,
                    "version-string",
                    "Override Sig's version string. The default is to find out through git.",
                );
                const version_slice = if (maybe_version_string) |version| version else v: {
                    const version_string = b.fmt("{f}", .{sig_version});

                    var code: u8 = undefined;
                    const git_describe_untrimmed = b.runAllowFail(&.{
                        "git",
                        "-C", b.build_root.path orelse ".", // affects the --git-dir argument
                        "--git-dir", ".git", // affected by the -C argument
                        "describe", "--match", "*.*.*", //
                        "--tags", "--abbrev=8", //  get the first 8 characters, or 4 bytes for the client version
                    }, &code, .Ignore) catch break :v version_string;
                    const git_describe = std.mem.trim(u8, git_describe_untrimmed, " \n\r");

                    switch (std.mem.count(u8, git_describe, &.{'-'})) {
                        0 => {
                            // This is a tagged release version (e.g. 0.2.0)
                            if (!std.mem.eql(u8, git_describe, version_string)) {
                                // Something must be very wrong.
                                std.debug.print("Sig's version '{s}' does not match Git tag '{s}'\n", .{ version_string, git_describe });
                                std.process.exit(1);
                            }
                            break :v version_string;
                        },
                        2 => {
                            // Untagged development build (e.g. 0.2.0-dev.1832+g5ef9eaf0b).
                            var it = std.mem.splitScalar(u8, git_describe, '-');
                            const tagged_ancestor = it.first();
                            const commit_height = it.next().?;
                            const commit_id = it.next().?;

                            // Check that the version of Sig we're compiling is after the latest tag. Something
                            // must have gone wrong for this not to be the case.
                            // We follow SemVerTag, so our tagged releases are versioned with vX.Y.Z, so we cut
                            // off the first character when parsing the SemVer.
                            const ancestor_ver = try std.SemanticVersion.parse(tagged_ancestor[1..]);
                            if (sig_version.order(ancestor_ver) != .gt) {
                                std.debug.print(
                                    "'{f}' must be greater than tagged ancestor '{f}'\n",
                                    .{ sig_version, ancestor_ver },
                                );
                                std.process.exit(1);
                            }

                            // Check that the commit hash is prefixed with a 'g' (a Git convention).
                            // e.g v0.1.0-1832-g5ef9eaf0b
                            if (commit_id.len < 1 or commit_id[0] != 'g') {
                                std.debug.print("Unexpected `git describe` output: {s}\n", .{git_describe});
                                break :v version_string;
                            }

                            // The version is reformatted in accordance with the https://semver.org specification.
                            break :v b.fmt("{s}-dev.{s}+{s}", .{ version_string, commit_height, commit_id[1..] });
                        },
                        else => {
                            std.debug.print("Unexpected `git describe` output: {s}\n", .{git_describe});
                            break :v version_string;
                        },
                    }
                };

                break :s try std.SemanticVersion.parse(version_slice);
            },
        };

        if (self.ssh_host) |host| {
            // Only use SSH to detect remote target if -Dtarget was not explicitly specified
            if (!b.user_input_options.contains("target")) {
                self.target = ssh.getHostTarget(b, host) catch |e| std.debug.panic("{}", .{e});
            }
        }

        return self;
    }
};

pub fn build(b: *Build) !void {
    const config = try Config.fromBuild(b);
    defer if (!config.install and !config.run) disableEmitBin(b);

    const build_options = b.addOptions();
    build_options.addOption(LedgerDB, "ledger_db", config.ledger_db);
    build_options.addOption(bool, "no_network_tests", config.no_network_tests);
    build_options.addOption(bool, "long_tests", config.long_tests);
    build_options.addOption(bool, "allow_no_sha", config.allow_no_sha);
    build_options.addOption(bool, "allow_no_avx512", config.allow_no_avx512);
    build_options.addOption(std.SemanticVersion, "version", config.version);

    const sig_step = b.step("sig", "Run the sig executable");
    const test_step = b.step("test", "Run library tests");
    const fuzz_step = b.step("fuzz", "Gossip fuzz testing");
    const benchmark_step = b.step("benchmark", "Benchmark client");
    const geyser_reader_step = b.step("geyser_reader", "Read data from geyser");
    const vm_step = b.step("vm", "Run the VM client");
    const test_send_transactions_step = b.step("test_send_transactions", "Attempt to land transactions on testnet using QUIC client");
    const test_mock_transfers_step = b.step("test_mock_transfers", "Test MockTransferService in RPC submission mode");
    const docs_step = b.step("docs", "Generate and install documentation for the Sig Library");

    // Dependencies
    const dep_opts = .{
        .target = config.target,
        .optimize = config.optimize,
    };

    const base58_mod = b.dependency("base58", dep_opts).module("base58");
    const httpz_mod = b.dependency("httpz", dep_opts).module("httpz");
    const xev_mod = b.dependency("xev", dep_opts).module("xev");
    const pretty_table_mod = b.dependency("prettytable", dep_opts).module("prettytable");
    const webzockets_mod = b.dependency("webzockets", dep_opts).module("webzockets");

    const lsquic_dep = b.dependency("lsquic", .{
        .target = config.target,
        .optimize = config.optimize,
    });
    const lsquic_mod = lsquic_dep.module("lsquic");

    const zstd_mod = b.dependency("zstd", .{
        .target = config.target,
        .optimize = config.optimize,
    }).module("zstd");

    const ssl_mod = lsquic_dep.builder.dependency("boringssl", .{
        .target = config.target,
        .optimize = config.optimize,
    }).module("ssl");

    const rocksdb_dep = b.dependency("rocksdb", .{
        .target = config.target,
        .optimize = config.optimize,
        // ledgers from other clients sometimes use Snappy compression
        .enable_snappy = true,
    });
    const rocksdb_mod = rocksdb_dep.module("bindings");
    // TODO: UB might be fixed by future RocksDB version upgrade.
    // reproducable via: zig build test -Dfilter="ledger"
    rocksdb_dep.artifact("rocksdb").root_module.sanitize_c = .off;

    // Options must match the `b.dependency("tracy", ...)` calls in
    // shared/build.zig and v2/build.zig exactly. Any drift produces two
    // `tracy` Module instances rooted at the same source file, which Zig 0.15
    // rejects when both sig and sig_v2 live in one compilation.
    const tracy_mod = b.dependency("tracy", .{
        .target = config.target,
        .optimize = config.optimize,
        .tracy_enable = config.enable_tracy,
        .tracy_on_demand = config.tracy_on_demand,
        .tracy_no_exit = config.tracy_no_exit,
        .tracy_no_system_tracing = false,
        .tracy_callstack = 6,
    }).module("tracy");
    tracy_mod.sanitize_c = .off; // Workaround UB in Tracy.

    const shared_dep = b.dependency("sig_v2", .{
        .target = config.target,
        .optimize = config.optimize,
        .@"long-tests" = config.long_tests,
        .@"allow-no-sha" = config.allow_no_sha,
        .@"allow-no-avx512" = config.allow_no_avx512,
        .@"use-llvm" = config.use_llvm,
        .@"enable-tracy" = config.enable_tracy,
        .@"tracy-on-demand" = config.tracy_on_demand,
        .@"tracy-no-exit" = config.tracy_no_exit,
        // Forwarded so downstream builds (in particular conformance/) can
        // match the options they pass to sig_v2 directly. See the option
        // definitions in Config for the full rationale.
        .@"debug-skip-shred-sig-verify" = config.debug_skip_shred_sig_verify,
        .@"debug-skip-shred-version-check" = config.debug_skip_shred_version_check,
    });
    const std14_mod = shared_dep.module("std14");

    const cli_mod = b.createModule(.{
        .root_source_file = b.path("src/cli.zig"),
        .target = config.target,
        .optimize = config.optimize,
    });
    cli_mod.addImport("std14", std14_mod);

    // Non-circulating supply pubkeys (pre-decoded at build time)
    const non_circulating_supply = b.createModule(.{
        .root_source_file = generateNonCirculatingSupply(b, config.use_llvm),
    });

    const sqlite_mod = genSqlite(b, config.target, config.optimize, config.use_llvm);
    const bzip2_mod = genBzip2(b, config.target, config.optimize, config.use_llvm);

    // zig fmt: off
    const imports: []const Build.Module.Import = &.{
        .{ .name = "base58",                 .module = base58_mod },
        .{ .name = "build-options",          .module = build_options.createModule() },
        .{ .name = "non-circulating-supply", .module = non_circulating_supply },
        .{ .name = "bzip2",                  .module = bzip2_mod },
        .{ .name = "httpz",                  .module = httpz_mod },
        .{ .name = "lsquic",                 .module = lsquic_mod },
        .{ .name = "prettytable",            .module = pretty_table_mod },
        .{ .name = "sqlite",                 .module = sqlite_mod },
        .{ .name = "ssl",                    .module = ssl_mod },
        .{ .name = "tracy",                  .module = tracy_mod },
        .{ .name = "webzockets",             .module = webzockets_mod },
        .{ .name = "xev",                    .module = xev_mod },
        .{ .name = "zstd",                   .module = zstd_mod },
    };
    // zig fmt: on

    const shared_mod = shared_dep.module("runtime");

    const imports_with_shared = b.allocator.alloc(
        Build.Module.Import,
        imports.len + 1,
    ) catch |err| std.debug.panic("{}", .{err});
    @memcpy(imports_with_shared[0..imports.len], imports);
    imports_with_shared[imports.len] = .{ .name = "shared", .module = shared_mod };

    const memcpy = b.addObject(.{
        .name = "memcpy",
        .root_module = b.createModule(.{
            .target = config.target,
            .optimize = config.optimize,
            .root_source_file = b.path("src/memcpy.zig"),
            .pic = true,
        }),
        .use_llvm = config.use_llvm,
    });

    const sig_mod = b.addModule("sig", .{
        .root_source_file = b.path("src/sig.zig"),
        .target = config.target,
        .optimize = config.optimize,
        .imports = imports_with_shared,
    });

    sig_mod.addImport("std14", std14_mod);

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
            .imports = imports_with_shared,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
        }),
        .use_llvm = config.use_llvm,
    });
    sig_exe.root_module.addObject(memcpy);
    sig_exe.root_module.addImport("cli", cli_mod);
    sig_exe.root_module.addImport("std14", std14_mod);

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
            .imports = imports_with_shared,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
        }),
        .filters = config.filters orelse &.{},
        .use_llvm = config.use_llvm,
    });
    unit_tests_exe.root_module.addObject(memcpy);
    unit_tests_exe.root_module.addImport("cli", cli_mod);
    unit_tests_exe.root_module.addImport("std14", std14_mod);
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
            .imports = imports_with_shared,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
        }),
        .use_llvm = config.use_llvm,
    });
    fuzz_exe.root_module.addObject(memcpy);
    fuzz_exe.root_module.addImport("cli", cli_mod);
    fuzz_exe.root_module.addImport("std14", std14_mod);
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
            .imports = imports_with_shared,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
            .link_libc = true,
        }),
        .use_llvm = config.use_llvm,
    });
    benchmark_exe.root_module.addObject(memcpy);
    benchmark_exe.root_module.addImport("cli", cli_mod);
    benchmark_exe.root_module.addImport("std14", std14_mod);

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
            .imports = imports_with_shared,
            .error_tracing = config.error_tracing,
            .sanitize_thread = config.enable_tsan,
        }),
        .use_llvm = config.use_llvm,
    });
    geyser_reader_exe.root_module.addObject(memcpy);
    geyser_reader_exe.root_module.addImport("sig", sig_mod);
    geyser_reader_exe.root_module.addImport("cli", cli_mod);
    geyser_reader_exe.root_module.addImport("std14", std14_mod);
    addInstallAndRun(b, geyser_reader_step, geyser_reader_exe, config);

    const vm_exe = b.addExecutable(.{
        .name = "vm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/vm/main.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports_with_shared,
            .sanitize_thread = config.enable_tsan,
            .error_tracing = config.error_tracing,
        }),
        .use_llvm = config.use_llvm,
    });
    vm_exe.root_module.addObject(memcpy);
    vm_exe.root_module.addImport("sig", sig_mod);
    vm_exe.root_module.addImport("cli", cli_mod);
    vm_exe.root_module.addImport("std14", std14_mod);
    addInstallAndRun(b, vm_step, vm_exe, config);

    const test_send_transactions_exe = b.addExecutable(.{
        .name = "test_send_transactions",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transaction_sender/test_send_transactions.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports_with_shared,
            .sanitize_thread = config.enable_tsan,
            .error_tracing = config.error_tracing,
            .link_libc = true,
        }),
        .use_llvm = config.use_llvm,
    });
    test_send_transactions_exe.root_module.addObject(memcpy);
    test_send_transactions_exe.root_module.addImport("sig", sig_mod);
    addInstallAndRun(b, test_send_transactions_step, test_send_transactions_exe, config);

    const test_mock_transfers_exe = b.addExecutable(.{
        .name = "test_mock_transfers",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/transaction_sender/test_mock_transfers.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = imports_with_shared,
            .sanitize_thread = config.enable_tsan,
            .error_tracing = config.error_tracing,
            .link_libc = true,
        }),
        .use_llvm = config.use_llvm,
    });
    test_mock_transfers_exe.root_module.addObject(memcpy);
    test_mock_transfers_exe.root_module.addImport("sig", sig_mod);
    addInstallAndRun(b, test_mock_transfers_step, test_mock_transfers_exe, config);

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
            const send = ssh.addSendArtifact(b, install, host, install_dir, config.use_llvm);
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

fn generateNonCirculatingSupply(b: *Build, use_llvm: bool) Build.LazyPath {
    const gen = b.addExecutable(.{
        .name = "gen_non_circulating_supply",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .Debug,
            .root_source_file = b.path("src/scripts/gen_non_circulating_supply.zig"),
            .imports = &.{
                .{
                    .name = "base58",
                    .module = b.dependency("base58", .{}).module("base58"),
                },
                .{
                    .name = "non-circulating-supply-zon",
                    .module = b.createModule(.{
                        .root_source_file = b.path("src/rpc/non_circulating_supply.zon"),
                    }),
                },
            },
        }),
        .use_llvm = use_llvm,
    });
    return b.addRunArtifact(gen).addOutputFileArg("non-circulating-supply.zig");
}

fn genSqlite(
    b: *Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    use_llvm: bool,
) *Build.Module {
    const dep = b.dependency("sqlite", .{});

    const lib = b.addLibrary(.{
        .name = "sqlite",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = use_llvm,
    });
    lib.addCSourceFile(.{ .file = dep.path("sqlite3.c") });
    lib.linkLibC();

    const translate_c = b.addTranslateC(.{
        .root_source_file = dep.path("sqlite3.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const mod = translate_c.createModule();
    mod.linkLibrary(lib);

    return mod;
}

fn genBzip2(
    b: *Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    use_llvm: bool,
) *Build.Module {
    const dep = b.dependency("bzip2", .{});

    const lib = b.addLibrary(.{
        .name = "bz",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
        .use_llvm = use_llvm,
    });
    lib.addCSourceFiles(.{
        .root = dep.path("."),
        .files = &.{
            "bzlib.c",
            "blocksort.c",
            "compress.c",
            "crctable.c",
            "decompress.c",
            "huffman.c",
            "randtable.c",
        },
    });
    lib.linkLibC();

    const translate_c = b.addTranslateC(.{
        .root_source_file = dep.path("bzlib.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const mod = translate_c.createModule();
    mod.linkLibrary(lib);

    return mod;
}

/// Reference/inspiration: https://kristoff.it/blog/improving-your-zls-experience/
fn disableEmitBin(b: *Build) void {
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
        use_llvm: bool,
    ) *Build.Step.Run {
        const local_path = b.getInstallPath(install.dest_dir.?, install.dest_sub_path);
        const remote_path = b.pathJoin(&.{ remote_dir, install.dest_sub_path });
        const exe = sendFileExe(b, use_llvm);
        const run = b.addRunArtifact(exe);
        run.addArgs(&.{ local_path, host, remote_path });
        return run;
    }

    /// Returns the executable for the `send-file` script, compiled
    /// exactly once regardless of how many times this is called.
    fn sendFileExe(b: *Build, use_llvm: bool) *Build.Step.Compile {
        const static = struct {
            var exe: ?*Build.Step.Compile = null;
        };

        if (static.exe == null) {
            static.exe = b.addExecutable(.{
                .name = "send-file",
                .root_module = b.createModule(.{
                    .root_source_file = b.path("src/scripts/send-file.zig"),
                    .target = b.graph.host,
                    .link_libc = true,
                }),
                .use_llvm = use_llvm,
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
