const std = @import("std");
const Build = std.Build;

const test_install_dir: Build.Step.InstallArtifact.Options.Dir = .{
    .override = .{ .custom = "bin/tests" },
};

pub fn build(b: *Build) !void {
    // -- Inputs ----------------------------

    const config: Config = .load(b);
    const deps: Dependencies = .load(b, config);

    // -- Artifacts -------------------------

    var unit_tests: UnitTests = .init(b, config);
    const sig: Sig = .init(b, config, deps, &unit_tests);
    const tools: Tools = .init(b, config, deps, &unit_tests, sig);

    // -- CLI Commands (Top Level Steps) ----

    // install (default step)
    const install_step = b.getInstallStep();
    install_step.dependOn(sig.exe.installStep());
    install_step.dependOn(tools.shred_stream.installStep());
    install_step.dependOn(tools.lint.installStep());
    for (unit_tests.tests.items) |exe| install_step.dependOn(exe.installStep());
    for (tools.black_box_tests) |exe| install_step.dependOn(exe.installStep());

    // run
    const run_step = b.step("run", "Run sig");
    sig.exe.addToStep(run_step);

    // sig
    const sig_step = b.step("sig", "Build only the sig binary, without running it.");
    sig_step.dependOn(sig.exe.installStep());

    // unit-test
    const unit_test_step = b.step("unit-test", "Run unit tests.");
    for (unit_tests.tests.items) |exe| unit_test_step.dependOn(exe.installStep());
    if (unit_tests.kcov) |kcov| {
        if (config.exe.run) unit_test_step.dependOn(kcov.save_results_step);
    } else for (unit_tests.tests.items) |unit_test| {
        if (unit_test.run) |run| unit_test_step.dependOn(&run.step);
    }

    // bb-test
    const bb_test_step = b.step("bb-test", "Run black box tests.");
    for (tools.black_box_tests) |bbt| bbt.addToStep(bb_test_step);

    // shred-stream
    const shred_stream_step = b.step("shred-stream", "Stream shreds from an Agave ledger");
    tools.shred_stream.addToStep(shred_stream_step);

    // lint
    const lint_step = b.step("lint", "Run lint checks");
    tools.lint.addToStep(lint_step);

    // test
    const test_step = b.step("test", "Run all tests.");
    test_step.dependOn(unit_test_step);
    test_step.dependOn(bb_test_step);

    // check
    const check_step = b.step("check", "Check step.");
    check_step.dependOn(install_step);

    // ci
    const ci_step = b.step("ci", "Run all checks used for CI");
    ci_step.dependOn(test_step);
    ci_step.dependOn(install_step);
    ci_step.dependOn(lint_step);
    ci_step.dependOn(&b.addFmt(.{ .check = true, .paths = &.{"."} }).step);

    // docs
    const docs_step = b.step("docs", "Emit docs");
    docs_step.dependOn(&tools.docs.step);
}

const Config = struct {
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    use_kcov: bool,
    use_llvm: bool,
    exe: Executable.Options,
    tracy_enable: bool,
    tracy_no_exit: bool,
    tracy_on_demand: bool,
    filters: []const []const u8,
    allow_no_sha: bool,
    allow_no_avx512: bool,
    debug_skip_shred_sig_verify: bool,
    debug_skip_shred_version_check: bool,

    pub fn load(b: *Build) Config {
        const optimize = b.standardOptimizeOption(.{});
        const use_kcov = b.option(bool, "kcov", "Use kcov to run the tests.") orelse false;
        const use_llvm = b.option(bool, "use-llvm", "Force usage of LLVM") orelse true;
        if (use_kcov and !use_llvm) @panic("cannot use kcov without llvm");
        return .{
            .target = b.standardTargetOptions(.{}),
            .optimize = optimize,
            .use_kcov = use_kcov,
            .use_llvm = use_llvm,
            .exe = .{
                .install = !(b.option(
                    bool,
                    "no-bin",
                    "Don't install artifacts implied by specified steps.",
                ) orelse false),
                .run = !(b.option(
                    bool,
                    "no-run",
                    "Don't execute run steps implied by the specified steps.",
                ) orelse false),
            },
            .tracy_enable = b.option(bool, "enable-tracy", "Enables tracy") orelse false,
            .tracy_no_exit = b.option(
                bool,
                "tracy-no-exit",
                "Delays process exit until Tracy has received data. Only has an effect if " ++
                    "tracy is enabled via enable-tracy.",
            ) orelse false,
            .tracy_on_demand = b.option(
                bool,
                "tracy-on-demand",
                "Start capturing profiler data when tracy starts",
            ) orelse false,
            .filters = b.option(
                []const []const u8,
                "filter",
                "List of unit test filters.",
            ) orelse &.{},
            .allow_no_sha = b.option(
                bool,
                "allow-no-sha",
                "Opt in to a slower software fallback when the target lacks the x86 SHA " ++
                    "extension. Without this flag, building for a target without SHA-NI is a " ++
                    "compile-time error, so the performance hit is not silently accepted.",
            ) orelse (optimize == .Debug),
            .allow_no_avx512 = b.option(
                bool,
                "allow-no-avx512",
                "Opt in to a slower generic ed25519 path when the target lacks AVX-512 " ++
                    "(avx512ifma + avx512vl). Without this flag, building for an x86_64 " ++
                    "target without these features is a compile-time error so the performance " ++
                    "hit is not silently accepted.",
            ) orelse (optimize == .Debug),
            .debug_skip_shred_sig_verify = b.option(
                bool,
                "debug-skip-shred-sig-verify",
                "Debug / harness use only. Skips leader lookup and ed25519 verify on " ++
                    "incoming shreds. Required by the conformance shred-parse harness, which " ++
                    "feeds shreds whose merkle roots are not signed by any known leader.",
            ) orelse false,
            .debug_skip_shred_version_check = b.option(
                bool,
                "debug-skip-shred-version-check",
                "Debug use only. Disables the shred_version mismatch rejection in Receiver. " ++
                    "Independent of -Ddebug-skip-shred-sig-verify so the harness can keep this " ++
                    "check on for parity with the reference implementations.",
            ) orelse false,
        };
    }
};

const Dependencies = struct {
    tracy: *Build.Module,
    base58: *Build.Module,
    zstd: *Build.Module,
    rocksdb: *Build.Module,
    rocksdb_c: *Build.Module,

    pub fn load(b: *Build, config: Config) Dependencies {
        const rocksdb_dep = b.dependency("rocksdb", .{
            .target = config.target,
            .optimize = config.optimize,
            .enable_snappy = true,
        });
        rocksdb_dep.artifact("rocksdb").root_module.sanitize_c = .off;

        return .{
            // Options must match the `b.dependency("tracy", ...)` call in
            // shared/build.zig exactly. Any drift produces two `tracy` Module
            // instances rooted at the same source file, which Zig 0.15 rejects
            // when both sig and sig_v2 live in one compilation (e.g. under
            // conformance/).
            .tracy = b.dependency("tracy", .{
                .target = config.target,
                .optimize = config.optimize,
                .tracy_enable = config.tracy_enable,
                .tracy_on_demand = config.tracy_on_demand,
                .tracy_no_exit = config.tracy_no_exit,
                .tracy_no_system_tracing = false,
                .tracy_callstack = 6,
            }).module("tracy"),
            .base58 = b.dependency("base58", .{
                .target = config.target,
                .optimize = config.optimize,
            }).module("base58"),
            // Options must match shared/build.zig's zstd dep. See tracy comment above.
            .zstd = b.dependency("zstd", .{
                .target = config.target,
                .optimize = config.optimize,
            }).module("zstd"),
            .rocksdb = rocksdb_dep.module("bindings"),
            .rocksdb_c = rocksdb_dep.module("rocksdb"),
        };
    }
};

/// All the modules, libraries, and executables that compose the main sig
/// validator binary. Does not include any tests, developer tools, docs, etc.
const Sig = struct {
    lib: *Build.Module,
    services_mod: *Build.Module,
    start_service: *Build.Module,
    service_libs: [services.len]Service,
    sig_init: *Build.Module,
    exe: Executable,

    const Service = struct {
        name: []const u8,
        module: *Build.Module,
        lib: *Build.Step.Compile,
    };

    const services = @typeInfo(@import("init/services.zig")).@"struct".decls;

    pub fn init(b: *Build, config: Config, deps: Dependencies, unit_tests: *UnitTests) Sig {
        const build_options = b.addOptions();
        build_options.addOption(bool, "allow_no_sha", config.allow_no_sha);
        build_options.addOption(bool, "allow_no_avx512", config.allow_no_avx512);
        build_options.addOption(
            bool,
            "debug_skip_shred_sig_verify",
            config.debug_skip_shred_sig_verify,
        );
        build_options.addOption(
            bool,
            "debug_skip_shred_version_check",
            config.debug_skip_shred_version_check,
        );
        const build_options_mod = build_options.createModule();

        // Consume shared's exported modules instead of building our own from
        // the same source files. Two `b.createModule` calls on features.zon /
        // the generated feature-set-id.zig produce distinct Module instances
        // that Zig 0.15 rejects when both sig and sig_v2 live in one
        // compilation (e.g. under conformance/).
        //
        // Options must match the `b.dependency("shared", ...)` call in
        // sig/build.zig exactly so that Zig deduplicates the two dep chains
        // into a single `shared` Package instance. Any drift produces two
        // distinct Packages, each with its own `feature-set-id` module.
        const shared_dep = b.dependency("shared", .{
            .target = config.target,
            .optimize = config.optimize,
            .@"long-tests" = false,
            .@"allow-no-sha" = config.allow_no_sha,
            .@"allow-no-avx512" = config.allow_no_avx512,
            .@"use-llvm" = config.use_llvm,
            .@"enable-tracy" = config.tracy_enable,
            .@"tracy-on-demand" = config.tracy_on_demand,
            .@"tracy-no-exit" = config.tracy_no_exit,
        });
        const features = shared_dep.module("features-zon");
        const feature_set_id = shared_dep.module("feature-set-id");

        // Exported by name so downstream packages can `dep.module("sig_v2")`.
        const lib = b.addModule("sig_v2", .{
            .root_source_file = b.path("lib/lib.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "base58", .module = deps.base58 },
                .{ .name = "tracy", .module = deps.tracy },
                .{ .name = "build-options", .module = build_options_mod },
                .{ .name = "zstd", .module = deps.zstd },
                .{ .name = "features-zon", .module = features },
                .{ .name = "feature-set-id", .module = feature_set_id },
            },
        });
        unit_tests.add("lib", lib);

        const start_service = b.createModule(.{
            .root_source_file = b.path("init/start_service.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .error_tracing = true,
            .imports = &.{
                .{ .name = "lib", .module = lib },
                .{ .name = "tracy", .module = deps.tracy },
            },
        });
        unit_tests.add("start_service", start_service);

        const services_mod = b.createModule(.{
            .root_source_file = b.path("init/services.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "lib", .module = lib },
            },
        });

        const sig_init = b.createModule(.{
            .root_source_file = b.path("init/main.zig"),
            .target = config.target,
            .optimize = config.optimize,
            .imports = &.{
                .{ .name = "lib", .module = lib },
                .{ .name = "tracy", .module = deps.tracy },
                .{ .name = "services", .module = services_mod },
            },
        });
        unit_tests.add("sig-init", sig_init);

        var service_libs: [services.len]Service = undefined;

        inline for (services, &service_libs) |service, *service_lib_entry| {
            const service_mod = b.createModule(.{
                .root_source_file = b.path("services").path(b, service.name ++ ".zig"),
                .target = config.target,
                .optimize = config.optimize,
                .single_threaded = true,
                .omit_frame_pointer = false,
                .error_tracing = true,
                .imports = &.{
                    .{ .name = "lib", .module = lib },
                    .{ .name = "start_service", .module = start_service },
                    .{ .name = "tracy", .module = deps.tracy },
                    .{ .name = "services", .module = services_mod },
                },
            });
            unit_tests.add(service.name, service_mod);

            const service_lib = b.addLibrary(.{
                .name = service.name,
                .root_module = service_mod,
                .use_llvm = config.use_llvm,
            });
            sig_init.linkLibrary(service_lib);

            service_lib_entry.* = .{
                .name = service.name,
                .module = service_mod,
                .lib = service_lib,
            };
        }

        return .{
            .lib = lib,
            .services_mod = services_mod,
            .start_service = start_service,
            .service_libs = service_libs,
            .sig_init = sig_init,
            .exe = .init(b, config.exe, .{
                .name = "sig-init",
                .root_module = sig_init,
                .use_llvm = config.use_llvm,
            }, .{}),
        };
    }
};

/// Everything other than Sig itself: developer tools, ci scripts, docs,
/// integration tests, etc.
const Tools = struct {
    shred_stream: Executable,
    lint: Executable,
    docs: *Build.Step.InstallDir,
    black_box_tests: [black_box_test_descriptions.len]Executable,

    const black_box_test_descriptions = [_]struct {
        name: []const u8,
        root_source_file: []const u8,
        services: []const []const u8,
    }{
        .{
            .name = "gossip",
            .root_source_file = "tests/gossip/main.zig",
            .services = &.{ "gossip", "telemetry" },
        },
    };

    pub fn init(
        b: *Build,
        config: Config,
        deps: Dependencies,
        unit_tests: *UnitTests,
        sig: Sig,
    ) Tools {
        const shred_stream_exe = blk: {
            const module = b.createModule(.{
                .root_source_file = b.path("scripts/shred_stream.zig"),
                .target = config.target,
                .optimize = config.optimize,
                .imports = &.{
                    .{ .name = "ipc-ring", .module = b.createModule(.{
                        .root_source_file = b.path("lib/ipc/ring.zig"),
                        .target = config.target,
                        .optimize = config.optimize,
                    }) },
                    .{ .name = "rocksdb", .module = deps.rocksdb },
                    .{ .name = "rocksdb-c", .module = deps.rocksdb_c },
                },
            });
            unit_tests.add("shred-stream", module);
            const shred_stream_exe: Executable = .init(b, config.exe, .{
                .name = "shred-stream",
                .root_module = module,
                .use_llvm = config.use_llvm,
            }, .{});
            break :blk shred_stream_exe;
        };

        const lint_exe: Executable = .init(b, config.exe, .{
            .name = "sig-lint",
            .root_module = b.createModule(.{
                .root_source_file = b.path("lint/main.zig"),
                .target = b.graph.host,
                .optimize = .ReleaseSafe,
            }),
        }, .{});
        unit_tests.add("lint-tests", b.createModule(.{
            .root_source_file = b.path("lint/main.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }));

        // generates unified docs for all modules
        // NOTE: have to specify `-Dno-bin` & `-Dno-run` in order to
        // avoid needing to run codegen for the sig binaries.
        const install_docs = blk: {
            const gen_docs_run = b.addRunArtifact(
                b.addExecutable(.{
                    .name = "gen-docs-entry",
                    .root_module = b.createModule(.{
                        .target = b.graph.host,
                        .optimize = .Debug,
                        .root_source_file = b.path("scripts/gen_docs_entry.zig"),
                    }),
                }),
            );

            const doc_modules: []const struct { name: []const u8, module: *Build.Module } = &.{
                .{ .name = "start_service", .module = sig.start_service },
                .{ .name = "sig_init", .module = sig.sig_init },
                .{ .name = "lib", .module = sig.lib },
            };

            inline for (&.{ sig.service_libs, doc_modules }) |module_list| {
                var str_buf: [1024]u8 = undefined;
                var services_str = std.io.Writer.fixed(&str_buf);

                for (module_list, 0..) |svc_mod, i| {
                    const end: []const u8 = if (i == module_list.len - 1) "" else ",";
                    services_str.print("{s}{s}", .{ svc_mod.name, end }) catch unreachable;
                }

                gen_docs_run.addArg(str_buf[0..services_str.end]);
            }

            const docs_mod = b.createModule(.{
                .target = config.target,
                .optimize = .Debug,
                .root_source_file = gen_docs_run.addOutputFileArg("docs.zig"),
            });
            for (doc_modules) |mod| docs_mod.addImport(mod.name, mod.module);
            for (sig.service_libs) |mod| docs_mod.addImport(mod.name, mod.module);

            const docs_obj = b.addTest(.{ .name = "docs", .root_module = docs_mod });

            const install_docs = b.addInstallDirectory(.{
                .source_dir = docs_obj.getEmittedDocs(),
                .install_dir = .prefix,
                .install_subdir = "docs",
            });
            break :blk install_docs;
        };

        var bbt_exes: [black_box_test_descriptions.len]Executable = undefined;
        for (black_box_test_descriptions, &bbt_exes) |description, *exe| {
            exe.* = .init(b, config.exe, .{
                .name = b.fmt("bbt-{s}", .{description.name}),
                .root_module = b.createModule(.{
                    .root_source_file = b.path(description.root_source_file),
                    .target = config.target,
                    .optimize = config.optimize,
                    .imports = &.{
                        .{ .name = "lib", .module = sig.lib },
                        .{ .name = "tracy", .module = deps.tracy },
                        .{ .name = "services", .module = sig.services_mod },
                    },
                }),
                .use_llvm = config.use_llvm,
            }, .{ .dest_dir = test_install_dir });

            for (description.services) |service_name| {
                exe.compile.linkLibrary(for (sig.service_libs) |entry| {
                    if (std.mem.eql(u8, entry.name, service_name)) break entry.lib;
                } else std.debug.panic("unknown service '{s}'", .{service_name}));
            }
        }

        return .{
            .shred_stream = shred_stream_exe,
            .lint = lint_exe,
            .docs = install_docs,
            .black_box_tests = bbt_exes,
        };
    }
};

/// Consolidated container for unit tests to make it easy to add them, and to
/// ensure the same configuration is applied to all tests.
const UnitTests = struct {
    tests: std.ArrayList(Executable),
    use_llvm: bool,
    filters: []const []const u8,
    build: *Build,
    exe_config: Executable.Options,
    kcov: ?struct {
        save_results_step: *Build.Step,
        merge_run: *Build.Step.Run,
    },

    pub fn init(b: *Build, config: Config) UnitTests {
        return .{
            .use_llvm = config.use_llvm,
            .filters = config.filters,
            .build = b,
            .tests = .{},
            .exe_config = config.exe,
            .kcov = if (config.use_kcov) kcov: {
                const merge_run = b.addSystemCommand(&.{ "kcov", "--merge" });
                const cache_dir = merge_run.addOutputDirectoryArg("merged");
                const save_results = b.addInstallDirectory(.{
                    .source_dir = cache_dir,
                    .install_dir = .prefix,
                    .install_subdir = "kcov",
                });
                save_results.step.dependOn(&merge_run.step);
                break :kcov .{
                    .save_results_step = &save_results.step,
                    .merge_run = merge_run,
                };
            } else null,
        };
    }

    pub fn add(self: *UnitTests, name: []const u8, module: *Build.Module) void {
        const unit_test = self.build.addTest(.{
            .name = name,
            .root_module = module,
            .use_llvm = self.use_llvm,
            .filters = self.filters,
        });
        self.tests.append(self.build.allocator, .{
            .compile = unit_test,
            .install = if (self.exe_config.install) self.build.addInstallArtifact(unit_test, .{
                .dest_sub_path = name,
                .dest_dir = test_install_dir,
            }) else null,
            .run = if (self.exe_config.run) self.build.addRunArtifact(unit_test) else null,
        }) catch @panic("oom");
        if (self.kcov) |kcov| {
            const kcov_run = self.build.addSystemCommand(&.{
                "kcov",
                "--collect-only",
                "--include-pattern=v2/",
                "--exclude-pattern=.cache",
            });
            const output_dir = kcov_run.addOutputDirectoryArg("output");
            kcov_run.addArtifactArg(unit_test);
            kcov_run.has_side_effects = true;
            kcov.merge_run.step.dependOn(&kcov_run.step);
            kcov.merge_run.addDirectoryArg(output_dir);
        }
    }
};

/// All executables can be compiled, installed, and run. It keeps things simple
/// to construct all the steps together and let callers decide when to use them.
///
/// Install and run are optional because we don't want to create them
/// unconditionally. Doing so forces the associated compile step to enter
/// codegen, even if those steps are not actually depended on by any other step.
const Executable = struct {
    compile: *Build.Step.Compile,
    install: ?*Build.Step.InstallArtifact,
    run: ?*Build.Step.Run,

    const Options = struct { install: bool, run: bool };

    pub fn init(
        b: *Build,
        options: Options,
        exe_options: Build.ExecutableOptions,
        install_options: Build.Step.InstallArtifact.Options,
    ) Executable {
        const exe = b.addExecutable(exe_options);
        return .{
            .compile = exe,
            .install = if (options.install) b.addInstallArtifact(exe, install_options) else null,
            .run = if (options.run) blk: {
                const run = b.addRunArtifact(exe);
                run.addArgs(b.args orelse &.{});
                break :blk run;
            } else null,
        };
    }

    pub fn addToStep(self: *const Executable, step: *Build.Step) void {
        step.dependOn(&self.compile.step);
        if (self.run) |run| step.dependOn(&run.step);
        if (self.install) |install| step.dependOn(&install.step);
    }

    /// The step to depend on when you want this executable installed (or only
    /// compiled, when using -Dno-bin), but not executed under any circumstances.
    pub fn installStep(self: *const Executable) *Build.Step {
        return if (self.install) |install| &install.step else &self.compile.step;
    }
};
