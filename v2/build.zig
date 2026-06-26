const std = @import("std");
const Build = std.Build;

const ServiceLib = struct {
    service: []const u8,
    lib: *Build.Step.Compile,
};

const test_install_dir: Build.Step.InstallArtifact.Options.Dir = .{
    .override = .{ .custom = "bin/tests" },
};

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const use_kcov = b.option(bool, "kcov", "Use kcov to run the tests.") orelse false;
    const use_llvm = b.option(
        bool,
        "use-llvm",
        "Force usage of LLVM (currently ignored for some artifacts).",
    ) orelse true;
    if (use_kcov and !use_llvm) @panic("cannot use kcov without llvm");
    const artifact_opts: ExeOutput.InitOptions = .{
        .no_bin = b.option(
            bool,
            "no-bin",
            "Don't install artifacts implied by specified steps.",
        ) orelse false,
        .no_run = b.option(
            bool,
            "no-run",
            "Don't execute run steps implied by the specified steps.",
        ) orelse false,
    };

    const tracy_enable = b.option(bool, "enable-tracy", "Enables tracy") orelse false;
    const tracy_no_exit = b.option(
        bool,
        "tracy-no-exit",
        "Delays process exit until Tracy has received data",
    ) orelse true;
    const tracy_on_demand = b.option(
        bool,
        "tracy-on-demand",
        "Start capturing profiler data when tracy starts",
    ) orelse false;

    const filters = b.option(
        []const []const u8,
        "filter",
        "List of unit test filters.",
    ) orelse &.{};

    const allow_no_sha = b.option(
        bool,
        "allow-no-sha",
        "Opt in to a slower software fallback when the target lacks the x86 SHA extension. " ++
            "Without this flag, building for a target without SHA-NI is a compile-time error " ++
            "so the performance hit is not silently accepted.",
    ) orelse (optimize == .Debug);

    const allow_no_avx512 = b.option(
        bool,
        "allow-no-avx512",
        "Opt in to a slower generic ed25519 path when the target lacks AVX-512 " ++
            "(avx512ifma + avx512vl). Without this flag, building for an x86_64 " ++
            "target without these features is a compile-time error so the performance hit is " ++
            "not silently accepted.",
    ) orelse (optimize == .Debug);

    const debug_skip_shred_checks = b.option(
        bool,
        "debug-skip-shred-checks",
        "Debug purposes only. Skips sig verify and ignores shred version mismatches.",
    ) orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "allow_no_sha", allow_no_sha);
    build_options.addOption(bool, "allow_no_avx512", allow_no_avx512);
    build_options.addOption(bool, "debug_skip_shred_checks", debug_skip_shred_checks);

    const build_options_mod = build_options.createModule();

    const install_step = b.getInstallStep();
    const run_step = b.step("run", "Run supervisor");
    const test_step = b.step("test", "Run all tests.");
    const unit_test_step = b.step("unit-test", "Run unit tests.");
    const bb_test_step = b.step("bb-test", "Run black box tests.");
    const check_step = b.step("check", "Check step.");
    const lint_step = b.step("lint", "Run lint checks");
    const lint_test_step = b.step("lint-test", "Run lint unit tests");
    const ci_step = b.step("ci", "Run all checks used for CI");
    const sig_step = b.step("sig", "Build only the sig binary");
    const docs_step = b.step("docs", "Emit docs");
    const shred_stream_step = b.step("shred-stream", "Stream shreds from an Agave ledger");

    test_step.dependOn(unit_test_step);
    test_step.dependOn(bb_test_step);

    ci_step.dependOn(test_step);
    ci_step.dependOn(install_step);
    ci_step.dependOn(lint_step);
    ci_step.dependOn(lint_test_step);
    check_step.dependOn(install_step);

    const kcov_merge_run = if (use_kcov and !artifact_opts.no_run) kcov_merge: {
        const run = b.addSystemCommand(&.{ "kcov", "--merge" });
        const cache_dir = run.addOutputDirectoryArg("merged");
        const install_dir = b.addInstallDirectory(.{
            .source_dir = cache_dir,
            .install_dir = .prefix,
            .install_subdir = "kcov",
        });
        install_dir.step.dependOn(&run.step);
        unit_test_step.dependOn(&install_dir.step);
        break :kcov_merge run;
    } else null;

    const tracy_mod = b.dependency("tracy", .{
        .target = target,
        .optimize = .ReleaseFast,
        .tracy_enable = tracy_enable,
        .tracy_no_system_tracing = false,
        .tracy_no_exit = tracy_no_exit,
        .tracy_on_demand = tracy_on_demand,
        .tracy_callstack = 6,
    }).module("tracy");
    const base58_mod = b.dependency("base58", .{
        .target = target,
        .optimize = optimize,
    }).module("base58");
    const zstd_mod = b.dependency("zstd", .{
        .target = target,
        .optimize = .ReleaseFast, // fast to compile once, no need to recompile when changing modes,
    }).module("zstd");
    const ipc_ring_mod = b.createModule(.{
        .root_source_file = b.path("lib/ipc/ring.zig"),
        .target = target,
        .optimize = optimize,
    });
    const rocksdb_dep = b.dependency("rocksdb", .{
        .target = target,
        .optimize = optimize,
        .enable_snappy = true,
    });
    const rocksdb_mod = rocksdb_dep.module("bindings");
    const rocksdb_c_mod = rocksdb_dep.module("rocksdb");
    rocksdb_dep.artifact("rocksdb").root_module.sanitize_c = .off;

    const fmt_check_step = b.addFmt(.{
        .check = true,
        .paths = &.{ "init/", "lib/", "services/", "scripts/", "build.zig", "lint/" },
    });
    ci_step.dependOn(&fmt_check_step.step);

    const lint_exe = b.addExecutable(.{
        .name = "sig-lint",
        .root_module = b.createModule(.{
            .root_source_file = b.path("lint/main.zig"),
            .target = b.graph.host,
            .optimize = .ReleaseSafe,
        }),
    });
    const run_lint = b.addRunArtifact(lint_exe);
    if (b.args) |args| run_lint.addArgs(args);
    lint_step.dependOn(&run_lint.step);

    const lint_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("lint/main.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const run_lint_tests = b.addRunArtifact(lint_tests);
    lint_test_step.dependOn(&run_lint_tests.step);

    const features = b.createModule(.{
        .root_source_file = b.path("../shared/core/features.zon"),
    });
    const feature_set_id = b.createModule(.{
        .root_source_file = b
            .addRunArtifact(addFeatureSetIdGenerator(b, features, use_llvm))
            .addOutputFileArg("feature-set-id.zig"),
    });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("lib/lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "base58", .module = base58_mod },
            .{ .name = "tracy", .module = tracy_mod },
            .{ .name = "build-options", .module = build_options_mod },
            .{ .name = "zstd", .module = zstd_mod },
            .{ .name = "features-zon", .module = features },
            .{ .name = "feature-set-id", .module = feature_set_id },
        },
    });
    _ = addTestOutputs(b, unit_test_step, null, artifact_opts, kcov_merge_run, .{
        .name = "lib",
        .root_module = lib_mod,
        .filters = filters,
        .use_llvm = use_llvm,
    });

    const services_mod = b.createModule(.{
        .root_source_file = b.path("init/services.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "lib", .module = lib_mod },
        },
    });

    const runner_imports: RunnerModuleOptions.Imports = .{
        .sig_lib = lib_mod,
        .tracy = tracy_mod,
        .services = services_mod,
    };

    const sig_init_mod = createRunnerModule(b, .{
        .root_source_file = b.path("init/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = runner_imports,
    });
    _ = addTestOutputs(b, unit_test_step, null, artifact_opts, kcov_merge_run, .{
        .name = "sig-init",
        .root_module = sig_init_mod,
        .filters = filters,
        .use_llvm = use_llvm,
    });

    {
        const sig_init_exe = b.addExecutable(.{
            .name = "sig-init",
            .root_module = sig_init_mod,
            .use_llvm = true,
        });
        const sig_init_out = addExeOutputs(b, sig_init_exe, run_step, artifact_opts, .{});
        sig_step.dependOn(&sig_init_exe.step);
        if (sig_init_out.install) |install| {
            sig_step.dependOn(&install.step);
        }
        if (sig_init_out.run) |sig_init_run| {
            sig_init_run.addArgs(b.args orelse &.{});
        }
    }

    {
        const module = b.createModule(.{
            .root_source_file = b.path("scripts/shred_stream.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ipc-ring", .module = ipc_ring_mod },
                .{ .name = "rocksdb", .module = rocksdb_mod },
                .{ .name = "rocksdb-c", .module = rocksdb_c_mod },
            },
        });
        const shred_stream_exe = b.addExecutable(.{
            .name = "shred-stream",
            .root_module = module,
            .use_llvm = true,
        });
        _ = addTestOutputs(b, unit_test_step, null, artifact_opts, kcov_merge_run, .{
            .name = "shred-stream",
            .root_module = module,
            .filters = filters,
            .use_llvm = true,
        });
        const shred_stream_out = addExeOutputs(
            b,
            shred_stream_exe,
            shred_stream_step,
            artifact_opts,
            .{},
        );
        if (shred_stream_out.run) |shred_stream_run| {
            shred_stream_run.addArgs(b.args orelse &.{});
        }
    }

    const start_service_mod = b.createModule(.{
        .root_source_file = b.path("init/start_service.zig"),
        .target = target,
        .optimize = optimize,
        .error_tracing = true,
        .imports = &.{
            .{ .name = "lib", .module = lib_mod },
            .{ .name = "tracy", .module = tracy_mod },
        },
    });
    _ = addTestOutputs(b, unit_test_step, null, artifact_opts, kcov_merge_run, .{
        .name = "start_service",
        .root_module = start_service_mod,
        .use_llvm = true,
    });

    const DocGenModule = struct { name: []const u8, module: *Build.Module };
    var doc_service_modules: std.ArrayListUnmanaged(DocGenModule) = .empty;
    defer doc_service_modules.deinit(b.allocator);

    const services = @typeInfo(@import("init/services.zig")).@"struct".decls;
    var service_libs: [services.len]ServiceLib = undefined;

    // build + link services
    inline for (services, &service_libs) |service, *service_lib_entry| {
        const service_mod = b.createModule(.{
            .root_source_file = b.path("services").path(b, service.name ++ ".zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .omit_frame_pointer = false,
            .error_tracing = true,
            .imports = &.{
                .{ .name = "lib", .module = lib_mod },
                .{ .name = "start_service", .module = start_service_mod },
                .{ .name = "tracy", .module = tracy_mod },
                .{ .name = "services", .module = services_mod },
            },
        });

        const service_lib = b.addLibrary(.{
            .name = service.name,
            .root_module = service_mod,
            .use_llvm = true,
        });
        sig_init_mod.linkLibrary(service_lib);
        service_lib_entry.* = .{ .service = service.name, .lib = service_lib };

        _ = addTestOutputs(b, unit_test_step, null, artifact_opts, kcov_merge_run, .{
            .root_module = service_mod,
            .name = service.name,
            .filters = filters,
            .use_llvm = use_llvm,
        });

        try doc_service_modules.append(
            b.allocator,
            .{ .name = service.name, .module = service_mod },
        );
    }

    const black_box_tests: []const BlackBoxTest = &.{
        .{
            .name = "gossip",
            .root_source_file = b.path("tests/gossip/main.zig"),
            .services = &.{ "gossip", "telemetry" },
        },
        .{
            .name = "replay",
            .root_source_file = b.path("tests/replay/main.zig"),
            .services = .initMany(&.{ .shred_receiver, .replay, .telemetry }),
        },
    };

    for (black_box_tests) |black_box_test| {
        addBlackBoxTest(b, bb_test_step, artifact_opts, .{
            .test_config = black_box_test,
            .target = target,
            .optimize = optimize,
            .imports = runner_imports,
            .service_libs = &service_libs,
        });
    }

    // generates unified docs for all modules
    // NOTE: have to specify `-Dno-bin` & `-Dno-run` in order to
    // avoid needing to run codegen for the sig binaries.
    {
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

        const doc_modules: []const DocGenModule = &.{
            .{ .name = "start_service", .module = start_service_mod },
            .{ .name = "sig_init", .module = sig_init_mod },
            .{ .name = "lib", .module = lib_mod },
        };

        inline for (&.{ doc_service_modules.items, doc_modules }) |module_list| {
            var services_str = std.io.Writer.Allocating.init(b.allocator);
            defer services_str.deinit();

            for (module_list, 0..) |svc_mod, i| {
                const end: []const u8 = if (i == module_list.len - 1) "" else ",";
                try services_str.writer.print("{s}{s}", .{ svc_mod.name, end });
            }

            gen_docs_run.addArg(services_str.written());
        }

        const docs_mod = b.createModule(.{
            .target = target,
            .optimize = .Debug,
            .root_source_file = gen_docs_run.addOutputFileArg("docs.zig"),
        });
        for (doc_modules) |mod| docs_mod.addImport(mod.name, mod.module);
        for (doc_service_modules.items) |mod| docs_mod.addImport(mod.name, mod.module);

        const docs_obj = b.addTest(.{ .name = "docs", .root_module = docs_mod });

        const install_docs = b.addInstallDirectory(.{
            .source_dir = docs_obj.getEmittedDocs(),
            .install_dir = .prefix,
            .install_subdir = "docs",
        });
        docs_step.dependOn(&install_docs.step);
    }
}

const RunnerModuleOptions = struct {
    root_source_file: Build.LazyPath,
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    imports: Imports,

    const Imports = struct {
        sig_lib: *Build.Module,
        tracy: *Build.Module,
        services: *Build.Module,
    };
};

const BlackBoxTest = struct {
    name: []const u8,
    root_source_file: Build.LazyPath,
    services: []const []const u8,
};

fn addBlackBoxTest(
    b: *Build,
    bb_test_step: *Build.Step,
    artifact_opts: ExeOutput.InitOptions,
    options: struct {
        test_config: BlackBoxTest,
        target: Build.ResolvedTarget,
        optimize: std.builtin.OptimizeMode,
        imports: RunnerModuleOptions.Imports,
        service_libs: []const ServiceLib,
    },
) void {
    const exe = b.addExecutable(.{
        .name = b.fmt("bbt-{s}", .{options.test_config.name}),
        .root_module = createRunnerModule(b, .{
            .root_source_file = options.test_config.root_source_file,
            .target = options.target,
            .optimize = options.optimize,
            .imports = options.imports,
        }),
        .use_llvm = true,
    });

    for (options.test_config.services) |service_name| {
        exe.linkLibrary(for (options.service_libs) |entry| {
            if (std.mem.eql(u8, entry.service, service_name)) break entry.lib;
        } else std.debug.panic("unknown service '{s}'", .{service_name}));
    }

    _ = addExeOutputs(b, exe, bb_test_step, artifact_opts, .{
        .dest_dir = test_install_dir,
    });
}

fn createRunnerModule(
    b: *Build,
    options: RunnerModuleOptions,
) *Build.Module {
    return b.createModule(.{
        .root_source_file = options.root_source_file,
        .target = options.target,
        .optimize = options.optimize,
        .imports = &.{
            .{ .name = "lib", .module = options.imports.sig_lib },
            .{ .name = "tracy", .module = options.imports.tracy },
            .{ .name = "services", .module = options.imports.services },
        },
    });
}

const ExeOutput = struct {
    install: ?*Build.Step.InstallArtifact,
    run: ?*Build.Step.Run,

    const InitOptions = struct {
        no_bin: bool,
        no_run: bool,
    };
};

fn addTestOutputs(
    b: *Build,
    artifact_step: *Build.Step,
    dest_sub_path: ?[]const u8,
    artifact_opts: ExeOutput.InitOptions,
    maybe_kcov_merge_run: ?*Build.Step.Run,
    test_options: Build.TestOptions,
) ExeOutput {
    const mod_test_exe = b.addTest(test_options);
    const install_opts: Build.Step.InstallArtifact.Options = .{
        .dest_sub_path = dest_sub_path,
        .dest_dir = test_install_dir,
    };

    if (maybe_kcov_merge_run) |kcov_merge_run| {
        const kcov_run = b.addSystemCommand(&.{
            "kcov",
            "--collect-only",
            "--include-pattern=v2/",
            "--exclude-pattern=.cache",
        });
        const output_dir = kcov_run.addOutputDirectoryArg("output");
        kcov_run.addArtifactArg(mod_test_exe);
        kcov_run.has_side_effects = true;

        kcov_merge_run.step.dependOn(&kcov_run.step);
        kcov_merge_run.addDirectoryArg(output_dir);

        var outputs = addExeOutputs(b, mod_test_exe, artifact_step, .{
            .no_bin = artifact_opts.no_bin,
            .no_run = true,
        }, install_opts);
        outputs.run = kcov_run;
        return outputs;
    } else return addExeOutputs(b, mod_test_exe, artifact_step, artifact_opts, install_opts);
}

fn addExeOutputs(
    b: *Build,
    artifact: *Build.Step.Compile,
    artifact_step: *Build.Step,
    artifact_opts: ExeOutput.InitOptions,
    install_opts: Build.Step.InstallArtifact.Options,
) ExeOutput {
    artifact_step.dependOn(&artifact.step);

    const install_step = b.getInstallStep();
    install_step.dependOn(&artifact.step);

    const install_opt = if (artifact_opts.no_bin)
        null
    else
        b.addInstallArtifact(artifact, install_opts);
    const run_opt = if (artifact_opts.no_run) null else b.addRunArtifact(artifact);

    if (install_opt) |install| {
        artifact_step.dependOn(&install.step);
        install_step.dependOn(&install.step);
    }

    if (run_opt) |run| {
        artifact_step.dependOn(&run.step);
    }

    return .{
        .install = install_opt,
        .run = run_opt,
    };
}

fn addFeatureSetIdGenerator(
    b: *Build,
    features: *Build.Module,
    use_llvm: ?bool,
) *Build.Step.Compile {
    // This generator runs on the host at build time, so its dependencies must
    // be fetched with default (host) target options — not the cross-compilation
    // target used for the main build. This should be repeated for other scripts if they
    // import a library in the future.
    return b.addExecutable(.{
        .name = "gen_feature_set_id",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .Debug,
            .root_source_file = b.path("../shared/scripts/gen_feature_set_id.zig"),
            .imports = &.{
                .{
                    .name = "base58",
                    .module = b.dependency("base58", .{}).module("base58"),
                },
                .{
                    .name = "features",
                    .module = features,
                },
            },
        }),
        .use_llvm = use_llvm,
    });
}
