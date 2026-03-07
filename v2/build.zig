const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const force_llvm = b.option(bool, "force-llvm", "Force usage of LLVM.");
    const artifact_opts: ExeOutput.InitOptions = .{
        .no_bin = b.option(bool, "no-bin", "Don't install artifacts implied by specified steps.") orelse false,
        .no_run = b.option(bool, "no-run", "Don't execute run steps implied by the specified steps.") orelse false,
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
    ) orelse true;

    const filters = b.option(
        []const []const u8,
        "filter",
        "List of unit test filters.",
    ) orelse &.{};

    const install_step = b.getInstallStep();
    const run_step = b.step("run", "Run supervisor");
    const test_step = b.step("test", "Run unit tests");
    const check_step = b.step("check", "Check step.");
    const ci_step = b.step("ci", "Run all checks used for CI");

    ci_step.dependOn(test_step);
    ci_step.dependOn(install_step);

    check_step.dependOn(install_step);

    const test_install_dir: Build.Step.InstallArtifact.Options.Dir = .{
        .override = .{ .custom = "bin/tests" },
    };

    const tracy_mod = b.dependency("tracy", .{
        .target = target,
        .optimize = .ReleaseFast,
        .tracy_enable = tracy_enable,
        .tracy_no_system_tracing = false,
        .tracy_no_exit = tracy_no_exit,
        .tracy_on_demand = tracy_on_demand,
        .tracy_callstack = 6,
    }).module("tracy");
    const binkode_mod = b.dependency("binkode", .{}).module("binkode");
    const base58_mod = b.dependency("base58", .{}).module("base58");

    const common_mod = b.createModule(.{
        .root_source_file = b.path("src/common.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "base58", .module = base58_mod },
            .{ .name = "binkode", .module = binkode_mod },
            .{ .name = "tracy", .module = tracy_mod },
        },
        .sanitize_thread = true,
    });
    const common_tests_exe = b.addTest(.{
        .name = "common",
        .root_module = common_mod,
        .use_llvm = force_llvm,
        .filters = filters,
    });
    _ = addExeOutputs(b, common_tests_exe, test_step, artifact_opts, .{
        .dest_dir = test_install_dir,
    });

    const sig_init_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "common", .module = common_mod },
            .{ .name = "tracy", .module = tracy_mod },
        },
    });
    const sig_init_tests_exe = b.addTest(.{
        .name = "sig_init",
        .root_module = sig_init_mod,
        .use_llvm = force_llvm,
        .filters = filters,
    });
    _ = addExeOutputs(b, sig_init_tests_exe, test_step, artifact_opts, .{
        .dest_dir = test_install_dir,
    });

    const start_service_mod = b.createModule(.{
        .root_source_file = b.path("src/start_service.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "common", .module = common_mod },
            .{ .name = "tracy", .module = tracy_mod },
        },
    });

    const start_service_tests_exe = b.addTest(.{
        .name = "start_service",
        .root_module = start_service_mod,
        .use_llvm = true,
        .filters = filters,
    });
    _ = addExeOutputs(b, start_service_tests_exe, test_step, artifact_opts, .{
        .dest_dir = test_install_dir,
    });

    const sig_init_exe = b.addExecutable(.{
        .name = "sig-init",
        .root_module = sig_init_mod,
        .use_llvm = true,
    });
    const sig_init_out = addExeOutputs(b, sig_init_exe, run_step, artifact_opts, .{});
    if (sig_init_out.run) |sig_init_run| {
        sig_init_run.addArgs(b.args orelse &.{});
    }

    // build + link services
    inline for (@import("src/services.zon")) |service_name| {
        const service_mod = b.createModule(.{
            .root_source_file = b.path("src/services").path(b, service_name ++ ".zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .omit_frame_pointer = false,
            .imports = &.{
                .{ .name = "common", .module = common_mod },
                .{ .name = "start", .module = start_service_mod },
                .{ .name = "tracy", .module = tracy_mod },
            },
        });

        const lib_svc = b.addLibrary(.{
            .name = service_name,
            .root_module = service_mod,
            .use_llvm = true,
        });
        sig_init_mod.linkLibrary(lib_svc);

        const service_tests_exe = b.addTest(.{
            .name = service_name,
            .root_module = service_mod,
            .use_llvm = force_llvm,
            .filters = filters,
        });
        _ = addExeOutputs(b, service_tests_exe, test_step, artifact_opts, .{
            .dest_dir = test_install_dir,
        });
    }

    const fmt_check_step = b.addFmt(.{
        .check = true,
        .paths = &.{ "src/", "build.zig" },
    });
    ci_step.dependOn(&fmt_check_step.step);

    const validate_services_list_exe = b.addExecutable(.{
        .name = "validate_services_list",
        .root_module = b.createModule(.{
            .root_source_file = b.path("scripts/validate_services_list.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
            .imports = &.{
                .{
                    .name = "services",
                    .module = b.createModule(.{ .root_source_file = b.path("src/services.zon") }),
                },
            },
        }),
        .use_llvm = force_llvm,
    });
    const validate_services_list_run = b.addRunArtifact(validate_services_list_exe);
    validate_services_list_run.addDirectoryArg(b.path("src/services"));
    install_step.dependOn(&validate_services_list_run.step);
}

const ExeOutput = struct {
    install: ?*Build.Step.InstallArtifact,
    run: ?*Build.Step.Run,

    const InitOptions = struct {
        no_bin: bool,
        no_run: bool,
    };
};

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

    const install_opt = if (artifact_opts.no_bin) null else b.addInstallArtifact(artifact, install_opts);
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
