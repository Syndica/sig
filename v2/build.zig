const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const fmt_check_step = b.addFmt(.{
        .check = true,
        .paths = &.{ "init/", "lib/", "services/", "build.zig" },
    });
    const test_step = b.step("test", "Run unit tests");
    const ci_step = b.step("ci", "Run all checks used for CI");
    const check_step = b.step("check", "Check step.");
    ci_step.dependOn(test_step);
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(&fmt_check_step.step);
    check_step.dependOn(b.getInstallStep());

    const tracy = b.dependency("tracy", .{
        .target = target,
        .optimize = .ReleaseFast,
        .tracy_enable = b.option(bool, "enable-tracy", "Enables tracy") orelse false,
        .tracy_no_system_tracing = false,
        .tracy_no_exit = b.option(
            bool,
            "tracy-no-exit",
            "Delays process exit until Tracy has received data",
        ) orelse true,
        .tracy_on_demand = b.option(
            bool,
            "tracy-on-demand",
            "Start capturing profiler data when tracy starts",
        ) orelse true,
        .tracy_callstack = 6,
    }).module("tracy");

    const lib = mod: {
        const lib = b.createModule(.{
            .root_source_file = b.path("lib/lib.zig"),
            .target = target,
            .optimize = optimize,
        });
        lib.addImport("base58", b.dependency("base58", .{}).module("base58"));
        lib.addImport("binkode", b.dependency("binkode", .{}).module("binkode"));
        lib.addImport("tracy", tracy);

        const lib_tests = b.addTest(.{ .root_module = lib, .name = "lib" });
        const lib_tests_run = b.addRunArtifact(lib_tests);
        test_step.dependOn(&lib_tests_run.step);

        break :mod lib;
    };

    const sig_init = mod: {
        const sig_init = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("init/main.zig"),
        });
        sig_init.addImport("lib", lib);
        sig_init.addImport("tracy", tracy);

        const sig_init_exe = b.addExecutable(.{
            .name = "sig-init",
            .root_module = sig_init,
            .use_llvm = true,
        });
        b.installArtifact(sig_init_exe);

        const sig_init_tests = b.addTest(.{ .root_module = sig_init, .name = "sig_init" });
        const sig_init_tests_run = b.addRunArtifact(sig_init_tests);
        test_step.dependOn(&sig_init_tests_run.step);

        const run_cmd = b.addRunArtifact(sig_init_exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }
        const run_step = b.step("run", "Run supervisor");
        run_step.dependOn(&run_cmd.step);

        break :mod sig_init;
    };

    const start_service = mod: {
        const start_service = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("init/start_service.zig"),
        });
        start_service.addImport("lib", lib);
        start_service.addImport("tracy", tracy);

        const start_service_tests = b.addTest(.{
            .root_module = start_service,
            .name = "start_service",
            .use_llvm = true,
        });
        const start_service_tests_run = b.addRunArtifact(start_service_tests);
        test_step.dependOn(&start_service_tests_run.step);

        break :mod start_service;
    };

    // build + link services
    inline for (@import("init/services.zon").services) |s| {
        const service_name = @tagName(s.name);
        const service_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("services").path(b, service_name ++ ".zig"),
            .single_threaded = true,
            .omit_frame_pointer = false,
        });
        service_mod.addImport("lib", lib);
        service_mod.addImport("start", start_service);
        service_mod.addImport("tracy", tracy);

        const lib_svc = b.addLibrary(.{
            .name = service_name,
            .root_module = service_mod,
            .use_llvm = true,
        });
        sig_init.linkLibrary(lib_svc);

        const service_tests = b.addTest(.{ .root_module = service_mod, .name = service_name });
        const service_tests_run = b.addRunArtifact(service_tests);
        test_step.dependOn(&service_tests_run.step);
    }
}
