const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run unit tests");
    const fmt_check_step = b.addFmt(.{ .check = true, .paths = &.{ "src/", "build.zig" } });
    const ci_step = b.step("ci", "Run all checks used for CI");
    ci_step.dependOn(test_step);
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(&fmt_check_step.step);

    const common = mod: {
        const common = b.createModule(.{
            .root_source_file = b.path("src/common.zig"),
            .target = target,
            .optimize = optimize,
        });
        common.addImport("base58", b.dependency("base58", .{}).module("base58"));
        common.addImport("binkode", b.dependency("binkode", .{}).module("binkode"));

        const common_tests = b.addTest(.{ .root_module = common, .name = "common" });
        const common_tests_run = b.addRunArtifact(common_tests);
        test_step.dependOn(&common_tests_run.step);

        break :mod common;
    };

    const sig_init = mod: {
        const sig_init = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/main.zig"),
        });
        sig_init.addImport("common", common);

        const sig_init_exe = b.addExecutable(.{
            .name = "sig-init",
            .root_module = sig_init,
            .use_llvm = false,
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
            .root_source_file = b.path("src/start_service.zig"),
        });
        start_service.addImport("common", common);

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
    {
        const services_dir = try b.build_root.handle.openDir("src/services", .{ .iterate = true });
        var iter = services_dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;

            const service_name = str: {
                var splitter = std.mem.splitScalar(u8, entry.name, '.');
                break :str splitter.next() orelse unreachable;
            };

            const service_mod = b.createModule(.{
                .target = target,
                .optimize = optimize,
                .root_source_file = b.path("src/services/").path(b, entry.name),
                .single_threaded = true,
                .omit_frame_pointer = false,
            });
            service_mod.addImport("common", common);
            service_mod.addImport("start", start_service);

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
}
