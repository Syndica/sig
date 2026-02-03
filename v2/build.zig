const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const common = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = "src/common.zig" } },
    });

    const start_service = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = "src/start-service.zig" } },
    });
    start_service.addImport("common", common);

    const sig_init = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = "src/main.zig" } },
    });
    sig_init.addImport("common", common);

    const sig_init_exe = b.addExecutable(.{
        .name = "sig-init",
        .root_module = sig_init,
    });
    b.installArtifact(sig_init_exe);

    const sig_init_tests = b.addTest(.{ .root_module = sig_init, .name = "sig_init" });
    const sig_init_tests_run = b.addRunArtifact(sig_init_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&sig_init_tests_run.step);

    inline for (&.{
        "svc_logger",
        "svc_prng",
    }, &.{
        "src/services/logger.zig",
        "src/services/prng.zig",
    }) |name, path| {
        const service_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = path } },
            .single_threaded = true,
            .omit_frame_pointer = false,
        });
        service_mod.addImport("common", common);
        service_mod.addImport("start", start_service);

        const svc_logger_lib = b.addLibrary(.{
            .name = name,
            .root_module = service_mod,
        });
        sig_init_exe.linkLibrary(svc_logger_lib);

        const service_tests = b.addTest(.{ .root_module = service_mod, .name = name });
        const service_tests_run = b.addRunArtifact(service_tests);
        test_step.dependOn(&service_tests_run.step);
    }

    const run_cmd = b.addRunArtifact(sig_init_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run supervisor");
    run_step.dependOn(&run_cmd.step);
}
