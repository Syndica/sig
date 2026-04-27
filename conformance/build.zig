const std = @import("std");
const pb = @import("pb");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "filter", "List of filters for tests.") orelse &.{};
    const bin_install = !(b.option(bool, "no-bin", "Don't install any of the artifacts implied by the specified steps.") orelse false);
    const bin_run = !(b.option(bool, "no-run", "Don't run any of the executables implied by the specified steps.") orelse false);
    // Disabled by default due to it slowing down test-vector execution.
    const enable_fuzz = b.option(bool, "enable-fuzz", "Enables SanCov points for fuzzing and tracing") orelse false;

    const install_step = b.getInstallStep();
    const solfuzz_sig_step = b.step("solfuzz_sig", "The solfuzz sig library.");
    const test_step = b.step("test", "Run unit tests");

    const proto_step = b.step(
        "protobuf",
        "Re-generate protobuf definitions from the protosol dependency pinned in build.zig.zon.",
    );

    const sig_dep = b.dependency("sig", .{
        .target = target,
        .optimize = optimize,
        .@"enable-tsan" = false,
        .ledger = .hashmap,
    });
    const sig_mod = sig_dep.module("sig");

    const pb_dep = b.dependency("pb", .{
        .target = target,
        .optimize = optimize,
    });
    const pb_mod = pb_dep.module("protobuf");

    const common_imports = [_]Build.Module.Import{
        .{ .name = "sig", .module = sig_mod },
        .{ .name = "protobuf", .module = pb_mod },
    };

    const solfuzz_sig_lib = b.addLibrary(.{
        .name = "solfuzz_sig",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .omit_frame_pointer = false,
            .fuzz = enable_fuzz,
            .imports = &common_imports,
        }),
    });
    // the self-hosted backend causes a lot of issues when running in python test suite
    solfuzz_sig_lib.use_llvm = true;
    solfuzz_sig_step.dependOn(&solfuzz_sig_lib.step);
    install_step.dependOn(&solfuzz_sig_lib.step);

    if (bin_install) {
        const solfuzz_sig_install = b.addInstallArtifact(solfuzz_sig_lib, .{});
        solfuzz_sig_step.dependOn(&solfuzz_sig_install.step);
        install_step.dependOn(&solfuzz_sig_install.step);
    }

    const test_exe = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &common_imports,
        }),
        .filters = filters,
    });
    test_step.dependOn(&test_exe.step);
    install_step.dependOn(&test_exe.step);

    if (bin_install) {
        const test_install = b.addInstallArtifact(test_exe, .{});
        test_step.dependOn(&test_install.step);
        install_step.dependOn(&test_install.step);
    }

    if (bin_run) {
        const test_run = b.addRunArtifact(test_exe);
        test_step.dependOn(&test_run.step);
    }

    const protosol_dep = b.dependency("protosol", .{});
    const proto_dir = protosol_dep.path("proto").getPath(b);
    const protoc_run = pb.RunProtocStep.create(pb_dep.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            std.fs.path.join(b.allocator, &.{ proto_dir, "vm.proto" }) catch @panic("OOM"),
            std.fs.path.join(b.allocator, &.{ proto_dir, "txn.proto" }) catch @panic("OOM"),
        },
        .include_directories = &.{proto_dir},
    });
    proto_step.dependOn(&protoc_run.step);
}
