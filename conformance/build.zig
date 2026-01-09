const std = @import("std");
const pb = @import("pb");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "filter", "List of filters for tests.") orelse &.{};
    const bin_install = !(b.option(bool, "no-bin", "Don't install any of the artifacts implied by the specified steps.") orelse false);
    const bin_run = !(b.option(bool, "no-run", "Don't run any of the executables implied by the specified steps.") orelse false);

    const install_step = b.getInstallStep();
    const solfuzz_sig_step = b.step("solfuzz_sig", "The solfuzz sig library.");
    const test_step = b.step("test", "Run unit tests");

    // current commit: 90ec31a506593fc9574d2c09f76e64d202b23124
    const proto_step = b.step(
        "protobuf",
        "Re-generate protobuf definitions based on the `protosol` directory." ++
            " Must clone the protosol repo for this to work." ++
            " You should never need to do under normal circumstances.",
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
            // NOTE: enable fuzzing for when we actually want to fuzz. This only slows us down when
            // running fixtures.
            .fuzz = false,
            .imports = &common_imports,
        }),
    });
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

    const protoc_run = pb.RunProtocStep.create(b, pb_dep.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            "protosol/proto/elf.proto",
            "protosol/proto/vm.proto",
            "protosol/proto/shred.proto",
            "protosol/proto/txn.proto",
        },
        .include_directories = &.{"protosol/proto"},
    });
    proto_step.dependOn(&protoc_run.step);
}
