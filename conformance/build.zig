const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sig = b.dependency("sig", .{
        .target = target,
        .optimize = optimize,
        .@"enable-tsan" = false,
        .blockstore = .hashmap,
        .force_pic = true,
    });

    const pb = b.lazyDependency("pb", .{
        .target = target,
        .optimize = optimize,
    }) orelse return;
    const protobuf = b.lazyImport(@This(), "pb") orelse return;

    var protoc_step = protobuf.RunProtocStep.create(b, pb.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = &.{
            "protosol/proto/elf.proto",
            "protosol/proto/vm.proto",
            "protosol/proto/shred.proto",
        },
        .include_directories = &.{"protosol/proto"},
    });

    const lib = b.addLibrary(.{
        .name = "solfuzz_sig",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .omit_frame_pointer = false,
            .imports = &.{
                .{ .name = "sig", .module = sig.module("sig") },
                .{ .name = "protobuf", .module = pb.module("protobuf") },
            },
        }),
    });

    lib.root_module.fuzz = true;
    lib.step.dependOn(&protoc_step.step);
    b.installArtifact(lib);
}
