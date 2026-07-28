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
    const include_sig = !(b.option(bool, "no-sig", "Exclude sig from the `run` executable (builds faster)") orelse false);
    const allow_no_sha = b.option(
        bool,
        "allow-no-sha",
        "Forwarded to the sig dependency. Opt in to a slower software fallback when the " ++
            "target lacks the x86 SHA extension.",
    ) orelse (optimize == .Debug);
    const allow_no_avx512 = b.option(
        bool,
        "allow-no-avx512",
        "Forwarded to the sig dependency. Opt in to a slower generic ed25519 path when the " ++
            "target lacks AVX-512.",
    ) orelse (optimize == .Debug);

    // Logs are on by default; pass `-Ddisable-feature-status-logs` to silence
    // them during noisy full fixture runs.
    const log_feature_status = !(b.option(
        bool,
        "disable-feature-status-logs",
        "Suppress the debug log lines emitted for fixture features that are unknown, " ++
            "reverted, or unsupported in Sig.",
    ) orelse false);

    const build_options = b.addOptions();
    build_options.addOption(bool, "include_sig", include_sig);
    build_options.addOption(bool, "log_feature_status", log_feature_status);

    const install_step = b.getInstallStep();
    const solfuzz_sig_step = b.step("solfuzz_sig", "The solfuzz sig library.");
    const run_step = b.step("run", "Run test fixtures");
    const feature_id_step = b.step("feature-id", "Print metadata for a feature by name or id.");
    const test_step = b.step("test", "Run unit tests");

    const proto_step = b.step(
        "protobuf",
        "Re-generate protobuf definitions from the protosol dependency pinned in build.zig.zon.",
    );

    // Every option we pass to sig_v2 directly must also be forwarded through
    // v1 (via the `sig` dependency below) with the same value. If any
    // option-value pair drifts between the two dep chains, Zig 0.15 treats
    // them as distinct sig_v2 packages and refuses to link the two `runtime`
    // module instances into one binary. The comments in v1/build.zig's
    // Config document each forwarded option.
    const v2_options = .{
        .target = target,
        .optimize = optimize,
        .@"long-tests" = false,
        .@"allow-no-sha" = allow_no_sha,
        .@"allow-no-avx512" = allow_no_avx512,
        .@"use-llvm" = true,
        .@"enable-tracy" = false,
        .@"tracy-on-demand" = false,
        .@"tracy-no-exit" = false,
        // The shred-parse harness feeds the Receiver shreds whose merkle
        // roots are not signed by any known leader, so sig_v2 is built with
        // the ed25519 verify path stubbed out at comptime. Shred-version
        // checking stays on (the default).
        .@"debug-skip-shred-sig-verify" = true,
        .@"debug-skip-shred-version-check" = false,
    };

    const sig_dep = b.dependency("sig", .{
        .target = target,
        .optimize = optimize,
        .@"enable-tsan" = false,
        .ledger = .hashmap,
        .@"allow-no-sha" = allow_no_sha,
        .@"allow-no-avx512" = allow_no_avx512,
        .@"long-tests" = v2_options.@"long-tests",
        .@"use-llvm" = v2_options.@"use-llvm",
        .@"enable-tracy" = v2_options.@"enable-tracy",
        .@"tracy-on-demand" = v2_options.@"tracy-on-demand",
        .@"tracy-no-exit" = v2_options.@"tracy-no-exit",
        .@"debug-skip-shred-sig-verify" = v2_options.@"debug-skip-shred-sig-verify",
        .@"debug-skip-shred-version-check" = v2_options.@"debug-skip-shred-version-check",
    });
    const sig_mod = sig_dep.module("sig");

    const sig_v2_dep = b.dependency("sig_v2", v2_options);
    const sig_v2_mod = sig_v2_dep.module("lib");
    const shred_api_mod = sig_v2_dep.module("shred_api");
    const shred_mod = sig_v2_dep.module("shred");

    const pb_dep = b.dependency("pb", .{
        .target = target,
        .optimize = optimize,
    });
    const pb_mod = pb_dep.module("protobuf");

    const common_imports = [_]Build.Module.Import{
        .{ .name = "sig", .module = sig_mod },
        .{ .name = "sig_v2", .module = sig_v2_mod },
        .{ .name = "shred_api", .module = shred_api_mod },
        .{ .name = "shred", .module = shred_mod },
        .{ .name = "protobuf", .module = pb_mod },
        .{ .name = "build-options", .module = build_options.createModule() },
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
    // Self-hosted backend hits issues in the python test suite and can't
    // lower sig_v2's AVX-512 vector code.
    solfuzz_sig_lib.use_llvm = true;
    solfuzz_sig_step.dependOn(&solfuzz_sig_lib.step);
    install_step.dependOn(&solfuzz_sig_lib.step);

    if (bin_install) {
        const solfuzz_sig_install = b.addInstallArtifact(solfuzz_sig_lib, .{});
        solfuzz_sig_step.dependOn(&solfuzz_sig_install.step);
        install_step.dependOn(&solfuzz_sig_install.step);
    }

    const exe = b.addExecutable(.{
        .name = "run",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = optimize,
            .root_source_file = b.path("src/main.zig"),
            .imports = if (include_sig)
                &common_imports
            else
                &.{.{ .name = "build-options", .module = build_options.createModule() }},
        }),
    });
    exe.linkLibC();
    exe.use_llvm = true;
    run_step.dependOn(&exe.step);
    install_step.dependOn(&exe.step);

    if (bin_install) {
        const exe_install = b.addInstallArtifact(exe, .{});
        run_step.dependOn(&exe_install.step);
        install_step.dependOn(&exe_install.step);
    }
    if (bin_run) {
        const run_cmd = b.addRunArtifact(exe);
        run_cmd.addArgs(b.args orelse &.{});
        run_step.dependOn(&run_cmd.step);
    }

    const feature_id_exe = b.addExecutable(.{
        .name = "feature-id",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = optimize,
            .root_source_file = b.path("src/feature_id.zig"),
            .imports = &.{
                .{ .name = "sig", .module = sig_mod },
                .{ .name = "build-options", .module = build_options.createModule() },
            },
        }),
    });
    feature_id_exe.linkLibC();
    feature_id_exe.use_llvm = true;
    feature_id_step.dependOn(&feature_id_exe.step);
    install_step.dependOn(&feature_id_exe.step);

    if (bin_install) {
        const feature_id_install = b.addInstallArtifact(feature_id_exe, .{});
        feature_id_step.dependOn(&feature_id_install.step);
        install_step.dependOn(&feature_id_install.step);
    }
    if (bin_run) {
        const feature_id_run = b.addRunArtifact(feature_id_exe);
        feature_id_run.addArgs(b.args orelse &.{});
        feature_id_step.dependOn(&feature_id_run.step);
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
    // The self-hosted backend can't lower sig_v2's AVX-512 vector code.
    test_exe.use_llvm = true;
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
            std.fs.path.join(b.allocator, &.{ proto_dir, "elf.proto" }) catch @panic("OOM"),
            std.fs.path.join(b.allocator, &.{ proto_dir, "vm_serialization.proto" }) catch @panic("OOM"),
            std.fs.path.join(b.allocator, &.{ proto_dir, "shred.proto" }) catch @panic("OOM"),
            std.fs.path.join(b.allocator, &.{ proto_dir, "metadata.proto" }) catch @panic("OOM"),
        },
        .include_directories = &.{proto_dir},
    });
    proto_step.dependOn(&protoc_run.step);
}
