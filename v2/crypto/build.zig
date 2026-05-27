const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    // Ignore consumer's optimize choice — always ReleaseFast for crypto.
    _ = b.standardOptimizeOption(.{});

    const allow_no_sha = b.option(
        bool,
        "allow-no-sha",
        "Opt in to a slower software fallback when the target lacks the x86 SHA extension.",
    ) orelse false;

    const allow_no_avx512 = b.option(
        bool,
        "allow-no-avx512",
        "Opt in to a slower generic ed25519 path when the target lacks AVX-512.",
    ) orelse false;

    const build_options = b.addOptions();
    build_options.addOption(bool, "allow_no_sha", allow_no_sha);
    build_options.addOption(bool, "allow_no_avx512", allow_no_avx512);
    const build_options_mod = build_options.createModule();

    const tracy_mod = b.dependency("tracy", .{
        .target = target,
        .optimize = .ReleaseFast,
    }).module("tracy");
    const binkode_mod = b.dependency("binkode", .{}).module("binkode");
    const base58_mod = b.dependency("base58", .{}).module("base58");

    const crypto_mod = b.addModule("crypto", .{
        .root_source_file = b.path("lib.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{
            .{ .name = "base58", .module = base58_mod },
            .{ .name = "binkode", .module = binkode_mod },
            .{ .name = "tracy", .module = tracy_mod },
            .{ .name = "build-options", .module = build_options_mod },
        },
    });
    // Self-reference so sub-files can @import("common") to reach the module root.
    crypto_mod.addImport("common", crypto_mod);

    // Test step
    const test_step = b.step("test", "Run crypto unit tests");
    const tests = b.addTest(.{
        .root_module = crypto_mod,
    });
    const run_tests = b.addRunArtifact(tests);
    test_step.dependOn(&run_tests.step);
}
