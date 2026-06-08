const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option(
        []const []const u8,
        "filter",
        "List of filters, used for example to filter unit tests by name. " ++
            "Specified as a series like `-Dfilter='filter1' -Dfilter='filter2'`.",
    );
    const use_llvm = b.option(
        bool,
        "use-llvm",
        "If disabled, uses experimental self-hosted backend. Only works for x86_64-linux",
    ) orelse true;
    const long_tests = b.option(
        bool,
        "long-tests",
        "Run extra tests that take a long time, for more exhaustive coverage.",
    ) orelse (filters != null);
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
            "(avx512ifma + avx512vl). Without this flag, building for an x86_64 target " ++
            "without these features is a compile-time error so the performance hit is " ++
            "not silently accepted.",
    ) orelse (optimize == .Debug);

    const test_step = b.step("test", "Run shared unit tests");

    const build_options = b.addOptions();
    build_options.addOption(bool, "long_tests", long_tests);
    build_options.addOption(bool, "allow_no_sha", allow_no_sha);
    build_options.addOption(bool, "allow_no_avx512", allow_no_avx512);

    const dep_opts = .{
        .target = target,
        .optimize = optimize,
    };

    const base58_mod = b.dependency("base58", dep_opts).module("base58");
    const poseidon_mod = b.dependency("poseidon", dep_opts).module("poseidon");
    const secp256k1_mod = b.dependency("secp256k1", dep_opts).module("secp256k1");
    const blst_mod = b.dependency("blst", dep_opts).module("blst");
    const tracy_mod = b.dependency("tracy", .{
        .target = target,
        .optimize = optimize,
        .tracy_enable = false,
        .tracy_on_demand = false,
        .tracy_no_system_tracing = false,
        .tracy_callstack = 6,
    }).module("tracy");
    tracy_mod.sanitize_c = .off;

    const std14_mod = b.createModule(.{
        .root_source_file = b.path("std14.zig"),
        .target = target,
        .optimize = optimize,
    });
    const feature_set_id_gen = b.addRunArtifact(addFeatureSetIdGenerator(b, use_llvm));
    const feature_set_id = b.createModule(.{
        .root_source_file = feature_set_id_gen.addOutputFileArg("feature-set-id.zig"),
    });
    const gh_table = b.createModule(.{
        .root_source_file = generateTable(b, use_llvm),
        .target = target,
        .optimize = optimize,
    });

    const imports: []const Build.Module.Import = &.{
        .{ .name = "base58", .module = base58_mod },
        .{ .name = "blst", .module = blst_mod },
        .{ .name = "build-options", .module = build_options.createModule() },
        .{ .name = "feature-set-id", .module = feature_set_id },
        .{ .name = "poseidon", .module = poseidon_mod },
        .{ .name = "secp256k1", .module = secp256k1_mod },
        .{ .name = "std14", .module = std14_mod },
        .{ .name = "table", .module = gh_table },
        .{ .name = "tracy", .module = tracy_mod },
    };

    const shared_mod = b.createModule(.{
        .root_source_file = b.path("lib.zig"),
        .target = target,
        .optimize = optimize,
        .imports = imports,
    });

    const shared_tests = b.addTest(.{
        .name = "shared",
        .root_module = shared_mod,
        .filters = filters orelse &.{},
        .use_llvm = use_llvm,
    });
    const run_shared_tests = b.addRunArtifact(shared_tests);
    test_step.dependOn(&run_shared_tests.step);
}

fn generateTable(b: *Build, use_llvm: bool) Build.LazyPath {
    const gen = b.addExecutable(.{
        .name = "generator_chain",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .Debug,
            .root_source_file = b.path("../scripts/generator_chain.zig"),
        }),
        .use_llvm = use_llvm,
    });
    const run = b.addRunArtifact(gen);
    const generated = run.captureStdOut();
    const wf = b.addWriteFiles();
    const table_file = wf.addCopyFile(generated, "table.zig");
    wf.step.dependOn(&run.step);
    return table_file;
}

fn addFeatureSetIdGenerator(b: *Build, use_llvm: bool) *Build.Step.Compile {
    return b.addExecutable(.{
        .name = "gen_feature_set_id",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            .optimize = .Debug,
            .root_source_file = b.path("../scripts/gen_feature_set_id.zig"),
            .imports = &.{
                .{
                    .name = "base58",
                    .module = b.dependency("base58", .{}).module("base58"),
                },
                .{
                    .name = "features",
                    .module = b.createModule(.{
                        .root_source_file = b.path("core/features.zon"),
                    }),
                },
            },
        }),
        .use_llvm = use_llvm,
    });
}
