const std = @import("std");

const package_name = "sig";
const package_path = "src/lib.zig";

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const opts = .{ .target = target, .optimize = optimize };
    const base58_module = b.dependency("base58-zig", opts).module("base58-zig");
    const zig_network_module = b.dependency("zig-network", opts).module("network");
    const zig_cli_module = b.dependency("zig-cli", opts).module("zig-cli");
    const getty_mod = b.dependency("getty", opts).module("getty");
    const httpz_mod = b.dependency("httpz", opts).module("httpz");
    const zigdig_mod = b.dependency("zigdig", opts).module("dns");

    const lib = b.addStaticLibrary(.{
        .name = "sig",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/lib.zig" },
        .target = target,
        .optimize = optimize,
    });

    // expose Sig as a module
    _ = b.addModule(package_name, .{
        .source_file = .{ .path = package_path },
        .dependencies = &.{
            .{
                .name = "zig-network",
                .module = zig_network_module,
            },
            .{
                .name = "base58-zig",
                .module = base58_module,
            },
            .{
                .name = "zig-cli",
                .module = zig_cli_module,
            },
            .{
                .name = "getty",
                .module = getty_mod,
            },
            .{
                .name = "httpz",
                .module = httpz_mod,
            },
            .{
                .name = "zigdig",
                .module = zigdig_mod,
            },
        },
    });

    lib.addModule("base58-zig", base58_module);
    lib.addModule("zig-network", zig_network_module);
    lib.addModule("zig-cli", zig_cli_module);
    lib.addModule("getty", getty_mod);
    lib.addModule("httpz", httpz_mod);
    lib.addModule("zigdig", zigdig_mod);

    // ZSTD
    const ZSTD_C_PATH = "src/zstd/c/lib";
    const zstd_lib = b.addStaticLibrary(.{
        .name = "zstd",
        .target = target,
        .optimize = optimize,
    });
    zstd_lib.linkLibC();
    zstd_lib.addIncludePath(.{ .path = ZSTD_C_PATH });
    zstd_lib.installHeader(ZSTD_C_PATH ++ "/zstd.h", "zstd.h");
    zstd_lib.installHeader(ZSTD_C_PATH ++ "/zstd_errors.h", "zstd_errors.h");

    // TODO: make sure we compile with -03
    const config_header = b.addConfigHeader(
        .{
            .style = .{ .autoconf = .{ .path = "src/zstd/c/config.h.in" } },
        },
        .{
            .ZSTD_MULTITHREAD_SUPPORT_DEFAULT = null,
            .ZSTD_LEGACY_SUPPORT = null,
        },
    );
    zstd_lib.addConfigHeader(config_header);
    zstd_lib.addCSourceFiles(&.{
        ZSTD_C_PATH ++ "/common/debug.c",
        ZSTD_C_PATH ++ "/common/entropy_common.c",
        ZSTD_C_PATH ++ "/common/error_private.c",
        ZSTD_C_PATH ++ "/common/fse_decompress.c",
        ZSTD_C_PATH ++ "/common/pool.c",
        ZSTD_C_PATH ++ "/common/threading.c",
        ZSTD_C_PATH ++ "/common/xxhash.c",
        ZSTD_C_PATH ++ "/common/zstd_common.c",

        ZSTD_C_PATH ++ "/compress/zstd_double_fast.c",
        ZSTD_C_PATH ++ "/compress/zstd_compress_literals.c",
        ZSTD_C_PATH ++ "/compress/zstdmt_compress.c",
        ZSTD_C_PATH ++ "/compress/zstd_opt.c",
        ZSTD_C_PATH ++ "/compress/zstd_compress_sequences.c",
        ZSTD_C_PATH ++ "/compress/zstd_lazy.c",
        ZSTD_C_PATH ++ "/compress/hist.c",
        ZSTD_C_PATH ++ "/compress/zstd_ldm.c",
        ZSTD_C_PATH ++ "/compress/huf_compress.c",
        ZSTD_C_PATH ++ "/compress/zstd_compress_superblock.c",
        ZSTD_C_PATH ++ "/compress/zstd_compress.c",
        ZSTD_C_PATH ++ "/compress/fse_compress.c",
        ZSTD_C_PATH ++ "/compress/zstd_fast.c",

        ZSTD_C_PATH ++ "/decompress/zstd_decompress.c",
        ZSTD_C_PATH ++ "/decompress/zstd_ddict.c",
        ZSTD_C_PATH ++ "/decompress/zstd_decompress_block.c",
        ZSTD_C_PATH ++ "/decompress/huf_decompress.c",
    }, &.{});
    zstd_lib.addAssemblyFile(.{ .path = ZSTD_C_PATH ++ "/decompress/huf_decompress_amd64.S" });
    b.installArtifact(zstd_lib);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // unit tests
    const tests = b.addTest(.{
        .root_source_file = .{ .path = "src/tests.zig" },
        .target = target,
        .optimize = optimize,
        .filter = if (b.args) |args| args[0] else null, // filter tests like so: zig build test -- "<FILTER>"
    });
    tests.addModule("zig-network", zig_network_module);
    tests.addModule("base58-zig", base58_module);
    tests.addModule("zig-cli", zig_cli_module);
    tests.addModule("getty", getty_mod);
    tests.addModule("httpz", httpz_mod);
    tests.addModule("zigdig", zigdig_mod);
    tests.linkLibrary(zstd_lib);

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&lib.step);
    test_step.dependOn(&run_tests.step);

    const exe = b.addExecutable(.{
        .name = "sig",
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addModule("base58-zig", base58_module);
    exe.addModule("zig-network", zig_network_module);
    exe.addModule("zig-cli", zig_cli_module);
    exe.addModule("getty", getty_mod);
    exe.addModule("httpz", httpz_mod);
    exe.addModule("zigdig", zigdig_mod);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const ExecCommand = struct {
        name: []const u8,
        path: []const u8,
        description: []const u8 = "",
    };

    const exec_commands = [_]ExecCommand{
        ExecCommand{
            .name = "fuzz",
            .path = "src/gossip/fuzz.zig",
            .description = "gossip fuzz testing",
        },
        ExecCommand{
            .name = "benchmark",
            .path = "src/benchmarks.zig",
            .description = "benchmark client",
        },
        ExecCommand{
            .name = "db",
            .path = "src/accountsdb/db.zig",
            .description = "run accounts-db code",
        },
    };

    for (exec_commands) |command_info| {
        const exec = b.addExecutable(.{
            .name = command_info.name,
            .root_source_file = .{ .path = command_info.path },
            .target = target,
            .optimize = optimize,
            .main_pkg_path = .{ .path = "src" },
        });

        // TODO: maybe we dont need all these for all bins
        exec.addModule("base58-zig", base58_module);
        exec.addModule("zig-network", zig_network_module);
        exec.addModule("zig-cli", zig_cli_module);
        exec.addModule("getty", getty_mod);
        exec.addModule("httpz", httpz_mod);
        exec.addModule("zigdig", zigdig_mod);

        // this lets us run it as an exec
        b.installArtifact(exec);
        exec.linkLibrary(zstd_lib);

        const cmd = b.addRunArtifact(exec);
        if (b.args) |args| cmd.addArgs(args);
        b
            .step(command_info.name, command_info.description)
            .dependOn(&cmd.step);
    }
}
