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
        },
    });

    lib.addModule("base58-zig", base58_module);
    lib.addModule("zig-network", zig_network_module);
    lib.addModule("zig-cli", zig_cli_module);
    lib.addModule("getty", getty_mod);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    // const main_tests = b.addTest(.{
    //     .root_source_file = .{ .path = "src/main.zig" },
    //     .target = target,
    //     .optimize = optimize,
    // });

    // const run_main_tests = b.addRunArtifact(main_tests);

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

    const run_tests = b.addRunArtifact(tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
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
}
