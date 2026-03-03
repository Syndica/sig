const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const xev_dep = b.dependency("libxev", .{ .target = target, .optimize = optimize });

    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "webzockets",
        .root_module = lib_mod,
    });

    _ = b.addModule("webzockets", .{
        .root_source_file = b.path("src/root.zig"),
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });

    b.installArtifact(lib);

    const echo_server_mod = b.createModule(.{
        .root_source_file = b.path("examples/echo_server.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });
    echo_server_mod.addImport("webzockets_lib", lib_mod);

    const echo_server_exe = b.addExecutable(.{
        .name = "echo-server",
        .root_module = echo_server_mod,
    });
    b.installArtifact(echo_server_exe);

    const run_echo_server_cmd = b.addRunArtifact(echo_server_exe);
    run_echo_server_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_echo_server_cmd.addArgs(args);
    }
    const run_echo_server_step = b.step("run-echo-server", "Run the example echo server");
    run_echo_server_step.dependOn(&run_echo_server_cmd.step);

    const echo_client_mod = b.createModule(.{
        .root_source_file = b.path("examples/simple_client.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });
    echo_client_mod.addImport("webzockets_lib", lib_mod);

    const echo_client_exe = b.addExecutable(.{
        .name = "simple-client",
        .root_module = echo_client_mod,
    });
    b.installArtifact(echo_client_exe);

    const run_echo_client_cmd = b.addRunArtifact(echo_client_exe);
    run_echo_client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_echo_client_cmd.addArgs(args);
    }
    const run_echo_client_step = b.step("run-simple-client", "Run the example simple client");
    run_echo_client_step.dependOn(&run_echo_client_cmd.step);

    // Autobahn testsuite echo server
    const autobahn_mod = b.createModule(.{
        .root_source_file = b.path("autobahn/server/server.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });
    autobahn_mod.addImport("webzockets_lib", lib_mod);

    const autobahn_exe = b.addExecutable(.{
        .name = "autobahn-server",
        .root_module = autobahn_mod,
    });

    b.installArtifact(autobahn_exe);

    const run_autobahn_cmd = b.addRunArtifact(autobahn_exe);
    run_autobahn_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_autobahn_cmd.addArgs(args);
    }

    const run_autobahn_step = b.step("run-autobahn", "Run the Autobahn testsuite echo server");
    run_autobahn_step.dependOn(&run_autobahn_cmd.step);

    // Autobahn testsuite client runner
    const autobahn_client_mod = b.createModule(.{
        .root_source_file = b.path("autobahn/client/client.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });
    autobahn_client_mod.addImport("webzockets_lib", lib_mod);

    const autobahn_client_exe = b.addExecutable(.{
        .name = "autobahn-client",
        .root_module = autobahn_client_mod,
    });

    b.installArtifact(autobahn_client_exe);

    const run_autobahn_client_cmd = b.addRunArtifact(autobahn_client_exe);
    run_autobahn_client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_autobahn_client_cmd.addArgs(args);
    }

    const run_autobahn_client_step = b.step(
        "run-autobahn-client",
        "Run the Autobahn testsuite client runner",
    );
    run_autobahn_client_step.dependOn(&run_autobahn_client_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const e2e_mod = b.createModule(.{
        .root_source_file = b.path("e2e_tests/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_dep.module("xev") },
        },
    });
    e2e_mod.addImport("webzockets_lib", lib_mod);

    const e2e_tests = b.addTest(.{
        .root_module = e2e_mod,
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_e2e_tests.step);
}
