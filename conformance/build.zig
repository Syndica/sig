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
        "Re-generate protobuf definitions by fetching proto files from the protosol" ++
            " repo at the commit pinned in commits.env (SOLFUZZ_AGAVE_PROTOSOL_COMMIT)." ++
            " Requires curl and network access on first run; results are cached in .zig-cache/.",
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

    // --- Protobuf generation step ---
    // Read the pinned protosol commit from commits.env and fetch proto files
    // directly from GitHub, cached in .zig-cache/protosol-<commit>/.
    const protosol_commit = parseCommitsEnv(b, "SOLFUZZ_AGAVE_PROTOSOL_COMMIT") orelse
        @panic("SOLFUZZ_AGAVE_PROTOSOL_COMMIT not found in commits.env");

    // Proto files to generate Zig code for:
    const source_protos = &[_][]const u8{ "vm.proto", "txn.proto" };
    // All proto files needed (sources + transitive imports):
    const all_protos = &[_][]const u8{
        "vm.proto",
        "txn.proto",
        "invoke.proto",
        "context.proto",
        "metadata.proto",
    };
    const fetch = FetchProtosStep.create(b, protosol_commit, all_protos);

    const protoc_run = pb.RunProtocStep.create(pb_dep.builder, target, .{
        .destination_directory = b.path("src/proto"),
        .source_files = fetch.getSourceFilePaths(b, source_protos),
        .include_directories = &.{fetch.getCacheDir()},
    });
    protoc_run.step.dependOn(&fetch.step);
    proto_step.dependOn(&protoc_run.step);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a KEY="VALUE" pair from commits.env (shell-style).
fn parseCommitsEnv(b: *Build, key: []const u8) ?[]const u8 {
    const content = b.build_root.handle.readFileAlloc(b.allocator, "commits.env", 8192) catch |err| {
        std.log.err("Failed to read commits.env: {}", .{err});
        return null;
    };

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Match KEY=... at line start
        if (!std.mem.startsWith(u8, trimmed, key)) continue;
        const rest = trimmed[key.len..];
        if (rest.len == 0 or rest[0] != '=') continue;

        const val = rest[1..];
        // Strip surrounding quotes if present
        if (val.len >= 2 and val[0] == '"' and val[val.len - 1] == '"') {
            return b.dupe(val[1 .. val.len - 1]);
        }
        return b.dupe(val);
    }
    return null;
}

// ---------------------------------------------------------------------------
// FetchProtosStep – downloads .proto files from GitHub at a pinned commit
// ---------------------------------------------------------------------------

const FetchProtosStep = struct {
    step: std.Build.Step,
    proto_names: []const []const u8,
    commit: []const u8,
    cache_dir: []const u8, // absolute path

    const github_raw_base = "https://raw.githubusercontent.com/firedancer-io/protosol";

    pub fn create(
        b: *Build,
        commit: []const u8,
        proto_names: []const []const u8,
    ) *FetchProtosStep {
        const sub_dir = std.fmt.allocPrint(b.allocator, "protosol-{s}", .{commit}) catch @panic("OOM");
        const cache_dir = b.cache_root.join(b.allocator, &.{sub_dir}) catch @panic("OOM");

        const self = b.allocator.create(FetchProtosStep) catch @panic("OOM");
        self.* = .{
            .step = std.Build.Step.init(.{
                .id = .check_file,
                .name = "fetch protosol proto files",
                .owner = b,
                .makeFn = make,
            }),
            .proto_names = b.dupeStrings(proto_names),
            .commit = b.dupe(commit),
            .cache_dir = cache_dir,
        };
        return self;
    }

    /// Return paths suitable for RunProtocStep.Options.source_files.
    pub fn getSourceFilePaths(self: *const FetchProtosStep, b: *Build, names: []const []const u8) []const []const u8 {
        const paths = b.allocator.alloc([]const u8, names.len) catch @panic("OOM");
        for (paths, names) |*dest, name| {
            dest.* = std.fs.path.join(b.allocator, &.{ self.cache_dir, name }) catch @panic("OOM");
        }
        return paths;
    }

    /// Return the cache directory path for use as a protoc -I include dir.
    pub fn getCacheDir(self: *const FetchProtosStep) []const u8 {
        return self.cache_dir;
    }

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const self: *FetchProtosStep = @fieldParentPtr("step", step);
        const b = step.owner;
        const cwd = std.fs.cwd();

        // Fast path: skip download if every file is already cached.
        const all_cached = blk: {
            for (self.proto_names) |name| {
                const path = try std.fs.path.join(b.allocator, &.{ self.cache_dir, name });
                cwd.access(path, .{}) catch break :blk false;
            }
            break :blk true;
        };

        if (all_cached) return;

        // Ensure the cache directory exists.
        cwd.makePath(self.cache_dir) catch |err| {
            std.log.err("Failed to create cache dir '{s}': {}", .{ self.cache_dir, err });
            return err;
        };

        // Download each missing proto file via curl.
        for (self.proto_names) |name| {
            const dest = try std.fs.path.join(b.allocator, &.{ self.cache_dir, name });

            // Skip files that are already present.
            cwd.access(dest, .{}) catch {
                const url = try std.fmt.allocPrint(
                    b.allocator,
                    "{s}/{s}/proto/{s}",
                    .{ github_raw_base, self.commit, name },
                );

                std.log.info("Fetching {s}", .{url});
                _ = try step.evalChildProcess(&.{ "curl", "-fsSL", "--create-dirs", "-o", dest, url });
                continue;
            };
        }
    }
};
