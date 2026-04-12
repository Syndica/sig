const std = @import("std");
const sig = @import("../../sig.zig");
const data = @import("data.zig");
const load = @import("load.zig");

const Allocator = std.mem.Allocator;
const GenesisConfig = sig.core.GenesisConfig;
const Manifest = data.Manifest;
const LoadedSnapshot = load.LoadedSnapshot;

const Logger = sig.trace.Logger("accountsdb.snapshot.reduced_checkpoint");

/// Initial reduced checkpoint format.
///
/// For the first bootstrap slice this stores only the reduced manifest metadata.
/// The associated reduced local accounts DB is expected to already exist on disk.
/// This keeps the first implementation small while establishing a dedicated
/// selective-bootstrap entry point in Sig.
pub const ReducedCheckpoint = struct {
    manifest: Manifest,

    pub fn deinit(self: *ReducedCheckpoint, allocator: Allocator) void {
        self.manifest.deinit(allocator);
    }

    pub fn readFromFilePath(
        allocator: Allocator,
        path: []const u8,
    ) !ReducedCheckpoint {
        return .{
            .manifest = try Manifest.readFromFilePath(allocator, path),
        };
    }
};

pub fn loadAsLoadedSnapshot(
    allocator: Allocator,
    logger: Logger,
    checkpoint_path: []const u8,
    genesis_file_path: []const u8,
) !LoadedSnapshot {
    logger.info().logf("loading reduced checkpoint from {s}", .{checkpoint_path});

    var checkpoint = try ReducedCheckpoint.readFromFilePath(allocator, checkpoint_path);
    errdefer checkpoint.deinit(allocator);

    const genesis_config = try GenesisConfig.init(allocator, genesis_file_path);
    errdefer genesis_config.deinit(allocator);

    try checkpoint.manifest.bank_fields.validate(&genesis_config);

    const full_manifest = try checkpoint.manifest.clone(allocator);
    errdefer full_manifest.deinit(allocator);

    const collapsed_manifest = checkpoint.manifest;
    checkpoint.manifest = undefined;

    return .{
        .allocator = allocator,
        .combined_manifest = .{
            .full = full_manifest,
            .incremental = null,
        },
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
    };
}
