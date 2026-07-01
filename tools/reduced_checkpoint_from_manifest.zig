const std = @import("std");
const sig = @import("sig");

const Manifest = sig.accounts_db.snapshot.Manifest;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;
const Args = struct {
    full_manifest: []u8,
    incremental_manifest: ?[]u8 = null,
    out: []u8,
};

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const args = parseArgs(allocator) catch |err| {
        std.debug.print(
            "usage: reduced-checkpoint-from-manifest --full-manifest <path> [--incremental-manifest <path>] --out <path>\nerror: {s}\n",
            .{@errorName(err)},
        );
        return err;
    };
    defer allocator.free(args.full_manifest);
    defer if (args.incremental_manifest) |path| allocator.free(path);
    defer allocator.free(args.out);

    var full_manifest = try Manifest.readFromFilePath(allocator, args.full_manifest);
    defer full_manifest.deinit(allocator);

    const maybe_incremental_manifest: ?Manifest = if (args.incremental_manifest) |path|
        try Manifest.readFromFilePath(allocator, path)
    else
        null;
    defer if (maybe_incremental_manifest) |manifest| manifest.deinit(allocator);

    const combined: FullAndIncrementalManifest = .{
        .full = full_manifest,
        .incremental = maybe_incremental_manifest,
    };

    var collapsed = try combined.collapse(allocator);
    defer collapsed.deinit(allocator);

    var checkpoint = try sig.accounts_db.snapshot.ReducedCheckpoint.fromManifest(allocator, &collapsed);
    defer checkpoint.deinit(allocator);

    try checkpoint.writeToFilePath(args.out);

    std.debug.print(
        "reduced_checkpoint_written path={s} root_slot={} full_slot={} incremental_slot={?}\n",
        .{
            args.out,
            collapsed.bank_fields.slot,
            full_manifest.bank_fields.slot,
            if (maybe_incremental_manifest) |manifest| manifest.bank_fields.slot else null,
        },
    );
}

fn parseArgs(allocator: std.mem.Allocator) !Args {
    const raw = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw);

    var full_manifest: ?[]u8 = null;
    var incremental_manifest: ?[]u8 = null;
    var out: ?[]u8 = null;

    var i: usize = 1;
    while (i < raw.len) : (i += 1) {
        const arg = raw[i];
        if (std.mem.eql(u8, arg, "--full-manifest")) {
            i += 1;
            if (i >= raw.len) return error.MissingFullManifest;
            full_manifest = try allocator.dupe(u8, raw[i]);
        } else if (std.mem.eql(u8, arg, "--incremental-manifest")) {
            i += 1;
            if (i >= raw.len) return error.MissingIncrementalManifest;
            incremental_manifest = try allocator.dupe(u8, raw[i]);
        } else if (std.mem.eql(u8, arg, "--out")) {
            i += 1;
            if (i >= raw.len) return error.MissingOutput;
            out = try allocator.dupe(u8, raw[i]);
        } else {
            return error.UnknownArgument;
        }
    }

    return .{
        .full_manifest = full_manifest orelse return error.MissingFullManifest,
        .incremental_manifest = incremental_manifest,
        .out = out orelse return error.MissingOutput,
    };
}
