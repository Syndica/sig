const std = @import("std");
const sig = @import("sig");

pub fn main() !void {
    const allocator = std.heap.c_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len != 2) {
        std.debug.print(
            \\usage: feature-id <name|id|id_hex|pubkey>
            \\  name:    feature name (e.g. "blake3_syscall_enabled")
            \\  id:      decimal u64 feature id
            \\  id_hex:  hex u64 feature id, with "0x" prefix
            \\  pubkey:  base58-encoded feature pubkey
            \\
        , .{});
        std.posix.exit(2);
    }

    const arg = args[1];

    const needle_id: ?u64 = std.fmt.parseInt(u64, arg, 0) catch null;
    const needle_pubkey: ?sig.core.Pubkey = sig.core.Pubkey.parseRuntime(arg) catch null;

    const match: ?sig.core.features.ZonInfo = for (sig.core.features.all_features) |feature| {
        if (std.mem.eql(u8, std.mem.sliceTo(feature.name, 0), arg)) break feature;
        if (needle_id) |needle| {
            if (feature.id() == needle) break feature;
        }
        if (needle_pubkey) |needle| {
            const fpk = sig.core.Pubkey.parseRuntime(std.mem.sliceTo(feature.pubkey, 0)) catch
                continue;
            if (fpk.equals(&needle)) break feature;
        }
    } else null;

    const feature = match orelse {
        std.debug.print("feature not found: {s}\n", .{arg});
        std.posix.exit(1);
    };

    const stdout = std.fs.File.stdout().deprecatedWriter();
    try stdout.print("name:        {s}\n", .{std.mem.sliceTo(feature.name, 0)});
    try stdout.print("pubkey:      {s}\n", .{std.mem.sliceTo(feature.pubkey, 0)});
    try stdout.print("id:          {d}\n", .{feature.id()});
    try stdout.print("id_hex:      0x{x:0>16}\n", .{feature.id()});
    try stdout.print("status:      {s}\n", .{@tagName(feature.status)});
    try stdout.print("description: {s}\n", .{std.mem.sliceTo(feature.description, 0)});
    if (feature.note) |note| {
        try stdout.print("note:\n{s}\n", .{std.mem.sliceTo(note, 0)});
    }
}
