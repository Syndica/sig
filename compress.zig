const std = @import("std");

pub fn main() !void {
    const file = try std.fs.cwd().openFile("manifest.abbrev.bin", .{});
    defer file.close();

    const outfile = try std.fs.cwd().createFile("manifest.abbrev.bin.gz", .{});
    defer outfile.close();

    const input = file.reader();
    const output = outfile.writer();
    try std.compress.gzip.compress(input, output, .{});
}
