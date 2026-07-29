const std = @import("std");

pub fn main() !u8 {
    var scratch_mem: [1 << 20]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&scratch_mem);
    const allocator = fba.allocator();

    if (std.os.argv.len != 2) {
        std.debug.print("Usage: {s} <path-to-build.zig.zon>\n", .{std.os.argv[0]});
        return 1;
    }
    const path = std.mem.span(std.os.argv[1]);

    const src = try std.fs.cwd().readFileAllocOptions(allocator, path, 1 << 20, null, .of(u8), 0);
    var ast: std.zig.Ast = try .parse(allocator, src, .zon);

    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    var json: std.json.Stringify = .{ .writer = &stdout_writer.interface };

    var b1: [2]std.zig.Ast.Node.Index = undefined;
    var b2: [2]std.zig.Ast.Node.Index = undefined;
    var b3: [2]std.zig.Ast.Node.Index = undefined;

    try json.beginObject();
    for (ast.fullStructInit(&b1, ast.rootDecls()[0]).?.ast.fields) |field| {
        if (!std.mem.eql(u8, ast.tokenSlice(ast.firstToken(field) - 2), "dependencies")) continue;

        for (ast.fullStructInit(&b2, field).?.ast.fields) |dep| {
            try json.objectField(ast.tokenSlice(ast.firstToken(dep) - 2));
            try json.beginObject();
            for (ast.fullStructInit(&b3, dep).?.ast.fields) |kv| {
                const key = ast.tokenSlice(ast.firstToken(kv) - 2);
                if (!std.mem.eql(u8, key, "url") and
                    !std.mem.eql(u8, key, "hash") and
                    !std.mem.eql(u8, key, "path")) continue;
                const val = try std.zig.string_literal
                    .parseAlloc(allocator, ast.tokenSlice(ast.firstToken(kv)));
                try json.objectField(key);
                try json.write(val);
            }
            try json.endObject();
        }
    }
    try json.endObject();
    try stdout_writer.interface.flush();
    return 0;
}
