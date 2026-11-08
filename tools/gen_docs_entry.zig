//! Usage: ./gen_docs_entry [options]
//!
//! Args:
//!   [1] comma separated service names
//!   [2] comma separated module names
//!   [3] generated output file path
//!

const std = @import("std");

const preamble =
    \\ //! # Generated Docs
    \\ //!
    \\ //! ## Services
    \\ //!
    \\ //! Sig runs as a collection of processes, called services, spawned by a root process.
    \\ //!
    \\ //! See `services` for services.
    \\ //! See `sig_init` for the root process.
    \\ //!
    \\ //! ## Libraries
    \\ //!
    \\ //! See `lib` for our libraries.
    \\ //!
    \\
    \\
    \\pub const std = @import("std");
    \\
    \\comptime {
    \\    _ = std.testing.refAllDecls(@This());
    \\}
    \\
;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 4) return error.NotEnoughArgs;

    const service_names_str = args[1];
    const module_names_str = args[2];
    const output_file_path = args[3];

    const file = try std.fs.cwd().createFile(output_file_path, .{});
    var buf: [4096]u8 = undefined;
    var writer_state = file.writer(&buf);
    const writer = &writer_state.interface;
    defer writer.flush() catch {};

    try generateDocs(writer, service_names_str, module_names_str);
    try writer.flush();
}

fn generateDocs(
    writer: *std.Io.Writer,
    service_names_str: []const u8,
    module_names_str: []const u8,
) std.Io.Writer.Error!void {
    try writer.writeAll(preamble);

    {
        var module_names = std.mem.splitScalar(u8, module_names_str, ',');
        while (module_names.next()) |mod_name| {
            try writer.print(
                "pub const {f} = @import(\"{s}\");\n",
                .{ std.zig.fmtId(mod_name), mod_name },
            );
        }
    }

    {
        var service_names = std.mem.splitScalar(u8, service_names_str, ',');
        try writer.print("pub const services = struct {{\n", .{});
        while (service_names.next()) |svc_name| {
            try writer.print(
                "    pub const {f} = @import(\"{s}\");\n",
                .{ std.zig.fmtId(svc_name), svc_name },
            );
        }
        try writer.print("}};\n\n", .{});
    }
}

test "generated docs escape module and service identifiers" {
    const allocator = std.testing.allocator;
    var buf: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    try generateDocs(&writer, "gossip-service,replay", "lib,feature-set-id,while");

    const source = try allocator.dupeZ(u8, writer.buffered());
    defer allocator.free(source);
    var ast = try std.zig.Ast.parse(allocator, source, .zig);
    defer ast.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), ast.errors.len);

    const expected_declarations = [_][]const u8{
        "pub const lib = @import(\"lib\");",
        "pub const @\"feature-set-id\" = @import(\"feature-set-id\");",
        "pub const @\"while\" = @import(\"while\");",
        "pub const @\"gossip-service\" = @import(\"gossip-service\");",
        "pub const replay = @import(\"replay\");",
    };
    for (expected_declarations) |declaration| {
        try std.testing.expect(std.mem.indexOf(u8, source, declaration) != null);
    }
}
