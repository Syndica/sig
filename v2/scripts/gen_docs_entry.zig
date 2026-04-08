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
    defer writer.flush() catch @panic("failed to flush");

    try writer.writeAll(preamble);

    {
        var module_names = std.mem.splitScalar(u8, module_names_str, ',');
        while (module_names.next()) |mod_name| {
            try writer.print(
                "pub const {[mod]s} = @import(\"{[mod]s}\");\n",
                .{ .mod = mod_name },
            );
        }
    }

    {
        var service_names = std.mem.splitScalar(u8, service_names_str, ',');
        try writer.print("pub const services = struct {{\n", .{});
        while (service_names.next()) |svc_name| {
            try writer.print(
                "    pub const {[svc]s} = @import(\"{[svc]s}\");\n",
                .{ .svc = svc_name },
            );
        }
        try writer.print("}};\n\n", .{});
    }

    try writer.flush();
}
