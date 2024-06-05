const std = @import("std");
const lib = @import("lib.zig");
const logger = @import("./trace/log.zig");

test {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    std.testing.log_level = std.log.Level.err;
    refAllDeclsRecursive(lib, 3);
}

/// Like std.testing.refAllDeclsRecursive, except:
/// - you can specify depth to avoid infinite or unnecessary recursion.
/// - runs at comptime to avoid compiler errors for hypothetical
///   code paths that would never actually run.
pub inline fn refAllDeclsRecursive(comptime T: type, comptime depth: usize) void {
    if (!@import("builtin").is_test) return;
    if (depth == 0) return;
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .Struct, .Enum, .Union, .Opaque => refAllDeclsRecursive(@field(T, decl.name), depth - 1),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}
