const std = @import("std");
const sig = @import("sig.zig");

test {
    std.testing.log_level = std.log.Level.err;
    refAllDeclsRecursive(sig, 2);
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
