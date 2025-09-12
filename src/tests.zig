const std = @import("std");
const sig = @import("sig.zig");

test {
    @setEvalBranchQuota(10_000);
    refAllDeclsRecursive(sig, 2);
    refAllDeclsRecursive(sig.accounts_db, 2);
    refAllDeclsRecursive(sig.ledger, 2);
    refAllDeclsRecursive(sig.runtime.program, 3);
    refAllDeclsRecursive(sig.runtime.sysvar, 3);
    refAllDeclsRecursive(sig.vm, 3);
    refAllDeclsRecursive(sig.consensus, 3);
    refAllDeclsRecursive(sig.crypto, 2);
    refAllDeclsRecursive(sig.zksdk, 3);
}

/// Like std.testing.refAllDeclsRecursive, except:
/// - you can specify depth to avoid infinite or unnecessary recursion.
/// - runs at comptime to avoid compiler errors for hypothetical
///   code paths that would never actually run.
pub inline fn refAllDeclsRecursive(comptime T: type, comptime depth: usize) void {
    @setEvalBranchQuota(2000); // Raise as required
    if (depth == 0) return;
    inline for (comptime std.meta.declarations(T)) |decl| {
        if (@TypeOf(@field(T, decl.name)) == type) {
            switch (@typeInfo(@field(T, decl.name))) {
                .@"struct",
                .@"enum",
                .@"union",
                .@"opaque",
                => refAllDeclsRecursive(@field(T, decl.name), depth - 1),
                else => {},
            }
        }
        _ = &@field(T, decl.name);
    }
}
