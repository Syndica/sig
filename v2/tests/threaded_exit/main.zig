const std = @import("std");
const topology = @import("topology");

const EmptySpec: topology.ServiceSpec = .{
    .ReadOnly = struct {},
    .ReadWrite = struct {},
};

const Topology = struct {
    failing: topology.ServiceRegions(EmptySpec),
    healthy: topology.ServiceRegions(EmptySpec),
};

pub fn main() !void {
    var args = std.process.args();
    _ = args.next();
    if (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--child")) return runChild();
    }

    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const allocator = dba_state.allocator();

    const self_exe = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(self_exe);

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ "timeout", "5", self_exe, "--child" },
        .max_output_bytes = 1024 * 1024,
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    std.debug.print("{s}{s}", .{ result.stdout, result.stderr });
    try std.testing.expectEqual(std.process.Child.Term{ .Exited = 1 }, result.term);
}

fn runChild() !void {
    var children: topology.Children(Topology) = undefined;
    try children.spawn(.threaded, .{
        .failing = .{ .ro = .{}, .rw = .{} },
        .healthy = .{ .ro = .{}, .rw = .{} },
    });

    const exit_status = try children.wait(null);
    children.shutdown(if (exit_status == .failed) 1 else 0);
}
