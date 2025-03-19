const std = @import("std");

const send_script =
    \\ssh {[host]s} mkdir -p "$(dirname "{[remote_path]s}")"
    \\if which rsync; then
    \\    rsync --compress --progress '{[local_path]s}' '{[host]s}:{[remote_path]s}'
    \\else
    \\    scp '{[local_path]s}' '{[host]s}:{[remote_path]s}'
    \\fi
;

const help =
    \\
    \\Send a local file to a remote path, making the remote directory if necessary.
    \\Depends on bash, ssh, and either scp or rsync.
    \\
    \\USAGE:
    \\
    \\     send-file [LOCAL_PATH] [HOST] [REMOTE_PATH]
    \\
    \\  LOCAL_PATH   Path on the local host to read the file from.
    \\  HOST         Remote host to send the artifact to.
    \\  REMOTE_PATH  Path on the remote host to write the file to.
    \\
    \\
;

pub fn main() !void {
    if (std.os.argv.len == 4)
        try runScript(std.heap.c_allocator, send_script, .{
            .local_path = std.mem.span(std.os.argv[1]),
            .host = std.mem.span(std.os.argv[2]),
            .remote_path = std.mem.span(std.os.argv[3]),
        })
    else
        std.debug.print(help, .{});
}

fn runScript(allocator: std.mem.Allocator, comptime script: []const u8, args: anytype) !void {
    const concrete_script = try std.fmt.allocPrint(allocator, script, args);
    defer allocator.free(concrete_script);
    var child = std.process.Child.init(&.{ "bash", "-c", concrete_script }, allocator);
    const term = try child.spawnAndWait();
    if (term.Exited != 0) {
        std.debug.print("exited with code {}\n", .{term.Exited});
        return error.SendArtifactError;
    }
}
