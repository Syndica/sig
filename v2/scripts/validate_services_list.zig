const std = @import("std");
const service_names: []const []const u8 = @import("services");

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    var argv_iter = try std.process.argsWithAllocator(gpa);
    defer argv_iter.deinit();

    if (!argv_iter.skip()) return error.EmptyArgv;
    const services_dir_path = argv_iter.next() orelse return error.MissingDirPath;
    if (argv_iter.next() != null) return error.TooManyArgs;

    var services_dir = try std.fs.cwd().openDir(services_dir_path, .{ .iterate = true });
    defer services_dir.close();

    const Adapter = struct {
        services_names: []const []const u8,

        pub fn hash(_: @This(), key: []const u8) u32 {
            return std.array_hash_map.hashString(key);
        }

        pub fn eql(ctx: @This(), a: []const u8, b_index: usize, b_index_index: usize) bool {
            _ = b_index_index;
            const b = ctx.services_names[b_index];
            return std.mem.eql(u8, a, b);
        }
    };
    const service_name_adapter: Adapter = .{ .services_names = service_names };

    var unmatched_service_names: std.AutoArrayHashMapUnmanaged(usize, void) = .empty;
    defer unmatched_service_names.deinit(gpa);

    try unmatched_service_names.ensureUnusedCapacity(gpa, service_names.len);
    for (service_names, 0..) |service_name, i| {
        const gop = unmatched_service_names.getOrPutAssumeCapacityAdapted(
            service_name,
            service_name_adapter,
        );
        if (gop.found_existing) {
            std.log.err("Service name '{s}' specified multiple times.", .{service_name});
            return error.DuplicateServiceName;
        }
        gop.key_ptr.* = i;
    }

    var dir_iter = services_dir.iterate();
    while (try dir_iter.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, std.fs.path.extension(entry.name), ".zig")) continue;
        const file_name_stem = std.fs.path.stem(entry.name);
        if (!unmatched_service_names.swapRemoveAdapted(file_name_stem, service_name_adapter)) {
            std.log.err("Service file '{f}' not listed in services.zon", .{
                std.fs.path.fmtJoin(&.{ services_dir_path, entry.name }),
            });
            return error.UnlistedFile;
        }
    }
}
