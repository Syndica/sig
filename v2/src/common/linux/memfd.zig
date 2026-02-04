const std = @import("std");
const linux = std.os.linux;
const E = linux.E;
const e = E.init;
const page_size_min = std.heap.page_size_min;

pub const RW = extern struct {
    fd: linux.fd_t,
    size: usize,
    name: [*:0]const u8,

    pub const empty: RW = .{ .fd = -1, .size = 0, .name = "empty-RW" };

    pub const Args = struct {
        name: [:0]const u8,
        size: usize,
    };

    pub fn init(args: Args) !RW {
        // Create a new memfd
        const fd_rw: linux.fd_t = blk: {
            // include/uapi/linux/memfd.h
            const CLOEXEC = linux.MFD.CLOEXEC; // this fd will be closed if we ever exec
            const ALLOW_SEALING = linux.MFD.ALLOW_SEALING; // allow sealing (needed below)
            const NOEXEC_SEAL = 0x8; // create it with exec disabled *permanently*

            const fd = linux.memfd_create(args.name, CLOEXEC | ALLOW_SEALING | NOEXEC_SEAL);
            switch (e(fd)) {
                .SUCCESS => {},
                else => |err| std.debug.panic("memfd_create failed with: {t}\n", .{err}),
            }
            break :blk @intCast(fd);
        };

        // Set file to correct size
        try std.posix.ftruncate(fd_rw, args.size);

        // Make sure the file cannot be later resized.
        {
            // include/uapi/linux/fcntl.h
            const F_LINUX_SPECIFIC_BASE = 1024;
            const F_ADD_SEALS = F_LINUX_SPECIFIC_BASE + 9;
            const F_SEAL_SHRINK = 0x0002; // prevent file shrink
            const F_SEAL_GROW = 0x0004; // prevent file grow

            _ = try std.posix.fcntl(fd_rw, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW);
        }

        return .{
            .fd = fd_rw,
            .size = args.size,
            .name = args.name,
        };
    }

    pub const mmap = mmapInner;
};

pub const RO = extern struct {
    fd: linux.fd_t,
    size: usize,
    name: [*:0]const u8,

    pub const empty: RO = .{ .fd = -1, .size = 0, .name = "empty-RO" };

    pub fn fromRW(rw: RW) !RO {
        var buf: [100]u8 = undefined;
        const path = try std.fmt.bufPrint(&buf, "/proc/self/fd/{}", .{rw.fd});
        const file = try std.fs.openFileAbsolute(path, .{ .mode = .read_only });

        return .{
            .fd = file.handle,
            .size = rw.size,
            .name = rw.name,
        };
    }

    pub const mmap = mmapInner;
};

fn mmapInner(self: anytype, ptr: ?[*]align(page_size_min) u8) ![]align(page_size_min) u8 {
    const access = switch (@TypeOf(self)) {
        *const RW, *RW, RW => linux.PROT.READ | linux.PROT.WRITE,
        *const RO, *RO, RO => linux.PROT.READ,
        else => @compileError("unsupported type"),
    };

    return try std.posix.mmap(
        ptr,
        self.size,
        access,
        .{ .TYPE = .SHARED },
        self.fd,
        0,
    );
}
