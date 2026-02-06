const std = @import("std");

const page_size_min = std.heap.page_size_min;

const common = @import("common");
const ServiceEntrypoint = common.ServiceFn;

const linux = std.os.linux;
const sigaction_fn = linux.Sigaction.sigaction_fn;
const memfd = common.linux.memfd;
const E = linux.E;
const e = E.init;

pub const Service = enum {
    prng,
    logger,
    net,
    ping,

    pub fn entrypoint(self: Service) ServiceEntrypoint {
        return switch (self) {
            inline else => |s| @extern(
                ServiceEntrypoint,
                .{ .name = "svc_main_" ++ @tagName(s) },
            ),
        };
    }

    pub fn faultHandler(self: Service) sigaction_fn {
        return switch (self) {
            inline else => |s| @extern(
                sigaction_fn,
                .{ .name = "svc_fault_handler_" ++ @tagName(s) },
            ),
        };
    }

    pub fn requiredRegions(self: Service) []const RequiredRegion {
        return switch (self) {
            .prng => &.{.{ .region = .prng_state, .rw = true }},
            .logger => &.{.{ .region = .prng_state }},
            .net => &.{.{ .region = .net_pair, .rw = true }},
            .ping => &.{.{ .region = .net_pair, .rw = true }},
        };
    }
};

const RequiredRegion = struct {
    region: Region,
    rw: bool = false,
};

const SharedRegion = struct {
    region: Region,
    shares: []const Share,
    requested_location: ?[*]align(page_size_min) u8 = null,

    pub fn format(self: SharedRegion, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("Region ({s}) shared with [", .{@tagName(self.region)});
        for (self.shares) |share| try writer.print(
            "{f}-{s}",
            .{ share.instance, if (share.rw) "rw" else "ro" },
        );
        try writer.print("]", .{});
    }
};

pub const Region = enum {
    prng_state,
    net_pair,

    pub fn size(self: Region) usize {
        return switch (self) {
            .prng_state => @sizeOf(std.Random.Xoroshiro128),
            .net_pair => @sizeOf(common.net.Pair),
        };
    }

    pub fn init(self: Region) *const fn ([]align(page_size_min) u8) void {
        return switch (self) {
            .prng_state => struct {
                fn f(buf: []align(page_size_min) u8) void {
                    std.debug.assert(buf.len == @sizeOf(std.Random.Xoroshiro128));
                    const data: *std.Random.Xoroshiro128 = @ptrCast(buf);

                    data.* = .init(0);
                }
            }.f,
            .net_pair => struct {
                fn f(buf: []align(page_size_min) u8) void {
                    std.debug.assert(buf.len == @sizeOf(common.net.Pair));
                    const data: *common.net.Pair = @ptrCast(buf);

                    data.recv.init();
                    data.send.init();
                    data.port = std.math.maxInt(u16);
                }
            }.f,
        };
    }
};

pub const ServiceInstance = struct {
    service: Service,
    n: u8 = 0,

    pub fn format(self: ServiceInstance, writer: *std.io.Writer) std.io.Writer.Error!void {
        try writer.print("{s}_{}", .{ @tagName(self.service), self.n });
    }
};

pub const Instances = [_]ServiceInstance{
    .{ .service = .prng, .n = 0 },
    .{ .service = .logger, .n = 0 },
    .{ .service = .net, .n = 0 },
    .{ .service = .ping, .n = 0 },
};

const Share = struct {
    instance: ServiceInstance,
    rw: bool = false,
};

const Map = std.AutoArrayHashMapUnmanaged(ServiceInstance, MapEntry);

const MapEntry = std.ArrayListUnmanaged(LookupResult);

const LookupResult = struct {
    shared: SharedRegion,
    rw: bool,
    memfd: memfd.RW,
};

fn serviceMap(
    allocator: std.mem.Allocator,
    comptime services: []const ServiceInstance,
    comptime regions: []const SharedRegion,
    region_memfds: []memfd.RW,
) !Map {
    // check all regions reference existing services
    inline for (regions) |region| {
        for (region.shares) |share| {
            const found_service: bool = for (services) |instance| {
                const matching =
                    instance.service == share.instance.service and
                    instance.n == share.instance.n;

                if (matching) break true;
            } else false;

            if (!found_service)
                std.debug.panic("Shared region {f} with unknown service {}\n", .{ region, share });
        }
    }

    var map: Map = .empty;
    errdefer map.deinit(allocator);

    // check all service instances request regions which are shared with them
    inline for (services) |instance| {
        for (instance.service.requiredRegions()) |region_instance| {
            const found_region: LookupResult = blk: for (
                regions,
                region_memfds,
            ) |shared_region, region_memfd| {
                if (shared_region.region != region_instance.region) continue;

                for (shared_region.shares) |share| {
                    if (instance.service == share.instance.service and
                        instance.n == share.instance.n)
                    {
                        std.debug.assert(region_memfd.size == shared_region.region.size());
                        break :blk .{
                            .shared = shared_region,
                            .rw = region_instance.rw,
                            .memfd = region_memfd,
                        };
                    }
                }
            } else std.debug.panic(
                "Service instance {f} requested {} region which was not shared with it",
                .{ instance, region_instance },
            );

            const entry = try map.getOrPut(allocator, instance);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.append(allocator, found_region);
        }
    }

    return map;
}

pub fn spawnAndWait(
    allocator: std.mem.Allocator,
    comptime services: []const ServiceInstance,
    comptime regions: []const SharedRegion,
) !void {
    const region_memfds: []memfd.RW = try allocator.alloc(memfd.RW, regions.len);
    defer allocator.free(region_memfds);
    {
        @memset(region_memfds, .empty);

        inline for (region_memfds, regions) |*region_memfd, shared_region| {
            region_memfd.* = try .init(.{
                .name = std.fmt.comptimePrint("{f}", .{shared_region}),
                .size = shared_region.region.size(),
            });
        }
    }

    const exit_memfds: []memfd.RW = try allocator.alloc(memfd.RW, services.len);
    defer allocator.free(exit_memfds);
    {
        @memset(exit_memfds, .empty);

        inline for (exit_memfds, services) |*exit_memfd, service_instance| {
            exit_memfd.* = try .init(.{
                .name = std.fmt.comptimePrint(
                    "exit_{s}_{}",
                    .{ @tagName(service_instance.service), service_instance.n },
                ),
                .size = @sizeOf(common.Exit),
            });
        }
    }

    for (regions, region_memfds) |shared_region, region_memfd| {
        const buf = try region_memfd.mmap(shared_region.requested_location);
        defer std.posix.munmap(buf);
        shared_region.region.init()(buf);
    }

    var map = try serviceMap(allocator, services, regions, region_memfds);
    defer {
        for (map.values()) |*value| value.deinit(allocator);
        map.deinit(allocator);
    }

    const ExitMeta = struct {
        pid: i32,
        exit: ?*common.Exit,
    };

    var exit_meta: std.MultiArrayList(ExitMeta) = .{};
    defer exit_meta.deinit(allocator);
    try exit_meta.ensureUnusedCapacity(allocator, services.len);

    inline for (services, exit_memfds) |service_instance, exit| {
        const child_pid = try spawnService(
            service_instance,
            exit,
            std.fs.File.stderr(),
            map.get(service_instance).?.items,
        );

        try exit_meta.append(allocator, .{ .pid = child_pid, .exit = null });
    }

    // only mmap exit after spawning the child processes, we don't want this mapped in children
    for (exit_meta.items(.exit), exit_memfds) |*exit, exit_fd| {
        exit.* = @ptrCast(try exit_fd.mmap(null));
    }

    // wait for the first child to exit
    var status: u32 = 0;
    const exited_pid: i32 = pid: {
        const ret: usize = linux.waitpid(-1, &status, 0);
        std.debug.assert(ret != -1);
        break :pid @intCast(ret);
    };

    const exited_service_idx = std.mem.indexOfScalar(
        i32,
        exit_meta.items(.pid),
        exited_pid,
    ) orelse std.debug.panic("Unknown child pid {} exited\n", .{exited_pid});

    dumpOnExit(
        exit_meta.items(.exit)[exited_service_idx].?,
        services[exited_service_idx],
        exited_pid,
        status,
    );
}

fn spawnService(
    service_instance: ServiceInstance,
    exit: memfd.RW,
    stderr: std.fs.File,
    regions: []const LookupResult,
) !i32 {
    const parent_pid = std.os.linux.getpid();

    const maybe_child_pid = common.linux.clone3.clone3(&.{
        .flags = .{
            // NOTE: all FDs currently open will remain open in the child
            // There is no way around this, except
            // 1) Immediately closing all FDs in the child
            // 2) Making sure all FDs were created with CLOEXEC, and using exec in the child
        },
        .exit_signal = std.os.linux.SIG.CHLD,
    });

    if (maybe_child_pid) |child_pid| {
        // parent code
        std.debug.print("Starting Service `{f}`, pid: {}\n", .{ service_instance, child_pid });
        return child_pid;
    }

    // register fault handlers
    {
        const act: *const std.os.linux.Sigaction = &.{
            .handler = .{ .sigaction = service_instance.service.faultHandler() },
            .mask = std.posix.sigemptyset(),
            .flags = (std.posix.SA.SIGINFO | std.posix.SA.RESTART | std.posix.SA.RESETHAND),
        };

        // standard signals in std.debug.updateSegfaultHandler
        std.posix.sigaction(std.posix.SIG.SEGV, act, null);
        std.posix.sigaction(std.posix.SIG.ILL, act, null);
        std.posix.sigaction(std.posix.SIG.BUS, act, null);
        std.posix.sigaction(std.posix.SIG.FPE, act, null);

        // catch seccomp too
        std.posix.sigaction(std.posix.SIG.SYS, act, null);
    }

    // Make sure that the services die when the parent exits
    {
        const ret = linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), linux.SIG.KILL, 0, 0, 0);
        if (e(ret) != .SUCCESS) std.debug.panic("prctl failed with: {}\n", .{e(ret)});

        // NOTE: this check does not work if we spawn each service into a new pid namespace, as
        // getppid will return 0 (including when the parent is dead).
        const parent_pid_now = std.os.linux.getppid();
        if (parent_pid != parent_pid_now) {
            // The parent died. In case this happened before we set SET_PDEATHSIG, let's exit
            // ourselves.
            @branchHint(.cold);
            std.debug.panic(
                "Parent died, parent pid changed ({}->{})\n",
                .{ parent_pid, parent_pid_now },
            );
        }
    }

    const resolved_args = try resolveArgs(exit, stderr, regions);

    // mseal our shared VMAs (essentially making sure their mapping can't be tampered with)
    for (resolved_args.ro, resolved_args.ro_len) |ptr, len| mseal(ptr orelse continue, len);
    for (resolved_args.rw, resolved_args.rw_len) |ptr, len| mseal(ptr orelse continue, len);
    mseal(resolved_args.exit, 4);

    closeAllFdsExceptStderr(stderr.handle);

    // makes it impossible for the service to gain privileges
    std.debug.assert(try std.posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 }) == 0);

    // install a basic seccomp filter that bans syscalls except write+sleep
    {
        const bpf_filters = common.linux.bpf.printSleepExit(stderr.handle);
        const program: common.linux.bpf.sock_fprog = .{
            .len = bpf_filters.len,
            .sock_filter = &bpf_filters,
        };

        const ret = linux.seccomp(linux.SECCOMP.SET_MODE_FILTER, 0, &program);
        const err = e(ret);
        if (err != .SUCCESS) {
            std.debug.panic("seccomp err: {}", .{err});
            return;
        }
    }

    service_instance.service.entrypoint()(resolved_args);
}

fn resolveArgs(
    exit: memfd.RW,
    stderr: std.fs.File,
    regions: []const LookupResult,
) !common.ResolvedArgs {
    var args: common.ResolvedArgs = .{
        .stderr = stderr.handle,
        .exit = (try exit.mmap(null)).ptr,

        .rw = @splat(null),
        .rw_len = @splat(0),
        .ro = @splat(null),
        .ro_len = @splat(0),
    };

    var i_rw: u8 = 0;
    var i_ro: u8 = 0;

    for (regions) |region| {
        std.debug.assert(region.shared.region.size() == region.memfd.size);

        if (region.rw) {
            args.rw[i_rw] = (try region.memfd.mmap(region.shared.requested_location)).ptr;
            args.rw_len[i_rw] = region.shared.region.size();
            i_rw += 1;
        } else {
            const ro_memfd = try memfd.RO.fromRW(region.memfd);
            args.ro[i_ro] = (try ro_memfd.mmap(region.shared.requested_location)).ptr;
            args.ro_len[i_ro] = region.shared.region.size();
            i_ro += 1;
        }
    }

    return args;
}

fn mseal(address: [*]align(std.heap.page_size_min) const u8, len: usize) void {
    switch (e(std.os.linux.mseal(address, len, 0))) {
        .SUCCESS => {},
        // syscall unsupported (6.12+),
        // TODO: consider making this required
        .NOSYS => {},
        else => |err| std.debug.panic("mseal failed: {}\n", .{err}),
    }
}

fn closeAllFdsExceptStderr(maybe_stderr: ?linux.fd_t) void {
    const max_fd = std.math.maxInt(linux.fd_t);

    if (maybe_stderr) |stderr| {
        // close (0..stderr, stderr+1..=max)
        if (std.os.linux.syscall3(.close_range, 0, @intCast(stderr - 1), 0) != 0)
            std.debug.panic("close_range failed\n", .{});
        if (std.os.linux.syscall3(.close_range, @intCast(stderr + 1), max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    } else {
        // close (0..=max)
        if (std.os.linux.syscall3(.close_range, 0, max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    }
}

fn dumpOnExit(
    meta: *common.Exit,
    service_instance: ServiceInstance,
    pid: i32,
    status: u32,
) void {
    if (meta.panicMsg()) |panic_msg| {
        std.debug.print(
            "Service `{f}` (pid: {}) panicked with message: {s}\n",
            .{ service_instance, pid, panic_msg },
        );
    }
    if (meta.errorName()) |error_string| {
        std.debug.print(
            "Service `{f}` (pid: {}) exited with error: {s}\n",
            .{ service_instance, pid, error_string },
        );
    }
    if (meta.faultMsg()) |fault_msg| {
        std.debug.print(
            "Service `{f}` (pid: {}) faulted with message: {s}\n",
            .{ service_instance, pid, fault_msg },
        );
    }

    if (linux.W.TERMSIG(status) != 0) {
        std.debug.print(
            "Service `{f}` (pid: {}) exited from signal {}\n",
            .{ service_instance, pid, linux.W.TERMSIG(status) },
        );
    }

    if (meta.errorReturnStackTrace()) |trace| {
        std.debug.print("Error trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.stackTrace()) |trace| {
        std.debug.print("Stack trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.faultStackTrace()) |trace| {
        std.debug.print("Fault trace:\n", .{});
        std.debug.dumpStackTrace(trace);
    }
}
