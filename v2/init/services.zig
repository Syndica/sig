//! Our services and how they're started up.
//!
//! This code is reponsible for:
//! - Defining services and their needed shared memory regions
//! - Initialising shared memory regions
//! - Starting up services and securing them down
//! - Dumping stack traces + errors on service exit

const std = @import("std");
const tracy = @import("tracy");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const page_size_min = std.heap.page_size_min;

const lib = @import("lib");
const ServiceEntrypoint = lib.ipc.ServiceFn;

const linux = std.os.linux;
const sigaction_fn = linux.Sigaction.sigaction_fn;
const memfd = lib.linux.memfd;
const E = linux.E;
const e = E.init;

const services_zon = @import("./services.zon");

pub const Service = blk: {
    var fields: []const std.builtin.Type.EnumField = &.{};
    for (services_zon.services) |instance| {
        const exists = for (fields) |f| {
            if (std.mem.eql(u8, f.name, @tagName(instance.name))) break true;
        } else false;

        if (!exists) {
            fields = fields ++ &[_]std.builtin.Type.EnumField{
                .{ .name = @tagName(instance.name), .value = fields.len },
            };
        }
    }

    break :blk @Type(.{ .@"enum" = .{
        .decls = &.{},
        .fields = fields,
        .is_exhaustive = true,
        .tag_type = u8,
    } });
};

fn getRequiredRegions(service: Service) []const RequiredRegion {
    switch (service) {
        inline else => |s| {
            inline for (services_zon.services) |_service| {
                if (comptime std.mem.eql(u8, @tagName(_service.name), @tagName(s))) {
                    comptime var required: []const RequiredRegion = &.{};
                    inline for (_service.regions) |r| {
                        required = required ++ &[_]RequiredRegion{.{
                            .region = @field(services_zon.regions, @tagName(r.name)),
                            .rw = switch (r.access) {
                                .rw => true,
                                .readonly => false,
                                else => @compileError("invalid access: " ++ @tagName(r.access)),
                            },
                        }};
                    }
                    return required;
                }
            } else comptime unreachable;
        },
    }
}

fn getFaultHandler(service: Service) sigaction_fn {
    return switch (service) {
        inline else => |s| @extern(
            sigaction_fn,
            .{ .name = "svc_fault_handler_" ++ @tagName(s) },
        ),
    };
}

pub fn getEntrypoint(service: Service) ServiceEntrypoint {
    return switch (service) {
        inline else => |s| @extern(
            ServiceEntrypoint,
            .{ .name = "svc_main_" ++ @tagName(s) },
        ),
    };
}

const RequiredRegion = struct {
    region: std.meta.Tag(Region),
    rw: bool = false,
};

const service_region_fields = std.meta.fields(@TypeOf(services_zon.regions));

pub const SharedRegionInstances = blk: {
    var fields: []const std.builtin.Type.StructField = &.{};
    for (service_region_fields) |r| {
        const RegionType = @TypeOf(@field(
            @as(Region, undefined),
            @tagName(@field(services_zon.regions, r.name)),
        ));
        fields = fields ++ [_]std.builtin.Type.StructField{.{
            .name = r.name,
            .type = RegionType,
            .default_value_ptr = null,
            .is_comptime = false,
            .alignment = @alignOf(RegionType),
        }};
    }
    break :blk @Type(.{ .@"struct" = .{
        .layout = .auto,
        .is_tuple = false,
        .decls = &.{},
        .fields = fields,
    } });
};

pub fn toSharedRegions(
    instances: SharedRegionInstances,
) [service_region_fields.len]SharedRegion {
    var shared_regions: [service_region_fields.len]SharedRegion = undefined;
    inline for (service_region_fields, 0..) |r, i| {
        comptime var shares: []const Share = &.{};
        inline for (services_zon.services) |s| {
            inline for (s.regions) |s_reg| {
                if (comptime std.mem.eql(u8, @tagName(s_reg.name), r.name)) {
                    // TODO: support referencing multiple service instances (.n > 0)
                    shares = shares ++ &[_]Share{.{
                        .instance = .{ .service = s.name, .n = 0 },
                        .rw = switch (s_reg.access) {
                            .rw => true,
                            .readonly => false,
                            else => @compileError("invalid access: " ++ @tagName(s_reg.access)),
                        },
                    }};
                }
            }
        }
        shared_regions[i] = .{
            .region = @unionInit(
                Region,
                @tagName(@field(services_zon.regions, r.name)),
                @field(instances, r.name),
            ),
            .shares = shares,
        };
    }
    return shared_regions;
}

pub const SharedRegion = struct {
    region: Region,
    shares: []const Share,
    requested_location: ?[*]align(page_size_min) u8 = null,

    pub fn format(self: SharedRegion, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("Region `{s}` shared with [ ", .{@tagName(self.region)});
        for (self.shares) |share| try writer.print(
            "{f} ({s}), ",
            .{ share.instance, if (share.rw) "rw" else "ro" },
        );
        try writer.print("]", .{});
    }
};

pub const Region = union(enum) {
    net_pair: struct { port: u16 },
    gossip_config: struct {
        cluster_info: lib.gossip.ClusterInfo,
        // TODO: this should live in signing service
        keypair: lib.gossip.KeyPair,
        turbine_recv_port: u16,
    },
    shred_recv_config: struct {
        // TODO: this should not exist - remove once we can open snapshots again
        schedule_string: *std.Io.Reader,
        shred_version: u16,
    },
    snapshot_queue: void,
    accounts_db_config: struct {
        folder: []const u8,
        min_snapshot_download_speed_mb: u64,
        min_snapshot_download_warmup_ms: u64,
        min_snapshot_download_timeout_ms: u64,
        min_snapshot_download_lockin_percent: f64,
    },

    pub fn size(self: Region) usize {
        return switch (self) {
            .net_pair => @sizeOf(lib.net.Pair),
            .gossip_config => @sizeOf(lib.gossip.Config),
            .shred_recv_config => @sizeOf(lib.shred.RecvConfig),
            .snapshot_queue => @sizeOf(lib.accounts_db.SnapshotQueue),
            .accounts_db_config => @sizeOf(lib.accounts_db.Config),
        };
    }

    pub fn init(self: Region, buf: []align(page_size_min) u8) !void {
        std.log.info("Initialising: {}", .{std.meta.activeTag(self)});

        return switch (self) {
            .net_pair => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.net.Pair));
                const data: *lib.net.Pair = @ptrCast(buf);

                data.recv.init();
                data.send.init();
                data.port = cfg.port;
            },
            .gossip_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.gossip.Config));
                const data: *lib.gossip.Config = @ptrCast(buf);

                data.keypair = cfg.keypair;
                data.cluster_info = cfg.cluster_info;
                data.turbine_recv_port = cfg.turbine_recv_port;
            },
            .shred_recv_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.shred.RecvConfig));
                const data: *lib.shred.RecvConfig = @ptrCast(buf);

                try lib.solana.LeaderSchedule.fromCommand(
                    &data.leader_schedule,
                    cfg.schedule_string,
                );
                data.shred_version = cfg.shred_version;
            },
            .snapshot_queue => {
                std.debug.assert(buf.len == @sizeOf(lib.accounts_db.SnapshotQueue));
                const data: *lib.accounts_db.SnapshotQueue = @ptrCast(buf);

                data.incoming.init();
                data.outgoing.init();
            },
            .accounts_db_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.accounts_db.Config));
                const data: *lib.accounts_db.Config = @ptrCast(buf);

                data.folder_path_len = std.math.cast(u8, cfg.folder.len) orelse
                    return error.FolderPathTooLong;
                @memcpy(data.folder_path[0..cfg.folder.len], cfg.folder);

                if (cfg.min_snapshot_download_lockin_percent > 1.0) {
                    std.debug.panic("min_snapshot_download_lockin_percent must be 0 to 1.0: {}", .{
                        cfg.min_snapshot_download_lockin_percent,
                    });
                }

                data.snapshot_download = .{
                    .min_speed_bytes = cfg.min_snapshot_download_speed_mb * 1_000_000,
                    .min_warmup_ns = cfg.min_snapshot_download_warmup_ms * 1_000_000,
                    .min_timeout_ns = cfg.min_snapshot_download_timeout_ms * 1_000_000,
                    .min_lockin_percent = cfg.min_snapshot_download_lockin_percent,
                };
            },
        };
    }
};

pub const ServiceInstance = struct {
    service: Service,
    /// for supporting multiple services of the same kind
    n: u8 = 0,

    pub fn format(self: ServiceInstance, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{s}_{}", .{ @tagName(self.service), self.n });
    }
};

const Share = struct {
    instance: ServiceInstance,
    rw: bool = false,
};

const Map = std.AutoArrayHashMapUnmanaged(ServiceInstance, MapEntry);

const MapEntry = std.ArrayListUnmanaged(LookupResult);

const LookupResult = struct {
    n: usize, // for supporting multiple regions of the same kind
    shared: SharedRegion,
    rw: bool,
    memfd: memfd.RW,
};

/// Pairs services up with their respective required regions and their rw/ro permission
fn serviceMap(
    allocator: std.mem.Allocator,
    comptime services: []const ServiceInstance,
    regions: []const SharedRegion,
    region_memfds: []memfd.RW,
) !Map {
    // check all regions reference existing services
    for (regions) |region| {
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
        for (getRequiredRegions(instance.service)) |required_region| {
            const found_region: LookupResult = blk: for (
                regions,
                region_memfds,
                0..,
            ) |shared_region, region_memfd, n| {
                if (shared_region.region != required_region.region) continue;

                for (shared_region.shares) |share| {
                    if (instance.service == share.instance.service and
                        instance.n == share.instance.n)
                    {
                        const result: LookupResult = .{
                            .n = n,
                            .shared = shared_region,
                            .rw = required_region.rw,
                            .memfd = region_memfd,
                        };

                        var exists = false;
                        if (map.getPtr(instance)) |entry| {
                            for (entry.items) |existing_result| {
                                if (lib.util.eql(existing_result, result)) {
                                    exists = true;
                                    break;
                                }
                            }
                        }

                        std.debug.assert(region_memfd.size == shared_region.region.size());
                        if (!exists) break :blk result;
                    }
                }
            } else std.debug.panic(
                "Service instance {f} requested {} region which was not shared with it",
                .{ instance, required_region },
            );

            const entry = try map.getOrPut(allocator, instance);
            if (!entry.found_existing) entry.value_ptr.* = .empty;
            try entry.value_ptr.append(allocator, found_region);
        }
    }

    return map;
}

/// Initialises the shared memory regions with their parameters, then securely starts up services.
/// Blocks until the first service has exited, before dumping out traces.
pub fn spawnAndWait(
    allocator: std.mem.Allocator,
    comptime services: []const ServiceInstance,
    regions: []const SharedRegion,
) !void {
    // Create memfds for each shared memory region
    const region_memfds: []memfd.RW = try allocator.alloc(memfd.RW, regions.len);
    defer allocator.free(region_memfds);
    {
        @memset(region_memfds, .empty);

        for (region_memfds, regions) |*region_memfd, shared_region| {
            // Providing a name - this name should be visible from a debugger, but serves no other
            // purpose.
            var fmt_buf: [100]u8 = undefined;
            const name = try std.fmt.bufPrintZ(&fmt_buf, "{f}", .{shared_region});

            region_memfd.* = try .init(.{
                .name = name,
                .size = shared_region.region.size(),
            });
        }
    }

    // Creates a memfd for every service, to be used for storing a lib.Exit value, which is used
    // for reporting traces+errors back to the main process.
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
                .size = @sizeOf(lib.ipc.Exit),
            });
        }
    }

    // Creates a mapping for each memfd region, initialising them, and unmapping them. We must unmap
    // to avoid sharing regions with services that don't need them.
    for (regions, region_memfds) |shared_region, region_memfd| {
        const buf = try region_memfd.mmap(shared_region.requested_location);
        defer std.posix.munmap(buf);
        try shared_region.region.init(buf);

        std.log.info("Initialised: {f}", .{shared_region});
    }

    var map = try serviceMap(allocator, services, regions, region_memfds);
    defer {
        for (map.values()) |*value| value.deinit(allocator);
        map.deinit(allocator);
    }

    const ExitMeta = struct {
        pid: i32,
        exit: ?*lib.ipc.Exit,
    };

    var exit_meta: std.MultiArrayList(ExitMeta) = .{};
    defer exit_meta.deinit(allocator);
    try exit_meta.ensureUnusedCapacity(allocator, services.len);

    // Start up all services, storing their pids
    inline for (services, exit_memfds) |service_instance, exit| {
        const child_pid = try spawnService(
            service_instance,
            exit,
            std.fs.File.stderr(),
            map.get(service_instance).?.items,
        );

        try exit_meta.append(allocator, .{ .pid = child_pid, .exit = null });
    }

    // We only mmap the exit regions after spawning the child processes, as we don't want them
    // mapped in children
    for (exit_meta.items(.exit), exit_memfds) |*exit, exit_fd| {
        exit.* = @ptrCast(try exit_fd.mmap(null));
    }

    // Wait for the first child to exit
    var status: u32 = 0;
    const exited_pid: i32 = pid: {
        const ret: usize = linux.waitpid(-1, &status, 0);
        std.debug.assert(e(ret) == .SUCCESS);
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

    const maybe_child_pid = lib.linux.clone3.clone3(&.{
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
        std.log.info("Starting Service `{f}`, pid: {}", .{ service_instance, child_pid });
        return child_pid;
    }

    switch (service_instance.service) {
        inline else => |svc| tracy.setThreadName("svc: " ++ @tagName(svc)),
    }

    // register fault handlers
    {
        const act: *const std.os.linux.Sigaction = &.{
            .handler = .{ .sigaction = getFaultHandler(service_instance.service) },
            .mask = std.os.linux.sigemptyset(),
            .flags = (std.posix.SA.SIGINFO | std.posix.SA.RESTART | std.posix.SA.RESETHAND),
        };

        // standard signals in std.debug.updateSegfaultHandler
        if (e(std.os.linux.sigaction(std.posix.SIG.SEGV, act, null)) != .SUCCESS) @panic("wtf");
        if (e(std.os.linux.sigaction(std.posix.SIG.ILL, act, null)) != .SUCCESS) @panic("wtf");
        if (e(std.os.linux.sigaction(std.posix.SIG.BUS, act, null)) != .SUCCESS) @panic("wtf");
        if (e(std.os.linux.sigaction(std.posix.SIG.FPE, act, null)) != .SUCCESS) @panic("wtf");

        // catch seccomp too
        if (e(std.os.linux.sigaction(std.posix.SIG.SYS, act, null)) != .SUCCESS) @panic("wtf");
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
    mseal(resolved_args.exit, @sizeOf(lib.ipc.Exit));

    closeAllFdsExceptStderr(stderr.handle);

    // makes it impossible for the service to gain privileges
    std.debug.assert(try std.posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 }) == 0);

    // install a basic seccomp filter that bans syscalls except write+sleep
    {
        const bpf_filters = lib.linux.bpf.printSleepExit(stderr.handle);
        const program: lib.linux.bpf.sock_fprog = .{
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

    getEntrypoint(service_instance.service)(resolved_args);
    std.process.exit(255);
}

/// Mmap in our memfds, and putting the regions in a type-erased extern struct
fn resolveArgs(
    exit: memfd.RW,
    stderr: std.fs.File,
    regions: []const LookupResult,
) !lib.ipc.ResolvedArgs {
    var args: lib.ipc.ResolvedArgs = .{
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

/// Prevents VMAs from being later modified
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
        if (std.os.linux.syscall3(.close_range, 0, @intCast(stderr -| 1), 0) != 0)
            std.debug.panic("close_range failed\n", .{});
        if (std.os.linux.syscall3(.close_range, @intCast(stderr +| 1), max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    } else {
        // close (0..=max)
        if (std.os.linux.syscall3(.close_range, 0, max_fd, 0) != 0)
            std.debug.panic("close_range failed\n", .{});
    }
}

fn dumpOnExit(
    meta: *lib.ipc.Exit,
    service_instance: ServiceInstance,
    pid: i32,
    status: u32,
) void {
    if (meta.panicMsg()) |panic_msg| {
        std.log.err(
            "Service `{f}` (pid: {}) panicked with message: {s}",
            .{ service_instance, pid, panic_msg },
        );
    }
    if (meta.errorName()) |error_string| {
        std.log.err(
            "Service `{f}` (pid: {}) exited with error: {s}",
            .{ service_instance, pid, error_string },
        );
    }
    if (meta.faultMsg()) |fault_msg| {
        std.log.err(
            "Service `{f}` (pid: {}) faulted with message: {s}",
            .{ service_instance, pid, fault_msg },
        );
    }

    if (linux.W.TERMSIG(status) != 0) {
        std.log.err(
            "Service `{f}` (pid: {}) exited from signal {}",
            .{ service_instance, pid, linux.W.TERMSIG(status) },
        );
    }

    if (meta.errorReturnStackTrace()) |trace| {
        std.log.err("Error trace:", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.stackTrace()) |trace| {
        std.log.err("Stack trace:", .{});
        std.debug.dumpStackTrace(trace);
    }

    if (meta.faultStackTrace()) |trace| {
        std.log.err("Fault trace:", .{});
        std.debug.dumpStackTrace(trace);
    }
}

pub fn spawnAndWaitNoSandbox(
    allocator: std.mem.Allocator,
    comptime services: []const ServiceInstance,
    regions: []const SharedRegion,
) !void {
    // Create memfds for each shared memory region
    const region_memfds: []memfd.RW = try allocator.alloc(memfd.RW, regions.len);
    defer allocator.free(region_memfds);
    {
        @memset(region_memfds, .empty);

        for (region_memfds, regions) |*region_memfd, shared_region| {
            // Providing a name - this name should be visible from a debugger, but serves no other
            // purpose.
            var fmt_buf: [100]u8 = undefined;
            const name = try std.fmt.bufPrintZ(&fmt_buf, "{f}", .{shared_region});

            region_memfd.* = try .init(.{
                .name = name,
                .size = shared_region.region.size(),
            });
        }
    }

    // Creates a memfd for every service, to be used for storing a lib.ipc.Exit value, which is used
    // for reporting traces+errors back to the main process.
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
                .size = @sizeOf(lib.ipc.Exit),
            });
        }
    }

    // Creates a mapping for each memfd region, initialising them, and unmapping them.
    for (regions, region_memfds) |shared_region, region_memfd| {
        const buf = try region_memfd.mmap(shared_region.requested_location);
        defer std.posix.munmap(buf);
        try shared_region.region.init(buf);

        std.log.info("Initialised: {f}", .{shared_region});
    }

    var map = try serviceMap(allocator, services, regions, region_memfds);
    defer {
        for (map.values()) |*value| value.deinit(allocator);
        map.deinit(allocator);
    }

    var reset_event: std.Thread.ResetEvent = .{};
    var finished_service_idx: std.atomic.Value(u16) = .init(std.math.maxInt(u16));

    // Start up all services, storing their pids
    inline for (services, exit_memfds, 0..) |service_instance, exit, i| {
        _ = try spawnServiceNoSandbox(
            service_instance,
            exit,
            std.fs.File.stderr(),
            map.get(service_instance).?.items,
            i,
            &finished_service_idx,
            &reset_event,
        );
    }

    // Wait for first service to exit
    reset_event.wait();

    const exited_idx = finished_service_idx.load(.seq_cst);
    std.debug.assert(exited_idx != std.math.maxInt(u16));

    dumpOnExit(@ptrCast(try exit_memfds[exited_idx].mmap(null)), services[exited_idx], 0, 0);
}

fn threadEntry(
    entry_point: ServiceEntrypoint,
    service: Service,
    args: lib.ipc.ResolvedArgs,
    service_idx: u16,
    finished_idx: *std.atomic.Value(u16),
    reset_event: *std.Thread.ResetEvent,
) void {
    switch (service) {
        inline else => |svc| tracy.setThreadName("svc: " ++ @tagName(svc)),
    }

    entry_point(args);
    reset_event.set();
    finished_idx.store(service_idx, .seq_cst);
}

fn spawnServiceNoSandbox(
    service_instance: ServiceInstance,
    exit: memfd.RW,
    stderr: std.fs.File,
    regions: []const LookupResult,
    service_idx: u16,
    finished_idx: *std.atomic.Value(u16),
    reset_event: *std.Thread.ResetEvent,
) !std.Thread {
    const resolved_args = try resolveArgs(exit, stderr, regions);

    return try std.Thread.spawn(
        .{},
        threadEntry,
        .{
            getEntrypoint(service_instance.service),
            service_instance.service,
            resolved_args,
            service_idx,
            finished_idx,
            reset_event,
        },
    );
}
