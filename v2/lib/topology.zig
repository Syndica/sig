//! Defines how our services communicate, and how they're started up.
//!
//! This code is reponsible for:
//! - Defining services and their needed shared memory regions
//! - Initialising shared memory regions
//! - Starting up services and securing them down
//! - Dumping stack traces + errors on service exit

const std = @import("std");
const lib = @import("lib.zig");
const tracy = @import("tracy");

const linux = std.os.linux;
const E = linux.E;
const e = E.init;
const SigactionFn = linux.Sigaction.sigaction_fn;
const ServiceEntrypoint = lib.ipc.ServiceFn;

const memfd = lib.linux.memfd;

const topology = @This();

pub const Schema = struct {
    services: []const Service,

    pub const Service = struct {
        /// The service's identifier.
        name: @Type(.enum_literal),
        /// The regions expected by this service.
        regions: []const Region,

        pub const Region = struct {
            /// The region's identifier, local to the service.
            name: @Type(.enum_literal),
            access: Access,

            pub const Access = enum { readonly, rw };
        };
    };
};

pub fn ServiceId(comptime schema: Schema) type {
    var fields: [schema.services.len]std.builtin.Type.EnumField = undefined;
    for (schema.services, &fields, 0..) |instance, *field, i| {
        field.* = .{
            .name = @tagName(instance.name),
            .value = i,
        };
    }
    return @Type(.{ .@"enum" = .{
        .tag_type = u8,
        .fields = &fields,
        .decls = &.{},
        .is_exhaustive = true,
    } });
}

/// Flattened enum representation of `ServiceRegionInfo`, where:
/// `.{ .service_name = .local_region_name }` <=> `.@"service_name:local_region_name"`
pub fn ServiceRegionId(comptime schema: Schema) type {
    var fields: []const std.builtin.Type.EnumField = &.{};
    for (schema.services) |service| {
        for (service.regions) |service_region| {
            fields = fields ++ [_]std.builtin.Type.EnumField{.{
                .name = @tagName(service.name) ++ ":" ++ @tagName(service_region.name),
                .value = fields.len,
            }};
        }
    }
    return @Type(.{ .@"enum" = .{
        .tag_type = std.math.IntFittingRange(0, fields.len -| 1),
        .fields = fields,
        .decls = &.{},
        .is_exhaustive = true,
    } });
}

pub fn BindingsMap(
    comptime schema: Schema,
    comptime RegionTag: type,
) type {
    return std.EnumArray(
        RegionTag,
        std.EnumSet(ServiceRegionId(schema)),
    );
}

/// Namespace of types and functions which, with respect to the equivalences
/// defined by `bindings_map`, assist in materializing the regions of the topology.
pub fn Bind(
    comptime schema: Schema,
    /// A tagged union of all the intended shared region bindings.
    /// The associated payload should be the type that will be used to initialize the region.
    /// Expected methods:
    /// ```zig
    /// /// returns the required mapped size of the region.
    /// fn size(r: Region) usize;
    ///
    /// /// asserts `buf.len == r.size()`, and initializes `buf` as a region as described by the union payload.
    /// fn init(r: Region, buf: []align(std.heap.page_size_min) u8) E!void;
    /// ```
    comptime Region: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Region` tag name).
    comptime bindings_map_init: BindingsMap(schema, @typeInfo(Region).@"union".tag_type.?),
) type {
    return struct {
        const bound = @This();

        pub const RegionTag = @typeInfo(Region).@"union".tag_type.?;
        pub const BindingsMap = topology.BindingsMap(schema, RegionTag);
        const BindingsIndexer = bound.BindingsMap.Indexer;
        pub const bindings_map = bindings_map_init;

        fn regionSize(r: Region) usize {
            return r.size();
        }

        comptime {
            if (validateBindingsMap(schema, RegionTag, bindings_map)) |result| switch (result) {
                inline .duplicated, .missing => |bad_set, reason| {
                    var err_msg: []const u8 = switch (reason) {
                        .duplicated => "The following regions were bound multiple times: ",
                        .missing => "The following regions are not bound: ",
                    };
                    var iter = bad_set.iterator();
                    for (0..bad_set.count()) |missing_i| {
                        const duplicated = iter.next().?;
                        const sep = if (missing_i == 0) "" else ", ";
                        err_msg = err_msg ++ sep ++ @tagName(duplicated);
                    }
                    if (iter.next() != null) unreachable;
                    @compileError(err_msg);
                },
            };
        }

        /// Enum with a tag for each service.
        /// NOTE: can also be used to index `schema.services`.
        pub const ServiceId = topology.ServiceId(schema);

        pub const ServiceRegionId = topology.ServiceRegionId(schema);

        /// Tagged union of enums, where the union tag is the service, and the
        /// payload is the corresponding `ServiceRegionIdLocal(service_id)`.
        /// i.e. `.{ .service_name = .local_region_name }`.
        pub const ServiceRegionInfo = @Type(.{ .@"union" = info: {
            var fields: [schema.services.len]std.builtin.Type.UnionField = undefined;
            for (schema.services, &fields) |service, *field| {
                const service_id = @field(bound.ServiceId, @tagName(service.name));
                const FieldType = LocalServiceRegionId(service_id);
                field.* = .{
                    .name = @tagName(service.name),
                    .type = FieldType,
                    .alignment = @alignOf(FieldType),
                };
            }
            break :info .{
                .layout = .auto,
                .tag_type = bound.ServiceId,
                .fields = &fields,
                .decls = &.{},
            };
        } });

        /// The region id enum local to `service`.
        /// NOTE: can also be used to index `schema.services[@intFromEnum(service)].regions`.
        pub fn LocalServiceRegionId(comptime service: bound.ServiceId) type {
            const regions = schema.services[@intFromEnum(service)].regions;
            var fields: [regions.len]std.builtin.Type.EnumField = undefined;
            for (regions, &fields, 0..) |region, *field, i| {
                field.* = .{
                    .name = @tagName(region.name),
                    .value = i,
                };
            }
            return @Type(.{ .@"enum" = .{
                .tag_type = u8,
                .fields = &fields,
                .decls = &.{},
                .is_exhaustive = true,
            } });
        }

        /// `.@"foo:bar"` -> `.{ .foo = .bar }`
        inline fn getServiceRegionIdInfo(service_id: bound.ServiceRegionId) ServiceRegionInfo {
            if (@inComptime()) {
                const str = @tagName(service_id);
                const colon = std.mem.indexOfScalarPos(u8, str, 0, ':').?;
                const service_str = str[0..colon];
                const service = @field(bound.ServiceId, service_str);
                const region = @field(LocalServiceRegionId(service), str[colon + 1 ..]);
                return @unionInit(ServiceRegionInfo, service_str, region);
            }
            return switch (service_id) {
                inline else => |iservice_id| comptime getServiceRegionIdInfo(iservice_id),
            };
        }

        pub const ServiceInstance = struct {
            service: bound.ServiceId,
            /// for supporting multiple services of the same kind
            n: u8 = 0,

            pub fn format(
                self: ServiceInstance,
                w: *std.Io.Writer,
            ) std.Io.Writer.Error!void {
                try w.print("{s}_{}", .{ @tagName(self.service), self.n });
            }
        };

        /// Returns the total number of spawned services will be sharing the specified `region`.
        /// This accounts for the maximum instance index (the `n` field).
        pub fn countRegionShares(
            region: RegionTag,
            services: []const ServiceInstance,
        ) usize {
            var service_counts: std.EnumArray(bound.ServiceId, u8) = .initFill(0);

            const region_bindings = bindings_map.get(region);
            var iter = region_bindings.iterator();
            for (0..region_bindings.count()) |_| {
                const service_region_id: bound.ServiceRegionId = iter.next().?;
                const info = getServiceRegionIdInfo(service_region_id);
                for (services) |instance| {
                    if (info == instance.service) {
                        const max_count_ptr = service_counts.getPtr(instance.service);
                        max_count_ptr.* = @max(max_count_ptr.*, instance.n + 1);
                    }
                }
            }
            if (iter.next() != null) unreachable;

            const vec: @Vector(service_counts.values.len, usize) = service_counts.values;
            return @reduce(.Add, vec);
        }

        pub const Share = struct {
            instance: ServiceInstance,
            rw: bool,
        };

        pub const SharedRegion = struct {
            region: Region,
            shares: []const Share,
            requested_location: ?[*]align(std.heap.page_size_min) u8 = null,

            pub fn format(
                self: SharedRegion,
                w: *std.Io.Writer,
            ) std.Io.Writer.Error!void {
                try w.print("Region `{s}` shared with [ ", .{@tagName(self.region)});
                for (self.shares, 0..) |share, i| {
                    if (i != 0) try w.writeAll(", ");
                    const mode = if (share.rw) "rw" else "ro";
                    try w.print("{f} ({s})", .{ share.instance, mode });
                }
                try w.writeAll(" ]");
            }
        };

        pub const SharedRegionInstances = @Type(.{ .@"struct" = info: {
            var fields: [bindings_map.values.len]std.builtin.Type.StructField = undefined;
            for (&fields, @typeInfo(Region).@"union".fields) |*s_field, u_field| {
                s_field.* = .{
                    .name = u_field.name,
                    .type = u_field.type,
                    .default_value_ptr = null,
                    .is_comptime = false,
                    .alignment = @alignOf(u_field.type),
                };
            }
            break :info .{
                .layout = .auto,
                .backing_integer = null,
                .fields = &fields,
                .decls = &.{},
                .is_tuple = false,
            };
        } });

        pub fn toSharedRegions(
            instances: SharedRegionInstances,
        ) [bindings_map.values.len]SharedRegion {
            @setEvalBranchQuota(
                bindings_map.values.len *
                    128 * // reasonable upper bound of 128 services
                    100, // reasonable upper bound of 100 bytes per service name
            );
            var shared_regions: [bindings_map.values.len]SharedRegion = undefined;
            inline for (bindings_map.values, 0..) |region_id_set, binding_i| {
                const region_binding_tag = comptime BindingsIndexer.keyForIndex(binding_i);

                comptime var shares: []const Share = &.{};

                comptime var iter = region_id_set.iterator();
                inline for (0..comptime region_id_set.count()) |_| {
                    const region_id = comptime iter.next().?;
                    const region_info = getServiceRegionIdInfo(region_id);
                    const local_region_id = @field(region_info, @tagName(region_info));
                    const service_entry = schema.services[@intFromEnum(region_info)];
                    const region_entry = service_entry.regions[@intFromEnum(local_region_id)];

                    shares = shares ++ [_]Share{.{
                        .instance = .{
                            .service = region_info,
                            .n = 0, // TODO: support referencing multiple service instances (.n > 0)
                        },
                        .rw = switch (region_entry.access) {
                            .readonly => false,
                            .rw => true,
                        },
                    }};
                }
                comptime if (iter.next() != null) unreachable;

                shared_regions[binding_i] = .{
                    .region = @unionInit(
                        Region,
                        @tagName(region_binding_tag),
                        @field(instances, @tagName(region_binding_tag)),
                    ),
                    .shares = shares,
                };
            }
            return shared_regions;
        }

        pub fn getRegionBinding(service_region_id: bound.ServiceRegionId) Region.Tag {
            return for (bindings_map.values, 0..) |region_id_set, i| {
                const binding_tag = BindingsIndexer.keyForIndex(i);
                if (!region_id_set.contains(service_region_id)) continue;
                break binding_tag;
            } else unreachable;
        }

        pub const RequiredRegion = struct {
            region: RegionTag,
            rw: bool = false,
        };

        pub inline fn getRequiredRegions(
            comptime service_id: bound.bound.ServiceId,
        ) []const RequiredRegion {
            comptime {
                @setEvalBranchQuota(100_000);

                const service_entry = schema.services[@intFromEnum(service_id)];
                var required: []const RequiredRegion = &.{};
                for (service_entry.regions) |region| {
                    required = required ++ &[_]RequiredRegion{.{
                        .region = getRegionBinding(@field(
                            bound.ServiceRegionId,
                            @tagName(service_id) ++ ":" ++ @tagName(region.name),
                        )),
                        .rw = switch (region.access) {
                            .rw => true,
                            .readonly => false,
                        },
                    }};
                }
                return required;
            }
        }

        // -- Service Externs -- //

        /// Returns the name of the segfault handler function exposed by the specified service.
        pub fn getFaultHandlerName(service: bound.ServiceId) [:0]const u8 {
            return switch (service) {
                inline else => |s| "svc_fault_handler_" ++ @tagName(s),
            };
        }

        /// Returns the segfault handler function exposed by the specified service.
        pub fn getFaultHandlerFn(service: bound.ServiceId) SigactionFn {
            return switch (service) {
                inline else => |s| @extern(SigactionFn, .{ .name = getFaultHandlerName(s) }),
            };
        }

        /// Returns the name of the entrypoint function exposed by the specified service.
        pub fn getEntrypointName(service: bound.ServiceId) [:0]const u8 {
            return switch (service) {
                inline else => |s| "svc_main_" ++ @tagName(s),
            };
        }

        /// Returns the entrypoint function exposed by the specified service.
        pub fn getEntrypointFn(service: bound.ServiceId) ServiceEntrypoint {
            return switch (service) {
                inline else => |s| @extern(ServiceEntrypoint, .{ .name = getEntrypointName(s) }),
            };
        }

        pub const ServiceMap = struct {
            inner: std.AutoArrayHashMapUnmanaged(
                ServiceInstance,
                std.ArrayList(LookupResult),
            ),

            pub const empty: ServiceMap = .{ .inner = .empty };

            pub const LookupResult = struct {
                n: usize, // for supporting multiple regions of the same kind
                shared: SharedRegion,
                rw: bool,
                memfd: lib.linux.memfd.RW,
            };

            pub fn deinit(self: *const ServiceMap, gpa: std.mem.Allocator) void {
                var map = self.inner;
                for (map.values()) |*lur| lur.deinit(gpa);
                map.deinit(gpa);
            }
        };

        /// Pairs services up with their respective required regions and their rw/ro permission
        pub fn serviceMap(
            allocator: std.mem.Allocator,
            comptime services: []const ServiceInstance,
            regions: []const SharedRegion,
            region_memfds: []const lib.linux.memfd.RW,
        ) std.mem.Allocator.Error!ServiceMap {
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
                        std.debug.panic(
                            "Shared region {f} with unknown service {}\n",
                            .{ region, share },
                        );
                }
            }

            var map: ServiceMap = .empty;
            errdefer map.deinit(allocator);

            // check all service instances request regions which are shared with them
            inline for (services) |instance| {
                for (getRequiredRegions(instance.service)) |required_region| {
                    const found_region: ServiceMap.LookupResult = blk: for (
                        regions,
                        region_memfds,
                        0..,
                    ) |shared_region, region_memfd, n| {
                        if (shared_region.region != required_region.region) continue;

                        for (shared_region.shares) |share| {
                            if (instance.service == share.instance.service and
                                instance.n == share.instance.n)
                            {
                                const result: ServiceMap.LookupResult = .{
                                    .n = n,
                                    .shared = shared_region,
                                    .rw = required_region.rw,
                                    .memfd = region_memfd,
                                };

                                var exists = false;
                                if (map.inner.getPtr(instance)) |entry| {
                                    for (entry.items) |existing_result| {
                                        if (std.meta.eql(existing_result, result)) {
                                            exists = true;
                                            break;
                                        }
                                    }
                                }

                                std.debug.assert(
                                    region_memfd.size == regionSize(shared_region.region),
                                );
                                if (!exists) break :blk result;
                            }
                        }
                    } else std.debug.panic(
                        "Service instance {f} requested {} region which was not shared with it",
                        .{ instance, required_region },
                    );

                    const entry = try map.inner.getOrPut(allocator, instance);
                    if (!entry.found_existing) entry.value_ptr.* = .empty;
                    try entry.value_ptr.append(allocator, found_region);
                }
            }

            return map;
        }

        // -- Memory Mapped fds -- //

        /// Mmap in our memfds, putting the regions in a type-erased extern struct.
        pub fn resolveArgs(
            params: struct {
                runner: memfd.RW,
                stderr: std.fs.File,
                regions: []const ServiceMap.LookupResult,
            },
        ) !lib.ipc.ResolvedArgs {
            var args: lib.ipc.ResolvedArgs = .{
                .stderr = params.stderr.handle,
                .runner = try params.runner.mmapStaticSize(lib.runner.Region, .{}),

                .rw = @splat(null),
                .rw_len = @splat(0),
                .ro = @splat(null),
                .ro_len = @splat(0),

                .thread_crash_ctx = null,
                .thread_crash_fn = null,
                .service_idx = std.math.maxInt(u16),
            };

            var i_rw: u8 = 0;
            var i_ro: u8 = 0;

            for (params.regions) |region| {
                const region_size = regionSize(region.shared.region);
                if (region_size != region.memfd.size) {
                    std.debug.panic(
                        "region {s}[{d}] expected to have size {Bi}, but memfd has size {Bi}.",
                        .{
                            @tagName(region.shared.region), region.n,
                            region_size,                    region.memfd.size,
                        },
                    );
                }

                if (region.rw) {
                    args.rw[i_rw] = (try region.memfd.mmap(.{
                        .at_ptr = region.shared.requested_location,
                        .populate = true,
                    })).ptr;
                    args.rw_len[i_rw] = region_size;
                    i_rw += 1;
                } else {
                    const ro_memfd = try memfd.RO.fromRW(region.memfd);
                    args.ro[i_ro] = (try ro_memfd.mmap(.{
                        .at_ptr = region.shared.requested_location,
                        .populate = true,
                    })).ptr;
                    args.ro_len[i_ro] = region_size;
                    i_ro += 1;
                }
            }

            return args;
        }

        /// Create and initialize memfds for each shared memory region (map it, initialize it, and then unmap it).
        /// We must unmap to avoid sharing regions with services that don't need them.
        fn createAndInitSharedRegionMemfds(
            gpa: std.mem.Allocator,
            regions: []const SharedRegion,
        ) ![]const memfd.RW {
            const region_memfds: []memfd.RW = try gpa.alloc(memfd.RW, regions.len);
            errdefer gpa.free(region_memfds);
            @memset(region_memfds, .empty);

            for (region_memfds, regions) |*region_memfd, shared_region| {
                // This name should be visible from a debugger, but serves no other purpose.
                var fmt_buf: [4096]u8 = undefined;
                const name = try std.fmt.bufPrintZ(&fmt_buf, "{f}", .{shared_region});

                region_memfd.* = try .init(.{
                    .name = name,
                    .size = shared_region.region.size(),
                });

                const buf = try region_memfd.mmap(.{ .at_ptr = shared_region.requested_location });
                defer std.posix.munmap(buf);
                try shared_region.region.init(buf);
                std.log.info("Initialised: {f}", .{shared_region});
            }

            return region_memfds;
        }

        // Creates a memfd for every service, to be used for storing a lib.runner.Region value, which is used
        // for reporting traces+errors back to the main process.
        fn createRunnerMemfds(
            comptime services: []const ServiceInstance,
            runner_memfds: *[services.len]memfd.RW,
        ) !void {
            @memset(runner_memfds, .empty);
            inline for (runner_memfds, services) |*runner_memfd, service_instance| {
                runner_memfd.* = try .init(.{
                    .name = std.fmt.comptimePrint(
                        "runner_{s}_{}",
                        .{ @tagName(service_instance.service), service_instance.n },
                    ),
                    .size = @sizeOf(lib.runner.Region),
                });
            }
        }

        // -- Service Spawning -- //

        /// Initialises the shared memory regions with their parameters, then securely starts up services.
        /// Blocks until the first service has exited, before dumping out traces.
        pub fn spawnAndWait(
            allocator: std.mem.Allocator,
            comptime services: []const ServiceInstance,
            regions: []const SharedRegion,
        ) !void {
            const region_memfds = try createAndInitSharedRegionMemfds(allocator, regions);
            defer allocator.free(region_memfds);

            var runner_memfds: [services.len]memfd.RW = undefined;
            try createRunnerMemfds(services, &runner_memfds);

            var map = try serviceMap(allocator, services, regions, region_memfds);
            defer map.deinit(allocator);

            const ExitMeta = struct {
                pid: i32,
                exit: ?*lib.runner.Exit,
            };

            var exit_meta: std.MultiArrayList(ExitMeta) = .{};
            defer exit_meta.deinit(allocator);
            try exit_meta.ensureUnusedCapacity(allocator, services.len);

            // Start up all services, storing their pids
            inline for (services, &runner_memfds) |service_instance, runner| {
                const child_pid = try spawnService(service_instance, .{
                    .runner = runner,
                    .stderr = .stderr(),
                    .regions = map.inner.get(service_instance).?.items,
                });

                try exit_meta.append(allocator, .{ .pid = child_pid, .exit = null });
            }

            // We only mmap the exit regions after spawning the child processes, as we don't want them
            // mapped in children
            for (exit_meta.items(.exit), &runner_memfds) |*exit, runner_fd| {
                const runner = try runner_fd.mmapStaticSize(lib.runner.Region, .{});
                exit.* = &runner.exit;
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
            params: struct {
                runner: memfd.RW,
                stderr: std.fs.File,
                regions: []const ServiceMap.LookupResult,
            },
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
                    .handler = .{ .sigaction = getFaultHandlerFn(service_instance.service) },
                    .mask = std.os.linux.sigemptyset(),
                    .flags = (std.posix.SA.SIGINFO | std.posix.SA.RESTART | std.posix.SA.RESETHAND),
                };

                const SIG = linux.SIG;
                // standard signals in std.debug.updateSegfaultHandler
                if (e(std.os.linux.sigaction(SIG.SEGV, act, null)) != .SUCCESS) @panic("wtf");
                if (e(std.os.linux.sigaction(SIG.ILL, act, null)) != .SUCCESS) @panic("wtf");
                if (e(std.os.linux.sigaction(SIG.BUS, act, null)) != .SUCCESS) @panic("wtf");
                if (e(std.os.linux.sigaction(SIG.FPE, act, null)) != .SUCCESS) @panic("wtf");

                // catch seccomp too
                if (e(std.os.linux.sigaction(SIG.SYS, act, null)) != .SUCCESS) @panic("wtf");
            }

            // Make sure that the services die when the parent exits
            {
                const ret = linux.prctl(
                    @intFromEnum(linux.PR.SET_PDEATHSIG),
                    linux.SIG.KILL,
                    0,
                    0,
                    0,
                );
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

            const resolved_args = try resolveArgs(.{
                .runner = params.runner,
                .stderr = params.stderr,
                .regions = params.regions,
            });

            // mseal our shared VMAs (essentially making sure their mapping can't be tampered with)
            for (resolved_args.ro, resolved_args.ro_len) |ptr, len| mseal(ptr orelse continue, len);
            for (resolved_args.rw, resolved_args.rw_len) |ptr, len| mseal(ptr orelse continue, len);
            mseal(@ptrCast(resolved_args.runner), @sizeOf(lib.runner.Region));

            closeAllFdsExceptStderr(params.stderr.handle);

            // makes it impossible for the service to gain privileges
            std.debug.assert(try std.posix.prctl(.SET_NO_NEW_PRIVS, .{ 1, 0, 0, 0 }) == 0);

            // install a basic seccomp filter that bans syscalls except write+sleep
            {
                const bpf_filters = lib.linux.bpf.printSleepExit(params.stderr.handle);
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

            getEntrypointFn(service_instance.service)(resolved_args);
            std.process.exit(255);
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
            meta: *lib.runner.Exit,
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
            const region_memfds = try createAndInitSharedRegionMemfds(allocator, regions);
            defer allocator.free(region_memfds);

            var runner_memfds: [services.len]memfd.RW = undefined;
            try createRunnerMemfds(services, &runner_memfds);

            var map = try serviceMap(allocator, services, regions, region_memfds);
            defer map.deinit(allocator);

            var reset_event: std.Thread.ResetEvent = .{};
            var finished_service_idx: std.atomic.Value(u16) = .init(std.math.maxInt(u16));

            const thread_exit_ctx: ThreadExitContext = .{
                .finished_idx = &finished_service_idx,
                .reset_event = &reset_event,
            };

            // Start up all services, storing their pids
            inline for (services, &runner_memfds, 0..) |service_instance, runner, i| {
                _ = try spawnServiceNoSandbox(service_instance, .{
                    .runner = runner,
                    .stderr = .stderr(),
                    .regions = map.inner.get(service_instance).?.items,
                    .service_idx = i,
                    .thread_exit_ctx = &thread_exit_ctx,
                });
            }

            // Wait for first service to exit
            reset_event.wait();

            const exited_idx = finished_service_idx.load(.seq_cst);
            std.debug.assert(exited_idx != std.math.maxInt(u16));

            const exited_runner_memfd = runner_memfds[exited_idx];
            const exited_runner = try exited_runner_memfd.mmapStaticSize(lib.runner.Region, .{});
            dumpOnExit(
                &exited_runner.exit,
                services[exited_idx],
                0,
                0,
            );
        }

        /// Context created by the service initializer, used to report thread exit or crash and wake the
        /// main thread. Services receive it as opaque data and must not inspect it.
        const ThreadExitContext = struct {
            finished_idx: *std.atomic.Value(u16),
            reset_event: *std.Thread.ResetEvent,
        };

        fn signalThreadExit(service_idx: u16, ctx: *const ThreadExitContext) void {
            ctx.finished_idx.store(service_idx, .seq_cst);
            ctx.reset_event.set();
        }

        // Called by service threads in no-sandbox mode. Uses C calling convention because the function
        // pointer crosses service/init compilation units.
        fn signalThreadCrash(ctx: ?*const anyopaque, service_idx: u16) callconv(.c) void {
            const thread_ctx: *const ThreadExitContext = @ptrCast(@alignCast(ctx orelse return));
            signalThreadExit(service_idx, thread_ctx);
        }

        fn threadEntry(
            entry_point: ServiceEntrypoint,
            service: bound.ServiceId,
            args: lib.ipc.ResolvedArgs,
            service_idx: u16,
            thread_exit_ctx: *const ThreadExitContext,
        ) void {
            switch (service) {
                inline else => |svc| tracy.setThreadName("svc: " ++ @tagName(svc)),
            }

            entry_point(args);
            signalThreadExit(service_idx, thread_exit_ctx);
        }

        fn spawnServiceNoSandbox(
            service_instance: ServiceInstance,
            params: struct {
                runner: memfd.RW,
                stderr: std.fs.File,
                regions: []const ServiceMap.LookupResult,
                service_idx: u16,
                thread_exit_ctx: *const ThreadExitContext,
            },
        ) !std.Thread {
            var resolved_args = try resolveArgs(.{
                .runner = params.runner,
                .stderr = params.stderr,
                .regions = params.regions,
            });
            resolved_args.thread_crash_ctx = params.thread_exit_ctx;
            resolved_args.thread_crash_fn = signalThreadCrash;
            resolved_args.service_idx = params.service_idx;

            return try std.Thread.spawn(
                .{},
                threadEntry,
                .{
                    getEntrypointFn(service_instance.service),
                    service_instance.service,
                    resolved_args,
                    params.service_idx,
                    params.thread_exit_ctx,
                },
            );
        }
    };
}

fn ValidateBindingsMapResult(
    comptime schema: Schema,
) type {
    return union(enum) {
        /// The tags in this set were specified in two bindings.
        duplicated: std.EnumSet(ServiceRegionId(schema)),
        /// The tags in this set were not specified in any binding.
        missing: std.EnumSet(ServiceRegionId(schema)),
    };
}

/// Returns null on success.
/// Otherwise returns a diagnostic describing the problem.
inline fn validateBindingsMap(
    comptime schema: Schema,
    /// A union of all the intended shared region bindings.
    comptime RegionTag: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Region` tag name).
    comptime bindings_map: BindingsMap(schema, RegionTag),
) ?ValidateBindingsMapResult(schema) {
    comptime {
        var accumulated_set: std.EnumSet(ServiceRegionId(schema)) = .{};
        for (bindings_map.values) |region_id_set| {
            const intersection = accumulated_set.intersectWith(region_id_set);
            if (intersection.count() == 0) {
                accumulated_set.setUnion(region_id_set);
                continue;
            }
            return .{ .duplicated = intersection };
        }
        if (accumulated_set.count() != @typeInfo(ServiceRegionId(schema)).@"enum".fields.len) {
            const missing = accumulated_set.complement();
            return .{ .missing = missing };
        }
        return null;
    }
}
