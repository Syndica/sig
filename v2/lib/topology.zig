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

pub fn Unbound(comptime schema: Schema) type {
    return struct {
        /// Enum with a tag for each service.
        /// NOTE: can also be used to index `schema.services`.
        pub const ServiceId = @Type(.{ .@"enum" = info: {
            var fields: [schema.services.len]std.builtin.Type.EnumField = undefined;
            for (schema.services, &fields, 0..) |service, *field, i| {
                field.* = .{
                    .name = @tagName(service.name),
                    .value = i,
                };
            }
            break :info .{
                .tag_type = u8,
                .fields = &fields,
                .decls = &.{},
                .is_exhaustive = true,
            };
        } });

        /// The region id enum local to `service`.
        /// NOTE: can also be used to index `schema.services[@intFromEnum(service)].regions`.
        pub fn RegionIdServiceLocal(comptime service: ServiceId) type {
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

        /// Enum comprised of unique ids for every region across every service.
        /// Each name is defined by `regionIdName`.
        /// It is also a flattened enum representation of `ServiceRegionInfo`, where:
        /// `.{ .service_name = .local_region_name }` <=> `.@"service_name:local_region_name"`
        pub const RegionId = @Type(.{ .@"enum" = info: {
            var fields: []const std.builtin.Type.EnumField = &.{};
            for (schema.services) |service_schema| {
                for (service_schema.regions) |region_schema| {
                    fields = fields ++ [_]std.builtin.Type.EnumField{.{
                        .name = regionIdName(service_schema.name, region_schema.name),
                        .value = fields.len,
                    }};
                }
            }
            break :info .{
                .tag_type = std.math.IntFittingRange(0, fields.len -| 1),
                .fields = fields,
                .decls = &.{},
                .is_exhaustive = true,
            };
        } });

        /// Returns a unique name for every region across every service.
        pub inline fn regionIdName(
            comptime service: ServiceId,
            region: RegionIdServiceLocal(service),
        ) [:0]const u8 {
            if (@inComptime()) {
                return @tagName(service) ++ ":" ++ @tagName(region);
            }
            return switch (region) {
                inline else => |iregion| comptime regionIdName(service, iregion),
            };
        }

        /// Tagged union of enums, where the union tag is the `ServiceId`, and the
        /// payload is the corresponding `RegionIdServiceLocal(service_id)`.
        /// i.e. `.{ .service_id = .region_id_local }`.
        pub const ServiceRegionId = @Type(.{ .@"union" = info: {
            var fields: [schema.services.len]std.builtin.Type.UnionField = undefined;
            for (schema.services, &fields) |service, *field| {
                const service_id = @field(ServiceId, @tagName(service.name));
                const FieldType = RegionIdServiceLocal(service_id);
                field.* = .{
                    .name = @tagName(service.name),
                    .type = FieldType,
                    .alignment = @alignOf(FieldType),
                };
            }
            break :info .{
                .layout = .auto,
                .tag_type = ServiceId,
                .fields = &fields,
                .decls = &.{},
            };
        } });

        /// `.@"foo:bar"` -> `.{ .foo = .bar }`
        pub inline fn serviceRegionIdFromRegionId(region_id: RegionId) ServiceRegionId {
            if (@inComptime()) {
                const str = @tagName(region_id);
                const colon = std.mem.indexOfScalar(u8, str, ':').?;
                const service_str = str[0..colon];
                const service = @field(ServiceId, service_str);
                const region = @field(RegionIdServiceLocal(service), str[colon + 1 ..]);
                return @unionInit(ServiceRegionId, service_str, region);
            }
            return switch (region_id) {
                inline else => |iservice_id| comptime serviceRegionIdFromRegionId(iservice_id),
            };
        }

        pub fn regionIdFromServiceAndRegionId(
            comptime service: ServiceId,
            region_id: RegionIdServiceLocal(service),
        ) RegionId {
            return switch (region_id) {
                inline else => |iregion| @field(RegionId, regionIdName(service, iregion)),
            };
        }

        /// Returns the read/write access associated with the region id.
        pub inline fn getServiceRegionIdAccess(
            region_id: RegionId,
        ) Schema.Service.Region.Access {
            return switch (region_id) {
                inline else => |itag| comptime blk: {
                    const region_info = serviceRegionIdFromRegionId(itag);
                    const Local = RegionIdServiceLocal(region_info);
                    const local_region_id: Local = @field(region_info, @tagName(region_info));
                    const service_entry = schema.services[@intFromEnum(region_info)];
                    const region_entry = service_entry.regions[@intFromEnum(local_region_id)];
                    break :blk region_entry.access;
                },
            };
        }

        // -- Service Externs -- //

        /// Returns the name of the segfault handler function exposed by the specified service.
        pub fn getFaultHandlerName(service: ServiceId) [:0]const u8 {
            return switch (service) {
                inline else => |s| "svc_fault_handler_" ++ @tagName(s),
            };
        }

        /// Returns the segfault handler function exposed by the specified service.
        pub fn getFaultHandlerFn(service: ServiceId) SigactionFn {
            return switch (service) {
                inline else => |s| @extern(SigactionFn, .{ .name = getFaultHandlerName(s) }),
            };
        }

        /// Returns the name of the entrypoint function exposed by the specified service.
        pub fn getEntrypointName(service: ServiceId) [:0]const u8 {
            return switch (service) {
                inline else => |s| "svc_main_" ++ @tagName(s),
            };
        }

        /// Returns the entrypoint function exposed by the specified service.
        pub fn getEntrypointFn(service: ServiceId) ServiceEntrypoint {
            return switch (service) {
                inline else => |s| @extern(ServiceEntrypoint, .{ .name = getEntrypointName(s) }),
            };
        }

        pub fn BindingsMap(comptime RegionTag: type) type {
            return std.EnumArray(
                RegionTag,
                std.EnumSet(Unbound(schema).RegionId),
            );
        }
    };
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
    comptime bindings_map_init: Unbound(schema).BindingsMap(@typeInfo(Region).@"union".tag_type.?),
) type {
    return struct {
        pub const unbound = Unbound(schema);

        pub const RegionTag = @typeInfo(Region).@"union".tag_type.?;
        pub const BindingsMap = unbound.BindingsMap(RegionTag);
        const BindingsIndexer = BindingsMap.Indexer;
        pub const bindings_map = bindings_map_init;

        fn regionSize(r: Region) usize {
            return r.size();
        }

        fn regionInit(r: Region, buf: []align(std.heap.page_size_min) u8) !void {
            try r.init(buf);
        }

        fn regionFmtShareInfo(region_tag: RegionTag) std.fmt.Alt(RegionTag, regionWriteShareInfo) {
            return .{ .data = region_tag };
        }

        fn regionWriteShareInfo(
            region: RegionTag,
            w: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            try w.print("Region `{t}` shared with [ ", .{region});

            var shares_copy = getRegionBindingShares(region);
            var shares_iter = shares_copy.iterator();
            for (0..shares_copy.count()) |i| {
                const share_entry = shares_iter.next().?;

                if (i != 0) try w.writeAll(", ");
                const mode = if (share_entry.value.access == .rw) "rw" else "ro";
                try w.print("{t} ({s})", .{ share_entry.key, mode });
            }
            if (shares_iter.next() != null) unreachable;

            try w.writeAll(" ]");
        }

        comptime {
            if (validateBindingsMap(schema, RegionTag, bindings_map)) |result| switch (result) {
                .unordered_tags => |unordered| {
                    const region_tag_fields = @typeInfo(RegionTag).@"enum".fields;
                    const prev = region_tag_fields[unordered.prev];
                    const next = region_tag_fields[unordered.next];
                    @compileError("The tag for the Region union isn't sorted" ++
                        std.fmt.comptimePrint(
                            "; {s} ({d}) is greater than {s} ({d})",
                            .{ prev.name, prev.value, next.name, next.value },
                        ));
                },
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

        /// Returns the total number of spawned services that will be sharing the specified `region`.
        pub fn countTotalRegionShares(region: RegionTag) usize {
            return bindings_map.get(region).count();
        }

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

        const RegionBindingSharesMap = std.EnumMap(unbound.ServiceId, struct {
            access: Schema.Service.Region.Access,
        });

        /// Returns a set of all the services which the specified region binding is shared with,
        /// with each entry accompanied by properties of the share.
        fn getRegionBindingShares(region_binding_tag: RegionTag) RegionBindingSharesMap {
            const region_id_set = bindings_map.getPtrConst(region_binding_tag);
            var shares: RegionBindingSharesMap = .{};
            var iter = region_id_set.iterator();
            for (0..region_id_set.count()) |_| {
                const region_id = iter.next().?;
                const region_info = unbound.serviceRegionIdFromRegionId(region_id);
                const prev_opt = shares.fetchPut(region_info, .{
                    .access = unbound.getServiceRegionIdAccess(region_id),
                });
                if (prev_opt != null) unreachable;
            }
            if (iter.next() != null) unreachable;
            return shares;
        }

        fn getRegionBinding(region_id: unbound.RegionId) RegionTag {
            return for (bindings_map.values, 0..) |region_id_set, i| {
                const binding_tag = BindingsIndexer.keyForIndex(i);
                if (!region_id_set.contains(region_id)) continue;
                break binding_tag;
            } else unreachable;
        }

        pub const ServiceMap = struct {
            inner: std.EnumMap(unbound.ServiceId, Entry),

            pub const empty: ServiceMap = .{ .inner = .{} };

            pub const Entry = struct {
                runner: memfd.RW,
                regions: std.ArrayList(LookupResult),
            };

            pub const LookupResult = struct {
                region: Region,
                access: Schema.Service.Region.Access,
                memfd: lib.linux.memfd.RW,
            };

            pub fn deinit(self: *const ServiceMap, gpa: std.mem.Allocator) void {
                var map = self.inner;
                for (&map.values) |*lur| lur.regions.deinit(gpa);
            }
        };

        /// Pairs services up with their respective required regions and their rw/ro permission
        pub fn serviceMap(
            allocator: std.mem.Allocator,
            instances: SharedRegionInstances,
        ) !ServiceMap {
            const regions: [bindings_map.values.len]Region = regions: {
                var regions: [bindings_map.values.len]Region = undefined;

                @setEvalBranchQuota(bindings_map.values.len * schema.services.len);
                inline for (&regions, 0..bindings_map.values.len) |*region, binding_i| {
                    const region_binding_tag = comptime BindingsIndexer.keyForIndex(binding_i);
                    region.* = @unionInit(
                        Region,
                        @tagName(region_binding_tag),
                        @field(instances, @tagName(region_binding_tag)),
                    );
                }

                break :regions regions;
            };

            var region_memfds: [regions.len]memfd.RW = undefined;
            try createAndInitSharedRegionMemfds(&regions, &region_memfds);

            var runner_memfds: [schema.services.len]memfd.RW = undefined;
            try createRunnerMemfds(&runner_memfds);

            var map: ServiceMap = .empty;
            errdefer map.deinit(allocator);

            // check all service instances request regions which are shared with them
            inline for (schema.services, &runner_memfds) |service_entry, runner_memfd| {
                const service: unbound.ServiceId = service_entry.name;

                inline for (service_entry.regions) |region_entry| {
                    const region_local_id: unbound.RegionIdServiceLocal(service) =
                        region_entry.name;
                    const region_id: unbound.RegionId =
                        unbound.regionIdFromServiceAndRegionId(service, region_local_id);

                    const found_region: ServiceMap.LookupResult = blk: for (
                        regions,
                        &region_memfds,
                    ) |region, region_memfd| {
                        std.debug.assert(region_memfd.size == regionSize(region));
                        if (region != getRegionBinding(region_id)) continue;

                        var shares = getRegionBindingShares(region);
                        var shares_iter = shares.iterator();
                        for (0..shares.count()) |_| {
                            const share_target = shares_iter.next().?.key;
                            if (service != share_target) continue;

                            const result: ServiceMap.LookupResult = .{
                                .region = region,
                                .access = region_entry.access,
                                .memfd = region_memfd,
                            };

                            const exists = if (map.inner.getPtr(service)) |entry| exists: {
                                break :exists for (entry.regions.items) |existing| {
                                    if (existing.region != std.meta.activeTag(result.region)) {
                                        continue;
                                    }
                                    if (existing.access != result.access) {
                                        continue;
                                    }
                                    break true;
                                } else false;
                            } else false;

                            if (!exists) break :blk result;
                        } else if (shares_iter.next() != null) unreachable;
                    } else std.debug.panic(
                        "Service instance {t} requested {} region which was not shared with it",
                        .{ service, region_entry },
                    );

                    if (!map.inner.contains(service)) map.inner.put(service, .{
                        .runner = runner_memfd,
                        .regions = .empty,
                    });
                    const lur_list = map.inner.getPtrAssertContains(service);
                    try lur_list.regions.append(allocator, found_region);
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
            std.debug.assert(std.os.linux.elf_aux_maybe != null);
            var args: lib.ipc.ResolvedArgs = .{
                .stderr = params.stderr.handle,
                .runner = try params.runner.mmapStaticSize(lib.runner.Region, null),
                .linux_auxv = std.os.linux.elf_aux_maybe,

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
                const region_size = regionSize(region.region);
                if (region_size != region.memfd.size) {
                    std.debug.panic(
                        "region {s} expected to have size {Bi}, but memfd has size {Bi}.",
                        .{
                            @tagName(region.region),
                            region_size,
                            region.memfd.size,
                        },
                    );
                }

                switch (region.access) {
                    .rw => {
                        args.rw[i_rw] = (try region.memfd.mmap(null)).ptr;
                        args.rw_len[i_rw] = region_size;
                        i_rw += 1;
                    },
                    .readonly => {
                        const ro_memfd = try memfd.RO.fromRW(region.memfd);
                        args.ro[i_ro] = (try ro_memfd.mmap(null)).ptr;
                        args.ro_len[i_ro] = region_size;
                        i_ro += 1;
                    },
                }
            }

            return args;
        }

        /// Create and initialize memfds for each shared memory region (map it, initialize it, and then unmap it).
        /// We must unmap to avoid sharing regions with services that don't need them.
        fn createAndInitSharedRegionMemfds(
            regions: *const [bindings_map.values.len]Region,
            region_memfds: *[regions.len]memfd.RW,
        ) !void {
            @memset(region_memfds, .empty);

            for (regions, region_memfds) |region, *region_memfd| {
                // This name should be visible from a debugger, but serves no other purpose.
                var fmt_buf: [4096]u8 = undefined;
                const name = try std.fmt.bufPrintZ(&fmt_buf, "{f}", .{regionFmtShareInfo(region)});

                region_memfd.* = try .init(.{
                    .name = name,
                    .size = regionSize(region),
                });

                const buf = try region_memfd.mmap(null);
                defer std.posix.munmap(buf);
                try regionInit(region, buf);
                std.log.info("Initialised: {f}", .{regionFmtShareInfo(region)});
            }
        }

        // Creates a memfd for every service, to be used for storing a lib.runner.Region value, which is used
        // for reporting traces+errors back to the main process.
        fn createRunnerMemfds(runner_memfds: *[schema.services.len]memfd.RW) !void {
            @memset(runner_memfds, .empty);
            inline for (runner_memfds, schema.services) |*runner_memfd, service_entry| {
                runner_memfd.* = try .init(.{
                    .name = std.fmt.comptimePrint("runner_{s}", .{@tagName(service_entry.name)}),
                    .size = @sizeOf(lib.runner.Region),
                });
            }
        }

        // -- Service Spawning -- //

        /// Initialises the shared memory regions with their parameters, then securely starts up services.
        /// Blocks until the first service has exited, before dumping out traces.
        pub fn spawnAndWait(map: *const ServiceMap) !void {
            const ExitMeta = struct {
                id: unbound.ServiceId,
                pid: i32,
                exit: ?*lib.runner.Exit,
            };

            var exit_meta_buf: [schema.services.len]ExitMeta = undefined;
            var exit_metas: std.ArrayList(ExitMeta) = .initBuffer(&exit_meta_buf);

            // Start up all services, storing their pids
            inline for (schema.services) |service_schema| {
                const entry = map.inner.get(service_schema.name).?;
                const child_pid = try spawnService(service_schema.name, .{
                    .runner = entry.runner,
                    .stderr = .stderr(),
                    .regions = entry.regions.items,
                });
                exit_metas.appendAssumeCapacity(.{
                    .id = service_schema.name,
                    .pid = child_pid,
                    .exit = null,
                });
            }

            // We only mmap the exit regions after spawning the child processes, as we don't want them
            // mapped in children
            for (exit_metas.items) |*exit_meta| {
                const entry = map.inner.get(exit_meta.id).?;
                const runner = try entry.runner.mmapStaticSize(lib.runner.Region, null);
                exit_meta.exit = &runner.exit;
            }

            // Wait for the first child to exit
            var status: u32 = 0;
            const exited_pid: i32 = pid: {
                const ret: usize = linux.waitpid(-1, &status, 0);
                std.debug.assert(e(ret) == .SUCCESS);
                break :pid @intCast(ret);
            };

            const exited_meta = for (exit_metas.items) |exit_meta| {
                if (exit_meta.pid == exited_pid) break exit_meta;
            } else std.debug.panic("Unknown child pid {} exited\n", .{exited_pid});

            dumpOnExit(
                exited_meta.exit.?,
                exited_meta.id,
                exited_meta.pid,
                status,
            );
        }

        fn spawnService(
            service: unbound.ServiceId,
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
                std.log.info("Starting Service `{t}`, pid: {}", .{ service, child_pid });
                return child_pid;
            }

            switch (service) {
                inline else => |svc| tracy.setThreadName("svc: " ++ @tagName(svc)),
            }

            // register fault handlers
            {
                const act: *const std.os.linux.Sigaction = &.{
                    .handler = .{ .sigaction = unbound.getFaultHandlerFn(service) },
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

            unbound.getEntrypointFn(service)(resolved_args);
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
            service: unbound.ServiceId,
            pid: i32,
            status: u32,
        ) void {
            if (meta.panicMsg()) |panic_msg| {
                std.log.err(
                    "Service `{t}` (pid: {}) panicked with message: {s}",
                    .{ service, pid, panic_msg },
                );
            }
            if (meta.errorName()) |error_string| {
                std.log.err(
                    "Service `{t}` (pid: {}) exited with error: {s}",
                    .{ service, pid, error_string },
                );
            }
            if (meta.faultMsg()) |fault_msg| {
                std.log.err(
                    "Service `{t}` (pid: {}) faulted with message: {s}",
                    .{ service, pid, fault_msg },
                );
            }

            if (linux.W.TERMSIG(status) != 0) {
                std.log.err(
                    "Service `{t}` (pid: {}) exited from signal {}",
                    .{ service, pid, linux.W.TERMSIG(status) },
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

        pub fn spawnAndWaitNoSandbox(map: *const ServiceMap) !void {
            var reset_event: std.Thread.ResetEvent = .{};
            var finished_service_idx: std.atomic.Value(u16) = .init(std.math.maxInt(u16));

            const thread_exit_ctx: ThreadExitContext = .{
                .finished_idx = &finished_service_idx,
                .reset_event = &reset_event,
            };

            // Start up all services, storing their pids
            inline for (schema.services, 0..) |service_entry, i| {
                const entry = map.inner.get(service_entry.name).?;
                _ = try spawnServiceNoSandbox(service_entry.name, .{
                    .runner = entry.runner,
                    .stderr = .stderr(),
                    .regions = map.inner.get(service_entry.name).?.regions.items,
                    .service_idx = i,
                    .thread_exit_ctx = &thread_exit_ctx,
                });
            }

            // Wait for first service to exit
            reset_event.wait();

            const exited_idx = finished_service_idx.load(.seq_cst);
            std.debug.assert(exited_idx != std.math.maxInt(u16));

            const exited_runner_memfd = map.inner.get(@enumFromInt(exited_idx)).?.runner;
            const exited_runner = try exited_runner_memfd.mmapStaticSize(lib.runner.Region, null);
            const exited_service_id: unbound.ServiceId = @enumFromInt(exited_idx);
            dumpOnExit(
                &exited_runner.exit,
                exited_service_id,
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
            service: unbound.ServiceId,
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
            service: unbound.ServiceId,
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
                    unbound.getEntrypointFn(service),
                    service,
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
    const unbound = Unbound(schema);
    return union(enum) {
        /// The two enums referenced by index are out of order.
        unordered_tags: struct {
            prev: usize,
            next: usize,
        },
        /// The tags in this set were specified in two bindings.
        duplicated: std.EnumSet(unbound.RegionId),
        /// The tags in this set were not specified in any binding.
        missing: std.EnumSet(unbound.RegionId),
    };
}

/// Returns null on success.
/// Otherwise returns a diagnostic describing the problem.
inline fn validateBindingsMap(
    comptime schema: Schema,
    /// A union of all the intended shared region bindings.
    comptime RegionTag: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Region` tag name).
    comptime bindings_map: Unbound(schema).BindingsMap(RegionTag),
) ?ValidateBindingsMapResult(schema) {
    comptime {
        const unbound = Unbound(schema);
        const region_tag_info = @typeInfo(RegionTag).@"enum";
        for (
            region_tag_info.fields[0 .. region_tag_info.fields.len - 1],
            0..,
            region_tag_info.fields[1..],
            1..,
        ) |prev, prev_i, next, next_i| {
            if (prev.value == next.value) unreachable;
            if (prev.value > next.value) return .{
                .unrodered_tags = .{
                    .prev = prev_i,
                    .next = next_i,
                },
            };
        }

        var accumulated_set: std.EnumSet(unbound.RegionId) = .{};
        for (bindings_map.values) |region_id_set| {
            const intersection = accumulated_set.intersectWith(region_id_set);
            if (intersection.count() == 0) {
                accumulated_set.setUnion(region_id_set);
                continue;
            }
            return .{ .duplicated = intersection };
        }
        if (accumulated_set.count() != @typeInfo(unbound.RegionId).@"enum".fields.len) {
            const missing = accumulated_set.complement();
            return .{ .missing = missing };
        }
        return null;
    }
}
