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

        pub fn renderPrettyZon(
            service: Service,
            sz: *std.zon.Serializer,
            options: std.zon.Serializer.ValueOptions,
        ) std.Io.Writer.Error!void {
            var sz_service = try sz.beginStruct(.{
                .whitespace_style = .{ .wrap = true },
            });

            {
                try sz_service.field("name", service.name, options);
            }

            {
                var sz_regions = try sz_service.beginTupleField("regions", .{
                    .whitespace_style = .{ .wrap = true },
                });
                inline for (service.regions) |region| {
                    try sz_regions.field(region, .{});
                }
                try sz_regions.end();
            }

            try sz_service.end();
        }
    };

    pub fn renderPrettyZonSubset(
        schema: Schema,
        sz: *std.zon.Serializer,
        options: std.zon.Serializer.ValueOptions,
        service_ids_subset: std.EnumSet(Unbound(schema).ServiceId),
    ) std.Io.Writer.Error!void {
        var sz_tuple = try sz.beginTuple(.{
            .whitespace_style = .{ .wrap = true },
        });
        try schema.renderPrettyZonSubsetFields(&sz_tuple, options, service_ids_subset);
        try sz_tuple.end();
    }

    pub fn renderPrettyZonSubsetFields(
        schema: Schema,
        sz_tuple: *std.zon.Serializer.Tuple,
        options: std.zon.Serializer.ValueOptions,
        service_ids_subset: std.EnumSet(Unbound(schema).ServiceId),
    ) std.Io.Writer.Error!void {
        var subset_iter = service_ids_subset.iterator();
        for (0..service_ids_subset.count()) |_| {
            try sz_tuple.fieldPrefix();
            const service_id = subset_iter.next().?;
            switch (service_id) {
                inline else => |itag| {
                    const service = schema.services[@intFromEnum(itag)];
                    try service.renderPrettyZon(sz_tuple.container.serializer, options);
                },
            }
        }
        if (subset_iter.next() != null) unreachable;
    }
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
        pub fn regionIdName(
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
        pub fn serviceRegionIdFromRegionId(region_id: RegionId) ServiceRegionId {
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
        pub fn getServiceRegionIdAccess(
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

        pub fn BindingsMap(comptime BindingTag: type) type {
            return std.EnumArray(
                BindingTag,
                std.EnumSet(Unbound(schema).RegionId),
            );
        }

        // -- Binding Validation -- //

        pub fn ValidateBindingsMapResult(comptime BindingTag: type) type {
            return union(enum) {
                /// The specified tag's value is not in the expected ascending order.
                unordered_binding: struct {
                    tag: BindingTag,
                    expected: usize,
                },
                /// The tags in this set were specified in two bindings.
                duplicated: std.EnumSet(RegionId),
                /// The tags in this set were not specified in any binding.
                missing: std.EnumSet(RegionId),
            };
        }

        /// Returns null on success.
        /// Otherwise returns a diagnostic describing the problem.
        pub fn validateBindingsMap(
            /// A union of all the intended shared region bindings.
            comptime BindingTag: type,
            /// Defines the equivalences between regions across all services, unifying them under one binding (the `Binding` tag name).
            comptime bindings_map: BindingsMap(BindingTag),
        ) ?ValidateBindingsMapResult(BindingTag) {
            comptime {
                const region_tag_info = @typeInfo(BindingTag).@"enum";
                for (region_tag_info.fields, 0..) |field, field_i| {
                    if (field.value != field_i) return .{
                        .unordered_binding = .{
                            .tag = @enumFromInt(field.value),
                            .expected = field_i,
                        },
                    };
                }

                var accumulated_set: std.EnumSet(RegionId) = .{};
                for (bindings_map.values) |region_id_set| {
                    const intersection = accumulated_set.intersectWith(region_id_set);
                    if (intersection.count() == 0) {
                        accumulated_set.setUnion(region_id_set);
                        continue;
                    }
                    return .{ .duplicated = intersection };
                }
                if (accumulated_set.count() != @typeInfo(RegionId).@"enum".fields.len) {
                    const missing = accumulated_set.complement();
                    return .{ .missing = missing };
                }
                return null;
            }
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
    /// /// returns the required mapped size of the bound region.
    /// fn size(r: Region) usize;
    ///
    /// /// asserts `buf.len == r.size()`, and initializes `buf` as a region as described by the union payload.
    /// fn init(r: Region, buf: []align(std.heap.page_size_min) u8) E!void;
    /// ```
    comptime Binding: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Binding` tag name).
    comptime bindings_map_init: Unbound(schema).BindingsMap(@typeInfo(Binding).@"union".tag_type.?),
) type {
    return struct {
        pub const unbound = Unbound(schema);

        /// Members validated to be tightly-packed and ordered, usable as a scalar index.
        pub const BindingTag = @typeInfo(Binding).@"union".tag_type.?;
        pub const BindingsMap = unbound.BindingsMap(BindingTag);
        pub const bindings_map = bindings_map_init;

        fn bindingSize(binding: Binding) usize {
            return binding.size();
        }

        fn bindingInit(binding: Binding, buf: []align(std.heap.page_size_min) u8) !void {
            try binding.init(buf);
        }

        fn bindingFmtShareInfo(
            binding_tag: BindingTag,
        ) std.fmt.Alt(BindingTag, bindingWriteRegionShareInfo) {
            return .{ .data = binding_tag };
        }

        fn bindingWriteRegionShareInfo(
            binding_tag: BindingTag,
            w: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            try w.print("Region `{t}` shared with [ ", .{binding_tag});

            const region_id_set = bindings_map.getPtrConst(binding_tag);

            var iter = region_id_set.iterator();
            for (0..region_id_set.count()) |i| {
                const region_id = iter.next().?;
                const service_id: unbound.ServiceId =
                    unbound.serviceRegionIdFromRegionId(region_id);
                const access = unbound.getServiceRegionIdAccess(region_id);

                if (i != 0) try w.writeAll(", ");
                const mode = if (access == .rw) "rw" else "ro";
                try w.print("{t} ({s})", .{ service_id, mode });
            }
            if (iter.next() != null) unreachable;

            try w.writeAll(" ]");
        }

        comptime {
            if (unbound.validateBindingsMap(BindingTag, bindings_map)) |result| switch (result) {
                .unordered_binding => |unordered| @compileError(std.fmt.comptimePrint(
                    "Expected Binding tag " ++ @tagName(unordered.tag) ++
                        " has value {d}, expected to have value {d}.",
                    .{ @intFromEnum(unordered.tag), unordered.expected },
                )),
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

        /// Returns the total number of spawned services that will be sharing the specified `binding`.
        pub fn countTotalBindingShares(binding: BindingTag) usize {
            return bindings_map.get(binding).count();
        }

        /// A struct whose fields consist of every Binding union payload in the topology.
        /// This is used to exhaustively initialize every Binding exactly once.
        pub const BindingsInit = @Type(.{ .@"struct" = info: {
            var fields: [bindings_map.values.len]std.builtin.Type.StructField = undefined;
            for (&fields, @typeInfo(Binding).@"union".fields) |*s_field, u_field| {
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

        /// Returns the binding that the specified `region_id` is bound to.
        fn getRegionBinding(region_id: unbound.RegionId) BindingTag {
            return for (bindings_map.values, 0..) |region_id_set, i| {
                const binding_tag: BindingTag = @enumFromInt(i);
                if (!region_id_set.contains(region_id)) continue;
                break binding_tag;
            } else unreachable;
        }

        pub const ServiceMap = struct {
            entries: lib.util.ArrayEnumMap(unbound.ServiceId, Entry),

            pub const empty: ServiceMap = .{ .entries = .empty };

            pub const Entry = struct {
                runner: memfd.RW,
                bindings: BindingInfos,

                pub const BindingInfos = lib.util.ArrayEnumMap(BindingTag, BindingInfo);
            };

            pub const BindingInfo = struct {
                access: Schema.Service.Region.Access,
                memfd: lib.linux.memfd.RW,
            };
        };

        /// Pairs services up with their respective required bound regions and their read/write permissions.
        pub fn serviceMap(instances: BindingsInit) !ServiceMap {
            const bindings: [bindings_map.values.len]Binding = regions: {
                var bindings: [bindings_map.values.len]Binding = undefined;

                @setEvalBranchQuota(bindings_map.values.len * schema.services.len);
                inline for (&bindings, 0..bindings_map.values.len) |*region, binding_i| {
                    const region_binding_tag: BindingTag = @enumFromInt(binding_i);
                    region.* = @unionInit(
                        Binding,
                        @tagName(region_binding_tag),
                        @field(instances, @tagName(region_binding_tag)),
                    );
                }

                break :regions bindings;
            };

            var region_memfds: [bindings_map.values.len]memfd.RW = @splat(.empty);
            for (&bindings, &region_memfds) |binding, *region_memfd| {
                region_memfd.* = try createAndInitSharedRegionMemfd(binding);
                std.log.info("Initialised: {f}", .{bindingFmtShareInfo(binding)});
            }

            var runner_memfds: [schema.services.len]memfd.RW = @splat(.empty);
            inline for (&runner_memfds, schema.services) |*runner_memfd, service_entry| {
                runner_memfd.* = try .init(.{
                    .name = std.fmt.comptimePrint("runner_{s}", .{@tagName(service_entry.name)}),
                    .size = @sizeOf(lib.runner.Region),
                });
            }

            var map: ServiceMap = .empty;

            // check all service instances request regions which are shared with them
            inline for (schema.services, &runner_memfds) |service_schema, runner_memfd| {
                const service: unbound.ServiceId = service_schema.name;
                const service_entry: *ServiceMap.Entry = entry: {
                    const gop = map.entries.getOrPut(service);
                    std.debug.assert(!gop.found_existing);
                    gop.value_ptr.* = .{
                        .runner = runner_memfd,
                        .bindings = .empty,
                    };
                    break :entry gop.value_ptr;
                };

                inline for (service_schema.regions) |region_schema| {
                    const region_local_id: unbound.RegionIdServiceLocal(service) =
                        region_schema.name;
                    const region_id: unbound.RegionId =
                        unbound.regionIdFromServiceAndRegionId(service, region_local_id);
                    const binding_tag = getRegionBinding(region_id);
                    const binding_memfd = region_memfds[@intFromEnum(binding_tag)];

                    const gop = service_entry.bindings.getOrPut(binding_tag);
                    if (gop.found_existing) {
                        std.debug.panic("Two equivalent binding entries for '{t}'", .{binding_tag});
                    }
                    gop.value_ptr.* = .{
                        .access = region_schema.access,
                        .memfd = binding_memfd,
                    };
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
                bindings: *const ServiceMap.Entry.BindingInfos,
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

            var binding_iter = params.bindings.iteratorImmut();
            for (0..params.bindings.len) |_| {
                const binding = binding_iter.next().?.value.*;
                const binding_size = binding.memfd.size;
                switch (binding.access) {
                    .rw => {
                        args.rw[i_rw] = (try binding.memfd.mmap(.{ .populate = true })).ptr;
                        args.rw_len[i_rw] = binding_size;
                        i_rw += 1;
                    },
                    .readonly => {
                        const ro_memfd = try memfd.RO.fromRW(binding.memfd);
                        args.ro[i_ro] = (try ro_memfd.mmap(.{ .populate = true })).ptr;
                        args.ro_len[i_ro] = binding_size;
                        i_ro += 1;
                    },
                }
            }
            if (binding_iter.next() != null) unreachable;

            return args;
        }

        /// Create and initialize a memfd for the shared memory region (map it, initialize it, and then unmap it).
        /// We must unmap it to avoid sharing regions with services that don't need them.
        fn createAndInitSharedRegionMemfd(binding_init: Binding) !memfd.RW {
            // This name should be visible from a debugger, but serves no other purpose.
            var fmt_buf: [4096]u8 = undefined;
            const name = try std.fmt.bufPrintZ(&fmt_buf, "{f}", .{
                bindingFmtShareInfo(binding_init),
            });

            const region_memfd: memfd.RW = try .init(.{
                .name = name,
                .size = bindingSize(binding_init),
            });

            const buf = try region_memfd.mmap(.{});
            defer std.posix.munmap(buf);
            try bindingInit(binding_init, buf);

            return region_memfd;
        }

        // -- Service Spawning -- //

        /// Initialises the shared memory regions with their parameters, then securely starts up services.
        /// Blocks until the first service has exited, before dumping out traces.
        pub fn spawnAndWait(map: *const ServiceMap) !void {
            const sandboxed = try spawnSandboxed(map);
            sandboxed.wait();
        }

        pub fn spawnAndWaitNoSandbox(map: *const ServiceMap) !void {
            var state: NoSandbox = undefined;
            try spawnNoSandbox(&state, map);
        }

        // -- Sandboxed -- //

        pub const Sandboxed = struct {
            services_index: lib.util.ArrayEnumMap(unbound.ServiceId, void),
            meta: struct {
                pids_buf: [schema.services.len]i32,
                runners_buf: [schema.services.len]*lib.runner.Region,
            },

            pub fn pids(self: *const Sandboxed) []const i32 {
                return self.meta.pids_buf[0..self.services_index.len];
            }

            pub fn runners(self: *const Sandboxed) []const *lib.runner.Region {
                return self.meta.runners_buf[0..self.services_index.len];
            }

            pub fn wait(self: *const Sandboxed) void {
                // Wait for the first child to exit
                var status: u32 = 0;
                const exited_pid: i32 = pid: {
                    const ret: usize = linux.waitpid(-1, &status, 0);
                    std.debug.assert(e(ret) == .SUCCESS);
                    break :pid @intCast(ret);
                };
                const exited_index = std.mem.indexOfScalar(i32, self.pids(), exited_pid) orelse
                    std.debug.panic("Unknown child pid {} exited\n", .{exited_pid});
                const id = self.services_index.keys()[exited_index];
                const pid = self.pids()[exited_index];
                const runner = self.runners()[exited_index];
                dumpOnExit(&runner.exit, id, pid, status);
            }
        };

        pub fn spawnSandboxed(map: *const ServiceMap) !Sandboxed {
            var sandboxed: Sandboxed = .{
                .services_index = .empty,
                .meta = .{
                    .pids_buf = @splat(undefined),
                    .runners_buf = @splat(undefined),
                },
            };

            // Start up all services, storing their pids
            inline for (schema.services) |service_schema| {
                const entry = map.entries.get(service_schema.name).?;
                const child_pid = try spawnService(service_schema.name, .{
                    .runner = entry.runner,
                    .stderr = .stderr(),
                    .bindings = &entry.bindings,
                });
                const index = sandboxed.services_index.len;
                sandboxed.services_index.putNoClobber(service_schema.name, {});
                sandboxed.meta.pids_buf[index] = child_pid;
            }

            // We only mmap the exit regions after spawning the child processes, as we don't want them
            // mapped in children
            for (sandboxed.services_index.keys(), &sandboxed.meta.runners_buf) |id, *meta| {
                const entry = map.entries.get(id).?;
                meta.* = try entry.runner.mmapStaticSize(lib.runner.Region, .{});
            }

            return sandboxed;
        }

        fn spawnService(
            service: unbound.ServiceId,
            params: struct {
                runner: memfd.RW,
                stderr: std.fs.File,
                bindings: *const ServiceMap.Entry.BindingInfos,
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
                .bindings = params.bindings,
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

        // -- No Sandbox -- //

        pub const NoSandbox = struct {
            runners: lib.util.ArrayEnumMap(unbound.ServiceId, *lib.runner.Region),
            thread_exit_ctx: ThreadExitContext,

            pub fn wait(state: *NoSandbox) !void {
                // Wait for first service to exit
                state.thread_exit_ctx.reset_event.wait();

                const exited_idx = state.thread_exit_ctx.finished_idx.load(.seq_cst);
                std.debug.assert(exited_idx != std.math.maxInt(u16));

                const exited_service_id: unbound.ServiceId = @enumFromInt(exited_idx);
                const exited_runner = state.runners.get(exited_service_id).?.*;
                dumpOnExit(&exited_runner.exit, exited_service_id, 0, 0);
            }
        };

        pub fn spawnNoSandbox(
            /// Will be overwritten after this call, and should be treated as a stable memory location thereafter.
            state: *NoSandbox,
            map: *const ServiceMap,
        ) !void {
            state.* = .{
                .runners = .empty,
                .thread_exit_ctx = .{
                    .finished_idx = .init(std.math.maxInt(u16)),
                    .reset_event = .{},
                },
            };

            // Start up all services, storing their pids
            inline for (schema.services, 0..) |service_entry, i| {
                const entry = map.entries.get(service_entry.name).?;
                _ = try spawnServiceNoSandbox(service_entry.name, .{
                    .runner = entry.runner,
                    .stderr = .stderr(),
                    .bindings = &map.entries.get(service_entry.name).?.bindings,
                    .service_idx = i,
                    .thread_exit_ctx = &state.thread_exit_ctx,
                });
            }

            // We only mmap the exit regions after spawning the child processes, as we don't want them
            // mapped in children
            for (map.entries.keys(), map.entries.values()) |k, v| {
                state.runners.putNoClobber(k, try v.runner.mmapStaticSize(lib.runner.Region, .{}));
            }
        }

        fn spawnServiceNoSandbox(
            service: unbound.ServiceId,
            params: struct {
                runner: memfd.RW,
                stderr: std.fs.File,
                bindings: *const ServiceMap.Entry.BindingInfos,
                service_idx: u16,
                thread_exit_ctx: *ThreadExitContext,
            },
        ) !std.Thread {
            var resolved_args = try resolveArgs(.{
                .runner = params.runner,
                .stderr = params.stderr,
                .bindings = params.bindings,
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

        /// Context created by the service initializer, used to report thread exit or crash and wake the
        /// main thread. Services receive it as opaque data and must not inspect it.
        const ThreadExitContext = struct {
            finished_idx: std.atomic.Value(u16),
            reset_event: std.Thread.ResetEvent,

            fn signalThreadExit(self: *ThreadExitContext, service_idx: u16) void {
                self.finished_idx.store(service_idx, .seq_cst);
                self.reset_event.set();
            }
        };

        fn threadEntry(
            entry_point: ServiceEntrypoint,
            service: unbound.ServiceId,
            args: lib.ipc.ResolvedArgs,
            service_idx: u16,
            thread_exit_ctx: *ThreadExitContext,
        ) void {
            switch (service) {
                inline else => |svc| tracy.setThreadName("svc: " ++ @tagName(svc)),
            }

            entry_point(args);
            thread_exit_ctx.signalThreadExit(service_idx);
        }

        // Called by service threads in no-sandbox mode. Uses C calling convention because the function
        // pointer crosses service/init compilation units.
        fn signalThreadCrash(ctx: ?*anyopaque, service_idx: u16) callconv(.c) void {
            const thread_exit_ctx: *ThreadExitContext = @ptrCast(@alignCast(ctx orelse return));
            thread_exit_ctx.signalThreadExit(service_idx);
        }

        // -- Shared Functionality -- //

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
    };
}
