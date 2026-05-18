const std = @import("std");
const lib = @import("lib.zig");

const linux = std.os.linux;
const sigaction_fn = linux.Sigaction.sigaction_fn;
const ServiceEntrypoint = lib.ipc.ServiceFn;

const TopologySchema = @This();
services: []const ServiceSchema,

pub const ServiceSchema = struct {
    /// The service's identifier.
    name: @Type(.enum_literal),
    /// The regions expected by this service.
    regions: []const RegionSchema,

    pub const RegionSchema = struct {
        /// The region's identifier, local to the service.
        name: @Type(.enum_literal),
        access: Access,

        pub const Access = enum { readonly, rw };
    };
};

pub fn ServiceId(comptime topo: TopologySchema) type {
    var fields: [topo.services.len]std.builtin.Type.EnumField = undefined;
    for (topo.services, &fields, 0..) |instance, *field, i| {
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
pub fn ServiceRegionId(comptime topo: TopologySchema) type {
    var fields: []const std.builtin.Type.EnumField = &.{};
    for (topo.services) |service| {
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

pub fn RegionBindingsMap(
    comptime topo: TopologySchema,
    comptime RegionTag: type,
) type {
    return std.EnumArray(
        RegionTag,
        std.EnumSet(topo.ServiceRegionId()),
    );
}

/// Namespace of types and functions which, with respect to the equivalences
/// defined by `bindings_map`, assist in materializing the regions of the topology.
pub fn Bind(
    comptime topo: TopologySchema,
    /// A tagged union of all the intended shared region bindings.
    /// The associated payload should be the type that will be used to initialize the region.
    comptime Region: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Region` tag name).
    comptime bindings_map: topo.RegionBindingsMap(@typeInfo(Region).@"union".tag_type.?),
) type {
    return struct {
        const bound = @This();

        pub const RegionTag = @typeInfo(Region).@"union".tag_type.?;
        pub const BindingsMap = topo.RegionBindingsMap(RegionTag);

        comptime {
            if (topo.validateBindingsMap(RegionTag, bindings_map)) |result| switch (result) {
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
        /// NOTE: can also be used to index `topo.services_schema`.
        pub const ServiceId = topo.ServiceId();

        pub const ServiceRegionId = topo.ServiceRegionId();

        /// Tagged union of enums, where the union tag is the service, and the
        /// payload is the corresponding `ServiceRegionIdLocal(service_id)`.
        /// i.e. `.{ .service_name = .local_region_name }`.
        pub const ServiceRegionInfo = @Type(.{ .@"union" = info: {
            var fields: [topo.services.len]std.builtin.Type.UnionField = undefined;
            for (topo.services, &fields) |service, *field| {
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
        /// NOTE: can also be used to index `topo.services_schema[@intFromEnum(service)].regions`.
        pub fn LocalServiceRegionId(comptime service: bound.ServiceId) type {
            const regions = topo.services[@intFromEnum(service)].regions;
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
                const region_binding_tag = comptime BindingsMap.Indexer.keyForIndex(binding_i);

                comptime var shares: []const Share = &.{};

                comptime var iter = region_id_set.iterator();
                inline for (0..comptime region_id_set.count()) |_| {
                    const region_id = comptime iter.next().?;
                    const region_info = getServiceRegionIdInfo(region_id);
                    const local_region_id = @field(region_info, @tagName(region_info));
                    const service_entry = topo.services[@intFromEnum(region_info)];
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
                const binding_tag = BindingsMap.Indexer.keyForIndex(i);
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
                const service_entry = topo.services[@intFromEnum(service_id)];
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

        pub fn getFaultHandler(service: bound.ServiceId) sigaction_fn {
            return switch (service) {
                inline else => |s| @extern(
                    sigaction_fn,
                    .{ .name = "svc_fault_handler_" ++ @tagName(s) },
                ),
            };
        }

        pub fn getEntrypoint(service: bound.ServiceId) ServiceEntrypoint {
            return switch (service) {
                inline else => |s| @extern(
                    ServiceEntrypoint,
                    .{ .name = "svc_main_" ++ @tagName(s) },
                ),
            };
        }

        // -- Service Map -- //

        pub const ServiceMap = std.AutoArrayHashMapUnmanaged(ServiceInstance, ServiceMapEntry);

        pub const ServiceMapEntry = std.ArrayListUnmanaged(ServiceMapLookupResult);

        pub const ServiceMapLookupResult = struct {
            n: usize, // for supporting multiple regions of the same kind
            shared: SharedRegion,
            rw: bool,
            memfd: lib.linux.memfd.RW,
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
                    const found_region: ServiceMapLookupResult = blk: for (
                        regions,
                        region_memfds,
                        0..,
                    ) |shared_region, region_memfd, n| {
                        if (shared_region.region != required_region.region) continue;

                        for (shared_region.shares) |share| {
                            if (instance.service == share.instance.service and
                                instance.n == share.instance.n)
                            {
                                const result: ServiceMapLookupResult = .{
                                    .n = n,
                                    .shared = shared_region,
                                    .rw = required_region.rw,
                                    .memfd = region_memfd,
                                };

                                var exists = false;
                                if (map.getPtr(instance)) |entry| {
                                    for (entry.items) |existing_result| {
                                        if (std.meta.eql(existing_result, result)) {
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
    };
}

fn ValidateBindingsMapResult(
    comptime topo: TopologySchema,
) type {
    return union(enum) {
        /// The tags in this set were specified in two bindings.
        duplicated: std.EnumSet(topo.ServiceRegionId()),
        /// The tags in this set were not specified in any binding.
        missing: std.EnumSet(topo.ServiceRegionId()),
    };
}

/// Returns null on success.
/// Otherwise returns a diagnostic describing the problem.
inline fn validateBindingsMap(
    comptime topo: TopologySchema,
    /// A union of all the intended shared region bindings.
    comptime RegionTag: type,
    /// Defines the equivalences between regions across all services, unifying them under one binding (the `Region` tag name).
    comptime bindings_map: topo.RegionBindingsMap(RegionTag),
) ?topo.ValidateBindingsMapResult() {
    comptime {
        var accumulated_set: std.EnumSet(topo.ServiceRegionId()) = .{};
        for (bindings_map.values) |region_id_set| {
            const intersection = accumulated_set.intersectWith(region_id_set);
            if (intersection.count() == 0) {
                accumulated_set.setUnion(region_id_set);
                continue;
            }
            return .{ .duplicated = intersection };
        }
        if (accumulated_set.count() != @typeInfo(topo.ServiceRegionId()).@"enum".fields.len) {
            const missing = accumulated_set.complement();
            return .{ .missing = missing };
        }
        return null;
    }
}
