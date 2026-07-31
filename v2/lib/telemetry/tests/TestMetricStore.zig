//! Owns allocator-backed telemetry storage for metrics used by in-process tests.

const std = @import("std");
const lib = @import("../../lib.zig");
const tel = lib.telemetry;

allocator: std.mem.Allocator,
memory: []align(@alignOf(tel.Region)) u8,

const TestMetricStore = @This();

pub const Options = struct {
    id_mem_len: u32 = 16 * 1024,
    gauges_len: u32 = 256,
    histogram_data_len: u32 = 0,
};

pub fn init(allocator: std.mem.Allocator, options: Options) !TestMetricStore {
    const params: tel.Region.InitParams = .{
        .port = 0,
        .log_filters_encoded = &.{},
        .service_count = 0,
        .id_mem_len = options.id_mem_len,
        .gauges_len = options.gauges_len,
        .histogram_data_len = options.histogram_data_len,
    };
    const memory = try allocator.alignedAlloc(
        u8,
        .of(tel.Region),
        params.info().regionSize(),
    );
    @memset(memory, 0);

    const region_ptr: *tel.Region = @ptrCast(memory.ptr);
    region_ptr.init(params);
    return .{
        .allocator = allocator,
        .memory = memory,
    };
}

pub fn appendMetrics(
    self: *TestMetricStore,
    comptime Metrics: type,
    comptime fields_config: tel.metric.FieldsConfig(Metrics),
) Metrics {
    const region: *tel.Region = @ptrCast(self.memory.ptr);
    return region.metricAppender().appendFields(Metrics, fields_config);
}

/// Clears all registrations and invalidates previously returned metric handles.
pub fn reset(self: *TestMetricStore) void {
    const region: *tel.Region = @ptrCast(self.memory.ptr);
    const info = region.info;
    @memset(self.memory, 0);
    region.init(.{
        .port = 0,
        .log_filters_encoded = &.{},
        .service_count = 0,
        .id_mem_len = info.id_mem_len,
        .gauges_len = info.gauges_len,
        .histogram_data_len = info.histogram_data_len,
    });
}

pub fn deinit(self: *TestMetricStore) void {
    self.allocator.free(self.memory);
}
