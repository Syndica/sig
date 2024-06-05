pub const _private = struct {
    pub const counter = @import("counter.zig");
    pub const gauge_fn = @import("gauge_fn.zig");
    pub const gauge = @import("gauge.zig");
    pub const histogram = @import("histogram.zig");
    pub const http = @import("http.zig");
    pub const metric = @import("metric.zig");
    pub const registry = @import("registry.zig");
};

pub const Counter = _private.counter.Counter;
pub const GaugeFn = _private.gauge_fn.GaugeFn;
pub const Gauge = _private.gauge.Gauge;
pub const Histogram = _private.histogram.Histogram;
pub const Registry = _private.registry.Registry;

pub const globalRegistry = _private.registry.globalRegistry;
pub const servePrometheus = _private.http.servePrometheus;
