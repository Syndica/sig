const std = @import("std");
const sig = @import("../sig.zig");

const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;

const globalRegistry = sig.prometheus.globalRegistry;

pub const Stats = struct {
    transaction_received: *Counter,
    duplicate_transaction_received: *Counter,
    transaction_sent: *Counter,
    transaction_dropped: *Counter,
    transaction_failed: *Counter,
    transaction_expired: *Counter,
    transaction_exceeded_max_retries: *Counter,
    transaction_retried: *Counter,
    transaction_rooted: *Counter,
    transaction_pool_size: *Gauge(u64),
    leaders_identified_pct: *Gauge(u64),

    pub fn init() GetMetricError!Stats {
        var self: Stats = undefined;
        const registry = globalRegistry();
        const stats_struct_info = @typeInfo(Stats).Struct;
        inline for (stats_struct_info.fields) |field| {
            if (field.name[0] != '_') {
                @field(self, field.name) = switch (field.type) {
                    *Counter => try registry.getOrCreateCounter(field.name),
                    *Gauge(u64) => try registry.getOrCreateGauge(field.name, u64),
                    else => @compileError("Unhandled field type: " ++ field.name ++ ": " ++ @typeName(field.type)),
                };
            }
        }
        return self;
    }
};
