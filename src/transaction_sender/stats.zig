const std = @import("std");
const sig = @import("../sig.zig");

const Logger = sig.trace.Logger;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const GetMetricError = sig.prometheus.registry.GetMetricError;

const globalRegistry = sig.prometheus.globalRegistry;

pub const Stats = struct {
    transactions_pending: *Gauge(u64),
    transactions_received_count: *Counter,
    transactions_retry_count: *Counter,
    transactions_sent_count: *Counter,
    transactions_rooted_count: *Counter,
    transactions_failed_count: *Counter,
    transactions_expired_count: *Counter,
    transactions_exceeded_max_retries_count: *Counter,
    number_of_leaders_identified: *Gauge(u64),

    process_transactions_latency_millis: *Gauge(u64),
    retry_transactions_latency_millis: *Gauge(u64),
    get_leader_addresses_latency_millis: *Gauge(u64),

    rpc_block_height_latency_millis: *Gauge(u64),
    rpc_signature_statuses_latency_millis: *Gauge(u64),

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

    pub fn log(self: *const Stats, logger: Logger) void {
        logger.infof("transaction-sender: {} received, {} pending, {} rooted, {} failed, {} expired, {} exceeded_retries", .{
            self.transactions_received_count.get(),
            self.transactions_pending.get(),
            self.transactions_rooted_count.get(),
            self.transactions_failed_count.get(),
            self.transactions_expired_count.get(),
            self.transactions_exceeded_max_retries_count.get(),
        });
    }
};
