const common = @import("common");
const ServiceEntrypoint = common.ServiceFn;

pub const prng = @extern(ServiceEntrypoint, .{ .name = "svc_main_prng" });
pub const logger = @extern(ServiceEntrypoint, .{ .name = "svc_main_logger" });
pub const net = @extern(ServiceEntrypoint, .{ .name = "svc_main_net" });
pub const ping = @extern(ServiceEntrypoint, .{ .name = "svc_main_ping" });
