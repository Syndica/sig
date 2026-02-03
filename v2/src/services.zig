const common = @import("common");
const ServiceEntrypoint = common.ServiceFn;

pub const prng = @extern(ServiceEntrypoint, .{ .name = "svc_main_prng" });
pub const logger = @extern(ServiceEntrypoint, .{ .name = "svc_main_logger" });
