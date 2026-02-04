const std = @import("std");

const common = @import("common");
const ServiceEntrypoint = common.ServiceFn;

pub const prng = @extern(ServiceEntrypoint, .{ .name = "svc_main_prng" });
pub const logger = @extern(ServiceEntrypoint, .{ .name = "svc_main_logger" });
pub const net = @extern(ServiceEntrypoint, .{ .name = "svc_main_net" });
pub const ping = @extern(ServiceEntrypoint, .{ .name = "svc_main_ping" });

pub const fault_handler = struct {
    const sigaction_fn = std.os.linux.Sigaction.sigaction_fn;

    pub const prng = @extern(sigaction_fn, .{ .name = "svc_fault_handler_prng" });
    pub const logger = @extern(sigaction_fn, .{ .name = "svc_fault_handler_logger" });
    pub const net = @extern(sigaction_fn, .{ .name = "svc_fault_handler_net" });
    pub const ping = @extern(sigaction_fn, .{ .name = "svc_fault_handler_ping" });
};
