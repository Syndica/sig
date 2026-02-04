const std = @import("std");

const common = @import("common");
const ServiceEntrypoint = common.ServiceFn;
const sigaction_fn = std.os.linux.Sigaction.sigaction_fn;

pub const Service = enum {
    prng,
    logger,
    net,
    ping,

    pub fn entrypoint(self: Service) ServiceEntrypoint {
        return switch (self) {
            inline else => |s| @extern(
                ServiceEntrypoint,
                .{ .name = "svc_main_" ++ @tagName(s) },
            ),
        };
    }

    pub fn faultHandler(self: Service) sigaction_fn {
        return switch (self) {
            inline else => |s| @extern(
                sigaction_fn,
                .{ .name = "svc_fault_handler_" ++ @tagName(s) },
            ),
        };
    }
};
