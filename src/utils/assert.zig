const std = @import("std");
const builtin = @import("builtin");

pub fn assertDebug(ok: bool) void {
    switch (builtin.mode) {
        .Debug => {
            if (!ok) {
                unreachable;
            }
        },
        else => {},
    }
}
