//! The `shred` component wraps the shred-receiver's private impl (`Receiver`,
//! `FecSetCtx`, reed-solomon reconstruction) around the public `api` surface
//! consumed by other services (`RecvConfig`, `DeshredRing`, `Shred`, ...).

comptime {
    if (@import("builtin").is_test) {
        _ = @import("receiver.zig");
        _ = @import("reed_solomon.zig");
    }
}

pub const api = @import("api");

pub const Receiver = @import("receiver.zig").Receiver;
pub const FecSetCtx = @import("receiver.zig").FecSetCtx;
