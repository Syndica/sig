pub const _private = struct {
    pub const entry = @import("entry.zig");
    pub const field = @import("field.zig");
    pub const level = @import("level.zig");
    pub const log = @import("log.zig");
    pub const logfmt = @import("logfmt.zig");
};

pub const Logger = _private.log.Logger;
pub const Level = _private.level.Level;
