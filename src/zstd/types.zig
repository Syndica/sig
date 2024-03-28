pub const ResetDirective = enum(u2) {
    session = 1,
    parameters = 2,
    session_and_parameters = 3,
};

pub const EndDirective = enum(u2) {
    continue_ = 0,
    flush = 1,
    end = 2,
};

pub const InBuffer = extern struct {
    src: [*]const u8,
    size: usize,
    pos: usize,
};

pub const OutBuffer = extern struct {
    dst: [*]u8,
    size: usize,
    pos: usize,
};
