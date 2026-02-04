const std = @import("std");

pub const linux = @import("common/linux.zig");
pub const Ring = @import("common/ring.zig").Ring;
pub const net = @import("common/net.zig");

const page_size_min = std.heap.page_size_min;

pub const ResolvedArgs = extern struct {
    stderr: std.os.linux.fd_t,
    exit: [*]align(page_size_min) u8,

    rw: [max_regions]?[*]align(page_size_min) u8,
    rw_len: [max_regions]usize,
    ro: [max_regions]?[*]align(page_size_min) const u8,
    ro_len: [max_regions]usize,

    pub const max_regions = 4; // chosen arbitrarily
};

pub const ServiceFn = *const fn (ResolvedArgs) callconv(.c) void;

/// This value should be written to before a service exits. Both fields may be active at once.
/// Each one is equivalent to an std.builtin.StackTrace.
pub const Exit = extern struct {
    /// when the service returned in an error
    error_return: [max_depth:empty_entry]usize = @splat(empty_entry),
    error_return_index: usize = 0,

    /// for panics, segfaults, etc
    trace: [max_depth:empty_entry]usize = @splat(empty_entry),
    trace_index: usize = 0,

    fault: [max_depth:empty_entry]usize = @splat(empty_entry),
    fault_index: usize = 0,

    error_name: [max_error_name:0]u8 = @splat(0),
    panic_msg: [max_panic_msg:0]u8 = @splat(0),
    fault_msg: [max_fault_msg:0]u8 = @splat(0),

    const empty_entry = std.math.maxInt(usize);

    // chosen arbitrarily
    const max_depth = 31;
    const max_error_name = 127;
    const max_panic_msg = 127;
    const max_fault_msg = 127;

    pub fn errorReturnStackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.error_return,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.error_return_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn stackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.trace,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.trace_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn faultStackTrace(self: *Exit) ?std.builtin.StackTrace {
        const instruction_addresses: []usize = std.mem.span(@as(
            [*:empty_entry]usize,
            &self.fault,
        ));
        if (instruction_addresses.len == 0) return null;
        return .{
            .index = self.fault_index,
            .instruction_addresses = instruction_addresses,
        };
    }

    pub fn errorName(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.error_name));
        if (str.len == 0) return null;
        return str;
    }

    pub fn panicMsg(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.panic_msg));
        if (str.len == 0) return null;
        return str;
    }

    pub fn faultMsg(self: *const Exit) ?[]const u8 {
        const str = std.mem.span(@as([*:0]const u8, &self.fault_msg));
        if (str.len == 0) return null;
        return str;
    }
};
