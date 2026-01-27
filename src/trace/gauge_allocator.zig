//! An allocator that supports a Prometheus guage.

const std = @import("std");
const sig = @import("../sig.zig");

const GaugeAllocator = @This();

parent: std.mem.Allocator,
counter: *sig.prometheus.Gauge(u64),

pub fn allocator(self: *GaugeAllocator) std.mem.Allocator {
    return .{
        .ptr = self,
        .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = std.mem.Allocator.noRemap,
            .free = free,
        },
    };
}

fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    const self: *GaugeAllocator = @ptrCast(@alignCast(ctx));
    const result = self.parent.rawAlloc(len, ptr_align, ret_addr);

    self.counter.add(len);

    return result;
}

fn resize(
    ctx: *anyopaque,
    buf: []u8,
    buf_align: std.mem.Alignment,
    new_len: usize,
    ret_addr: usize,
) bool {
    const self: *GaugeAllocator = @ptrCast(@alignCast(ctx));
    const result = self.parent.rawResize(buf, buf_align, new_len, ret_addr);
    if (!result) return false;

    self.counter.sub(buf.len);
    self.counter.add(new_len);

    return true;
}

fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
    const self: *GaugeAllocator = @ptrCast(@alignCast(ctx));

    self.counter.sub(buf.len);

    self.parent.rawFree(buf, buf_align, ret_addr);
}
