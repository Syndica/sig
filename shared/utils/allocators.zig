const std = @import("std");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

pub const failing = struct {
    pub const Config = struct {
        alloc: Mode = .noop_or_fail,
        resize: Mode = .noop_or_fail,
        free: Mode = .noop_or_fail,
    };

    pub const Mode = enum {
        /// alloc = return null
        /// resize = return false
        /// free = noop
        noop_or_fail,
        /// Panics with 'Unexpected call to <method>'.
        panics,
        /// Asserts the method is never reached with `unreachable`.
        assert,
    };

    /// Returns a comptime-known stateless allocator where each method fails in the specified manner.
    /// By default each method is a simple failure or noop, and can be escalated to a panic which is
    /// enabled in safe and unsafe modes, or to an assertion which triggers checked illegal behaviour.
    pub inline fn allocator(config: Config) Allocator {
        const S = struct {
            fn alloc(_: *anyopaque, _: usize, _: Alignment, _: usize) ?[*]u8 {
                return switch (config.alloc) {
                    .noop_or_fail => null,
                    .panics => @panic("Unexpected call to alloc"),
                    .assert => unreachable,
                };
            }
            fn resize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
                return switch (config.resize) {
                    .noop_or_fail => false,
                    .panics => @panic("Unexpected call to resize"),
                    .assert => unreachable,
                };
            }
            fn remap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
                return switch (config.resize) {
                    .noop_or_fail => null,
                    .panics => @panic("Unexpected call to resize"),
                    .assert => unreachable,
                };
            }
            fn free(_: *anyopaque, _: []u8, _: Alignment, _: usize) void {
                return switch (config.free) {
                    .noop_or_fail => {},
                    .panics => @panic("Unexpected call to free"),
                    .assert => unreachable,
                };
            }
        };
        comptime return .{
            .ptr = undefined,
            .vtable = &.{
                .alloc = S.alloc,
                .resize = S.resize,
                .remap = S.remap,
                .free = S.free,
            },
        };
    }
};

pub const LimitAllocator = struct {
    bytes_remaining: usize,
    backing_allocator: Allocator,

    /// Needs a stable vtable address to check if an allocator is from LimitAllocator.
    const vtable: *const Allocator.VTable = &.{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    pub fn init(backing_alloc: std.mem.Allocator, byte_limit: usize) LimitAllocator {
        // NOTE: LimitAllocators must not be nested.
        std.debug.assert(tryFrom(backing_alloc) == null);
        return .{
            .bytes_remaining = byte_limit,
            .backing_allocator = backing_alloc,
        };
    }

    pub fn allocator(self: *LimitAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = vtable,
        };
    }

    pub fn tryFrom(allocator_: std.mem.Allocator) ?*LimitAllocator {
        if (allocator_.vtable != LimitAllocator.vtable) return null;
        const self: *LimitAllocator = @ptrCast(@alignCast(allocator_.ptr));
        return self;
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        alignment: Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        if (len > self.bytes_remaining) {
            return null;
        }
        const new_ptr = self.backing_allocator.rawAlloc(len, alignment, return_address) orelse
            return null;
        self.bytes_remaining -= len;
        return new_ptr;
    }

    fn resize(
        ctx: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        new_len: usize,
        ra: usize,
    ) bool {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        // free case
        if (new_len <= memory.len) {
            if (!self.backing_allocator.rawResize(memory, alignment, new_len, ra))
                return false;
            self.bytes_remaining += memory.len - new_len;
            return true;
        }
        // alloc case
        const remaining = self.bytes_remaining + memory.len;
        if (new_len > remaining) {
            return false;
        }
        if (!self.backing_allocator.rawResize(memory, alignment, new_len, ra))
            return false;
        self.bytes_remaining = remaining - new_len;
        return true;
    }

    fn remap(
        ctx: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        new_len: usize,
        ra: usize,
    ) ?[*]u8 {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        // free case
        if (new_len <= memory.len) {
            const new_ptr = self.backing_allocator.rawRemap(memory, alignment, new_len, ra) orelse
                return null;
            self.bytes_remaining += memory.len - new_len;
            return new_ptr;
        }
        // alloc case
        const remaining = self.bytes_remaining + memory.len;
        if (new_len > remaining) {
            return null;
        }
        const new_ptr = self.backing_allocator.rawRemap(memory, alignment, new_len, ra) orelse
            return null;
        self.bytes_remaining = remaining - new_len;
        return new_ptr;
    }

    fn free(
        ctx: *anyopaque,
        old_mem: []u8,
        alignment: Alignment,
        ra: usize,
    ) void {
        const self: *LimitAllocator = @ptrCast(@alignCast(ctx));
        self.backing_allocator.rawFree(old_mem, alignment, ra);
        self.bytes_remaining += old_mem.len;
    }
};
