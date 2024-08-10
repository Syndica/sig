const std = @import("std");

pub const RecycleFBA = struct {
    // this allocates the underlying memory + dynamic expansions
    // (only used on init/deinit + arraylist expansion)
    backing_allocator: std.mem.Allocator,
    // this does the data allocations (data is returned from alloc)
    alloc_allocator: std.heap.FixedBufferAllocator,
    // recycling depot
    records: std.ArrayList(Record),

    // for thread safety
    mux: std.Thread.Mutex = .{},

    const Record = struct { is_free: bool, buf: [*]u8, len: u64 };
    const Self = @This();

    pub fn init(backing_allocator: std.mem.Allocator, n_bytes: u64) !Self {
        const buf = try backing_allocator.alloc(u8, n_bytes);
        const alloc_allocator = std.heap.FixedBufferAllocator.init(buf);
        const records = std.ArrayList(Record).init(backing_allocator);

        return .{
            .backing_allocator = backing_allocator,
            .alloc_allocator = alloc_allocator,
            .records = records,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backing_allocator.free(self.alloc_allocator.buffer);
        self.records.deinit();
    }

    pub fn allocator(self: *Self) std.mem.Allocator {
        return std.mem.Allocator{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    /// creates a new file with size aligned to page_size and returns a pointer to it
    pub fn alloc(ctx: *anyopaque, n: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        if (n > self.alloc_allocator.buffer.len) {
            @panic("RecycleFBA.alloc: requested size too large, make the buffer larger");
        }

        // check for a buf to recycle
        for (self.records.items) |*item| {
            if (item.is_free and item.len >= n and std.mem.isAlignedLog2(@intFromPtr(item.buf), log2_align)) {
                item.is_free = false;
                return item.buf;
            }
        }

        // otherwise, allocate a new one
        const buf = self.alloc_allocator.allocator().rawAlloc(n, log2_align, return_address) orelse {
            // std.debug.print("RecycleFBA alloc error: {}\n", .{ err });
            return null;
        };

        self.records.append(.{ .is_free = false, .buf = buf, .len = n }) catch {
            // std.debug.print("RecycleFBA append error: {}\n", .{ err });
            return null;
        };

        return buf;
    }

    pub fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = log2_align;
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        for (self.records.items) |*item| {
            if (item.buf == buf.ptr) {
                item.is_free = true;
                return;
            }
        }
        @panic("RecycleFBA.free: could not find buf to free");
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        _ = log2_align;
        _ = return_address;

        const self: *Self = @ptrCast(@alignCast(ctx));
        for (self.records.items) |*item| {
            if (item.buf == buf.ptr) {
                if (item.len >= new_size) {
                    return true;
                } else {
                    return false;
                }
            }
        }

        // not supported
        return false;
    }
};
