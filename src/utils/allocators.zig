const std = @import("std");

pub const RecycleFBA = struct {
    // this allocates the underlying memory + dynamic expansions
    // (only used on init/deinit + arraylist expansion)
    backing_allocator: std.mem.Allocator,
    // this does the data allocations (data is returned from alloc)
    fb_allocator: std.heap.FixedBufferAllocator,
    // recycling depot
    records: std.ArrayList(Record),

    // for thread safety
    mux: std.Thread.Mutex = .{},

    const Record = struct { is_free: bool, buf: []u8 };
    const Self = @This();

    pub fn init(backing_allocator: std.mem.Allocator, n_bytes: u64) !Self {
        const buf = try backing_allocator.alloc(u8, n_bytes);
        const fba = std.heap.FixedBufferAllocator.init(buf);
        const records = std.ArrayList(Record).init(backing_allocator);

        return .{
            .backing_allocator = backing_allocator,
            .fb_allocator = fba,
            .records = records,
        };
    }

    pub fn deinit(self: *Self) void {
        self.backing_allocator.free(self.fb_allocator.buffer);
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
        _ = log2_align;
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        // check for a buf to recycle
        for (self.records.items) |*item| {
            if (item.is_free and item.buf.len >= n) {
                item.is_free = false;
                return item.buf.ptr;
            }
        }

        // otherwise, allocate a new one
        const buf = self.fb_allocator.allocator().alloc(u8, n) catch {
            // std.debug.print("RecycleFBA alloc error: {}\n", .{ err });
            return null;
        };

        self.records.append(.{ .is_free = false, .buf = buf }) catch {
            // std.debug.print("RecycleFBA append error: {}\n", .{ err });
            return null;
        };

        return buf.ptr;
    }

    pub fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = log2_align;
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        for (self.records.items) |*item| {
            if (item.buf.ptr == buf.ptr) {
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
            if (item.buf.ptr == buf.ptr) {
                if (item.buf.len >= new_size) {
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
