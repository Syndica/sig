const std = @import("std");
const sig = @import("../sig.zig");

pub const RecycleFBA = struct {
    // this allocates the underlying memory + dynamic expansions
    // (only used on init/deinit + arraylist expansion)
    backing_allocator: std.mem.Allocator,
    // this does the data allocations (data is returned from alloc)
    alloc_allocator: std.heap.FixedBufferAllocator,
    // recycling depot
    records: std.ArrayList(Record),

    // for thread safety
    // TODO: add a config option to enable threadsafe in all the methods
    // instead of having to manually lock the allocator outside of the method calls
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

        // TODO(PERF, x19): allocate len+1 and store is_free at index 0, `free` could then be O(1)
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
        const self: *Self = @ptrCast(@alignCast(ctx));
        for (self.records.items) |*item| {
            if (item.buf == buf.ptr) {
                if (item.len >= new_size) {
                    return true;
                } else {
                    return self.alloc_allocator.allocator().rawResize(
                        buf,
                        log2_align,
                        new_size,
                        return_address,
                    );
                }
            }
        }

        // not supported
        return false;
    }
};

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    filepath: []const u8,
    count: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    const Self = @This();

    pub fn init(filepath: []const u8) Self {
        return Self{
            .filepath = filepath,
        };
    }

    /// deletes all allocated files + optionally frees the filepath with the allocator
    pub fn deinit(self: *Self, str_allocator: ?std.mem.Allocator) void {
        // delete all files
        var buf: [1024]u8 = undefined;
        for (0..self.count.load(.acquire)) |i| {
            // this should never fail since we know the file exists in alloc()
            const filepath = std.fmt.bufPrint(&buf, "{s}_{d}", .{ self.filepath, i }) catch unreachable;
            std.fs.cwd().deleteFile(filepath) catch |err| {
                std.debug.print("Disk Memory Allocator deinit: error: {}\n", .{err});
            };
        }
        if (str_allocator) |a| {
            a.free(self.filepath);
        }
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

        const count = self.count.fetchAdd(1, .monotonic);

        var buf: [1024]u8 = undefined;
        const filepath = std.fmt.bufPrint(&buf, "{s}_{d}", .{ self.filepath, count }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };

        var file = std.fs.cwd().createFile(filepath, .{ .read = true }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {} filepath: {s}\n", .{ err, filepath });
            return null;
        };
        defer file.close();

        const aligned_size = std.mem.alignForward(usize, n, std.mem.page_size);
        const file_size = (file.stat() catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        }).size;

        if (file_size < aligned_size) {
            // resize the file
            file.seekTo(aligned_size - 1) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
            _ = file.write(&[_]u8{1}) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
            file.seekTo(0) catch |err| {
                std.debug.print("Disk Memory Allocator error: {}\n", .{err});
                return null;
            };
        }

        const memory = std.posix.mmap(
            null,
            aligned_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        ) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };

        return memory.ptr;
    }

    /// unmaps the memory (file still exists and is removed on deinit())
    pub fn free(_: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = log2_align;
        _ = return_address;
        // TODO: build a mapping from ptr to file so we can delete the corresponding file on free
        const buf_aligned_len = std.mem.alignForward(usize, buf.len, std.mem.page_size);
        std.posix.munmap(@alignCast(buf.ptr[0..buf_aligned_len]));
    }

    /// not supported rn
    fn resize(
        _: *anyopaque,
        buf_unaligned: []u8,
        log2_buf_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        // not supported
        _ = buf_unaligned;
        _ = log2_buf_align;
        _ = new_size;
        _ = return_address;
        return false;
    }
};

test "recycle allocator" {
    const backing_allocator = std.testing.allocator;
    var allocator = try RecycleFBA.init(backing_allocator, 1024);
    defer allocator.deinit();

    // alloc a slice of 100 bytes
    const bytes = try allocator.allocator().alloc(u8, 100);
    const ptr = bytes.ptr;
    // free the slice
    allocator.allocator().free(bytes);

    // realloc should be the same (ie, recycled data)
    const bytes2 = try allocator.allocator().alloc(u8, 100);
    try std.testing.expectEqual(ptr, bytes2.ptr);
    allocator.allocator().free(bytes2);

    // same result with smaller slice
    const bytes3 = try allocator.allocator().alloc(u8, 50);
    try std.testing.expectEqual(ptr, bytes3.ptr);
    allocator.allocator().free(bytes3);

    // diff result with larger slice
    const bytes4 = try allocator.allocator().alloc(u8, 200);
    try std.testing.expect(ptr != bytes4.ptr);
    allocator.allocator().free(bytes4);
}

test "disk allocator on hashmaps" {
    var allocator = DiskMemoryAllocator.init(sig.TEST_DATA_DIR ++ "tmp");
    defer allocator.deinit(null);

    var refs = std.AutoHashMap(u8, u8).init(allocator.allocator());
    try refs.ensureTotalCapacity(100);

    try refs.put(10, 19);

    const r = refs.get(10) orelse return error.Unreachable;
    try std.testing.expectEqual(19, r);
}

test "disk allocator on arraylists" {
    var allocator = DiskMemoryAllocator.init(sig.TEST_DATA_DIR ++ "tmp");

    var disk_account_refs = try std.ArrayList(u8).initCapacity(
        allocator.allocator(),
        1,
    );
    defer disk_account_refs.deinit();

    disk_account_refs.appendAssumeCapacity(19);

    try std.testing.expectEqual(19, disk_account_refs.items[0]);

    // this will lead to another allocation
    try disk_account_refs.append(21);

    try std.testing.expectEqual(19, disk_account_refs.items[0]);
    try std.testing.expectEqual(21, disk_account_refs.items[1]);

    // these should exist
    try std.fs.cwd().access(sig.TEST_DATA_DIR ++ "tmp_0", .{});
    try std.fs.cwd().access(sig.TEST_DATA_DIR ++ "tmp_1", .{});

    // this should delete them
    allocator.deinit(null);

    // these should no longer exist
    var did_error = false;
    std.fs.cwd().access(sig.TEST_DATA_DIR ++ "tmp_0", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
    did_error = false;
    std.fs.cwd().access(sig.TEST_DATA_DIR ++ "tmp_1", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
}

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
    pub inline fn allocator(config: Config) std.mem.Allocator {
        const S = struct {
            fn alloc(_: *anyopaque, _: usize, _: u8, _: usize) ?[*]u8 {
                return switch (config.alloc) {
                    .noop_or_fail => null,
                    .panics => @panic("Unexpected call to alloc"),
                    .assert => unreachable,
                };
            }
            fn resize(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
                return switch (config.resize) {
                    .noop_or_fail => false,
                    .panics => @panic("Unexpected call to resize"),
                    .assert => unreachable,
                };
            }
            fn free(_: *anyopaque, _: []u8, _: u8, _: usize) void {
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
                .free = S.free,
            },
        };
    }
};
