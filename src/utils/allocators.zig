const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

pub fn RecycleFBA(config: struct {
    /// If enabled, all operations will require an exclusive lock.
    thread_safe: bool = !builtin.single_threaded,
}) type {
    return struct {
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

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            if (n > self.alloc_allocator.buffer.len) {
                @panic("RecycleFBA.alloc: requested size too large, make the buffer larger");
            }

            // check for a buf to recycle
            for (self.records.items) |*item| {
                if (item.is_free and
                    item.len >= n and
                    std.mem.isAlignedLog2(@intFromPtr(item.buf), log2_align))
                {
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

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

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

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

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
}

test "recycle allocator" {
    const backing_allocator = std.testing.allocator;
    var allocator = try RecycleFBA(.{}).init(backing_allocator, 1024);
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

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    dir: std.fs.Dir,
    logger: sig.trace.Logger,
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    const Self = @This();

    pub inline fn init(
        index_dir: std.fs.Dir,
        logger: sig.trace.Logger,
    ) Self {
        return .{
            .dir = index_dir,
            .logger = logger,
        };
    }

    /// Metadata stored at the end of each allocation.
    const Metadata = extern struct {
        file_index: u32,
    };

    pub inline fn allocator(self: *Self) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .free = free,
            },
        };
    }

    /// creates a new file with size aligned to page_size and returns a pointer to it
    fn alloc(ctx: *anyopaque, size: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const aligned_size = alignedFileSize(size);

        const file_index = self.count.fetchAdd(1, .monotonic);
        const file_name_bounded = fileNameBounded(file_index);
        const file_name = file_name_bounded.constSlice();

        const file = self.dir.createFile(file_name, .{ .read = true, .truncate = true }) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };
        defer file.close();

        // resize the file
        file.setEndPos(aligned_size) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };

        const full_alloc = std.posix.mmap(
            null,
            aligned_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        ) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };

        std.mem.bytesAsValue(Metadata, full_alloc[size..][0..@sizeOf(Metadata)]).* = .{
            .file_index = file_index,
        };
        return full_alloc.ptr;
    }

    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const aligned_size = alignedFileSize(buf.len);
        const new_aligned_size = alignedFileSize(new_size);

        const buf_ptr: [*]align(std.mem.page_size) u8 = @alignCast(buf.ptr);
        const metadata: Metadata = @bitCast(buf_ptr[buf.len..][0..@sizeOf(Metadata)].*);
        const file_name_bounded = fileNameBounded(metadata.file_index);
        const file_name = file_name_bounded.constSlice();

        if (aligned_size == new_aligned_size) return true;

        if (new_aligned_size < aligned_size) {
            std.posix.munmap(@alignCast(buf_ptr[new_aligned_size..aligned_size]));
            std.mem.bytesAsValue(Metadata, buf_ptr[new_size..][0..@sizeOf(Metadata)]).* = .{
                .file_index = metadata.file_index,
            };
            return true;
        } else {
            const file = self.dir.openFile(file_name, .{ .mode = .read_write }) catch |err| {
                self.logFailure(err, file_name);
                return false;
            };
            defer file.close();

            const mapped = std.posix.mmap(
                buf_ptr,
                new_aligned_size,
                std.posix.PROT.READ | std.posix.PROT.WRITE,
                std.posix.MAP{ .TYPE = .SHARED },
                file.handle,
                0,
            ) catch |err| {
                self.logFailure(err, file_name);
                return false;
            };
            std.debug.assert(mapped.ptr == buf_ptr);

            return true;
        }
    }

    /// unmaps the memory (file still exists and is removed on deinit())
    fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const aligned_size = alignedFileSize(buf.len);

        const buf_ptr: [*]align(std.mem.page_size) u8 = @alignCast(buf.ptr);
        const metadata: Metadata = @bitCast(buf_ptr[buf.len..][0..@sizeOf(Metadata)].*);

        const file_name_bounded = fileNameBounded(metadata.file_index);
        const file_name = file_name_bounded.constSlice();

        std.posix.munmap(buf_ptr[0..aligned_size]);
        self.dir.deleteFile(file_name) catch |err| {
            self.logFailure(err, file_name);
        };
    }

    /// Returns the aligned size with enough space for `size` and `Metadata` at the end.
    inline fn alignedFileSize(size: usize) usize {
        return std.mem.alignForward(usize, size + @sizeOf(Metadata), std.mem.page_size);
    }

    fn logFailure(self: Self, err: anyerror, file_name: []const u8) void {
        self.logger.errf("Disk Memory Allocator error: {s}, filepath: {s}", .{
            @errorName(err), sig.utils.fmt.tryRealPath(self.dir, file_name),
        });
    }

    const file_name_max_len = sig.utils.fmt.boundedLenValue("bin_{d}", .{std.math.maxInt(u32)});
    inline fn fileNameBounded(file_index: u32) std.BoundedArray(u8, file_name_max_len) {
        return sig.utils.fmt.boundedFmt("bin_{d}", .{file_index});
    }
};

test "disk allocator on hashmaps" {
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    var allocator = DiskMemoryAllocator.init(tmp_dir, .noop);

    var refs = std.AutoHashMap(u8, u8).init(allocator.allocator());
    defer refs.deinit();

    try refs.ensureTotalCapacity(100);

    try refs.put(10, 19);

    const r = refs.get(10) orelse return error.Unreachable;
    try std.testing.expectEqual(19, r);
}

test "disk allocator on arraylists" {
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    var dma_state = DiskMemoryAllocator.init(tmp_dir, .noop);
    const dma = dma_state.allocator();

    {
        try std.testing.expectError(error.FileNotFound, tmp_dir.access("bin_0", .{})); // this should not exist

        var disk_account_refs = try std.ArrayList(u8).initCapacity(dma, 1);
        defer disk_account_refs.deinit();

        disk_account_refs.appendAssumeCapacity(19);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);

        try disk_account_refs.append(21);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);
        try std.testing.expectEqual(21, disk_account_refs.items[1]);

        try tmp_dir.access("bin_0", .{}); // this should exist
        try std.testing.expectError(error.FileNotFound, tmp_dir.access("bin_1", .{})); // this should not exist

        const array_ptr = try dma.create([4096]u8);
        defer dma.destroy(array_ptr);
        @memset(array_ptr, 0);

        try tmp_dir.access("bin_1", .{}); // this should now exist
    }

    try std.testing.expectError(error.FileNotFound, tmp_dir.access("bin_0", .{}));
    try std.testing.expectError(error.FileNotFound, tmp_dir.access("bin_1", .{}));
}

/// Namespace housing the different components for the stateless failing allocator.
/// This allows easily importing everything related therein.
/// NOTE: we represent it in this way instead of as a struct like GPA, because
/// the allocator doesn't have any meaningful state to point to, being much more
/// similar to allocators like `page_allocator`, `c_allocator`, etc, except
/// parameterized at compile time.
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
