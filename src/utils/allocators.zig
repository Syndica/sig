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

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    dir: std.fs.Dir,
    logger: sig.trace.Logger,
    /// The address space mmap'd to a particular file will be at least
    /// `(file_size * (1000 + mmap_ratio)) / 1000` in integer terms.
    /// With a value of 0, the mmap'd size will be equal to the file size.
    /// With a value of 1000, the mmap'd size will be double the file size.
    /// NOTE: not intended to be changed after initialization.
    mmap_ratio: MmapRatio = 0,
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    const Self = @This();

    pub const MmapRatio = u32;

    /// Metadata stored at the end of each allocation.
    const Metadata = extern struct {
        file_index: u32,
        /// In an extern struct only ABI-sized types are allowed, so this is a `std.math.Log2Int(usize)`,
        /// wrapped in a packed struct to define the padding bits.
        mmap_size: packed struct(u8) {
            /// The log2 of the mmap size - the actual mmap size can be acquired via `1 << log2`. See `get`.
            /// This is done this way to minimize the amount of redundantly stored information: the mmap size
            /// will always be a power of two, and as such can be represented minimally using its log2.
            log2: UsizeLog2,
            _padding: enum(PaddingInt) { unset = 0 } = .unset,

            const UsizeLog2 = std.math.Log2Int(usize);
            const PaddingInt = std.meta.Int(.unsigned, @bitSizeOf(u8) - @bitSizeOf(UsizeLog2));

            pub inline fn get(self: @This()) usize {
                return @as(usize, 1) << self.log2;
            }
        },
    };

    /// Returns the aligned size with enough space for `size` and `Metadata` at the end.
    inline fn alignedFileSize(size: usize) usize {
        return std.mem.alignForward(usize, size + @sizeOf(Metadata), std.mem.page_size);
    }

    /// Returns the aligned size to mmap relative to `alignedFileSize(size)`.
    inline fn alignedMmapSize(
        /// Must be `= alignedFileSize(size)`.
        aligned_file_size: usize,
        mmap_ratio: MmapRatio,
    ) usize {
        const min_mmap_size = (aligned_file_size * (1000 + mmap_ratio)) / 1000;
        return std.mem.alignForward(usize, min_mmap_size, std.mem.page_size);
    }

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

    /// creates a new file with size aligned to page_size and returns a pointer to it.
    ///
    /// mmaps at least enough memory to the file for `size`, the metadata, and optionally
    /// more based on the `mmap_ratio` field, in order to accommodate potential growth
    /// from `resize` calls.
    fn alloc(ctx: *anyopaque, size: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const file_aligned_size = alignedFileSize(size);
        const aligned_mmap_size = alignedMmapSize(file_aligned_size, self.mmap_ratio);

        const file_index = self.count.fetchAdd(1, .monotonic);
        const file_name_bounded = fileNameBounded(file_index);
        const file_name = file_name_bounded.constSlice();

        const file = self.dir.createFile(file_name, .{ .read = true, .truncate = true }) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };
        defer file.close();

        // resize the file
        file.setEndPos(file_aligned_size) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };

        const full_alloc = std.posix.mmap(
            null,
            aligned_mmap_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        ) catch |err| {
            self.logFailure(err, file_name);
            return null;
        };

        std.debug.assert(size <= file_aligned_size - @sizeOf(Metadata)); // sanity check
        std.mem.bytesAsValue(Metadata, full_alloc[size..][0..@sizeOf(Metadata)]).* = .{
            .file_index = file_index,
            .mmap_size = .{ .log2 = std.math.log2_int(usize, aligned_mmap_size) },
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

        const old_file_aligned_size = alignedFileSize(buf.len);
        const new_file_aligned_size = alignedFileSize(new_size);

        if (new_file_aligned_size == old_file_aligned_size) {
            return true;
        }

        const buf_ptr: [*]align(std.mem.page_size) u8 = @alignCast(buf.ptr);
        const metadata: Metadata = @bitCast(buf_ptr[old_file_aligned_size - @sizeOf(Metadata) ..][0..@sizeOf(Metadata)].*);

        if (new_file_aligned_size > metadata.mmap_size.get()) {
            return false;
        }

        const file_name_bounded = fileNameBounded(metadata.file_index);
        const file_name = file_name_bounded.constSlice();

        const file = self.dir.openFile(file_name, .{ .mode = .read_write }) catch |err| {
            self.logFailure(err, file_name);
            return false;
        };
        defer file.close();

        file.setEndPos(new_file_aligned_size) catch return false;

        std.debug.assert(new_size <= new_file_aligned_size - @sizeOf(Metadata)); // sanity check
        std.mem.bytesAsValue(Metadata, buf_ptr[new_size..][0..@sizeOf(Metadata)]).* = .{
            .file_index = metadata.file_index,
            .mmap_size = metadata.mmap_size,
        };

        return true;
    }

    /// unmaps the memory and deletes the associated file.
    fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));

        std.debug.assert(buf.len != 0); // should be ensured by the allocator interface

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const file_aligned_size = alignedFileSize(buf.len);
        const mmap_aligned_size = alignedMmapSize(file_aligned_size, self.mmap_ratio);

        const buf_ptr: [*]align(std.mem.page_size) u8 = @alignCast(buf.ptr);
        const metadata: Metadata = @bitCast(buf_ptr[buf.len..][0..@sizeOf(Metadata)].*);

        const file_name_bounded = fileNameBounded(metadata.file_index);
        const file_name = file_name_bounded.constSlice();

        std.posix.munmap(buf_ptr[0..mmap_aligned_size]);
        self.dir.deleteFile(file_name) catch |err| {
            self.logFailure(err, file_name);
        };
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

test "disk allocator stdlib test" {
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    for ([_]DiskMemoryAllocator.MmapRatio{
        0,    1,    2,    3,  4,  5,
        10,   11,   12,   13, 14, 15,
        20,   21,   22,   23, 24, 25,
        30,   31,   32,   33, 34, 35,
        40,   41,   42,   43, 44, 45,
        50,   51,   52,   53, 54, 55,
        1000, 2000, 3000,
    }) |ratio| {
        var dma_state: DiskMemoryAllocator = .{
            .dir = tmp_dir,
            .logger = .noop,
            .mmap_ratio = ratio,
        };
        const dma = dma_state.allocator();

        try std.heap.testAllocator(dma);
        try std.heap.testAllocatorAligned(dma);
        try std.heap.testAllocatorLargeAlignment(dma);
        try std.heap.testAllocatorAlignedShrink(dma);
    }
}

test "disk allocator on hashmaps" {
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    var dma_state: DiskMemoryAllocator = .{
        .dir = tmp_dir,
        .logger = .noop,
    };
    const dma = dma_state.allocator();

    var refs = std.AutoHashMap(u8, u8).init(dma);
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

    var dma_state: DiskMemoryAllocator = .{
        .dir = tmp_dir,
        .logger = .noop,
    };
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

test "disk allocator large realloc" {
    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    var dma_state: DiskMemoryAllocator = .{
        .dir = tmp_dir,
        .logger = .noop,
    };
    const dma = dma_state.allocator();

    var page1 = try dma.alloc(u8, std.mem.page_size);
    defer dma.free(page1);

    page1 = try dma.realloc(page1, std.mem.page_size * 15);

    page1[page1.len - 1] = 10;
}

