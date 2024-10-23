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
        bytes_allocator: std.mem.Allocator,
        // this does the data allocations (data is returned from alloc)
        fba_allocator: std.heap.FixedBufferAllocator,
        // recycling depot
        records: std.ArrayList(Record),
        // for thread safety
        mux: std.Thread.Mutex = .{},

        const Record = struct { is_free: bool, buf: [*]u8, len: u64 };
        const AllocatorConfig = struct {
            // used for the records array
            records_allocator: std.mem.Allocator,
            // used for the underlying memory for the allocations
            bytes_allocator: std.mem.Allocator,
        };
        const Self = @This();

        pub fn init(allocator_config: AllocatorConfig, n_bytes: u64) !Self {
            const buf = try allocator_config.bytes_allocator.alloc(u8, n_bytes);
            const fba_allocator = std.heap.FixedBufferAllocator.init(buf);
            const records = std.ArrayList(Record).init(allocator_config.records_allocator);

            return .{
                .bytes_allocator = allocator_config.bytes_allocator,
                .fba_allocator = fba_allocator,
                .records = records,
            };
        }

        pub fn create(allocator_config: AllocatorConfig, n_bytes: u64) !*Self {
            const self = try allocator_config.records_allocator.create(Self);
            self.* = try Self.init(allocator_config, n_bytes);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.bytes_allocator.free(self.fba_allocator.buffer);
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

            if (n > self.fba_allocator.buffer.len) {
                std.debug.panic("RecycleFBA.alloc: requested size too large ({d} > {d}), make the buffer larger", .{ n, self.fba_allocator.buffer.len });
            }

            // check for a buf to recycle
            var is_possible_to_recycle = false;
            for (self.records.items) |*item| {
                if (item.len >= n and
                    std.mem.isAlignedLog2(@intFromPtr(item.buf), log2_align))
                {
                    if (item.is_free) {
                        item.is_free = false;
                        // TODO/PERF: if this is an overallocation, we could split it
                        return item.buf;
                    } else {
                        // additional saftey check
                        is_possible_to_recycle = true;
                    }
                }
            }

            // TODO(PERF, x19): allocate len+1 and store is_free at index 0, `free` could then be O(1)
            // otherwise, allocate a new one
            const buf = self.fba_allocator.allocator().rawAlloc(n, log2_align, return_address) orelse {
                if (!is_possible_to_recycle) {
                    // not enough memory to allocate and no possible recycles will be perma stuck
                    // TODO(x19): loop this and have a comptime limit?
                    self.collapse();
                    if (!self.isPossibleToAllocate(n, log2_align)) {
                        @panic("RecycleFBA.alloc: no possible recycles and not enough memory to allocate");
                    }

                    // try again : TODO(x19): remove the extra lock/unlock
                    if (config.thread_safe) self.mux.unlock(); // no deadlock
                    defer if (config.thread_safe) self.mux.lock();
                    return alloc(ctx, n, log2_align, return_address);
                }
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
                        return self.fba_allocator.allocator().rawResize(
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

        pub fn ensureCapacity(self: *Self, n: u64) !void {
            const current_buf = self.fba_allocator.buffer;
            if (current_buf.len >= n) return;

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            if (!self.bytes_allocator.resize(current_buf, n)) {
                const current_usage = self.fba_allocator.end_index;
                if (current_usage != 0) return error.ResizeUsedAllocatorNotSupported;

                // NOTE: this can be expensive on memory (if two large bufs)
                const new_buf = try self.bytes_allocator.alloc(u8, n);
                self.fba_allocator.buffer = new_buf;
                self.bytes_allocator.free(current_buf);
            }
        }

        /// frees the unused space of a buf.
        /// this is useful when a buf is initially overallocated and then resized.
        pub fn freeUnusedSpace(self: *Self, valid_buf: []u8) void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.records.items) |*record| {
                if (record.buf == valid_buf.ptr) {
                    const unused_len = record.len - valid_buf.len;
                    if (unused_len > 0) {
                        const unused_buf_ptr = valid_buf.ptr + valid_buf.len + 1;
                        self.records.append(.{ .is_free = true, .buf = unused_buf_ptr, .len = unused_len }) catch {
                            @panic("RecycleFBA.freeUnusedSpace: unable to append to records");
                        };
                    }
                }
            }
        }

        pub fn isPossibleToAllocate(self: *Self, n: u64, log2_align: u8) bool {
            // direct alloc check
            const fba_size_left = self.fba_allocator.buffer.len - self.fba_allocator.end_index;
            if (fba_size_left >= n) {
                return true;
            }

            // check for a buf to recycle
            for (self.records.items) |*item| {
                if (item.len >= n and
                    std.mem.isAlignedLog2(@intFromPtr(item.buf), log2_align))
                {
                    return true;
                }
            }

            return false;
        }

        /// collapses adjacent free records into a single record
        pub fn collapse(self: *Self) void {
            var new_records = std.ArrayList(Record).init(self.records.allocator);
            var last_was_free = false;

            for (self.records.items) |record| {
                if (record.is_free) {
                    if (last_was_free) {
                        new_records.items[new_records.items.len - 1].len += record.len;
                    } else {
                        last_was_free = true;
                        new_records.append(record) catch {
                            @panic("RecycleFBA.collapse: unable to append to new_records");
                        };
                    }
                } else {
                    new_records.append(record) catch {
                        @panic("RecycleFBA.collapse: unable to append to new_records");
                    };
                    last_was_free = false;
                }
            }

            self.records.deinit();
            self.records = new_records;
        }
    };
}

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    dir: std.fs.Dir,
    logger: sig.trace.Logger,
    /// The amount of memory mmap'd for a particular allocation will be `file_size * mmap_ratio`.
    /// See `alignedFileSize` and its usages to understand the relationship between an allocation
    /// size, and the size of a file, and by extension, how this then relates to the allocated
    /// address space.
    mmap_ratio: MmapRatio = 1,
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    const Self = @This();

    pub const MmapRatio = u16;

    /// Metadata stored at the end of each allocation.
    pub const Metadata = extern struct {
        file_index: u32,
        mmap_size: usize align(4),
    };

    /// Returns the aligned size with enough space for `size` and `Metadata` at the end.
    pub inline fn alignedFileSize(size: usize) usize {
        return std.mem.alignForward(usize, size + @sizeOf(Metadata), std.mem.page_size);
    }

    pub inline fn alignedMmapSize(
        /// Must be `= alignedFileSize(size)`.
        aligned_file_size: usize,
        mmap_ratio: MmapRatio,
    ) usize {
        return aligned_file_size *| mmap_ratio;
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
    pub fn alloc(ctx: *anyopaque, size: usize, log2_align: u8, return_address: usize) ?[*]u8 {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);

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
            .mmap_size = aligned_mmap_size,
        };
        return full_alloc.ptr;
    }

    /// Resizes the allocation within the bounds of the mmap'd address space if possible.
    pub fn resize(
        ctx: *anyopaque,
        buf: []u8,
        log2_align: u8,
        new_size: usize,
        return_address: usize,
    ) bool {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);

        const alignment = @as(usize, 1) << @intCast(log2_align);
        std.debug.assert(alignment <= std.mem.page_size); // the allocator interface shouldn't allow this (aside from the *Raw methods).

        const old_file_aligned_size = alignedFileSize(buf.len);
        const new_file_aligned_size = alignedFileSize(new_size);

        if (new_file_aligned_size == old_file_aligned_size) {
            return true;
        }

        const buf_ptr: [*]align(std.mem.page_size) u8 = @alignCast(buf.ptr);
        const metadata: Metadata = @bitCast(buf_ptr[old_file_aligned_size - @sizeOf(Metadata) ..][0..@sizeOf(Metadata)].*);

        if (new_file_aligned_size > metadata.mmap_size) {
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
        std.mem.bytesAsValue(Metadata, buf_ptr[new_size..][0..@sizeOf(Metadata)]).* = metadata;

        return true;
    }

    /// unmaps the memory and deletes the associated file.
    pub fn free(ctx: *anyopaque, buf: []u8, log2_align: u8, return_address: usize) void {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);
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

    pub fn logFailure(self: Self, err: anyerror, file_name: []const u8) void {
        self.logger.err().logf("Disk Memory Allocator error: {s}, filepath: {s}", .{
            @errorName(err), sig.utils.fmt.tryRealPath(self.dir, file_name),
        });
    }

    const file_name_max_len = sig.utils.fmt.boundedLenValue("memory_{d}", .{std.math.maxInt(u32)});
    pub inline fn fileNameBounded(file_index: u32) std.BoundedArray(u8, file_name_max_len) {
        return sig.utils.fmt.boundedFmt("memory_{d}", .{file_index});
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

test "recycle allocator: freeUnused" {
    const backing_allocator = std.testing.allocator;
    var allocator = try RecycleFBA(.{}).init(.{
        .records_allocator = backing_allocator,
        .bytes_allocator = backing_allocator,
    }, 200);
    defer allocator.deinit();

    // alloc a slice of 100 bytes
    const bytes = try allocator.allocator().alloc(u8, 100);
    defer allocator.allocator().free(bytes);
    // free the unused space
    allocator.freeUnusedSpace(bytes[0..50]);

    // this should be ok now
    const bytes2 = try allocator.allocator().alloc(u8, 50);
    defer allocator.allocator().free(bytes2);

    const expected_ptr: [*]u8 = @alignCast(@ptrCast(&bytes[51]));
    try std.testing.expectEqual(expected_ptr, bytes2.ptr);
}

test "recycle allocator: collapse" {
    const bytes_allocator = std.testing.allocator;
    var allocator = try RecycleFBA(.{}).init(.{
        .records_allocator = bytes_allocator,
        .bytes_allocator = bytes_allocator,
    }, 200);
    defer allocator.deinit();

    // alloc a slice of 100 bytes
    const bytes = try allocator.allocator().alloc(u8, 100);
    // alloc a slice of 100 bytes
    const bytes2 = try allocator.allocator().alloc(u8, 100);

    // free both slices
    allocator.allocator().free(bytes);
    allocator.allocator().free(bytes2);

    allocator.collapse();
    // this should be ok now
    const bytes3 = try allocator.allocator().alloc(u8, 150);
    allocator.allocator().free(bytes3);
}

test "recycle allocator" {
    const bytes_allocator = std.testing.allocator;
    var allocator = try RecycleFBA(.{}).init(.{
        .records_allocator = bytes_allocator,
        .bytes_allocator = bytes_allocator,
    }, 1024);
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
        1,  2,  3,  4,  5,
        10, 11, 12, 13, 14,
        15, 20, 21, 22, 23,
        24, 25, 30, 31, 32,
        33, 34, 35, 40, 41,
        42, 43, 44, 45, 50,
        51, 52, 53, 54, 55,
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

    const file0 = "memory_0"; // DiskMemoryAllocator.fileNameBounded(0).constSlice();
    const file1 = "memory_1"; // DiskMemoryAllocator.fileNameBounded(1).constSlice();
    {
        try std.testing.expectError(error.FileNotFound, tmp_dir.access(file0, .{})); // this should not exist

        var disk_account_refs = try std.ArrayList(u8).initCapacity(dma, 1);
        defer disk_account_refs.deinit();

        disk_account_refs.appendAssumeCapacity(19);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);

        try disk_account_refs.append(21);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);
        try std.testing.expectEqual(21, disk_account_refs.items[1]);

        try tmp_dir.access(file0, .{}); // this should exist
        try std.testing.expectError(error.FileNotFound, tmp_dir.access(file1, .{})); // this should not exist

        const array_ptr = try dma.create([4096]u8);
        defer dma.destroy(array_ptr);
        @memset(array_ptr, 0);

        try tmp_dir.access(file1, .{}); // this should now exist
    }

    try std.testing.expectError(error.FileNotFound, tmp_dir.access(file0, .{}));
    try std.testing.expectError(error.FileNotFound, tmp_dir.access(file1, .{}));
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
