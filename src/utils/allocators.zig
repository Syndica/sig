const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;
const Atomic = std.atomic.Value;
const FixedBufferAllocator = std.heap.FixedBufferAllocator;

const bytesAsValue = std.mem.bytesAsValue;

/// very similar to RecycleFBA but with a few differences:
/// - this uses an explicit T type and only returns slices of that type (instead of a generic u8)
/// - additional memory blocks are supported (instead of using a fixed-buffer-allocator approach)
///
/// when `alloc` returns error.AllocFailed the allocation failed and the caller should try again
/// (after some records/buffers have been free'd/recycle'd).
/// If the allocation size is too big to be recycled after trying to collapse smaller records
/// (config.max_collapse_tries times) then we panic (or return error.CollapseFailed in allocUnsafe).
pub fn RecycleBuffer(comptime T: type, default_init: T, config: struct {
    /// If enabled, all operations will require an exclusive lock.
    thread_safe: bool = !builtin.single_threaded,
    max_collapse_tries: u32 = 5,
    collapse_sleep_ms: u32 = 100,
    min_split_size: u64 = 128,
}) type {
    std.debug.assert(config.min_split_size > 0);

    return struct {
        records_allocator: Allocator,
        /// records are used to keep track of the memory blocks
        records: std.ArrayListUnmanaged(Record),
        /// allocator used to alloc the memory blocks
        memory_allocator: Allocator,
        /// memory holds blocks of memory ([]T) that can be allocated/deallocated
        memory: std.ArrayListUnmanaged([]T),
        /// total number of T elements we have in memory
        capacity: u64,
        /// the maximum contiguous capacity we have in memory
        /// NOTE: since we support multiple memory slices, this tells us the max single alloc size
        max_continguous_capacity: u64,
        /// for thread safety
        mux: std.Thread.Mutex = .{},
        const Self = @This();

        pub const Record = struct {
            is_free: bool,
            buf: []T,
            len: u64,
            // NOTE: this is tracked for correct usage of collapse()
            memory_index: u64,
        };

        const AllocatorConfig = struct {
            records_allocator: Allocator,
            memory_allocator: Allocator,
        };

        pub fn init(allocator_config: AllocatorConfig) Self {
            return .{
                .records_allocator = allocator_config.records_allocator,
                .records = .{},
                .memory_allocator = allocator_config.memory_allocator,
                .memory = .{},
                .capacity = 0,
                .max_continguous_capacity = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.memory.items) |block| {
                self.memory_allocator.free(block);
            }
            self.memory.deinit(self.memory_allocator);
            self.records.deinit(self.records_allocator);
        }

        pub fn create(allocator_config: AllocatorConfig) !*Self {
            const self = try allocator_config.records_allocator.create(Self);
            self.* = Self.init(allocator_config);
            return self;
        }

        pub fn destroy(self: *Self) void {
            self.deinit();
            self.records_allocator.destroy(self);
        }

        /// append a block of N elements to the manager
        pub fn expandCapacity(self: *Self, n: u64) Allocator.Error!void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            return self.expandCapacityUnsafe(n);
        }

        pub fn expandCapacityUnsafe(self: *Self, n: u64) Allocator.Error!void {
            if (n == 0) return;

            try self.records.ensureUnusedCapacity(self.records_allocator, 1);
            try self.memory.ensureUnusedCapacity(self.memory_allocator, 1);

            const buf = try self.memory_allocator.alloc(T, n);
            // NOTE: we do this here so bincode serialization can work correctly
            // otherwise, we run into undefined memory which breaks bincode
            @memset(buf, default_init);

            self.records.appendAssumeCapacity(.{
                .is_free = true,
                .buf = buf,
                .len = buf.len,
                .memory_index = self.memory.items.len,
            });
            self.memory.appendAssumeCapacity(buf);
            self.capacity += buf.len;
            self.max_continguous_capacity = @max(self.max_continguous_capacity, buf.len);
        }

        const AllocError = error{
            AllocTooBig,
            AllocFailed,
            // NOTE: even though this doesnt get hit on `alloc`, zig isnt smart enough to know that
            CollapseFailed,
        } || Allocator.Error;

        pub fn alloc(self: *Self, n: u64) AllocError![]T {
            if (n == 0) return &.{};

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (0..config.max_collapse_tries) |_| {
                return self.allocUnsafe(n) catch |err| {
                    switch (err) {
                        error.CollapseFailed => {
                            if (config.thread_safe) self.mux.unlock();
                            defer if (config.thread_safe) self.mux.lock();
                            // wait some time and try to collapse again.
                            std.Thread.sleep(std.time.ns_per_ms * config.collapse_sleep_ms);
                            // NOTE: this is because there may be new free records
                            // (which were free'd by some other consumer thread) which
                            // can be collapsed and the alloc call will then succeed.
                            continue;
                        },
                        else => return err,
                    }
                };
            }
            // not enough memory to allocate and no possible recycles will be perma stuck.
            // though its possible to recover from this, its very unlikely, so we panic
            @panic("not enough memory and collapse failed max times");
        }

        /// same as alloc but if the alloc fails due to not having enough free records (error.AllocFailed),
        /// it expands the records to max(min_split_size, n) and retrys (which should always succeed)
        pub fn allocOrExpand(self: *Self, n: u64) AllocError![]T {
            if (n == 0) return &.{};

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (0..config.max_collapse_tries) |_| {
                return self.allocUnsafe(n) catch |err| {
                    switch (err) {
                        error.CollapseFailed => {
                            if (config.thread_safe) self.mux.unlock();
                            defer if (config.thread_safe) self.mux.lock();
                            // wait some time and try to collapse again.
                            std.Thread.sleep(std.time.ns_per_ms * config.collapse_sleep_ms);
                            // NOTE: this is because there may be new free records
                            // (which were free'd by some other consumer thread) which
                            // can be collapsed and the alloc call will then succeed.
                            continue;
                        },
                        // not able to recycle anything, so we break to expand the capacity
                        error.AllocFailed, error.AllocTooBig => break,
                        else => return err,
                    }
                };
            }

            // if allocation failed, then expand the capacity and try again
            try self.expandCapacityUnsafe(@max(config.min_split_size, n));
            return self.allocUnsafe(n);
        }

        pub fn allocUnsafe(self: *Self, n: u64) AllocError![]T {
            if (n == 0) return &.{};
            // this would never succeed
            if (n > self.max_continguous_capacity) return error.AllocTooBig;

            // check for a buf to recycle
            var is_possible_to_recycle = false;
            for (self.records.items) |*record| {
                if (record.buf.len >= n) { // allocation is possible
                    if (record.is_free) {
                        record.is_free = false;
                        // local copy because next line will likely change the record pointer
                        const buf = record.buf[0..n];
                        _ = self.tryRecycleUnusedSpaceWithRecordUnsafe(record, n);
                        return buf;
                    } else {
                        is_possible_to_recycle = true;
                    }
                }
            }

            if (is_possible_to_recycle) {
                // they can try again later since recycle is possible
                return error.AllocFailed;
            } else {
                // try to collapse small record chunks and allocate again
                self.collapseUnsafe();
                const collapse_succeed = self.isPossibleToAllocateUnsafe(n);
                if (collapse_succeed) {
                    // exit here
                    return self.allocUnsafe(n);
                } else {
                    // up to the caller but should sleep and try collapse/alloc again
                    return error.CollapseFailed;
                }
            }
        }

        pub fn free(self: *Self, buf_ptr: [*]T) void {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.records.items) |*record| {
                if (record.buf.ptr == buf_ptr) {
                    record.is_free = true;
                    return;
                }
            }
            @panic("attempt to free invalid buf");
        }

        /// frees the unused space of a buf.
        /// this is useful when a buf is initially overallocated and then resized.
        pub fn tryRecycleUnusedSpace(self: *Self, buf_ptr: [*]T, used_len: u64) bool {
            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            for (self.records.items) |*record| {
                if (record.buf.ptr == buf_ptr) {
                    return self.tryRecycleUnusedSpaceWithRecordUnsafe(record, used_len);
                }
            }
            @panic("attempt to recycle invalid buf");
        }

        fn tryRecycleUnusedSpaceWithRecordUnsafe(
            self: *Self,
            record: *Record,
            used_len: u64,
        ) bool {
            const unused_len = record.buf.len -| used_len;
            if (unused_len > config.min_split_size) {
                // update the state of the record
                const split_buf = record.buf[used_len..];
                // NOTE: this record ptr is updated before the append which could invalidate the record ptr
                record.buf = record.buf[0..used_len];
                record.len = used_len;
                // add new unused record to the list
                // NOTE: errors here are unreachable because if we hit OOM, were left in a bad state
                self.records.append(self.records_allocator, .{
                    .is_free = true,
                    .buf = split_buf,
                    .len = split_buf.len,
                    .memory_index = record.memory_index,
                }) catch unreachable;
                return true;
            } else {
                // dont try to split if its too small
                return false;
            }
        }

        /// collapses adjacent free records into a single record.
        /// we use the memory_index to ensure we dont collapse two separate buffers
        /// into one, which would result in a segfault.
        pub fn collapseUnsafe(self: *Self) void {
            const records = &self.records;
            var i: usize = 1;
            while (i < records.items.len) {
                const prev = records.items[i - 1];
                const curr = records.items[i];

                const both_free = prev.is_free and curr.is_free;
                const shared_memory_index = prev.memory_index == curr.memory_index;

                if (both_free and shared_memory_index) {
                    records.items[i - 1].buf.len += curr.buf.len;
                    _ = records.orderedRemove(i);
                } else {
                    i += 1;
                }
            }
        }

        pub fn isPossibleToAllocateUnsafe(self: *Self, n: u64) bool {
            for (self.records.items) |*record| {
                if (record.buf.len >= n) {
                    return true;
                }
            }
            return false;
        }
    };
}

pub fn RecycleFBA(config: struct {
    /// If enabled, all operations will require an exclusive lock.
    thread_safe: bool = !builtin.single_threaded,
}) type {
    return struct {
        // this allocates the underlying memory + dynamic expansions
        // (only used on init/deinit + arraylist expansion)
        bytes_allocator: Allocator,
        // this does the data allocations (data is returned from alloc)
        fba_allocator: std.heap.FixedBufferAllocator,
        // recycling depot
        records: std.ArrayList(Record),
        // for thread safety
        mux: std.Thread.Mutex = .{},

        const Record = struct { is_free: bool, buf: [*]u8, len: u64 };
        const AllocatorConfig = struct {
            // used for the records array
            records_allocator: Allocator,
            // used for the underlying memory for the allocations
            bytes_allocator: Allocator,
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

        pub fn deinit(self: *Self) void {
            self.bytes_allocator.free(self.fba_allocator.buffer);
            self.records.deinit();
        }

        pub fn allocator(self: *Self) Allocator {
            return Allocator{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        /// creates a new file with size aligned to page_size and returns a pointer to it
        pub fn alloc(
            ctx: *anyopaque,
            n: usize,
            alignment: Alignment,
            return_address: usize,
        ) ?[*]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx));

            if (config.thread_safe) self.mux.lock();
            defer if (config.thread_safe) self.mux.unlock();

            if (n > self.fba_allocator.buffer.len) {
                @panic("RecycleFBA.alloc: requested size too large, make the buffer larger");
            }

            // check for a buf to recycle
            var is_possible_to_recycle = false;
            for (self.records.items) |*item| {
                if (item.len >= n and
                    alignment.check(@intFromPtr(item.buf)))
                {
                    if (item.is_free) {
                        item.is_free = false;
                        return item.buf;
                    } else {
                        // additional saftey check
                        is_possible_to_recycle = true;
                    }
                }
            }

            // TODO(PERF, x19): allocate len+1 and store is_free at index 0, `free` could then be O(1)
            // otherwise, allocate a new one
            const buf = self.fba_allocator.allocator().rawAlloc(
                n,
                alignment,
                return_address,
            ) orelse {
                if (!is_possible_to_recycle) {
                    // not enough memory to allocate and no possible recycles will be perma stuck
                    // TODO(x19): loop this and have a comptime limit?
                    self.tryCollapse();
                    if (!self.isPossibleToAllocate(n, alignment)) {
                        @panic("RecycleFBA.alloc: no possible recycles " ++
                            "and not enough memory to allocate");
                    }

                    // try again : TODO(x19): remove the extra lock/unlock
                    if (config.thread_safe) self.mux.unlock(); // no deadlock
                    defer if (config.thread_safe) self.mux.lock();
                    return alloc(ctx, n, alignment, return_address);
                }
                return null;
            };

            self.records.append(.{ .is_free = false, .buf = buf, .len = n }) catch {
                // std.debug.print("RecycleFBA append error: {}\n", .{ err });
                return null;
            };

            return buf;
        }

        pub fn free(
            ctx: *anyopaque,
            buf: []u8,
            alignment: Alignment,
            return_address: usize,
        ) void {
            _ = alignment;
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
            alignment: Alignment,
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
                            alignment,
                            new_size,
                            return_address,
                        );
                    }
                }
            }

            // not supported
            return false;
        }

        fn remap(
            context: *anyopaque,
            memory: []u8,
            alignment: Alignment,
            new_len: usize,
            return_address: usize,
        ) ?[*]u8 {
            return if (resize(
                context,
                memory,
                alignment,
                new_len,
                return_address,
            )) memory.ptr else null;
        }

        pub fn isPossibleToAllocate(self: *Self, n: u64, alignment: Alignment) bool {
            // direct alloc check
            const fba_size_left = self.fba_allocator.buffer.len - self.fba_allocator.end_index;
            if (fba_size_left >= n) {
                return true;
            }

            // check for a buf to recycle
            for (self.records.items) |*item| {
                if (item.len >= n and
                    alignment.check(@intFromPtr(item.buf)))
                {
                    return true;
                }
            }

            return false;
        }

        /// collapses adjacent free records into a single record
        pub fn tryCollapse(self: *Self) void {
            var new_records = std.ArrayList(Record).init(self.bytes_allocator);
            var last_was_free = false;

            for (self.records.items) |record| {
                if (record.is_free) {
                    if (last_was_free) {
                        new_records.items[new_records.items.len - 1].len += record.len;
                    } else {
                        last_was_free = true;
                        new_records.append(record) catch {
                            @panic("RecycleFBA.tryCollapse: unable to append to new_records");
                        };
                    }
                } else {
                    new_records.append(record) catch {
                        @panic("RecycleFBA.tryCollapse: unable to append to new_records");
                    };
                    last_was_free = false;
                }
            }

            self.records.deinit();
            self.records = new_records;
        }
    };
}

/// Always allocates from the backing allocator in batches at least as large as batch_size.
pub const BatchAllocator = struct {
    backing_allocator: Allocator,
    batch_size: usize,
    last_batch: Atomic(?*Batch) = Atomic(?*Batch).init(null),
    new_batch_lock: std.Thread.RwLock = .{},
    new_batch_waiters: Atomic(usize) = Atomic(usize).init(0),
    new_batch_wait_lock: std.Thread.RwLock = .{},

    const Self = @This();

    const Batch = struct {
        fba: FixedBufferAllocator,
        num_allocs: Atomic(usize),

        const DONE = 1 << (@bitSizeOf(usize) - 1);

        fn deinit(self: *Batch, backing_allocator: Allocator) void {
            backing_allocator.rawFree(
                (self.fba.buffer.ptr - @sizeOf(Batch))[0 .. self.fba.buffer.len + @sizeOf(Batch)],
                .fromByteUnits(@alignOf(Batch)),
                @returnAddress(),
            );
        }

        /// allocates the full size, which includes extra space at the end for the batch,
        /// and writes the batch pointer in the extra space.
        fn alloc(
            batch: *Batch,
            len: usize,
            alignment: Alignment,
            ret_addr: usize,
        ) ?[*]u8 {
            // allocate the full slice including space for the *Batch
            const full_ptr = batch.fba.threadSafeAllocator()
                .rawAlloc(len + @sizeOf(*Batch), alignment, ret_addr) orelse
                return null;

            // write the *Batch into the end of the slice
            bytesAsValue(*Batch, full_ptr[len..]).* = batch;

            return full_ptr;
        }

        /// identifies the batch by extending the buf,
        /// then frees the buf using the batch's fba.
        fn free(buf: []u8, log2_buf_align: Alignment, return_address: usize) *Batch {
            // extract the batch pointer from after the end of the buffer
            const batch_bytes = buf.ptr[buf.len..][0..@sizeOf(*Batch)];
            const batch = bytesAsValue(*Batch, batch_bytes).*;

            // free the full allocation
            batch.fba.threadSafeAllocator().rawFree(
                buf.ptr[0 .. buf.len + @sizeOf(*Batch)],
                log2_buf_align,
                return_address,
            );

            return batch;
        }
    };

    /// only after all the allocated data has been freed.
    pub fn deinit(self: *BatchAllocator) void {
        if (self.last_batch.load(.acquire)) |batch| {
            batch.deinit(self.backing_allocator);
        }
    }

    pub fn allocator(self: *BatchAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = Allocator.noResize,
                .remap = Allocator.noRemap,
                .free = free,
            },
        };
    }

    fn alloc(
        ctx: *anyopaque,
        len: usize,
        log2_ptr_align: Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        const self: *BatchAllocator = @ptrCast(@alignCast(ctx));

        while (true) {
            // try to allocate from a prior batch
            if (self.tryAllocOldBatch(len, log2_ptr_align, ret_addr)) |success| {
                return success;
            }

            // existing batch is not suitable. create a new one
            if (self.tryAllocNewBatch(len, log2_ptr_align, ret_addr)) |success| {
                return success;
            }
        }
    }

    fn tryAllocOldBatch(
        self: *Self,
        len: usize,
        log2_ptr_align: Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        self.new_batch_lock.lockShared();
        defer self.new_batch_lock.unlockShared();

        if (self.last_batch.load(.monotonic)) |batch| {
            _ = batch.num_allocs.fetchAdd(1, .monotonic);
            if (batch.alloc(len, log2_ptr_align, ret_addr)) |ptr| {
                return ptr;
            } else {
                _ = batch.num_allocs.fetchSub(1, .monotonic);
            }
        }
        return null;
    }

    fn tryAllocNewBatch(
        self: *Self,
        len: usize,
        alignment: Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        // only one thread should do this at a time.
        // other threads should wait until the first one finishes.
        if (self.new_batch_waiters.fetchAdd(1, .monotonic) > 0) {
            _ = self.new_batch_waiters.fetchSub(1, .monotonic);
            std.atomic.spinLoopHint();
            return null;
        }
        defer _ = self.new_batch_waiters.fetchSub(1, .monotonic);
        self.new_batch_lock.lock();
        defer self.new_batch_lock.unlock();

        const padding = alignment.forward(@sizeOf(Batch));
        const batch_size = @max(self.batch_size, padding + len + @sizeOf(*Batch));

        // create new batch
        const batch_bytes = self.backing_allocator
            .rawAlloc(batch_size, .fromByteUnits(@alignOf(Batch)), ret_addr) orelse return null;
        const new_batch: *Batch = @alignCast(@ptrCast(batch_bytes));
        new_batch.* = Batch{
            .fba = FixedBufferAllocator.init(batch_bytes[@sizeOf(Batch)..batch_size]),
            .num_allocs = Atomic(usize).init(1),
        };

        // use new batch for allocation
        const ptr = new_batch.alloc(len, alignment, ret_addr) orelse unreachable;

        if (batch_size > self.batch_size) {
            // this batch won't be useful for any other allocations
            _ = new_batch.num_allocs.fetchOr(Batch.DONE, .monotonic);
        } else {
            // make new batch available to future allocations, and mark old batch as done
            if (self.last_batch.swap(new_batch, .monotonic)) |old_batch| {
                if (0 == old_batch.num_allocs.fetchOr(Batch.DONE, .monotonic)) {
                    // free old batch since all allocations are freed
                    old_batch.deinit(self.backing_allocator);
                }
            }
        }

        return ptr;
    }

    fn free(
        ctx: *anyopaque,
        buf: []u8,
        log2_buf_align: Alignment,
        return_address: usize,
    ) void {
        const self: *BatchAllocator = @ptrCast(@alignCast(ctx));

        const batch = Batch.free(buf, log2_buf_align, return_address);

        if (Batch.DONE + 1 == batch.num_allocs.fetchSub(1, .monotonic)) {
            batch.deinit(self.backing_allocator);
        }
    }
};

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    dir: std.fs.Dir,
    logger: sig.trace.Logger(@typeName(Self)),
    /// The amount of memory mmap'd for a particular allocation will be `file_size * mmap_ratio`.
    /// See `alignedFileSize` and its usages to understand the relationship between an allocation
    /// size, and the size of a file, and by extension, how this then relates to the allocated
    /// address space.
    mmap_ratio: MmapRatio = 1,
    count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    const Self = @This();

    pub const MmapRatio = u16;

    /// Metadata stored at the end of each allocation.
    const Metadata = extern struct {
        file_index: u32,
        mmap_size: usize align(4),
    };

    /// Returns the aligned size with enough space for `size` and `Metadata` at the end.
    inline fn alignedFileSize(size: usize) usize {
        return std.mem.alignForward(usize, size + @sizeOf(Metadata), std.heap.pageSize());
    }

    inline fn alignedMmapSize(
        /// Must be `= alignedFileSize(size)`.
        aligned_file_size: usize,
        mmap_ratio: MmapRatio,
    ) usize {
        return aligned_file_size *| mmap_ratio;
    }

    pub inline fn allocator(self: *Self) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    /// creates a new file with size aligned to page_size and returns a pointer to it.
    ///
    /// mmaps at least enough memory to the file for `size`, the metadata, and optionally
    /// more based on the `mmap_ratio` field, in order to accommodate potential growth
    /// from `resize` calls.
    fn alloc(
        ctx: *anyopaque,
        requested_size: usize,
        alignment: Alignment,
        return_address: usize,
    ) ?[*]u8 {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);

        // the allocator interface shouldn't allow this (aside from the *Raw methods).
        std.debug.assert(alignment.toByteUnits() <= std.heap.pageSize());

        const file_aligned_size = alignedFileSize(requested_size);
        const aligned_mmap_size = alignedMmapSize(file_aligned_size, self.mmap_ratio);

        const file_index = self.count.fetchAdd(1, .monotonic);
        const file_name_bounded = fileNameBounded(file_index);
        const file_name = file_name_bounded.constSlice();

        const file = self.dir.createFile(file_name, .{
            .read = true,
            .truncate = true,
        }) catch |err| {
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

        std.debug.assert(requested_size <= file_aligned_size - @sizeOf(Metadata)); // sanity check
        const metadata_start = file_aligned_size - @sizeOf(Metadata);
        std.mem.bytesAsValue(Metadata, full_alloc[metadata_start..][0..@sizeOf(Metadata)]).* = .{
            .file_index = file_index,
            .mmap_size = aligned_mmap_size,
        };
        return full_alloc.ptr;
    }

    /// Resizes the allocation within the bounds of the mmap'd address space if possible.
    fn resize(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        requested_size: usize,
        return_address: usize,
    ) bool {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);

        // the allocator interface shouldn't allow this (aside from the *Raw methods).
        std.debug.assert(alignment.toByteUnits() <= std.heap.pageSize());

        const old_file_aligned_size = alignedFileSize(buf.len);
        const new_file_aligned_size = alignedFileSize(requested_size);

        if (new_file_aligned_size == old_file_aligned_size) {
            return true;
        }

        const buf_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(buf.ptr);
        const old_metadata_start = old_file_aligned_size - @sizeOf(Metadata);
        const metadata: Metadata = @bitCast(blk: {
            // you might think this block can be replaced with:
            //      buf_ptr[old_metadata_start..][0..@sizeOf(Metadata)].*
            // but no, that causes bus errors. it's not the same!
            var metadata_bytes: [@sizeOf(Metadata)]u8 = undefined;
            @memcpy(&metadata_bytes, buf_ptr[old_metadata_start..][0..@sizeOf(Metadata)]);
            break :blk metadata_bytes;
        });

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

        std.debug.assert(requested_size <= new_file_aligned_size - @sizeOf(Metadata));
        const new_metadata_start = new_file_aligned_size - @sizeOf(Metadata);
        std.mem.bytesAsValue(
            Metadata,
            buf_ptr[new_metadata_start..][0..@sizeOf(Metadata)],
        ).* = metadata;

        return true;
    }

    fn remap(
        context: *anyopaque,
        memory: []u8,
        alignment: Alignment,
        new_len: usize,
        return_address: usize,
    ) ?[*]u8 {
        return if (resize(
            context,
            memory,
            alignment,
            new_len,
            return_address,
        )) memory.ptr else null;
    }

    /// unmaps the memory and deletes the associated file.
    fn free(
        ctx: *anyopaque,
        buf: []u8,
        alignment: Alignment,
        return_address: usize,
    ) void {
        _ = return_address;
        const self: *Self = @ptrCast(@alignCast(ctx));
        std.debug.assert(self.mmap_ratio != 0);
        std.debug.assert(buf.len != 0); // should be ensured by the allocator interface

        // the allocator interface shouldn't allow this (aside from the *Raw methods).
        std.debug.assert(alignment.toByteUnits() <= std.heap.pageSize());

        const file_aligned_size = alignedFileSize(buf.len);

        const buf_ptr: [*]align(std.heap.page_size_min) u8 = @alignCast(buf.ptr);
        const metadata_start = file_aligned_size - @sizeOf(Metadata);
        const metadata: Metadata = @bitCast(buf_ptr[metadata_start..][0..@sizeOf(Metadata)].*);

        const file_name_bounded = fileNameBounded(metadata.file_index);
        const file_name = file_name_bounded.constSlice();

        std.posix.munmap(buf_ptr[0..metadata.mmap_size]);
        self.dir.deleteFile(file_name) catch |err| {
            self.logFailure(err, file_name);
        };
    }

    fn logFailure(self: Self, err: anyerror, file_name: []const u8) void {
        self.logger.err().logf("Disk Memory Allocator error: {s}, filepath: {s}", .{
            @errorName(err), sig.utils.fmt.tryRealPath(self.dir, file_name),
        });
    }

    const FileNameFmtSpec = sig.utils.fmt.BoundedSpec("bin_{d}");
    inline fn fileNameBounded(file_index: u32) FileNameFmtSpec.BoundedArray(struct { u32 }) {
        return FileNameFmtSpec.fmt(.{file_index});
    }
};

pub fn createAndMmapFile(
    dir: std.fs.Dir,
    file_name: []const u8,
    n: u64,
) ![]align(std.heap.page_size_min) u8 {
    const file = try dir.createFile(file_name, .{ .read = true, .truncate = true });
    defer file.close();

    try file.setEndPos(n);

    const memory = std.posix.mmap(
        null,
        n,
        std.posix.PROT.READ | std.posix.PROT.WRITE,
        .{ .TYPE = .SHARED },
        file.handle,
        0,
    );

    return memory;
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

test "recycle buffer: freeUnused" {
    const backing_allocator = std.testing.allocator;
    const X = struct {
        a: u8,
        pub const DEFAULT: @This() = .{ .a = 0 };
    };

    var allocator = RecycleBuffer(X, X.DEFAULT, .{
        .min_split_size = 10,
    }).init(.{
        .records_allocator = backing_allocator,
        .memory_allocator = backing_allocator,
    });
    defer allocator.deinit();

    // append some memory
    try allocator.expandCapacity(100);

    // alloc a slice of 100 bytes
    const bytes = try allocator.alloc(100);
    defer allocator.free(bytes.ptr);

    // free the unused space
    const did_recycle = allocator.tryRecycleUnusedSpace(bytes.ptr, 50);
    try std.testing.expectEqual(true, did_recycle);

    // this should be ok now
    const bytes2 = try allocator.alloc(50);
    defer allocator.free(bytes2.ptr);

    const expected_ptr: [*]X = @alignCast(@ptrCast(&bytes[50]));
    try std.testing.expectEqual(expected_ptr, bytes2.ptr);
}

test "recycle allocator: tryCollapse" {
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

    allocator.tryCollapse();
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
    if (true) return error.SkipZigTest;

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

    {
        try std.testing.expectError(
            error.FileNotFound,
            tmp_dir.access("bin_0", .{}),
        ); // this should not exist

        var disk_account_refs = try std.ArrayList(u8).initCapacity(dma, 1);
        defer disk_account_refs.deinit();

        disk_account_refs.appendAssumeCapacity(19);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);

        try disk_account_refs.append(21);

        try std.testing.expectEqual(19, disk_account_refs.items[0]);
        try std.testing.expectEqual(21, disk_account_refs.items[1]);

        try tmp_dir.access("bin_0", .{}); // this should exist
        try std.testing.expectError(
            error.FileNotFound,
            tmp_dir.access("bin_1", .{}),
        ); // this should not exist

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

    var page1 = try dma.alloc(u8, std.heap.pageSize());
    defer dma.free(page1);

    page1 = try dma.realloc(page1, std.heap.pageSize() * 15);

    page1[page1.len - 1] = 10;
}

test "fuzzDiskMemoryAllocator - past failures" {
    const test_cases = [_]struct { usize, u16, usize }{
        .{ 18813, 8, 2 },
        .{ 40309, 8, 2 },
        .{ 41790, 8, 2 },
        .{ 47097, 8, 2 },
        .{ 2952, 8, 10 },
        .{ 6143, 8, 10 },
        .{ 10455, 8, 10 },
        .{ 10887, 8, 10 },
        .{ 11639, 8, 10 },
        .{ 79, 8, 100 },
        .{ 13, 8, 1000 },
        // .{ 0, 8, 10_000 }, // slow
    };
    const debug = false;
    for (test_cases) |case| {
        const seed, const mmap_ratio, const iterations = case;
        var rng = std.Random.DefaultPrng.init(seed);
        if (debug) std.debug.print(
            "\n>>> Test Case: {}, {}, {}\n",
            .{ seed, mmap_ratio, iterations },
        );
        try fuzzDiskMemoryAllocator(.{
            .allocator = std.testing.allocator,
            .random = rng.random(),
            .iterations = iterations,
            .debug = debug,
        }, mmap_ratio);
    }
}

test "fuzzBatchAllocator - past failures" {
    const test_cases = [_]struct { usize, usize, usize }{
        .{ 0, 10, 32457527 },
        .{ 13, 10, 1315344 },
        .{ 44, 10, 122063 },
        .{ 200, 10, 1439666 },
        .{ 1139, 3, 240 },
        .{ 144, 10, 293 },
        .{ 12, 10000, 1067751 },
        .{ 1, 5, 1433431 },
    };
    const debug = false;
    for (test_cases) |case| {
        const seed, const iterations, const batch_size = case;
        var rng = std.Random.DefaultPrng.init(seed);
        if (debug) std.debug.print(
            "\n>>> Test Case: {}, {}, {}\n",
            .{ seed, iterations, batch_size },
        );
        try fuzzBatchAllocator(.{
            .allocator = std.testing.allocator,
            .random = rng.random(),
            .iterations = iterations,
            .debug = debug,
        }, batch_size);
    }
}

/// args "[allocator] [max_actions]"
pub fn runFuzzer(seed: u64, args: []const []const u8) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;

    // parse args
    const Fuzzable = enum { all, disk, batch };
    var to_fuzz: Fuzzable = .all;
    var max_actions: usize = std.math.maxInt(usize);
    if (args.len > 0) {
        const next_arg = args[0];
        if (std.meta.stringToEnum(Fuzzable, next_arg)) |fuzzable| {
            to_fuzz = fuzzable;
            if (args.len > 1) {
                const max_actions_str = args[1];
                max_actions = try std.fmt.parseInt(usize, max_actions_str, 10);
            }
        } else {
            max_actions = try std.fmt.parseInt(usize, next_arg, 10);
        }
    }

    const debug = false;
    const iterations = 10_000;
    for (0..max_actions / iterations) |i| {
        var rng = std.Random.DefaultPrng.init(seed +% i);
        const random = rng.random();
        const config: AllocatorFuzzParams = .{
            .allocator = gpa.allocator(),
            .random = random,
            .iterations = iterations,
            .debug = debug,
        };

        if (to_fuzz == .all or to_fuzz == .disk) {
            const mmap_ratio: u16 = randomLog2(random, u16, 16);
            std.debug.print(
                "DiskMemoryAllocator | seed: {}, iterations: {}, mmap_ratio: {}\n",
                .{ seed +% i, iterations, mmap_ratio },
            );
            try fuzzDiskMemoryAllocator(config, mmap_ratio);
        }

        if (to_fuzz == .all or to_fuzz == .batch) {
            const batch_size: usize = randomLog2(random, usize, 30);
            std.debug.print(
                "BatchAllocator      | seed: {}, iterations: {}, batch_size: {}\n",
                .{ seed +% i, iterations, batch_size },
            );
            try fuzzBatchAllocator(config, batch_size);
        }
    }
    if (gpa.deinit() == .leak) return error.Leaked;
}

fn fuzzDiskMemoryAllocator(config: AllocatorFuzzParams, mmap_ratio: u16) !void {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    var disk_memory_allocator = DiskMemoryAllocator{
        .dir = dir.dir,
        .logger = .noop,
        .mmap_ratio = mmap_ratio,
    };
    try fuzzAllocator(config, disk_memory_allocator.allocator());
}

fn fuzzBatchAllocator(config: AllocatorFuzzParams, batch_size: usize) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    {
        var batch_allocator = BatchAllocator{
            .backing_allocator = gpa.allocator(),
            .batch_size = batch_size,
        };
        defer batch_allocator.deinit();
        if (config.debug) {
            std.debug.print(
                \\var batch_allocator = BatchAllocator{{
                \\    .backing_allocator = std.testing.allocator,
                \\    .batch_size = {},
                \\}};
                \\defer batch_allocator.deinit();
                \\const allocator = batch_allocator.allocator();
                \\
            , .{batch_size});
        }
        try fuzzAllocatorMultiThreaded(1, config, batch_allocator.allocator());
        // try fuzzAllocator(config, batch_allocator.allocator());
    }
    if (gpa.detectLeaks()) return error.Leaked;
}

const AllocatorFuzzParams = struct {
    /// Used for bookkeeping during the test. This allocator will *not* be fuzzed.
    allocator: Allocator,
    /// Determines which actions to take, and how much to allocate.
    random: std.Random,
    /// Number of actions to take.
    iterations: usize,
    /// Set true to print code that runs this specific test case.
    debug: bool,
};

/// Randomly takes actions with the allocator: alloc, realloc, or free
fn fuzzAllocatorMultiThreaded(
    comptime num_threads: usize,
    params: AllocatorFuzzParams,
    /// The allocator being tested.
    subject: Allocator,
) !void {
    var threads: [num_threads - 1]std.Thread = undefined;
    for (0..num_threads - 1) |i| {
        threads[i] = try std.Thread.spawn(.{}, fuzzAllocator, .{ params, subject });
    }
    try fuzzAllocator(params, subject);
    for (threads) |t| t.join();
}

/// Randomly takes actions with the allocator: alloc, realloc, or free
fn fuzzAllocator(
    params: AllocatorFuzzParams,
    /// The allocator being tested.
    subject: Allocator,
) Allocator.Error!void {
    // all existing allocations from the allocator
    var allocations = std.ArrayList(struct { usize, []u8 }).init(params.allocator);
    defer {
        for (allocations.items) |pair| {
            const item_id, const item = pair;
            if (params.debug) std.debug.print("allocator.free(item{});\n", .{item_id});
            subject.free(item);
        }
        allocations.deinit();
        if (params.debug) std.debug.print("done\n", .{});
    }

    // take some random actions: alloc, realloc, or free
    var item_id_sequence: usize = 0;
    for (0..params.iterations) |_| {
        const Options = enum { alloc, realloc, free };
        const choice = if (allocations.items.len == 0)
            .alloc
        else
            params.random.enumValue(Options);
        switch (choice) {
            .alloc => {
                const size = randomLog2(params.random, usize, 20);
                if (params.debug) std.debug.print(
                    "var item{} = try allocator.alloc(u8, {});\n",
                    .{ item_id_sequence, size },
                );
                const data = try subject.alloc(u8, size);
                errdefer subject.free(data);
                @memset(data, 0x22);
                try allocations.append(.{ item_id_sequence, data });
                item_id_sequence += 1;
            },
            .realloc => {
                const index = params.random.intRangeLessThan(usize, 0, allocations.items.len);
                const size = randomLog2(params.random, usize, 20);
                const item_id, const item = allocations.items[index];
                if (params.debug) std.debug.print(
                    "item{} = try allocator.realloc(item{}, {});\n",
                    .{ item_id, item_id, size },
                );
                const new_data = try subject.realloc(item, size);
                @memset(new_data, 0x33);
                allocations.items[index] = .{ item_id, new_data };
            },
            .free => {
                const index = params.random.intRangeLessThan(usize, 0, allocations.items.len);
                const item_id, const data = allocations.swapRemove(index);
                if (params.debug) std.debug.print("allocator.free(item{});\n", .{item_id});
                subject.free(data);
            },
        }
    }
}

fn randomLog2(random: std.Random, T: type, max_pow2: u64) T {
    return @intFromFloat(std.math.pow(
        f64,
        2,
        @as(f64, @floatFromInt(max_pow2)) * random.float(f64),
    ));
}

/// An allocator that transparently limits the amount of bytes allocated with the backing_allocator.
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

test "LimitAllocator" {
    var buffer: [1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);

    const limit = 512;
    var limit_alloc = LimitAllocator.init(fba.allocator(), limit);

    // alloc normal
    const slice = try limit_alloc.allocator().alloc(u8, 12);
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 12);
    try std.testing.expectEqual(fba.end_index, 12);

    // alloc (over)
    try std.testing.expectError(error.OutOfMemory, limit_alloc.allocator().alloc(u8, limit + 1));
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 12);
    try std.testing.expectEqual(fba.end_index, 12);

    // remap shrink
    var new_slice = limit_alloc.allocator().remap(slice, 8).?;
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 8);
    try std.testing.expectEqual(fba.end_index, 8);

    // remap grow
    new_slice = limit_alloc.allocator().remap(new_slice, 100).?;
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 100);
    try std.testing.expectEqual(fba.end_index, 100);

    // remap grow (over)
    try std.testing.expectEqual(null, limit_alloc.allocator().remap(new_slice, limit + 1));
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 100);
    try std.testing.expectEqual(fba.end_index, 100);

    // resize shrink
    try std.testing.expect(limit_alloc.allocator().resize(new_slice, 12));
    new_slice.len = 12;
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 12);
    try std.testing.expectEqual(fba.end_index, 12);

    // resize grow
    try std.testing.expect(limit_alloc.allocator().resize(new_slice, 100));
    new_slice.len = 100;
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 100);
    try std.testing.expectEqual(fba.end_index, 100);

    // resize grow (over)
    try std.testing.expectEqual(false, limit_alloc.allocator().resize(new_slice, limit + 1));
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit - 100);
    try std.testing.expectEqual(fba.end_index, 100);

    // free
    limit_alloc.allocator().free(new_slice);
    try std.testing.expectEqual(limit_alloc.bytes_remaining, limit);
    try std.testing.expectEqual(fba.end_index, 0);
}
