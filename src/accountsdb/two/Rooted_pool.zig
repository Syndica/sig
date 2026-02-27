//! Database for rooted accounts.
const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");
const tracy = @import("tracy");
const Rooted = @This();

const posix = std.posix;
const RwLock = std.Thread.RwLock;

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

const AccountSharedData = sig.runtime.AccountSharedData;
const AccountFile = sig.accounts_db.accounts_file.AccountFile;

/// Handle to the underlying database.
db: Db,
/// Synchronization for the Db
rwlock: RwLock,
/// Tracks the largest rooted slot.
largest_rooted_slot: ?Slot,

pub fn init(file_path: [:0]const u8) !Rooted {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.init" });
    defer zone.deinit();

    const db = try Db.open(file_path);
    errdefer db.close();

    return .{
        .db = db,
        .rwlock = .{},
        .largest_rooted_slot = null,
    };
}

pub fn initSnapshot(
    allocator: std.mem.Allocator,
    file_path: [:0]const u8,
    /// Set to directory which contains snapshot account files to pre-load the rooted storage from them.
    accounts_dir: std.fs.Dir,
) !Rooted {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.initSnapshot" });
    defer zone.deinit();

    var self: Rooted = try .init(file_path);
    errdefer self.deinit();

    if (self.db.e44) {
        std.debug.print("db has entries, skipping load from snapshot\n", .{});
    } else {
        std.debug.print("db is empty -  loading from snapshot!\n", .{});
        try self.insertFromSnapshot(allocator, accounts_dir);
    }

    return self;
}

pub fn deinit(self: *Rooted) void {
    // sanity check
    std.debug.assert(self.rwlock.tryLock());
    self.rwlock.unlock();

    self.db.close();
}

fn insertFromSnapshot(
    self: *Rooted,
    allocator: std.mem.Allocator,
    accounts_dir: std.fs.Dir,
) !void {
    const insert_zone = tracy.Zone.init(@src(), .{ .name = "Rooted.insertFromSnapshot" });
    defer insert_zone.deinit();

    var bp = try sig.accounts_db.buffer_pool.BufferPool.init(allocator, 20480 + 2);
    defer bp.deinit(allocator);

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    self.beginTransaction();
    defer self.commitTransaction();

    const AccountFileRef = struct{ slot: u64, id: u32 };
    var account_file_refs: std.ArrayListUnmanaged(AccountFileRef) = .{};
    try account_file_refs.ensureTotalCapacity(arena.allocator(), (try accounts_dir.stat()).size);
    defer account_file_refs.deinit(arena.allocator());

    var accounts_iter = accounts_dir.iterate();
    while (try accounts_iter.next()) |entry| {
        if (entry.kind != .file) return error.BadAccountsDir;

        const split = std.mem.indexOf(u8, entry.name, ".") orelse return error.BadAccountsDir;
        if (entry.name.len - 1 == split) return error.BadAccountsDir;

        const slot = try std.fmt.parseInt(u64, entry.name[0..split], 10);
        const id = try std.fmt.parseInt(u32, entry.name[split + 1 ..], 10);
        try account_file_refs.append(arena.allocator(), .{ .slot = slot, .id = id });
    }

    std.mem.sort(AccountFileRef, account_file_refs.items, {}, struct {
        fn lessThan(_: void, a: AccountFileRef, b: AccountFileRef) bool {
            return a.slot < b.slot;
        }
    }.lessThan);

    const progress = std.Progress.start(.{});
    defer progress.end();

    var progress_node = progress.start("loading account files", account_file_refs.items.len);
    defer progress_node.end();

    var sub_arena = std.heap.ArenaAllocator.init(arena.allocator());
    defer sub_arena.deinit();

    for (account_file_refs.items) |entry| {
        defer {
            progress_node.completeOne();
            _ = sub_arena.reset(.retain_capacity);
        }

        const slot, const id = entry;
        var entry_path_buffer: [std.fs.max_path_bytes]u8 = undefined;
        const entry_path = try std.fmt.bufPrint(&entry_path_buffer, "{d}.{d}", .{ slot, id });

        const file = try accounts_dir.openFile(entry_path, .{});
        defer file.close();

        // TODO: assuming length is the file length is technically not correct
        const accounts_file = try AccountFile.init(
            file,
            .{ .id = .fromInt(id), .length = (try file.stat()).size },
            slot,
        );

        const file_zone = tracy.Zone.init(
            @src(),
            .{ .name = "Rooted.insertFromSnapshot: accounts files" },
        );
        defer file_zone.deinit();

        var n_accounts_in_file: u48 = 0;
        defer file_zone.value(n_accounts_in_file);

        var accounts = accounts_file.iterator(&bp);
        while (try accounts.next(sub_arena.allocator())) |account| {
            defer account.deinit(sub_arena.allocator());
            n_accounts_in_file += 1;

            const data = try account.data.readAllAllocate(sub_arena.allocator());
            defer sub_arena.allocator().free(data);

            try self.db.put(
                account.store_info.pubkey,
                accounts_file.slot,
                .{
                    .owner = account.account_info.owner,
                    .lamports = account.account_info.lamports,
                    .rent_epoch = account.account_info.rent_epoch,
                    .executable = account.account_info.executable,
                    .data = data,
                },
            );
        }
    }    
}

/// For API compatibility.
pub fn deinitThreadLocals() void {}

/// Returns `null` if no such account exists.
///
/// The `data` field in the returned `AccountSharedData` is owned by the caller and is allocated
/// by the provided allocator.
///
/// TODO: we really don't want to be doing these clones, so some other solution would be good.
pub fn get(
    self: *Rooted,
    allocator: std.mem.Allocator,
    address: Pubkey,
) error{OutOfMemory}!?AccountSharedData {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.get" });
    defer zone.deinit();

    self.rwlock.lockShared();
    defer self.rwlock.unlockShared();

    return self.db.get(allocator, address);
}

/// For API compatibility.
pub fn getLargestRootedSlot(self: *const Rooted) ?Slot {
    if (!builtin.is_test) @compileError("only used in tests");
    return self.largest_rooted_slot;
}

pub fn beginTransaction(self: *Rooted) void {
    self.rwlock.lock();
}

pub fn commitTransaction(self: *Rooted) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.commitTransaction" });
    defer zone.deinit();

    self.db.commit() catch |err| std.debug.panic("db.commit() failed: {}", .{err});
    self.rwlock.unlock();
}

/// Should not be called outside of snapshot loading or slot rooting.
/// TODO: write putRootedSlot(slot, []pk, []account) and make that public instead.
pub fn put(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.put" });
    defer zone.deinit();

    self.db.put(address, slot, account) catch |err| {
        std.debug.panic("db.put() failed: {}", .{err});
    };
}

/// An on-disk KV database simulating a HashMap(Pubkey, { Slot, AccountSharedData }).
/// Backed by a B- Tree implementation from: https://en.algorithmica.org/hpc/data-structures/b-tree/
const Db = struct {
    file: posix.fd_t,
    size: u64,
    mapped: *align(std.heap.page_size_min) [max_memory_size]u8,

    const max_memory_size = 32 * 1024 * 1024 * 1024;
    const min_file_growth = 4 * 1024 * 1024;
    const max_dirty_queue = 4 * 1024;
    const page_size = 64 * 1024;

    pub fn open(file_path: [:0]const u8) !Db {
        const file = try std.fs.cwd().createFileZ(file_path, .{ .read = true, .lock = .exclusive });
        errdefer file.close();

        var size = (try file.stat()).size;
        if (size < min_file_growth) {
            size = std.mem.alignForward(u64, min_file_growth, page_size);
            try posix.ftruncate(file.handle, size);
        }

        const mapped = try posix.mmap(
            null,
            max_memory_size,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        errdefer posix.munmap(mapped);

        

        return .{
            .file = file.handle,
            .size = size,
            .mapped = mapped,
        };
    }

    pub fn close(self: *Db) void {
        self.commit() catch |e| std.debug.panic("db.commit() failed: {}", .{e});
        posix.munmap(self.mapped);
        posix.close(self.file);
    }

    pub fn commit(self: *Db) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.commit" });
        defer zone.deinit();
    }

    pub fn get(self: *const Db, allocator: std.mem.Allocator, pubkey: Pubkey) !?AccountSharedData {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.get" });
        defer zone.deinit();

        
    }

    pub fn put(self: *Db, pubkey: Pubkey, slot: Slot, new_account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.put" });
        defer zone.deinit();

        
    }

    const Header = extern struct {
        pool: Pool,
        comptime { std.debug.assert(@sizeOf(Header) <= page_size); }
    };

    const Memory = extern struct {
        header: Header,
        cache: PageCache,
    };

    fn getMemory(self: *const Db) *Memory {
        return @ptrCast(self.mapped);
    }

    fn getPageArray(self: *const Db) *[@divExact(max_memory_size, page_size)][page_size]u8 {
        return @ptrCast(self.mapped);
    }
    
    const DiskOffset = u64;
    const Pool = extern struct {
        allocated_pages: u32,
        free_lists: [size_classes.len]DiskOffset,
        bump_pages: [for (size_classes, 0..) |size, i| {
            if (size >= page_size) break i; 
        } else unreachable]DiskOffset,
    };

    const size_classes = [_]u32{
        64,              256,             512,
        1024,            4 * 1024,        8 * 1024,
        16 * 1024,       64 * 1024,       1024 * 1024,
        2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
        10 * 1024 * 1024, // Account with 10 MB data
    };

    fn getSizeClassIndex(num_bytes: u32) ?u8 {
        comptime var bits_to_idx: [32 + 1]u8 = @splat(size_classes.len);
        inline for (1..32) |bits| {
            bits_to_idx[bits] = @intCast(for (size_classes, 0..) |size, idx| {
                if (size >= (1 << bits) - 1) break idx;
            } else size_classes.len);
        }

        std.debug.assert(num_bytes > 0);
        const sc_idx = bits_to_idx[32 - @clz(num_bytes)];
        return if (sc_idx < size_classes.len) sc_idx else null;
    }

    fn allocDisk(self: *Db, num_bytes: u32) !DiskOffset {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.alloc" });
        defer zone.deinit();

        if (num_bytes == 0) return 0;
        const sc_idx = getSizeClassIndex(num_bytes) orelse return error.InvalidDiskAlloc;
        const pool = &self.getMemory().header.pool;

        // Check free list first.
        const free_list = &pool.free_lists[sc_idx];
        const free_offset = free_list.*;
        if (free_offset > 0) {
            std.debug.assert(free_offset < @as(u64, pool.allocated_pages) * page_size);

            // Read next_offset from disk & update free_list top to it.
            var next_offset: u64 = undefined;
            if (try getCachedSlice(self, .data, .read_only, free_offset, @sizeOf(u64))) |slice| {
                next_offset = @bitCast(slice[0..@sizeOf(DiskOffset)].*);
            } else {
                try readFromDisk(self.file, free_offset, std.mem.asByteS(&next_offset));
            }
            if (next_offset > 0) {
                std.debug.assert(next_offset < @as(u64, pool.allocated_pages) * page_size);
            }
            free_list.* = next_offset;
            return free_offset;
        }

        // For allocs < a page, bump alloc from their size-class-page
        const alloc_size = size_classes[sc_idx];
        if (alloc_size < page_size) {
            const bump_offset = &pool.bump_pages[sc_idx];
            if (bump_offset.* % page_size == 0) {
                bump_offset.* = try self.allocDiskPages(1);
            }
            const new_offset = bump_offset.*;
            std.debug.assert(new_offset > 0);
            std.debug.assert(new_offset < @as(u64, pool.allocated_pages) * page_size);
            bump_offset.* += alloc_size;
            return new_offset;
        }

        // For allocs >= page, alloc pages directly
        const num_pages: u32 = @intCast(@divExact(alloc_size, page_size));
        return self.allocDiskPages(num_pages);
    }

    fn allocDiskPages(self: *Db, num_pages: u32) !DiskOffset {
        const pool = &self.getMemory().header.pool;
        std.debug.assert(num_pages > 0);

        const new_offset = @as(u64, pool.allocated_pages) * page_size;
        std.debug.assert(new_offset > 0);
        std.debug.assert(new_offset % page_size == 0);
        pool.allocated_pages += num_pages;

        const new_size = @as(u64, pool.allocated_pages) * page_size;
        if (new_size > self.size) {
            const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.extend" });
            defer zone.deinit();

            self.size = @max(new_size, self.size + min_file_growth);
            try posix.ftruncate(self.file, self.size);
        }

        return new_offset;
    }

    fn freeDisk(self: *Db, offset: DiskOffset, num_bytes: u32) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.free" });
        defer zone.deinit();

        if (num_bytes == 0) return 0;
        const sc_idx = getSizeClassIndex(num_bytes) orelse return error.InvalidDiskAlloc;

        const pool = &self.getMemory().header.pool;
        std.debug.assert(offset > 0);
        std.debug.assert(offset < @as(u64, pool.allocated_pages) * page_size);
        std.debug.assert(size_classes[sc_idx] >= @sizeOf(u64));

        const free_list: *DiskOffset = &pool.free_lists[sc_idx];
        if (free_list.* > 0) {
            std.debug.assert(free_list.* < @as(u64, pool.allocated_pages) * page_size);
        }

        if (try getCachedSlice(self, .data, .write_only, offset, @sizeOf(u64))) |slice| {
            slice[0..@sizeOf(u64)].* = @bitCast(free_list.*);
            try self.markWritten(.data, offset);
        } else {
            try writeToDisk(self.file, offset, std.mem.asBytes(free_list));
        }

        free_list.* = offset;
    }

    // --

    fn getCachedSlice(
        self: anytype,
        comptime kind: DiskPage.Kind,
        comptime access: DiskPage.Access,
        offset: DiskOffset,
        num_bytes: u32,
    ) !?[]u8 {
        const pool: *Pool = &self.getMemory().header.pool;
        std.debug.assert(offset > 0);
        std.debug.assert(offset < @as(u64, pool.allocated_pages) * page_size);

        const page_offset = std.mem.alignBackward(DiskOffset, offset, page_size);
        std.debug.assert(offset + num_bytes <= page_offset + page_size);
        std.debug.assert(page_offset > 0);

        // TODO: check in dirty-map

        if (try queryPageEntry(self, .{
            .index = @intCast(@divExact(page_offset, page_size)),
            .kind = kind,
        })) |e| {
            std.debug.assert(e.state != .writing);
            const page = &self.getPageArray()[e.index];
            if (access != .write_only and e.state == .empty) {
                try readFromDisk(self.file, page_offset, page);
                e.state = .populated;
            }
            if (access != .read_only) {
                std.debug.assert(e.state == .populated or e.state == .dirty);
                e.state = .writing;
            }
            return page[offset - page_offset..][0..num_bytes];
        }
        
        return null;
    }

    fn markWritten(self: *Db, comptime kind: DiskPage.Kind, offset: DiskOffset) !void {
        const pool: *Pool = &self.getMemory().header.pool;
        std.debug.assert(offset > 0);
        std.debug.assert(offset < @as(u64, pool.allocated_pages) * page_size);

        const page_offset = std.mem.alignBackward(DiskOffset, offset, page_size);
        const e = (queryPageEntry(@as(*const Db, self), .{
            .index = @intCast(@divExact(page_offset, page_size)),
            .kind = kind,
        }) catch unreachable) orelse {
            std.debug.panic("markWritten({s}, {x}) not found", .{@tagName(kind), offset});
        };
        std.debug.assert(e.state == .writing);
        e.state = .dirty;
    }

    const PageCache = extern struct {
        allocated_pages: u32 = @divExact(
            std.mem.alignForward(u64, @sizeOf(Memory), page_size),
            page_size,
        ),
        dirty_map: [max_dirty_queue * 2]DirtyEntry,
        entries: [@divExact(max_memory_size, page_size)]PageEntry = @splat(.{}),
    };
    const DirtyEntry = packed struct(u32) {
        index: u31,
        into: enum(u1) { page_array, page_cache },
    };
    const PageEntry = packed struct(u64) {
        disk_page: DiskPage = .{ .index = 0, .kind = .data },
        state: enum(u2){ empty, populated, writing, dirty },
        index: u30 = 0,
    };
    const DiskPage = packed struct(u32) {
        index: u31,
        kind: Kind,
        const Access = enum{ read_only, read_write, write_only };
        const Kind = enum(u1) { data = 0, index = 1 };
    };

    fn queryPageEntry(self: anytype, disk_page: DiskPage) !?*PageEntry {
        const pool = &self.getMemory().header.pool;
        std.debug.assert(disk_page.index > 0);
        std.debug.assert(disk_page.index < pool.allocated_pages);

        const cache: *PageCache = &self.getMemory().cache;
        comptime std.debug.assert(std.math.isPowerOfTwo(cache.slots.len));
        const shift: u6 = comptime @intCast(@as(u32, 64) - @ctz(cache.slots.len));

        const h1 = (@as(u64, 0x9e3779b97f4a7c15) * @as(u32, @bitCast(disk_page))) >> shift;
        const h2 = (@as(u64, 0xf1357aea2e62a9c5) * @as(u32, @bitCast(disk_page))) >> shift;
        const e1 = &cache.entries[h1];
        const e2 = &cache.entries[h2];
        
        // Check for cache hit.
        var maybe_e: ?*PageEntry = null;
        if (@as(u32, @bitCast(e1.disk_page)) == @as(u32, @bitCast(disk_page))) maybe_e = e1;
        if (@as(u32, @bitCast(e2.disk_page)) == @as(u32, @bitCast(disk_page))) maybe_e = e2;
        if (maybe_e) |e| return e;

        if (@TypeOf(self) == *Db) insert: {
            // Check for empty entries to insert into.
            const kind = @intFromEnum(disk_page.kind);
            if (@as(u32, @bitCast(e1.disk_page)) == 0) maybe_e = e1;
            if (@as(u32, @bitCast(e2.disk_page)) == 0) maybe_e = e2;

            const evicted = if (maybe_e) |e| blk: {
                // Reserve new cache page
                if (cache.allocated_pages < cache.entries.len) {
                    e.* = .{
                        .disk_page = disk_page,
                        .state = .empty,
                        .index = @intCast(cache.allocated_pages),
                    };
                    cache.allocated_pages += 1;
                    return e;
                }

                // Ran out of cache pages. Try to evict the other entry.
                const other = if (e == e1) e2 else e1;
                break :blk if (
                    @as(u32, @bitCast(other.disk_page)) != 0 and
                    other.state != .writing and
                    @intFromEnum(other.disk_page.kind) <= kind
                ) other else break :insert;
            } else blk: {
                // Try to evict both of the entries.
                if (e2.state != .writing and @intFromEnum(e2.disk_page.kind) <= kind) maybe_e = e2;
                if (e1.state != .writing and @intFromEnum(e1.disk_page.kind) <= kind) maybe_e = e1;
                break :blk maybe_e orelse break :insert;
            };

            // Overwrite an evicted entry.
            std.debug.assert(evicted.state != .writing);
            if (evicted.state == .dirty) {
                try self.pushDirtyPage(.{ .index = evicted.index, .to = .page_array });
            }
            evicted.* = .{
                .disk_page = disk_page,
                .index = evicted.index,
                .state = .empty,
            };
            return evicted;
        }

        // Cache miss
        return null;
    }

    fn pushDirtyPage(self: *Db, entry: DirtyEntry) !void {

    }

    // -- 

    fn writeToDisk(file: posix.fd_t, offset: u64, data: []const u8) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.pwrite" });
        defer zone.deinit();

        var n: u64 = 0;
        while (n < data.len) n += try posix.pwrite(file, data[n..], offset + n);
    }

    fn readFromDisk(file: posix.fd_t, offset: u64, data: []u8) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.pread" });
        defer zone.deinit();

        var n: u64 = 0;
        while (n < data.len) n += try posix.pread(file, data[n..], offset + n);
    }
};
