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

    if (self.db.count() > 0) {
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

    const progress = std.Progress.start(.{});
    defer progress.end();

    const num_accounts_entries = (try accounts_dir.stat()).size;
    var progress_node = progress.start("loading account files", num_accounts_entries);
    defer progress_node.end();

    self.beginTransaction();
    defer self.commitTransaction();

    var accounts_iter = accounts_dir.iterate();
    while (try accounts_iter.next()) |entry| {
        if (entry.kind != .file) return error.BadAccountsDir;
        defer progress_node.completeOne();

        const split = std.mem.indexOf(u8, entry.name, ".") orelse return error.BadAccountsDir;
        if (entry.name.len - 1 == split) return error.BadAccountsDir;
        const slot = try std.fmt.parseInt(u64, entry.name[0..split], 10);
        const id = try std.fmt.parseInt(u32, entry.name[split + 1 ..], 10);

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
        while (try accounts.next(arena.allocator())) |account| {
            defer account.deinit(arena.allocator());
            n_accounts_in_file += 1;

            const data = try account.data.readAllAllocate(arena.allocator());
            defer arena.allocator().free(data);

            self.db.put(
                account.store_info.pubkey,
                accounts_file.slot,
                .{
                    .owner = account.account_info.owner,
                    .lamports = account.account_info.lamports,
                    .rent_epoch = account.account_info.rent_epoch,
                    .executable = account.account_info.executable,
                    .data = data,
                },
            ) catch |err| switch (err) {
                error.InvalidSlot => {}, // simulate sorting by ignoring older slot puts
                else => |e| return e,
            };
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
    disk: Disk,
    header: Header,

    const Header = extern struct {
        pool: Pool,
        tree: BTree,
    };

    pub fn open(file_path: [:0]const u8) !Db {
        var disk = try Disk.open(file_path);
        errdefer disk.close();

        if (disk.getReadable().len < @sizeOf(Header)) {
            std.debug.print("disk is empty - initializing new db\n", .{});
            try disk.ensureTotalCapacity(@sizeOf(Header));
        }

        var header: Header = @bitCast(disk.getReadable()[0..@sizeOf(Header)].*);
        if (header.pool.allocated == 0) {
            std.debug.print("creating a new disk index\n", .{});
            header = std.mem.zeroes(Header);
            header.pool.allocated = Pool.size_classes[Pool.sizeClassIndex(@sizeOf(Header)).?];
        } else {
            std.debug.print("using existing disk index\n", .{});
        }

        return .{ .disk = disk, .header = header };
    }

    pub fn close(self: *Db) void {
        self.commit() catch |err| std.debug.panic("failed to commit DB: {}", .{err});
        self.disk.close();
    }

    pub fn count(self: *const Db) usize {
        return self.header.tree.size.count;
    }

    pub fn commit(self: *Db) !void {
        const header_slice = try self.disk.getMutPtr(0, @sizeOf(Header), @alignOf(Header));
        header_slice[0..@sizeOf(Header)].* = @bitCast(self.header);
        try self.disk.commitWrites();
    }

    const Account = extern struct {
        owner: Pubkey,
        lamports: u64,
        rent_epoch: Epoch,
        slot: Slot,
        data: packed struct (u32) {
            executable: bool,
            len: u31,
        },

        comptime {
            std.debug.assert(@sizeOf(Account) <= 64);
        }
    };

    pub fn get(self: *const Db, allocator: std.mem.Allocator, pubkey: Pubkey) !?AccountSharedData {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.get" });
        defer zone.deinit();

        const offset = self.header.tree.get(&self.disk, &pubkey) orelse return null; 
        const account: *const Account = @ptrCast(@alignCast(
            self.disk.getReadable()[offset..][0..@sizeOf(Account)],
        ));

        const read_zone = tracy.Zone.init(@src(), .{ .name = "Db.readAccount" });
        defer read_zone.deinit();

        const data = self.disk.getReadable()[offset + @sizeOf(Account)..][0..account.data.len];
        return .{
            .owner = account.owner,
            .lamports = account.lamports,
            .rent_epoch = account.rent_epoch,
            .executable = account.data.executable,
            .data = try allocator.dupe(u8, data),
        };
    }

    pub fn put(self: *Db, pubkey: Pubkey, slot: Slot, new_account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.put" });
        defer zone.deinit();

        const offset_ptr = try self.header.tree.put(&self.disk, &self.header.pool, &pubkey);
        const new_size: u32 = @intCast(@sizeOf(Account) + new_account.data.len);

        var offset = offset_ptr.*;
        if (offset > 0) {
            const account: *const Account = @ptrCast(@alignCast(
                self.disk.getConstPtr(offset, @sizeOf(Account))[0..@sizeOf(Account)],
            ));

            if (account.slot > slot) {
                return error.InvalidSlot;
            }
            
            const old_size: u32 = @intCast(@sizeOf(Account) + account.data.len);
            if (Pool.sizeClassIndex(old_size) != Pool.sizeClassIndex(new_size)) {
                try self.header.pool.free(&self.disk, offset, old_size);
                offset = 0;
            }
        }

        if (offset == 0) {
            offset = try self.header.pool.alloc(&self.disk, new_size);
            offset_ptr.* = offset;
        }

        const write_zone = tracy.Zone.init(@src(), .{ .name = "Db.writeAccount" });
        defer write_zone.deinit();

        const new_slice = try self.disk.getMutPtr(offset, new_size, @alignOf(Account));
        new_slice[0..@sizeOf(Account)].* = @bitCast(Account{
            .owner = new_account.owner,
            .lamports = new_account.lamports,
            .rent_epoch = new_account.rent_epoch,
            .slot = slot,
            .data = .{
                .executable = new_account.executable,
                .len = @intCast(new_account.data.len),
            },
        });
        @memcpy(new_slice[@sizeOf(Account)..][0..new_account.data.len], new_account.data);
    }
};

const BTree = extern struct {
    root: Disk.Offset,
    size: packed struct(u64) {
        height: u4,
        count: u60,
    },
    node_cache: extern struct {
        ptr: Disk.Offset,
        end: Disk.Offset,
    },

    const node_cache_size = Pool.size_classes[Pool.size_classes.len - 1];

    const Key = u64;
    const Value = Disk.Offset;

    const B = 32;
    const max_height = 10;
    const InnerNode = extern struct {
        keys: [B]Key,
        values: [B]Disk.Offset,
    };
    const LeafNode = extern struct {
        keys: [B]Key,
        values: [B]extern struct {
            pubkey: Pubkey,
            value: Value,
        },
    };

    fn countLessThan(keys: *const [B]Key, key: Key) u32 {
        const key_vec: @Vector(B, Key) = @splat(key);
        const keys_vec: @Vector(B, Key) = keys.*;
        const lt_mask: std.meta.Int(.unsigned, B) = @bitCast(keys_vec < key_vec);
        return @popCount(lt_mask);
    }

    fn get(self: *const BTree, disk: *const Disk, pubkey: *const Pubkey) ?Value {
        const zone = tracy.Zone.init(@src(), .{ .name = "BTree.get" });
        defer zone.deinit();

        var node = self.root;
        if (node == 0) return null;

        var key: Key = @truncate(pubkey.hash());
        key -= @intFromBool(key == std.math.maxInt(Key));

        for (0..self.size.height) |_| {
            const inner: *const InnerNode = @ptrCast(@alignCast(
                disk.getReadSlice(node, @sizeOf(InnerNode))[0..@sizeOf(InnerNode)],
            ));
            const idx = countLessThan(&inner.keys, key);
            node = inner.values[idx];
        }

        const leaf: *const LeafNode = @ptrCast(@alignCast(
            disk.getReadSlice(node, @sizeOf(LeafNode))[0..@sizeOf(LeafNode)],
        ));
        var idx = countLessThan(&leaf.keys, key);
        while (leaf.keys[idx] == key) : (idx += 1) {
            @branchHint(.likely);
            const value = &leaf.values[idx];
            if (value.pubkey.equals(pubkey)) {
                @branchHint(.likely);
                return value.value;
            }
        }
        return null;
    }

    fn insertAt(array: anytype, idx: u32, value: @TypeOf(array[0])) void {
        std.mem.copyBackwards(@TypeOf(array[0]), array[idx + 1 ..], array[idx .. B - 1]);
        array[idx] = value;
    }

    fn moveHalf(noalias old_node: anytype, noalias new_node: @TypeOf(old_node)) void {
        @memset(new_node.keys[B / 2 ..], std.math.maxInt(Key));
        @memcpy(new_node.keys[0 .. B / 2], old_node.keys[B / 2 ..]);
        @memset(old_node.keys[B / 2 ..], std.math.maxInt(Key));
        @memcpy(new_node.values[0 .. B / 2], old_node.values[B / 2 ..]);
    }

    fn allocNode(self: *BTree, disk: *Disk, pool: *Pool, comptime Node: type) !Disk.Offset {
        var new_offset = std.mem.alignForward(Disk.Offset, self.node_cache.ptr, @alignOf(Node));
        self.node_cache.ptr = new_offset + @sizeOf(Node);

        if (self.node_cache.ptr > self.node_cache.end) {
            @branchHint(.unlikely);
            
            new_offset = try pool.alloc(disk, node_cache_size);
            self.node_cache.end = new_offset + node_cache_size;

            new_offset = std.mem.alignForward(Disk.Offset, new_offset, @alignOf(Node));
            self.node_cache.ptr = new_offset + @sizeOf(Node);
            std.debug.assert(self.node_cache.ptr <= self.node_cache.end);
        }

        return new_offset;
    } 

    fn getNodeMut(disk: *Disk, offset: Disk.Offset, comptime Node: type) !*Node {
        const slice = try disk.getMutPtr(offset, @sizeOf(Node), @alignOf(Node));
        return @ptrCast(@alignCast(slice[0..@sizeOf(Node)]));
    }

    fn put(self: *BTree, disk: *Disk, pool: *Pool, pubkey: *const Pubkey) !*Value {
        const zone = tracy.Zone.init(@src(), .{ .name = "BTree.put" });
        defer zone.deinit();

        var key: Key = @truncate(pubkey.hash());
        key -= @intFromBool(key == std.math.maxInt(Key));

        var node = self.root;
        if (node == 0) {
            @branchHint(.unlikely);
            const new_root = try self.allocNode(disk, pool, LeafNode);
            const new_leaf = try getNodeMut(disk, new_root, LeafNode);
            @memset(&new_leaf.keys, std.math.maxInt(Key));
            new_leaf.keys[0] = key;
            new_leaf.values[0] = .{ .pubkey = pubkey.*, .value = std.mem.zeroes(Value) };
            return &new_leaf.values[0].value;
        }

        var path: [max_height]struct{ Disk.Offset, u32 } = undefined;
        for (0..self.size.height) |h| {
            const inner_ptr = disk.getConstPtr(node, @sizeOf(InnerNode))[0..@sizeOf(InnerNode)];
            const inner: *const InnerNode = @ptrCast(@alignCast(inner_ptr));
            const idx = countLessThan(&inner.keys, key);
            path[h] = .{ node, idx };
            node = inner.values[idx];
        }

        const leaf = try getNodeMut(disk, node, LeafNode);

        var idx = countLessThan(&leaf.keys, key);
        while (leaf.keys[idx] == key) : (idx += 1) {
            @branchHint(.likely);
            const value = &leaf.values[idx];
            if (value.pubkey.equals(pubkey)) {
                @branchHint(.likely);
                return &value.value;
            }
        }

        const insert_zone = tracy.Zone.init(@src(), .{ .name = "BTree.insert" });
        defer insert_zone.deinit();

        const max_entries = comptime std.math.pow(u64, B / 2, max_height);
        if (self.size.count == max_entries) return error.TooManyAccounts;
        self.size.count += 1;

        var value_ptr = &leaf.values[idx].value;
        var filled = leaf.keys[B - 2] != std.math.maxInt(Key);
        insertAt(&leaf.keys, idx, key);
        insertAt(&leaf.values, idx, .{ .pubkey = pubkey.*, .value = std.mem.zeroes(Value) });
        if (filled) split: {
            @branchHint(.unlikely);

            // The leaf was filled & needs to be split into a new one.
            var new_node = try self.allocNode(disk, pool, LeafNode);
            const new_leaf = try getNodeMut(disk, new_node, LeafNode);
            moveHalf(leaf, new_leaf);
            key = leaf.keys[B / 2 - 1];

            // Branchlessly reassign the value if it was moved to the new_leaf.
            const new_idx = idx -% (B / 2);
            const new_value_ptr = &new_leaf.values[0..].ptr[new_idx].value;
            if (new_idx < idx) value_ptr = new_value_ptr;

            // Ascend up the tree until we reach either the root or an non-full node
            var h = @as(u32, self.size.height) -% 1;
            while (h != std.math.maxInt(u32)) : (h -%= 1) {
                const p = path[h];
                node = p.@"0";
                idx = p.@"1";

                // Insert to inner node
                const inner = try getNodeMut(disk, node, InnerNode);
                filled = inner.keys[B - 3] != std.math.maxInt(Key);
                insertAt(&inner.keys, idx, key);
                insertAt(&inner.values, idx + 1, new_node);
                if (!filled) break :split;

                // The inner was filled & needs to be split into a new one.
                new_node = try self.allocNode(disk, pool, InnerNode);
                const new_inner = try getNodeMut(disk, new_node, InnerNode);
                moveHalf(inner, new_inner);

                key = inner.keys[(B / 2) - 1];
                inner.keys[(B / 2) - 1] = std.math.maxInt(Key);
            }

            // Reached the root which needs to be split
            const new_root = try self.allocNode(disk, pool, InnerNode);
            const new_inner = try getNodeMut(disk, new_root, InnerNode);
            @memset(&new_inner.keys, std.math.maxInt(Key));
            new_inner.keys[0] = key;
            new_inner.values[0] = self.root;
            new_inner.values[1] = new_node;

            self.root = new_root;
            self.size.height += 1;
        }

        return value_ptr;
    }
};

const Pool = extern struct {
    allocated: u64,
    free_lists: [size_classes.len]Disk.Offset,

    const size_classes = [_]u32{
        64,              256,             512,
        1024,            4 * 1024,        8 * 1024,
        16 * 1024,       64 * 1024,       1024 * 1024,
        2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
        (10 * 1024 * 1024) + 64, // Account with metadata(64) + 10 MB data
        64 * 1024 * 1024, // 64 MB for larger Btree chunks
    };

    /// Compute the size_classes index for the given amount of bytes.
    fn sizeClassIndex(bytes: u32) ?u8 {
        comptime var bits_to_idx: [32 + 1]u8 = @splat(@intCast(size_classes.len));
        inline for (1..32 + 1) |bits| {
            bits_to_idx[bits] = comptime @intCast(for (size_classes, 0..) |size, idx| {
                if (size >= (1 << bits) - 1) break idx;
            } else size_classes.len - 1);
        }

        if (bytes == 0 or bytes > size_classes[size_classes.len - 1]) return null;
        const sc_idx = bits_to_idx[32 - @clz(bytes)];
        std.debug.assert(sc_idx < size_classes.len);
        return sc_idx;
    }

    fn alloc(self: *Pool, disk: *Disk, bytes: u32) !Disk.Offset {
        if (bytes == 0) return 0;
        const sc_idx = sizeClassIndex(bytes) orelse return error.InvalidDiskAllocation;

        const free_list = &self.free_lists[sc_idx];
        const free_offset = free_list.*;
        if (free_offset > 0) {
            const free_block = disk.getConstPtr(free_offset, @sizeOf(Disk.Offset));
            free_list.* = @bitCast(free_block[0..@sizeOf(Disk.Offset)].*);
            return free_offset;
        }

        const new_offset = self.allocated;
        self.allocated += size_classes[sc_idx];
        if (self.allocated > disk.getReadable().len) {
            @branchHint(.unlikely);
            try disk.ensureTotalCapacity(self.allocated);
        }

        return new_offset;
    }

    fn free(self: *Pool, disk: *Disk, offset: Disk.Offset, bytes: u32) !void {
        if (bytes == 0) return;
        std.debug.assert(offset > 0);

        const sc_idx = sizeClassIndex(bytes) orelse return error.InvalidDiskAllocation;

        const free_list = &self.free_lists[sc_idx];
        const free_block = try disk.getMutPtr(offset, @sizeOf(Disk.Offset), @alignOf(u8));
        free_block[0..@sizeOf(Disk.Offset)].* = @bitCast(free_list.*);
        free_list.* = offset;
    }
};

const ThreadPool = sig.sync.ThreadPool;
const Disk = struct {
    file: posix.fd_t,
    size: u64,
    reads: struct {
        mapped: *align(std.heap.page_size_min) [max_file_size]u8,
    },
    writes: struct {
        mapped: *align(std.heap.page_size_min) [max_write_buf]u8,
        size: u32 = 0,
        queued: u32 = 0,
    },
    pool: ThreadPool,
    wg: std.Thread.WaitGroup = .{},
    
    const max_file_size = 64*1024*1024*1024*1024;
    const min_file_grow = 4*1024*1024*1024;

    const max_write_buf = 1*1024*1024*1024;
    const max_write_queue = 256;

    const Offset = u64;
    const WriteOp = packed struct(u64) {
        disk_offset: u40,
        len: u24,
    };

    const WriteBufOffset = u32;
    const WriteMap = extern struct {
        array: [capacity]Entry,

        const Entry = extern struct {
            op: WriteOp align(@alignOf(WriteBufOffset)),
            buf_offset: WriteBufOffset,
        };

        // https://probablydance.com/2018/06/16/fibonacci-hashing-the-optimization-that-the-world-forgot-or-a-better-alternative-to-integer-modulo/
        const capacity = max_write_queue * 2;
        const hash_mult = 11400714819323198485;
        const hash_shift: u6 = @intCast(@as(u32, 64) - @ctz(@as(u32, capacity)));
    };

    const WriteTask = struct {
        task: ThreadPool.Task = .{ .callback = run },
        disk: *Disk,
        entry_idx: u32,

        const Array = [max_write_queue]WriteTask;

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "Disk.pwrite" });
            defer zone.deinit();

            const self: *WriteTask = @alignCast(@fieldParentPtr("task", task));
            const disk = self.disk;
            defer disk.wg.finish();

            const entry = disk.getWriteMap().array[self.entry_idx];
            const data = disk.getWriteBuffer()[entry.buf_offset..][0..entry.op.len];

            var n: usize = 0;
            while (n < data.len) {
                n += posix.pwrite(disk.file, data[n..], entry.buf_offset + n) catch |err| {
                    std.debug.panic("pwrite err: {}\n", .{err});
                };
            }
        }
    };
    
    fn open(file_path: [:0]const u8) !Disk {
        const file = try std.fs.cwd().createFileZ(file_path, .{ .read = true, .lock = .exclusive });
        errdefer file.close();

        const read_map = try posix.mmap(
            null,
            max_file_size,
            posix.PROT.NONE,
            .{ .TYPE = .SHARED },
            file.handle,
            0,
        );
        errdefer posix.munmap(read_map);

        const size = (try file.stat()).size;
        try posix.mprotect(read_map[0..size], posix.PROT.READ);
        try posix.madvise(read_map.ptr, size, posix.MADV.RANDOM);

        // Could use an std.mem.Allocator here, but w/e.
        const write_map = try posix.mmap(
            null,
            max_write_buf,
            posix.PROT.READ | posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );
        errdefer posix.munmap(write_map);

        try posix.madvise(write_map.ptr, write_map.len, posix.MADV.SEQUENTIAL);
        @memset(write_map[0..@sizeOf(WriteMap)], 0);
        
        return .{
            .file = file.handle,
            .size = size,
            .reads = .{ .mapped = read_map[0..max_file_size] },
            .writes = .{ .mapped = write_map[0..max_write_buf] },
            .pool = .init(.{ .max_threads = 64 }),
        };
    }

    fn close(self: *Disk) void {
        self.commitWrites() catch {};
        
        self.pool.shutdown();
        self.pool.deinit();
        
        posix.munmap(self.writes.mapped);
        posix.munmap(self.reads.mapped);
        posix.close(self.file);
    }

    fn commitWrites(self: *Disk) !void {
        try self.flushWrites(); // flush pending writes to disk
        try posix.fsync(self.file); // make sure they reach the disk
        try posix.msync(self.reads.mapped[0..self.size], posix.MSF.SYNC); // update read mapping
    }

    fn ensureTotalCapacity(self: *Disk, new_size: u64) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Disk.extend" });
        defer zone.deinit();

        if (new_size <= self.size) return;
        self.size = @max(self.size + min_file_grow, new_size);
        try posix.ftruncate(self.file, self.size);

        try posix.mprotect(self.reads.mapped, posix.PROT.READ);
        try posix.madvise(self.reads.mapped, self.size, posix.MADV.RANDOM);
    }

    fn getReadable(self: *const Disk) []align(std.heap.page_size_min) const u8 {
        return self.reads.mapped[0..self.size];
    }

    fn getReadSlice(self: *const Disk, disk_offset: Offset, bytes: u32) []const u8 {
        std.debug.assert(disk_offset > 0);
        return self.getReadable()[disk_offset..][0..bytes];
    } 

    fn getWriteMap(self: *const Disk) *WriteMap {
        return @ptrCast(self.writes.mapped[0..@sizeOf(WriteMap)].ptr);
    }

    fn getWriteBuffer(self: *const Disk) []u8 {
        return self.writes.mapped[@sizeOf(WriteMap)..max_write_buf - @sizeOf(WriteTask.Array)];
    }

    fn getWriteTasks(self: *const Disk) *WriteTask.Array {
        return @ptrCast(@alignCast(self.writes.mapped[max_write_buf - @sizeOf(WriteTask.Array)..]));
    }

    fn getConstPtr(self: *const Disk, disk_offset: Offset, bytes: u32) []const u8 {
        const zone = tracy.Zone.init(@src(), .{ .name = "Disk.getConstPtr" });
        defer zone.deinit();

        std.debug.assert(disk_offset > 0);

        const write_map = self.getWriteMap();
        var idx: usize = @intCast((disk_offset *% WriteMap.hash_mult) >> WriteMap.hash_shift);
        while (true) {
            // If not being written to, go directly to read buffer.
            const entry = write_map.array[idx];
            if (entry.op.disk_offset == 0) {
                @branchHint(.likely);
                return self.getReadSlice(disk_offset, bytes);
            }

            // Currently in write buffer, read directly from that write.
            idx = (idx +% 1) % write_map.array.len;
            if (entry.op.disk_offset == disk_offset) {
                @branchHint(.likely);
                std.debug.assert(entry.op.len >= bytes);
                return self.getWriteBuffer()[entry.buf_offset..][0..bytes];
            }
        }
    }

    fn getMutPtr(self: *Disk, disk_offset: Offset, bytes: u32, aligned: u32) ![]u8 {
        const zone = tracy.Zone.init(@src(), .{ .name = "Disk.getMutPtr" });
        defer zone.deinit();

        std.debug.assert(disk_offset > 0);

        const write_map = self.getWriteMap();
        var idx: usize = @intCast((disk_offset *% WriteMap.hash_mult) >> WriteMap.hash_shift);
        while (true) {
            // Not being written to, push to write buffer.
            const entry_ptr = &write_map.array[idx];
            var entry = entry_ptr.*;
            if (@as(u64, @bitCast(entry.op)) == 0) {
                @branchHint(.likely);
                entry.op = .{ .disk_offset = @intCast(disk_offset), .len = @intCast(bytes) };
                entry.buf_offset = try self.queueWrite(entry.op, aligned);
                entry_ptr.* = entry;
            }

            // Being written to: use its memory in write buffer.
            idx = (idx +% 1) % write_map.array.len;
            if (entry.op.disk_offset == disk_offset) {
                @branchHint(.likely);
                std.debug.assert(entry.op.len >= bytes);
                return self.getWriteBuffer()[entry.buf_offset..][0..bytes];
            }
        }
    }

    fn queueWrite(self: *Disk, op: WriteOp, aligned: u32) !WriteBufOffset {
        while (true) {
            const total_write_offset = 
                std.mem.alignForward(WriteBufOffset, @sizeOf(WriteMap) + self.writes.size, aligned);
            const new_offset = total_write_offset - @sizeOf(WriteMap);
            const new_size = new_offset + op.len;
            const new_queued = self.writes.queued + 1;

            if (new_size <= self.getWriteBuffer().len and new_queued <= max_write_queue) {
                @branchHint(.likely);
                self.writes.size = new_size;
                self.writes.queued = new_queued;
                return new_offset;
            }
            
            try self.flushWrites();
        }
    }

    fn flushWrites(self: *Disk) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Disk.flushWrites" });
        zone.value(self.writes.queued);
        defer zone.deinit();

        {
            self.wg.startMany(self.writes.queued);
            defer self.wg.wait();

            var batch = ThreadPool.Batch{};
            defer self.pool.schedule(batch);

            var i: usize = 0;
            for (&self.getWriteMap().array, 0..) |entry, idx| {
                if (@as(u64, @bitCast(entry.op)) == 0) continue;
                const task = &self.getWriteTasks()[i];
                i += 1;
                task.* = .{
                    .disk = self,
                    .entry_idx = @intCast(idx),
                };
                batch.push(.from(&task.task));
            } 
        }

        @memset(self.writes.mapped[0..@sizeOf(WriteMap)], 0);
        self.writes.queued = 0;
        self.writes.size = 0;
        self.wg = .{};
    }
};
