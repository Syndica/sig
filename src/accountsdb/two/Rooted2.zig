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
db: *Db,
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

    try self.db.flush(.sync);
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

/// For API compatibility.
pub fn beginTransaction(self: *Rooted) void {
    _ = self;
}

pub fn commitTransaction(self: *Rooted) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.commitTransaction" });
    defer zone.deinit();

    self.db.flush(.sync) catch |err| std.debug.panic("db.sync() failed: {}", .{err});
}

/// Should not be called outside of snapshot loading or slot rooting.
/// TODO: write putRootedSlot(slot, []pk, []account) and make that public instead.
pub fn put(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    const zone = tracy.Zone.init(@src(), .{ .name = "Rooted.put" });
    defer zone.deinit();

    self.rwlock.lock();
    defer self.rwlock.unlock();

    self.db.put(address, slot, account) catch |err| {
        std.debug.panic("db.put() failed: {}", .{err});
    };
}

/// An on-disk KV database simulating a HashMap(Pubkey, { Slot, AccountSharedData }).
/// Backed by a B- Tree implementation from: https://en.algorithmica.org/hpc/data-structures/b-tree/
const Db = extern struct {
    _: [0]u8 align(std.heap.page_size_min),
    file: extern struct {
        handle: posix.fd_t,
        size: u64,
    },
    pool: extern struct {
        allocated: Offset,
        free_lists: [size_classes.len]Offset,
    },
    tree: extern struct {
        root: Offset,
        height: u32,
        count: u32,
        node_cache: extern struct {
            ptr: Offset,
            end: Offset,
        },
    },

    // Absurdely large limit to avoid having to mremap ever
    const max_file_size = 64 * 1024 * 1024 * 1024 * 1024; // 64 TB

    // Smallest size in bytes when extending the file on disk (to amortize ftruncate/mprotect calls)
    const min_file_growth = 4 * 1024 * 1024 * 1024; // 4 GB

    // Smallest possible alignment
    const min_align = size_classes[0];

    // Amount of memory to grab in chunks at a time for BTree nodes
    const node_cache_size = size_classes[size_classes.len - 1];

    // All possible bins disk allocations can fit into.
    const size_classes = [_]u32{
        64,              256,             512,
        1024,            4 * 1024,        8 * 1024,
        16 * 1024,       64 * 1024,       1024 * 1024,
        2 * 1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
        @sizeOf(Account) + 10 * 1024 * 1024, // Account with 10 MB
        64 * 1024 * 1024, // 64 MB for larger Btree chunks
    };

    // Byte-wise index into the Db memory map. A value of 0 is null.
    const Offset = u64;

    // Pubkeys are converted into this format to accelerate tree operations.
    const Key = u64;
    const EMPTY_KEY: Key = std.math.maxInt(u64);

    /// The database's internal representation of an Account.
    const Account = extern struct {
        owner: Pubkey,
        lamports: u64,
        rent_epoch: Epoch,
        slot: Slot,
        data: packed struct(u32) {
            executable: bool,
            len: u31,
        },

        fn getData(self: *Account) []u8 {
            return @as([*]u8, @ptrCast(self))[@sizeOf(Account)..][0..self.data.len];
        }
    };

    const B = 32;
    const max_height = 8; // allows for `pow(B / 2, height)` max entries

    const InnerNode = extern struct {
        keys: [B]Key,
        values: [B]Offset,
    };
    const LeafNode = extern struct {
        keys: [B]Key,
        values: [B]extern struct {
            pubkey: Pubkey,
            account: Offset,
        },
    };

    pub fn open(file_path: [:0]const u8) !*Db {
        const file = try std.fs.cwd().createFile(file_path, .{ .read = true, .lock = .exclusive });
        errdefer file.close();

        var size = (try file.stat()).size;
        if (size < @sizeOf(Db)) {
            size = @max(@sizeOf(Db), min_file_growth);
            try posix.ftruncate(file.handle, size);
        }

        const memory = try posix.mmap(
            null, // let the kernel choose the memory address start.
            max_file_size, // ADDRESS SPACE (not physical memory).
            posix.PROT.NONE, // mapped with no perms so that theres no physical backing.
            .{ .TYPE = .SHARED }, // direct page cache: writes are propagated down to the file.
            file.handle,
            0, // it's a view of the entire file
        );
        errdefer posix.munmap(memory);

        try posix.mprotect(memory[0..size], posix.PROT.READ | posix.PROT.WRITE);
        const self: *Db = @ptrCast(memory[0..@sizeOf(Db)].ptr);
        self.file = .{ .handle = file.handle, .size = size };

        if (self.pool.allocated == 0) {
            self.pool = .{
                .allocated = @sizeOf(Db),
                .free_lists = @splat(0),
            };
            self.tree = .{
                .root = try self.allocNode(LeafNode),
                .height = 0,
                .count = 0,
                .node_cache = .{ .ptr = 0, .end = 0 },
            };
        }

        return self;
    }

    pub fn close(self: *Db) void {
        self.flush(.sync) catch {};

        const handle = self.file.handle; // read out handle before unmapping Db memory.
        posix.munmap(self.getMapped());
        posix.close(handle);
    }

    /// Tell the database to flush all inflight updates to disk.
    /// If mode == .async, this *tries* to return early and do the flushing in the background.
    pub fn flush(self: *Db, mode: enum { sync, @"async" }) !void {
        try posix.msync(self.getDiskMapped(), switch (mode) {
            .sync => posix.MSF.SYNC,
            .@"async" => posix.MSF.ASYNC,
        });
        if (mode == .sync) try posix.fsync(self.file.handle);
    }

    //// Returns the number of Accounts's currently present in the databse.
    pub fn count(self: *const Db) usize {
        return self.tree.count;
    }

    pub fn get(
        self: *const Db,
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
    ) !?AccountSharedData {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.get" });
        defer zone.deinit();

        var path: Path = undefined;
        const offset_ptr = self.lookup(&path, &pubkey) orelse return null;

        const offset = offset_ptr.*;
        if (offset == 0) return null;

        const read_zone = tracy.Zone.init(@src(), .{ .name = "Db.readAccount" });
        defer read_zone.deinit();

        const acc = self.getPtr(Account, offset);
        return .{
            .owner = acc.owner,
            .lamports = acc.lamports,
            .rent_epoch = acc.rent_epoch,
            .executable = acc.data.executable,
            .data = try allocator.dupe(u8, acc.getData()),
        };
    }

    pub fn put(self: *Db, pubkey: Pubkey, slot: Slot, account: AccountSharedData) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.put" });
        defer zone.deinit();

        var path: Path = undefined;
        const offset_ptr = self.lookup(&path, &pubkey) orelse blk: {
            if (account.isDeleted()) return;
            break :blk try self.insert(&path, &pubkey);
        };

        const new_size: u32 = @intCast(@sizeOf(Account) + account.data.len);

        var offset = offset_ptr.*;
        if (offset > 0) {
            const acc = self.getPtr(Account, offset);
            const acc_size: u32 = @intCast(@sizeOf(Account) + acc.data.len);

            if (slot <= acc.slot) {
                return error.InvalidSlot;
            }

            if (account.isDeleted()) {
                self.free(offset, acc_size);
                offset_ptr.* = 0;
                return;
            }

            if (sizeClassIndex(acc_size) != sizeClassIndex(new_size)) {
                self.free(offset, acc_size);
                offset = 0;
            }
        }

        if (offset == 0) {
            offset = try self.alloc(new_size);
            offset_ptr.* = offset;
        }

        const write_zone = tracy.Zone.init(@src(), .{ .name = "Db.writeAccount" });
        defer write_zone.deinit();

        const acc = self.getPtr(Account, offset);
        acc.* = .{
            .owner = account.owner,
            .lamports = account.lamports,
            .rent_epoch = account.rent_epoch,
            .slot = slot,
            .data = .{ .executable = account.executable, .len = @intCast(account.data.len) },
        };
        @memcpy(acc.getData(), account.data);
    }

    /// Returns all memory that was mapped for the file (some of it may not be accessible).
    fn getMapped(self: *const Db) *align(std.heap.page_size_min) [max_file_size]u8 {
        return @ptrCast(@constCast(self));
    }

    /// Returns all memory thats backed by the file on disk.
    fn getDiskMapped(self: *const Db) []align(std.heap.page_size_min) u8 {
        return self.getMapped()[0..self.file.size];
    }

    /// Returns all blocks the disk has marked allocated.
    fn getMemory(self: *const Db) []align(std.heap.page_size_min) u8 {
        return self.getDiskMapped()[0..self.pool.allocated];
    }

    fn getSlice(self: *const Db, T: type, offset: Offset, len: usize) []align(min_align) T {
        if (len == 0) return &.{};
        std.debug.assert(offset > 0);
        const bytes = self.getMemory()[offset..][0 .. @sizeOf(T) * len];
        return @as([*]align(min_align) T, @ptrCast(@alignCast(bytes.ptr)))[0..len];
    }

    fn getPtr(self: *const Db, T: type, offset: Offset) *align(min_align) T {
        return @ptrCast(self.getSlice(T, offset, 1).ptr);
    }

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

    fn alloc(self: *Db, bytes: u32) !Offset {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.allocBuffer" });
        defer zone.deinit();

        if (bytes == 0) return 0;
        const sc_idx = sizeClassIndex(bytes) orelse {
            std.debug.panic("db alloc too large: {}", .{bytes});
        };

        // Check the free list first.
        const free_list = &self.pool.free_lists[sc_idx];
        const free_offset = free_list.*;
        if (free_offset != 0) {
            const next_link = self.getPtr(Offset, free_offset);
            free_list.* = next_link.*;
            return free_offset;
        }

        // Bump alloc new run of blocks.
        const new_offset = self.pool.allocated;
        self.pool.allocated += size_classes[sc_idx];

        // Extend the disk/memory as needed.
        if (self.pool.allocated > self.file.size) {
            @branchHint(.unlikely);

            const extend_zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.extend" });
            defer extend_zone.deinit();

            const new_file_size = @max(self.pool.allocated, self.file.size + min_file_growth);
            try posix.ftruncate(self.file.handle, new_file_size);

            self.file.size = new_file_size;
            try posix.mprotect(self.getDiskMapped(), posix.PROT.READ | posix.PROT.WRITE);
        }

        return new_offset;
    }

    fn free(self: *Db, offset: Offset, bytes: u32) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Disk.freeBuffer" });
        defer zone.deinit();

        if (bytes == 0) return;
        std.debug.assert(offset < self.pool.allocated);

        const sc_idx = sizeClassIndex(bytes) orelse {
            std.debug.panic("db free too large: {}", .{bytes});
        };

        // push to free list
        const free_list = &self.pool.free_lists[sc_idx];
        const next_link = self.getPtr(Offset, offset);
        next_link.* = free_list.*;
        free_list.* = offset;
    }

    fn allocNode(self: *Db, Node: type) !Offset {
        var offset = self.tree.node_cache.ptr;
        self.tree.node_cache.ptr += @sizeOf(Node);

        if (self.tree.node_cache.ptr > self.tree.node_cache.end) {
            @branchHint(.unlikely);

            offset = try self.alloc(node_cache_size);
            self.tree.node_cache.ptr = offset + @sizeOf(Node);
            self.tree.node_cache.end = offset + node_cache_size;
        }

        const node = self.getPtr(Node, offset);
        @memset(&node.keys, EMPTY_KEY);
        @memset(&node.values, undefined);
        return offset;
    }

    /// Returns number of keys in array that are less than the given key.
    fn countLessThan(keys: *[B]Key, key: Key) u8 {
        const key_vec: @Vector(B, Key) = @splat(key);
        const keys_vec: @Vector(B, Key) = keys.*;
        const lt_mask: std.meta.Int(.unsigned, B) = @bitCast(keys_vec < key_vec);
        return @popCount(lt_mask);
    }

    const Path = extern struct {
        key: Key,
        idx_stack: [max_height]u8,
        node_stack: [max_height]Offset,
    };

    fn lookup(noalias self: *const Db, noalias path: *Path, noalias pubkey: *const Pubkey) ?*Offset {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.BTree.lookup" });
        defer zone.deinit();

        // Covert pubkey into searching Key value.
        var key = pubkey.hash();
        key -= @intFromBool(key == EMPTY_KEY); // make sure its not EMPTY_KEY
        path.key = key;

        // Traverse down inner nodes until we reach a LeafNode, recording the path.
        var node = self.tree.root;
        for (0..self.tree.height) |h| {
            const inner = self.getPtr(InnerNode, node);
            const idx = countLessThan(&inner.keys, key);
            path.idx_stack[h] = idx;
            path.node_stack[h] = node;
            node = inner.values[idx];
        }

        // Find lower bound in leaf.
        const leaf = self.getPtr(LeafNode, node);
        var idx = countLessThan(&leaf.keys, key);
        path.idx_stack[self.tree.height] = idx;
        path.node_stack[self.tree.height] = node;

        // Its technically possible, although extremely unlikely, for 2 pubkeys to hash to same Key.
        // In that case, we must scan for the right AccountInfo.
        // The last key in a node is always EMPTY_KEY, so we can rely on key comparison to exit loop
        while (leaf.keys[idx] == key) : (idx += 1) {
            @branchHint(.likely);
            const value = &leaf.values[idx];
            if (value.pubkey.equals(pubkey)) {
                @branchHint(.likely);
                return &value.account;
            }
        }
        return null;
    }

    fn insertAt(array: anytype, idx: u32, value: @TypeOf(array[0])) void {
        std.mem.copyBackwards(@TypeOf(array[0]), array[idx + 1 ..], array[idx .. B - 1]);
        array[idx] = value;
    }

    fn moveHalf(noalias old_node: anytype, noalias new_node: @TypeOf(old_node)) void {
        @memset(new_node.keys[B / 2 ..], EMPTY_KEY);
        @memcpy(new_node.keys[0 .. B / 2], old_node.keys[B / 2 ..]);
        @memset(old_node.keys[B / 2 ..], EMPTY_KEY);
        @memcpy(new_node.values[0 .. B / 2], old_node.values[B / 2 ..]);
    }

    /// Using a path populated from a lookup which returned null, allocate a new Account
    fn insert(noalias self: *Db, noalias path: *Path, noalias pubkey: *const Pubkey) !*Offset {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.BTree.insert" });
        defer zone.deinit();

        const max_entries = comptime std.math.pow(u64, B / 2, max_height);
        if (self.tree.count == max_entries) return posix.TruncateError.FileTooBig;
        self.tree.count += 1;

        var key = path.key;
        var idx = path.idx_stack[self.tree.height];
        var node = path.node_stack[self.tree.height];

        const leaf = self.getPtr(LeafNode, node);
        var value = &leaf.values[idx].account;
        @prefetch(value, .{});

        // Insert the key and value, pipelining the check for if leaf will be full.
        var filled = leaf.keys[B - 2] != EMPTY_KEY;
        insertAt(&leaf.keys, idx, key);
        insertAt(&leaf.values, idx, .{ .pubkey = pubkey.*, .account = 0 });
        if (filled) split: {
            @branchHint(.unlikely);

            // The leaf was filled & needs to be split into a new one.
            var new_node = try self.allocNode(LeafNode);
            const new_leaf = self.getPtr(LeafNode, new_node);
            moveHalf(leaf, new_leaf);
            key = leaf.keys[B / 2 - 1];

            // Branchlessly reassign the value if it was moved to the new_leaf.
            const new_idx = idx -% (B / 2);
            const new_value = &new_leaf.values[0..].ptr[new_idx].account;
            if (new_idx < idx) value = new_value;

            // Ascend up the tree until we reach either the root or an non-full node
            var h = @as(u32, self.tree.height) -% 1;
            while (h != std.math.maxInt(u32)) : (h -%= 1) {
                idx = path.idx_stack[h];
                node = path.node_stack[h];

                // Insert to inner node
                const inner = self.getPtr(InnerNode, node);
                filled = inner.keys[B - 3] != EMPTY_KEY;
                insertAt(&inner.keys, idx, key);
                insertAt(&inner.values, idx + 1, new_node);
                if (!filled) break :split;

                // The inner was filled & needs to be split into a new one.
                new_node = try self.allocNode(InnerNode);
                const new_inner = self.getPtr(InnerNode, new_node);
                moveHalf(inner, new_inner);

                key = inner.keys[(B / 2) - 1];
                inner.keys[(B / 2) - 1] = EMPTY_KEY;
            }

            // Reached the root which needs to be split
            const new_root = try self.allocNode(InnerNode);
            const new_inner = self.getPtr(InnerNode, new_root);
            new_inner.keys[0] = key;
            new_inner.values[0] = self.tree.root;
            new_inner.values[1] = new_node;

            self.tree.root = new_root;
            self.tree.height += 1;
        }

        return value;
    }
};
