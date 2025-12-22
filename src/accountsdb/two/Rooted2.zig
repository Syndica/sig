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

    std.debug.print("db is empty -  loading from snapshot!\n", .{});

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

            const acc = try self.db.put(account.store_info.pubkey);
            // simulate sorting by skipping account updates on older accounts_file entries.
            if (acc.slot > accounts_file.slot) continue;

            acc.slot = accounts_file.slot;
            acc.owner = account.account_info.owner;
            acc.lamports = account.account_info.lamports;
            acc.rent_epoch = account.account_info.rent_epoch;
            acc.data.executable = account.account_info.executable;

            const data = try account.data.readAllAllocate(arena.allocator());
            defer arena.allocator().free(data);

            // Resize with `.uninitialize` as itll immediately be memcpy'd over.
            try self.db.setAccountDataLength(acc, @intCast(data.len), .uninitialize);
            @memcpy(self.db.getAccountData(acc), data);
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
    self.rwlock.lockShared();
    defer self.rwlock.unlockShared();

    const acc = self.db.get(address) orelse return null;
    return .{
        .owner = acc.owner,
        .lamports = acc.lamports,
        .rent_epoch = acc.rent_epoch,
        .executable = acc.data.executable,
        .data = try allocator.dupe(u8, self.db.getAccountData(acc)),
    };
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
    self.db.flush(.@"async") catch |err| std.debug.panic("db.sync() failed: {}", .{err});
}

/// Should not be called outside of snapshot loading or slot rooting.
/// TODO: write putRootedSlot(slot, []pk, []account) and make that public instead.
pub fn put(self: *Rooted, address: Pubkey, slot: Slot, account: AccountSharedData) void {
    self.rwlock.lock();
    defer self.rwlock.unlock();

    // Avoid db.put() if just trying to delete an account.
    if (account.isDeleted()) {
        const acc = self.db.get(address) orelse return;
        self.db.remove(acc);
        return;
    }

    const acc = self.db.put(address) catch |err| {
        std.debug.panic("db.put() failed: {}", .{err});
    };

    acc.slot = slot;
    acc.owner = account.owner;
    acc.lamports = account.lamports;
    acc.rent_epoch = account.rent_epoch;
    acc.data.executable = account.executable;

    // Resize with .uninitialize and we'll be overwriting all of it with memcpy anyway.
    self.db.setAccountDataLength(acc, @intCast(account.data.len), .uninitialize) catch |err| {
        std.debug.panic("db account data size failed: {}", .{err});
    };
    @memcpy(self.db.getAccountData(acc), account.data);
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
        num_blocks: u64,
        free_lists: [size_classes.len]Offset,
    },
    tree: packed struct(u128) {
        root: Offset,
        height: u4,
        count: u60,
    },

    // Absurdely large limit to avoid having to mremap ever
    const max_file_size = 64 * 1024 * 1024 * 1024; // 64 TB

    // Smallest size in bytes when extending the file on disk (to amortize ftruncate/mprotect calls)
    const min_file_growth = 64 * 1024 * 1024; // 64 MB

    // Smallest addressible unit of memory for disk allocations
    const Block = extern struct { _: [64]u8 align(64) };
    const Offset = u64;

    // All possible bins disk allocations can fit into.
    const size_classes = [_]u32{
        64,               256,             512,
        1024,             4 * 1024,        8 * 1024,
        16 * 1024,        64 * 1024,       1024 * 1024,
        2 * 1024 * 1024,  4 * 1024 * 1024, 8 * 1024 * 1024,
        10 * 1024 * 1024,
    };

    // Pubkeys are converted into this format to accelerate tree operations.
    const Key = u64;
    const EMPTY_KEY: Key = std.math.maxInt(u64);

    /// The database's representation of an Account. Db users are free to modify most fields.
    const Account = extern struct {
        pubkey: Pubkey,
        owner: Pubkey,
        lamports: u64,
        rent_epoch: Epoch,
        slot: Slot,

        /// NOTE contains internal fields. Only read/write `.executable`, or read `.len`.
        /// The data bytes themselves are interfaced with `getAccountData`/`setAccountDataLength`.
        data: packed struct(u64) {
            executable: bool,
            deleted: bool, // TODO: eventually replace this with actual b-tree index removal
            offset: u38, // enough to address 275 million Blocks
            len: u24, // enough to address 10 MB
        },
    };

    const B = 32;
    const max_height = 8; // allows for `pow(B / 2, height)` max entries

    const InnerNode = extern struct {
        keys: [B]Key,
        values: [B]Offset,
    };
    const LeafNode = extern struct {
        keys: [B]Key,
        values: [B]Account,
    };

    pub fn open(file_path: [:0]const u8) !*Db {
        const file = try std.fs.cwd().createFile(file_path, .{ .read = true, .lock = .exclusive });
        errdefer file.close();

        const memory = try posix.mmap(
            null, // let the kernel choose the memory address start.
            max_file_size, // ADDRESS SPACE (not physical memory).
            posix.PROT.NONE, // mapped with no perms so that theres no physical backing.
            .{ .TYPE = .SHARED }, // direct page cache: writes are propagated down to the file.
            file.handle,
            0, // it's a view of the entire file
        );
        errdefer posix.munmap(memory);

        // Make sure there's enough room for Db struct.
        var size = (try file.stat()).size;
        if (size < @sizeOf(Db)) {
            size = @max(@sizeOf(Db), min_file_growth);
            try posix.ftruncate(file.handle, size);
        }

        // Allow access only to memory that encompasses the file data on disk & init Db.
        try posix.mprotect(memory[0..size], posix.PROT.READ | posix.PROT.WRITE);
        const self: *Db = @ptrCast(memory[0..@sizeOf(Db)].ptr);
        self.file = .{ .handle = file.handle, .size = size };

        // mmap + ftruncate zeroes out memory by default. So on first access, setup the Db.
        if (self.pool.num_blocks == 0) {
            // mark Db header as already allocted.
            self.pool.num_blocks = blockCount(@sizeOf(Db));

            // initialize b-tree
            self.tree.root = try self.alloc(@sizeOf(LeafNode));
            const leaf = self.getPtr(LeafNode, self.tree.root);
            @memset(&leaf.keys, EMPTY_KEY);
        }

        return self;
    }

    pub fn close(self: *Db) void {
        self.flush(.sync) catch {};

        const handle = self.file.handle; // read out handle before unmapping Db memory.
        posix.munmap(self.mapped());
        posix.close(handle);
    }

    /// For the given pubkey, return's an existing Account if any.
    pub fn get(self: *const Db, pubkey: Pubkey) ?*Account {
        var path: Path = undefined;
        const acc = self.lookup(&path, &pubkey) orelse return null;
        return if (!acc.data.deleted) acc else null;
    }

    /// For the given pubkey, either return an existing Account, or create a new one.
    /// Newly created Accounts have their state zeroed out (excluding the pubkey).
    pub fn put(self: *Db, pubkey: Pubkey) !*Account {
        var path: Path = undefined;
        if (self.lookup(&path, &pubkey)) |acc| {
            acc.data.deleted = false;
            return acc;
        }

        const acc = try self.insert(&path);
        acc.* = std.mem.zeroes(Account);
        acc.pubkey = pubkey;
        return acc;
    }

    /// Mark the account (returned from a valid get()) as deleted,
    /// zeroing out the account state (excluding the pubkey).
    pub fn remove(self: *Db, acc: *Account) void {
        std.debug.assert(!acc.data.deleted);
        self.free(acc.data.offset, acc.data.len);
        self.tree.count -= 1;

        const pubkey = acc.pubkey;
        acc.* = std.mem.zeroes(Account);
        acc.pubkey = pubkey;
        acc.data.deleted = true;
    }

    //// Returns the number of Accounts's currently present in the databse.
    pub fn count(self: *const Db) usize {
        return self.tree.count;
    }

    /// Get the account data held by the given Account.
    pub fn getAccountData(self: *const Db, acc: *Account) []align(@alignOf(Block)) u8 {
        return getSlice(@constCast(self), u8, acc.data.offset, acc.data.len);
    }

    /// Change the size of the account data at the given Account.
    /// The new length must not be larger than the maximum addressible data by the databse (10 MB).
    /// When the mode is `uninitialize`, the contents of the data after resizing are unspecified.
    /// When the mode is `truncate`, shrinking keeps data & growing extends with zeroes.
    pub fn setAccountDataLength(
        self: *Db,
        acc: *Account,
        new_len: u32,
        mode: enum { truncate, uninitialize },
    ) !void {
        // Check if a realloc is required.
        if (sizeClassIndex(acc.data.len) != sizeClassIndex(new_len)) {
            const new_offset = try self.alloc(new_len);
            if (mode == .truncate) {
                const keep = @min(acc.data.len, new_len);
                const new_slice = self.getSlice(u8, new_offset, new_len);
                @memcpy(new_slice[0..keep], self.getAccountData(acc)[0..keep]);
                @memset(new_slice[keep..], 0);
            }
            self.free(acc.data.offset, acc.data.len);
            acc.data.offset = @intCast(new_offset);
        }
        acc.data.len = @intCast(new_len);
    }

    /// Tell the database to flush all inflight updates to disk.
    /// If mode == .async, this *tries* to return early and do the flushing in the background.
    pub fn flush(self: *Db, mode: enum { sync, @"async" }) !void {
        try posix.msync(self.mapped(), switch (mode) {
            .sync => posix.MSF.SYNC,
            .@"async" => posix.MSF.ASYNC,
        });
        if (mode == .sync) try posix.fsync(self.file.handle);
    }

    /// Returns all memory that was mapped for the file (some of it may not be accessible).
    fn mapped(self: *Db) *align(std.heap.page_size_min) [max_file_size]u8 {
        return @ptrCast(self);
    }

    /// Returns all memory thats backed by the file on disk.
    fn slice(self: *Db) []align(std.heap.page_size_min) u8 {
        return self.mapped()[0..self.file.size];
    }

    /// Returns all blocks the disk has marked allocated.
    fn blocks(self: *Db) []Block {
        return std.mem.bytesAsSlice(Block, self.slice()[0 .. self.pool.num_blocks * @sizeOf(Block)]);
    }

    /// Returns the number of blocks needed to hold the given amount of bytes.
    fn blockCount(bytes: u64) u64 {
        return @divExact(std.mem.alignForward(u64, bytes, @sizeOf(Block)), @sizeOf(Block));
    }

    /// Compute the size_classes index for the given amount of bytes.
    fn sizeClassIndex(bytes: u32) ?u8 {
        comptime var bits_to_idx: [32 + 1]u8 = @splat(@intCast(size_classes.len));
        inline for (1..32 + 1) |bits| {
            bits_to_idx[bits] = comptime @intCast(for (size_classes, 0..) |size, idx| {
                std.debug.assert(size % @sizeOf(Block) == 0);
                std.debug.assert(size >= @sizeOf(Block));
                if (size >= (1 << bits) - 1) break idx;
            } else size_classes.len);
        }

        const sc_idx = bits_to_idx[32 - @clz(bytes)];
        return if (sc_idx < size_classes.len) sc_idx else null;
    }

    fn alloc(self: *Db, bytes: u32) !Offset {
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
        const new_offset = self.pool.num_blocks;
        self.pool.num_blocks += blockCount(size_classes[sc_idx]);

        // Extend the disk/memory as needed.
        var new_file_size = self.pool.num_blocks * @sizeOf(Block);
        if (new_file_size > self.slice().len) {
            @branchHint(.unlikely);

            new_file_size = @max(new_file_size, self.slice().len + min_file_growth);
            try posix.ftruncate(self.file.handle, new_file_size);
            self.file.size = new_file_size;
            try posix.mprotect(self.slice(), posix.PROT.READ | posix.PROT.WRITE);
        }

        return new_offset;
    }

    fn free(self: *Db, offset: Offset, bytes: u32) void {
        if (offset == 0 or bytes == 0) return;
        std.debug.assert(offset < self.blocks().len);

        const sc_idx = sizeClassIndex(bytes) orelse {
            std.debug.panic("db free too large: {}", .{bytes});
        };

        // push to free list
        const free_list = &self.pool.free_lists[sc_idx];
        const next_link = self.getPtr(Offset, offset);
        next_link.* = free_list.*;
        free_list.* = offset;
    }

    /// Returns a slice of memory that was previously allocated.
    fn getSlice(self: *Db, comptime T: type, offset: Offset, len: u32) []align(@alignOf(Block)) T {
        const num_blocks = blockCount(@sizeOf(T) * len);
        const ptr: [*]align(@alignOf(Block)) T = @ptrCast(self.blocks()[offset..][0..num_blocks]);
        return ptr[0..len];
    }

    /// Returns a single item that was previously allocated.
    fn getPtr(self: *Db, comptime T: type, offset: Offset) *T {
        return &self.getSlice(T, offset, 1)[0];
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

    /// Search for an AccountInfo that matches the pubkey, saving the Path along the way.
    fn lookup(
        noalias self: *const Db,
        noalias path: *Path,
        noalias pubkey: *const Pubkey,
    ) ?*Account {
        // Covert pubkey into searching Key value.
        var key = pubkey.hash();
        key -= @intFromBool(key == EMPTY_KEY); // make sure its not EMPTY_KEY
        path.key = key;

        // Traverse down inner nodes until we reach a LeafNode, recording the path.
        var node = self.tree.root;
        for (0..self.tree.height) |h| {
            const inner = getPtr(@constCast(self), InnerNode, node);
            const idx = countLessThan(&inner.keys, key);
            path.idx_stack[h] = idx;
            path.node_stack[h] = node;
            node = inner.values[idx];
        }

        // Find lower bound in leaf.
        const leaf = getPtr(@constCast(self), LeafNode, node);
        var idx = countLessThan(&leaf.keys, key);
        path.idx_stack[self.tree.height] = idx;
        path.node_stack[self.tree.height] = node;

        // Its technically possible, although extremely unlikely, for 2 pubkeys to hash to same Key.
        // In that case, we must scan for the right AccountInfo.
        // The last key in a node is always EMPTY_KEY, so we can rely on key comparison to exit loop
        while (leaf.keys[idx] == key) : (idx += 1) {
            @branchHint(.likely);
            const acc_info = &leaf.values[idx];
            if (acc_info.pubkey.equals(pubkey)) {
                @branchHint(.likely);
                return acc_info;
            }
        }
        return null;
    }

    fn insertAt(comptime T: type, array: *[B]T, idx: u32, value: T) void {
        std.mem.copyBackwards(T, array[idx + 1 ..], array[idx .. B - 1]);
        array[idx] = value;
    }

    fn moveHalf(noalias old_node: anytype, noalias new_node: @TypeOf(old_node)) void {
        @memset(new_node.keys[B / 2 ..], EMPTY_KEY);
        @memcpy(new_node.keys[0 .. B / 2], old_node.keys[B / 2 ..]);
        @memset(old_node.keys[B / 2 ..], EMPTY_KEY);
        @memcpy(new_node.values[0 .. B / 2], old_node.values[B / 2 ..]);
    }

    /// Using a path populated from a lookup which returned null, allocate a new Account
    fn insert(noalias self: *Db, noalias path: *Path) !*Account {
        const max_entries = comptime std.math.pow(u64, B / 2, max_height);
        if (self.tree.count == max_entries) return posix.TruncateError.FileTooBig;
        self.tree.count += 1;

        var key = path.key;
        var idx = path.idx_stack[self.tree.height];
        var node = path.node_stack[self.tree.height];

        const leaf = self.getPtr(LeafNode, node);
        var value = &leaf.values[idx];
        @prefetch(value, .{});

        // Insert the key and value, pipelining the check for if leaf will be full.
        var filled = leaf.keys[B - 2] != EMPTY_KEY;
        insertAt(Key, &leaf.keys, idx, key);
        insertAt(Account, &leaf.values, idx, undefined);
        if (filled) split: {
            @branchHint(.unlikely);

            // The leaf was filled & needs to be split into a new one.
            var new_node = try self.alloc(@sizeOf(LeafNode));
            const new_leaf = self.getPtr(LeafNode, new_node);
            moveHalf(leaf, new_leaf);
            key = leaf.keys[B / 2 - 1];

            // Branchlessly reassign the value if it was moved to the new_leaf.
            const new_idx = @as(u32, idx) -% (B / 2);
            const new_value: *Account = @ptrCast(new_leaf.values[0..].ptr + new_idx);
            if (new_idx < idx) value = new_value;

            // Ascend up the tree until we reach either the root or an non-full node
            var h = @as(u32, self.tree.height) -% 1;
            while (h != std.math.maxInt(u32)) : (h -%= 1) {
                idx = path.idx_stack[h];
                node = path.node_stack[h];

                // Insert to inner node
                const inner = self.getPtr(InnerNode, node);
                filled = inner.keys[B - 3] != EMPTY_KEY;
                insertAt(Key, &inner.keys, idx, key);
                insertAt(Offset, &inner.values, idx + 1, new_node);
                if (!filled) break :split;

                // The inner was filled & needs to be split into a new one.
                new_node = try self.alloc(@sizeOf(InnerNode));
                const new_inner = self.getPtr(InnerNode, new_node);
                moveHalf(inner, new_inner);

                key = inner.keys[(B / 2) - 1];
                inner.keys[(B / 2) - 1] = EMPTY_KEY;
            }

            // Reached the root which needs to be split
            const new_root = try self.alloc(@sizeOf(InnerNode));
            const new_inner = self.getPtr(InnerNode, new_root);
            @memset(&new_inner.keys, EMPTY_KEY);
            new_inner.keys[0] = key;
            new_inner.values[0] = self.tree.root;
            new_inner.values[1] = new_node;

            self.tree.root = new_root;
            self.tree.height += 1;
        }

        return value;
    }
};
