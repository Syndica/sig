//! all index related structs (account ref, simd hashmap, …)

const std = @import("std");
const lib = @import("../sig.zig");

const Slot = lib.core.time.Slot;
const Pubkey = lib.core.pubkey.Pubkey;
const FileId = lib.accounts_db.accounts_file.FileId;
const RwMux = lib.sync.RwMux;

const swiss_map = @import("swiss_map.zig");
pub const SwissMapManaged = swiss_map.SwissMapManaged;
pub const SwissMapUnmanaged = swiss_map.SwissMapUnmanaged;
pub const BenchmarkSwissMap = swiss_map.BenchmarkSwissMap;
pub const BenchHashMap = swiss_map.BenchHashMap;

// for sync reasons we need a stable head with a lock
pub const AccountReferenceHead = RwMux(struct {
    ref_ptr: *AccountRef,

    const Self = @This();

    pub fn highestRootedSlot(self: *const Self, rooted_slot_max: Slot) struct { usize, Slot } {
        var ref_slot_max: usize = 0;
        var rooted_ref_count: usize = 0;

        var curr: ?*AccountRef = self.ref_ptr;
        while (curr) |ref| : (curr = ref.next_ptr) {
            // only track states less than the rooted slot (ie, they are also rooted)
            const is_not_rooted = ref.slot > rooted_slot_max;
            if (is_not_rooted) continue;

            const is_larger_slot = ref.slot > ref_slot_max or rooted_ref_count == 0;
            if (is_larger_slot) {
                ref_slot_max = ref.slot;
            }
            rooted_ref_count += 1;
        }

        return .{ rooted_ref_count, ref_slot_max };
    }
});

/// reference to an account (either in a file or cache)
pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,
    next_ptr: ?*AccountRef = null,

    /// Analogous to [StorageLocation](https://github.com/anza-xyz/agave/blob/b47a4ec74d85dae0b6d5dd24a13a8923240e03af/accounts-db/src/account_info.rs#L23)
    pub const AccountLocation = union(enum(u8)) {
        File: struct {
            file_id: FileId,
            offset: usize,
        },
        Cache: struct {
            index: usize,
        },
    };

    pub fn default() AccountRef {
        return AccountRef{
            .pubkey = Pubkey.default(),
            .slot = 0,
            .location = .{
                .Cache = .{ .index = 0 },
            },
        };
    }
};

/// stores the mapping from Pubkey to the account location (AccountRef)
///
/// Analogous to [AccountsIndex](https://github.com/anza-xyz/agave/blob/a6b2283142192c5360ad0f53bec1eb4a9fb36154/accounts-db/src/accounts_index.rs#L644)
pub const AccountIndex = struct {
    allocator: std.mem.Allocator,
    reference_allocator: std.mem.Allocator,
    reference_memory: RwMux(ReferenceMemory),
    bins: []RwMux(RefMap),
    pubkey_bin_calculator: PubkeyBinCalculator,
    const Self = @This();

    pub const ReferenceMemory = std.AutoHashMap(Slot, std.ArrayList(AccountRef));
    pub const RefMap = SwissMapManaged(Pubkey, AccountReferenceHead, pubkey_hash, pubkey_eql);

    pub fn init(
        /// used to allocate the hashmap data
        allocator: std.mem.Allocator,
        /// used to allocate the references
        reference_allocator: std.mem.Allocator,
        /// number of bins to shard across
        number_of_bins: usize,
    ) !Self {
        const bins = try allocator.alloc(RwMux(RefMap), number_of_bins);
        errdefer allocator.free(number_of_bins);
        @memset(bins, RwMux(RefMap).init(RefMap.init(allocator)));

        return Self{
            .allocator = allocator,
            .reference_allocator = reference_allocator,
            .bins = bins,
            .pubkey_bin_calculator = PubkeyBinCalculator.init(number_of_bins),
            .reference_memory = RwMux(ReferenceMemory).init(ReferenceMemory.init(allocator)),
        };
    }

    pub fn deinit(self: *Self, free_memory: bool) void {
        for (self.bins) |*bin_rw| {
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();
            bin.deinit();
        }
        self.allocator.free(self.bins);

        {
            const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
            defer reference_memory_lg.unlock();

            if (free_memory) {
                var iter = reference_memory.iterator();
                while (iter.next()) |entry| {
                    entry.value_ptr.deinit();
                }
            }
            reference_memory.deinit();
        }
    }

    pub fn ensureTotalCapacity(self: *Self, size: u32) !void {
        for (self.bins) |*bin_rw| {
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();

            try bin.ensureTotalCapacity(size);
        }
    }

    pub fn putReferenceBlock(self: *Self, slot: Slot, references: std.ArrayList(AccountRef)) !void {
        const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();
        try reference_memory.putNoClobber(slot, references);
    }

    pub fn freeReferenceBlock(self: *Self, slot: Slot) error{MemoryNotFound}!void {
        const reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();

        if (!reference_memory.remove(slot)) {
            return error.MemoryNotFound;
        }
    }

    pub fn getReference(self: *Self, pubkey: *const Pubkey) ?AccountReferenceHead {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).readWithLock();
        defer bin_lg.unlock();
        return bin.get(pubkey.*);
    }

    /// returns a reference to the slot in the index which is a local copy
    /// useful for reading the slot without holding the lock.
    /// NOTE: its not safe to read the underlying data without holding the lock
    pub fn getReferenceSlot(self: *Self, pubkey: *const Pubkey, slot: Slot) ?AccountRef {
        var head_ref_rw = self.getReference(pubkey) orelse return null;
        const head_ref, var head_ref_lg = head_ref_rw.readWithLock();
        defer head_ref_lg.unlock();

        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const slot_ref = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break ref.*;
        } else null;

        return slot_ref;
    }

    pub fn exists(self: *Self, pubkey: *const Pubkey, slot: Slot) bool {
        var head_reference_rw = self.getReference(pubkey) orelse return false;
        const head_ref, var head_reference_lg = head_reference_rw.readWithLock();
        defer head_reference_lg.unlock();

        // find the slot in the reference list
        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const does_exists = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break true;
        } else false;

        return does_exists;
    }

    /// adds the reference to the index if there is not a duplicate (ie, the same slot).
    /// returns if the reference was inserted.
    pub fn indexRefIfNotDuplicateSlot(self: *Self, account_ref: *AccountRef) bool {
        const bin_rw = self.getBinFromPubkey(&account_ref.pubkey);

        const bin, var bin_lg = bin_rw.writeWithLock();
        const result = bin.getOrPutAssumeCapacity(account_ref.pubkey);
        bin_lg.unlock();

        if (result.found_existing) {
            // traverse until you find the end
            var head_ref_rw: AccountReferenceHead = result.value_ptr.*;
            const head_ref, var head_ref_lg = head_ref_rw.writeWithLock();
            defer head_ref_lg.unlock();

            var curr = head_ref.ref_ptr;
            while (true) {
                if (curr.slot == account_ref.slot) {
                    // found a duplicate => dont do the insertion
                    return false;
                } else if (curr.next_ptr == null) {
                    // end of the list => insert it here
                    curr.next_ptr = account_ref;
                    return true;
                } else {
                    // keep traversing
                    curr = curr.next_ptr.?;
                }
            }
        } else {
            result.value_ptr.* = AccountReferenceHead.init(.{ .ref_ptr = account_ref });
            return true;
        }
    }

    /// adds a reference to the index
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRef(self: *Self, account_ref: *AccountRef) void {
        const bin_rw = self.getBinFromPubkey(&account_ref.pubkey);

        const bin, var bin_lg = bin_rw.writeWithLock();
        const result = bin.getOrPutAssumeCapacity(account_ref.pubkey); // 1)

        if (result.found_existing) {
            // we can release the lock now
            bin_lg.unlock();

            // traverse until you find the end
            var head_ref_rw: AccountReferenceHead = result.value_ptr.*;
            const head_ref, var head_ref_lg = head_ref_rw.writeWithLock();
            defer head_ref_lg.unlock();

            var curr = head_ref.ref_ptr;
            while (true) {
                if (curr.next_ptr == null) { // 2)
                    curr.next_ptr = account_ref;
                    break;
                } else {
                    curr = curr.next_ptr.?;
                }
            }
        } else {
            result.value_ptr.* = AccountReferenceHead.init(.{ .ref_ptr = account_ref });
            bin_lg.unlock();
        }
    }

    pub fn updateReference(self: *Self, pubkey: *const Pubkey, slot: Slot, new_ref: *AccountRef) !void {
        var head_ref_rw = self.getReference(pubkey) orelse unreachable;
        const head_ref, var head_ref_lg = head_ref_rw.writeWithLock();
        var curr_ref = head_ref.ref_ptr;

        // 1) it relates to the head (we get a ptr and update directly)
        if (curr_ref.slot == slot) {
            const bin_rw = self.getBinFromPubkey(pubkey);
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();

            // NOTE: rn we have a stack copy of the head reference -- we need a pointer to modify it
            // so we release the head_lock so we can get a pointer -- because we need a pointer,
            // we also need a write lock on the bin itself to make sure the pointer isnt invalidated
            head_ref_lg.unlock();

            // NOTE: `getPtr` is important here vs `get` used above
            var head_reference_ptr_rw = bin.getPtr(pubkey.*) orelse unreachable;
            var head_ref_ptr, var head_ref_ptr_lg = head_reference_ptr_rw.writeWithLock();
            defer head_ref_ptr_lg.unlock();

            const head_next_ptr = head_ref_ptr.ref_ptr.next_ptr;
            // insert into linked list
            head_ref_ptr.ref_ptr = new_ref;
            new_ref.next_ptr = head_next_ptr;
        } else {
            defer head_ref_lg.unlock();

            // 2) it relates to a normal linked-list
            var prev_ref = curr_ref;
            curr_ref = curr_ref.next_ptr orelse return error.SlotNotFound;
            blk: while (true) {
                if (curr_ref.slot == slot) {
                    // update prev -> curr -> next
                    //    ==> prev -> new -> next
                    prev_ref.next_ptr = new_ref;
                    new_ref.next_ptr = curr_ref.next_ptr;
                    break :blk;
                } else {
                    // keep traversing
                    prev_ref = curr_ref;
                    curr_ref = curr_ref.next_ptr orelse return error.SlotNotFound;
                }
            }
        }
    }

    pub fn removeReference(self: *Self, pubkey: *const Pubkey, slot: Slot) error{ SlotNotFound, PubkeyNotFound }!void {
        // need to hold bin lock to update the head ptr value (need to hold a reference to it)

        const head_ref, var head_reference_lg = blk: {
            const bin_rw = self.getBinFromPubkey(pubkey);
            // NOTE: we only get a read since most of the time it will update the linked-list and not the head
            const bin, var bin_lg = bin_rw.readWithLock();
            defer bin_lg.unlock();

            var head_reference_rw = bin.get(pubkey.*) orelse return error.PubkeyNotFound;
            break :blk head_reference_rw.writeWithLock();
        };
        defer head_reference_lg.unlock();

        var curr_reference = head_ref.ref_ptr;

        // structure will always be: head -> [a] -> [b] -> [c]
        // 1) handle base case with head: head -> [a] -> [b] => head -> [b]
        // 2) handle normal linked-list case: [a] -> [b] -> [c]

        // 1) it relates to the head
        if (curr_reference.slot == slot) {
            const bin_rw = self.getBinFromPubkey(pubkey);
            const bin, var bin_lg = bin_rw.writeWithLock();
            defer bin_lg.unlock();

            if (curr_reference.next_ptr) |next_ptr| {
                // NOTE: rn we have a stack copy of the head reference -- we need a pointer to modify it
                // so we release the head_lock so we can get a pointer -- because we need a pointer,
                // we also need a write lock on the bin itself to make sure the pointer isnt invalidated
                // NOTE: `getPtr` is important here vs `get` used above
                var head_reference_ptr_rw = bin.getPtr(pubkey.*) orelse unreachable;
                // SAFE: we have a write lock on the bin
                // and the head reference already, we just need to access the ptr
                head_reference_ptr_rw.private.v.ref_ptr = next_ptr;
            } else {
                // head -> [a] => remove from hashmap
                bin.remove(pubkey.*) catch unreachable;
            }
        } else {
            // 2) it relates to a normal linked-list
            var previous_reference = curr_reference;
            curr_reference = curr_reference.next_ptr orelse return error.SlotNotFound;
            while (true) {
                if (curr_reference.slot == slot) {
                    previous_reference.next_ptr = curr_reference.next_ptr;
                    return;
                } else {
                    previous_reference = curr_reference;
                    curr_reference = curr_reference.next_ptr orelse return error.SlotNotFound;
                }
            }
        }
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.pubkey_bin_calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *RwMux(RefMap) {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *RwMux(RefMap) {
        const bin_index = self.pubkey_bin_calculator.binIndex(pubkey);
        return self.getBin(bin_index);
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }
};

pub inline fn pubkey_hash(key: Pubkey) u64 {
    return std.mem.readInt(u64, key.data[0..8], .little);
}

pub inline fn pubkey_eql(key1: Pubkey, key2: Pubkey) bool {
    return key1.equals(&key2);
}

pub const DiskMemoryConfig = struct {
    // path to where disk files will be stored
    dir_path: []const u8,
    // size of each bins' reference arraylist to preallocate
    capacity: usize,
};

pub const RamMemoryConfig = struct {
    // size of each bins' reference arraylist to preallocate
    capacity: usize = 0,
    // we found this leads to better 'append' performance vs GPA
    allocator: std.mem.Allocator = std.heap.page_allocator,
};

/// calculator to know which bin a pubkey belongs to
/// (since the index is sharded into bins).
///
/// Analogous to [PubkeyBinCalculator24](https://github.com/anza-xyz/agave/blob/c87f9cdfc98e80077f68a3d86aefbc404a1cb4d6/accounts-db/src/pubkey_bins.rs#L4)
pub const PubkeyBinCalculator = struct {
    n_bins: usize,
    shift_bits: u6,

    pub fn init(n_bins: usize) PubkeyBinCalculator {
        // u8 * 3 (ie, we consider on the first 3 bytes of a pubkey)
        const MAX_BITS: u32 = 24;
        // within bounds
        std.debug.assert(n_bins > 0);
        std.debug.assert(n_bins <= (1 << MAX_BITS));
        // power of two
        std.debug.assert((n_bins & (n_bins - 1)) == 0);
        // eg,
        // 8 bins
        // => leading zeros = 28
        // => shift_bits = (24 - (32 - 28 - 1)) = 21
        // ie,
        // if we have the first 24 bits set (u8 << 16, 8 + 16 = 24)
        // want to consider the first 3 bits of those 24
        // 0000 ... [100]0 0000 0000 0000 0000 0000
        // then we want to shift right by 21
        // 0000 ... 0000 0000 0000 0000 0000 0[100]
        // those 3 bits can represent 2^3 (= 8) bins
        const shift_bits = @as(u6, @intCast(MAX_BITS - (32 - @clz(@as(u32, @intCast(n_bins))) - 1)));

        return PubkeyBinCalculator{
            .n_bins = n_bins,
            .shift_bits = shift_bits,
        };
    }

    pub fn binIndex(self: *const PubkeyBinCalculator, pubkey: *const Pubkey) usize {
        const data = &pubkey.data;
        return (@as(usize, data[0]) << 16 |
            @as(usize, data[1]) << 8 |
            @as(usize, data[2])) >> self.shift_bits;
    }
};

/// thread safe disk memory allocator
pub const DiskMemoryAllocator = struct {
    filepath: []const u8,
    count: usize = 0,
    mux: std.Thread.Mutex = .{},

    const Self = @This();

    pub fn init(filepath: []const u8) Self {
        return Self{
            .filepath = filepath,
        };
    }

    /// deletes all allocated files + optionally frees the filepath with the allocator
    pub fn deinit(self: *Self, str_allocator: ?std.mem.Allocator) void {
        self.mux.lock();
        defer self.mux.unlock();

        // delete all files
        var buf: [1024]u8 = undefined;
        for (0..self.count) |i| {
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

        const count = blk: {
            self.mux.lock();
            defer self.mux.unlock();
            const c = self.count;
            self.count += 1;
            break :blk c;
        };

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

test "account index update/remove reference" {
    const allocator = std.testing.allocator;

    var index = try AccountIndex.init(allocator, allocator, 8);
    defer index.deinit(true);
    try index.ensureTotalCapacity(100);

    // pubkey -> a
    var ref_a = AccountRef.default();
    index.indexRef(&ref_a);

    var ref_b = AccountRef.default();
    ref_b.slot = 1;
    index.indexRef(&ref_b);

    // make sure indexRef works
    {
        var ref_head_rw = index.getReference(&ref_a.pubkey).?;
        const ref_head, var ref_head_lg = ref_head_rw.writeWithLock();
        ref_head_lg.unlock();
        _, const ref_max = ref_head.highestRootedSlot(10);
        try std.testing.expectEqual(1, ref_max);
    }

    // update the tail
    try std.testing.expect(ref_b.location == .Cache);
    var ref_b2 = ref_b;
    ref_b2.location = .{ .File = .{
        .file_id = FileId.fromInt(@intCast(1)),
        .offset = 10,
    } };
    try index.updateReference(&ref_b.pubkey, 1, &ref_b2);
    {
        const ref = index.getReferenceSlot(&ref_a.pubkey, 1).?;
        try std.testing.expect(ref.location == .File);
    }

    // update the head
    var ref_a2 = ref_a;
    ref_a2.location = .{ .File = .{
        .file_id = FileId.fromInt(1),
        .offset = 20,
    } };
    try index.updateReference(&ref_a.pubkey, 0, &ref_a2);
    {
        const ref = index.getReferenceSlot(&ref_a.pubkey, 0).?;
        try std.testing.expect(ref.location == .File);
    }

    // remove the head
    try index.removeReference(&ref_a2.pubkey, 0);
    try std.testing.expect(!index.exists(&ref_a2.pubkey, 0));
    try std.testing.expect(index.exists(&ref_b2.pubkey, 1));

    // remove the tail
    try index.removeReference(&ref_b2.pubkey, 1);
    try std.testing.expect(!index.exists(&ref_b2.pubkey, 1));
}

test "disk allocator on hashmaps" {
    var allocator = DiskMemoryAllocator.init("test_data/tmp");
    defer allocator.deinit(null);

    var refs = std.AutoHashMap(Pubkey, AccountRef).init(allocator.allocator());
    try refs.ensureTotalCapacity(100);

    var ref = AccountRef.default();
    ref.location.Cache.index = 2;
    ref.slot = 144;

    try refs.put(Pubkey.default(), ref);

    const r = refs.get(Pubkey.default()) orelse return error.MissingAccount;
    try std.testing.expect(std.meta.eql(r, ref));
}

test "disk allocator" {
    var allocator = DiskMemoryAllocator.init("test_data/tmp");

    var disk_account_refs = try std.ArrayList(AccountRef).initCapacity(
        allocator.allocator(),
        1,
    );
    defer disk_account_refs.deinit();

    var ref = AccountRef.default();
    ref.location.Cache.index = 2;
    ref.slot = 10;
    disk_account_refs.appendAssumeCapacity(ref);

    try std.testing.expect(std.meta.eql(disk_account_refs.items[0], ref));

    var ref2 = AccountRef.default();
    ref2.location.Cache.index = 4;
    ref2.slot = 14;
    // this will lead to another allocation
    try disk_account_refs.append(ref2);

    try std.testing.expect(std.meta.eql(disk_account_refs.items[0], ref));
    try std.testing.expect(std.meta.eql(disk_account_refs.items[1], ref2));

    // these should exist
    try std.fs.cwd().access("test_data/tmp_0", .{});
    try std.fs.cwd().access("test_data/tmp_1", .{});

    // this should delete them
    allocator.deinit(null);

    // these should no longer exist
    var did_error = false;
    std.fs.cwd().access("test_data/tmp_0", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
    did_error = false;
    std.fs.cwd().access("test_data/tmp_1", .{}) catch {
        did_error = true;
    };
    try std.testing.expect(did_error);
}
