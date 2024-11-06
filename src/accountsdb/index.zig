//! all index related structs (account ref, simd hashmap, …)
const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const FileId = sig.accounts_db.accounts_file.FileId;
const RwMux = sig.sync.RwMux;
const SwissMap = sig.accounts_db.swiss_map.SwissMap;
const DiskMemoryAllocator = sig.utils.allocators.DiskMemoryAllocator;
const RecycleFBA = sig.utils.allocators.RecycleFBA;

/// reference to an account (either in a file or in the unrooted_map)
pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,
    // TODO(fastload): remove
    next_ptr: ?*AccountRef = null,
    next_index: ?u64 = null, // this points to the memory

    pub const DEFAULT: AccountRef = .{
        .pubkey = Pubkey.ZEROES,
        .slot = 0,
        .location = .{ .UnrootedMap = .{ .index = 0 } },
    };

    /// Analogous to [StorageLocation](https://github.com/anza-xyz/agave/blob/b47a4ec74d85dae0b6d5dd24a13a8923240e03af/accounts-db/src/account_info.rs#L23)
    pub const AccountLocation = union(enum(u8)) {
        File: struct {
            file_id: FileId,
            offset: usize,
        },
        UnrootedMap: struct {
            index: usize,
        },
    };
};

/// stores the mapping from Pubkey to the account location (AccountRef)
///
/// Analogous to [AccountsIndex](https://github.com/anza-xyz/agave/blob/a6b2283142192c5360ad0f53bec1eb4a9fb36154/accounts-db/src/accounts_index.rs#L644)
pub const AccountIndex = struct {
    allocator: std.mem.Allocator,
    /// map from Pubkey -> AccountRefHead
    pubkey_ref_map: ShardedPubkeyRefMap,
    /// map from Slot -> []AccountRef
    slot_reference_map: RwMux(SlotRefMap),

    /// this is the allocator used to allocate reference_memory
    reference_allocator: ReferenceAllocator,
    /// preallocated memory which is used by the reference_manager
    /// NOTE: we store this here to 1) read from a given index and 2) be able to free it on deinit
    reference_memory: std.ArrayList([]AccountRef),
    /// manages reference memory throughout the life of the program (ie, manages the state of free/used AccountRefs)
    reference_manager: *sig.utils.allocators.RecycleBuffer(AccountRef, .{}),

    pub const SlotRefMap = std.AutoHashMap(Slot, []AccountRef);
    pub const AllocatorConfig = union(enum) {
        Ram: struct { allocator: std.mem.Allocator },
        Disk: struct { accountsdb_dir: std.fs.Dir },
    };
    pub const GetAccountRefError = error{ SlotNotFound, PubkeyNotFound };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        allocator_config: AllocatorConfig,
        /// number of shards for the pubkey_ref_map
        number_of_shards: usize,
    ) !Self {
        const reference_allocator: ReferenceAllocator = switch (allocator_config) {
            .Ram => |ram| blk: {
                logger.info().logf("using ram memory for account index", .{});
                break :blk .{ .ram = ram.allocator };
            },
            .Disk => |disk| blk: {
                var index_dir = try disk.accountsdb_dir.makeOpenPath("index", .{});
                errdefer index_dir.close();
                const disk_allocator = try allocator.create(DiskMemoryAllocator);
                disk_allocator.* = .{ .dir = index_dir, .logger = logger };
                logger.info().logf("using disk memory (@{s}) for account index", .{sig.utils.fmt.tryRealPath(index_dir, ".")});
                break :blk .{ .disk = .{ .dma = disk_allocator, .ptr_allocator = allocator } };
            },
        };

        const reference_memory = std.ArrayList([]AccountRef).init(allocator);
        const reference_manager = try sig.utils.allocators.RecycleBuffer(AccountRef, .{}).create(allocator, &.{});

        return .{
            .allocator = allocator,
            .pubkey_ref_map = try ShardedPubkeyRefMap.init(allocator, number_of_shards),
            .slot_reference_map = RwMux(SlotRefMap).init(SlotRefMap.init(allocator)),
            .reference_allocator = reference_allocator,
            .reference_memory = reference_memory,
            .reference_manager = reference_manager,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pubkey_ref_map.deinit();

        {
            const slot_reference_map, var slot_reference_map_lg = self.slot_reference_map.writeWithLock();
            defer slot_reference_map_lg.unlock();
            slot_reference_map.deinit();
        }

        self.reference_manager.deinit();
        self.allocator.destroy(self.reference_manager);
        for (self.reference_memory.items) |ref_block| {
            self.reference_allocator.get().free(ref_block);
        }
        self.reference_memory.deinit();
        self.reference_allocator.deinit();
    }

    pub fn deinitLoadingThread(self: *Self) void {
        self.pubkey_ref_map.deinit();
        {
            const slot_reference_map, var slot_reference_map_lg = self.slot_reference_map.writeWithLock();
            defer slot_reference_map_lg.unlock();
            slot_reference_map.deinit();
        }

        // // this is the main index's manager
        // self.reference_manager.deinit();
        // self.allocator.destroy(self.reference_manager);
        // // dont free the references -- ownership is transferred to the main index
        // for (self.reference_memory) |ref_block| {
        //     self.reference_allocator.get().free(ref_block);
        // }
        // // the reference_allocator is the same as the main index's reference_allocator
        // self.reference_allocator.deinit();

        // the array list can be deinitialized, but the memory it holds not freed
        self.reference_memory.deinit();
    }

    pub fn ensureReferenceCapacity(self: *Self, capacity: u64) !void {
        if (self.reference_manager.capacity < capacity) {
            const alloc_size = capacity - self.reference_manager.capacity;
            const new_memory = try self.reference_allocator.get().alloc(AccountRef, alloc_size);
            // track for deinit
            try self.reference_memory.append(new_memory);
            // add to manager
            try self.reference_manager.append(new_memory);
        }
    }

    /// adds the reference to the index if there is not a duplicate (ie, the same slot).
    /// returns if the reference was inserted.
    pub fn indexRefIfNotDuplicateSlotAssumeCapacity(self: *Self, account_ref: *AccountRef, global_index: u64) bool {
        // NOTE: the lock on the shard also locks the reference map
        const shard_map, var lock = self.pubkey_ref_map.getShard(&account_ref.pubkey).writeWithLock();
        defer lock.unlock();

        // init value if dne or append to end of the linked-list
        const map_entry = shard_map.getOrPutAssumeCapacity(account_ref.pubkey);
        if (!map_entry.found_existing) {
            map_entry.value_ptr.* = .{ .ref_ptr = account_ref, .ref_index = global_index };
            return true;
        }

        // traverse until you find the end
        var curr_ref = map_entry.value_ptr.ref_ptr;
        while (true) {
            if (curr_ref.slot == account_ref.slot) {
                // found a duplicate => dont do the insertion
                return false;
            }
            const next_ptr = curr_ref.next_ptr orelse {
                // end of the list => insert it here
                curr_ref.next_ptr = account_ref; // TODO(fl): remove
                curr_ref.next_index = global_index;
                return true;
            };
            // keep traversing
            curr_ref = next_ptr;
        }
    }

    /// adds a reference to the index
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRefAssumeCapacity(self: *const Self, account_ref: *AccountRef, index: u64) void {
        // NOTE: the lock on the shard also locks the reference map
        const pubkey_ref_map, var lock = self.pubkey_ref_map.getShard(&account_ref.pubkey).writeWithLock();
        defer lock.unlock();

        // init value if dne or append to end of the linked-list
        const map_entry = pubkey_ref_map.getOrPutAssumeCapacity(account_ref.pubkey);
        if (!map_entry.found_existing) {
            map_entry.value_ptr.* = .{ .ref_ptr = account_ref, .ref_index = index };
            return;
        }

        // traverse until you find the end
        var curr_ref = map_entry.value_ptr.ref_ptr;
        if (@import("builtin").mode == .Debug and curr_ref.slot == account_ref.slot) {
            std.debug.panic("duplicate slot in index: {any} {any}", .{ account_ref, curr_ref });
        }
        while (account_ref.next_ptr) |next_ref| {
            // sanity check in debug mode
            if (@import("builtin").mode == .Debug and next_ref.slot == account_ref.slot) {
                std.debug.panic("duplicate slot in index: {any} {any}", .{ account_ref, next_ref });
            }
            curr_ref = next_ref;
        }
        curr_ref.next_ptr = account_ref;
        curr_ref.next_index = index;
    }

    pub fn getRef(self: *Self, index: u64) !*AccountRef {
        const nested_refs = sig.common.merkle_tree.NestedList(AccountRef){
            .items = self.reference_memory.items,
        };
        return nested_refs.getValue(index);
    }

    pub fn updateReference(
        self: *Self,
        pubkey: *const Pubkey,
        slot: Slot,
        new_ref: *AccountRef,
    ) GetAccountRefError!void {
        const ref_parent, var lock = try self.getReferenceParent(pubkey, slot);
        defer lock.unlock();

        const ptr_to_ref_field = switch (ref_parent) {
            .head => |head| &head.ref_ptr,
            .parent => |parent| &parent.next_ptr.?,
        };
        // sanity checks
        std.debug.assert(ptr_to_ref_field.*.slot == slot);
        std.debug.assert(ptr_to_ref_field.*.pubkey.equals(pubkey));
        // update
        ptr_to_ref_field.* = new_ref;
    }

    pub fn removeReference(self: *Self, pubkey: *const Pubkey, slot: Slot) error{ SlotNotFound, PubkeyNotFound }!void {
        const pubkey_ref_map, var lock = self.pubkey_ref_map.getShard(pubkey).writeWithLock();
        defer lock.unlock();

        const head_ref = pubkey_ref_map.getPtr(pubkey.*) orelse return error.PubkeyNotFound;
        switch (head_ref.getParentRefOf(slot)) {
            .null => return error.SlotNotFound,
            .head => head_ref.ref_ptr = head_ref.ref_ptr.next_ptr orelse {
                _ = pubkey_ref_map.remove(pubkey.*) catch |err| return switch (err) {
                    error.KeyNotFound => error.PubkeyNotFound,
                };
                return;
            },
            .parent => |parent| parent.next_ptr = if (parent.next_ptr) |ref| ref.next_ptr else null,
        }
    }

    pub fn exists(self: *Self, pubkey: *const Pubkey, slot: Slot) bool {
        const head_ref, var lock = self.pubkey_ref_map.getRead(pubkey) orelse return false;
        defer lock.unlock();

        // find the slot in the reference list
        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const does_exist = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break true;
        } else false;

        return does_exist;
    }

    pub const ReferenceParent = union(enum) {
        head: *AccountReferenceHead,
        parent: *AccountRef,
    };

    /// Get a pointer to the account reference pointer with slot `slot` and pubkey `pubkey`,
    /// alongside the write lock guard for the parent shard, and thus by extension the account
    /// reference; this also locks access to all other account references in the parent shard.
    /// This can be used to update an account reference (ie by replacing the `*AccountRef`).
    pub fn getReferenceParent(self: *Self, pubkey: *const Pubkey, slot: Slot) GetAccountRefError!struct {
        ReferenceParent,
        ShardedPubkeyRefMap.ShardWriteLock,
    } {
        const head_ref, var lock = self.pubkey_ref_map.getWrite(pubkey) orelse return error.PubkeyNotFound;
        errdefer lock.unlock();

        const ref_parent: ReferenceParent = switch (head_ref.getParentRefOf(slot)) {
            .null => return error.SlotNotFound,
            .head => .{ .head = head_ref },
            .parent => |parent| .{ .parent = parent },
        };
        return .{ ref_parent, lock };
    }

    /// returns a reference to the slot in the index which is a local copy
    /// useful for reading the slot without holding the lock.
    /// NOTE: its not safe to read the underlying data without holding the lock
    pub fn getReferenceSlotCopy(self: *Self, pubkey: *const Pubkey, slot: Slot) ?AccountRef {
        const head_ref, var lock = self.pubkey_ref_map.getRead(pubkey) orelse return null;
        defer lock.unlock();

        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        var slot_ref_copy: AccountRef = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break ref.*;
        } else return null;
        // since this will purely be a copy, it's safer to not allow the caller
        // to observe the `next_ptr` value, because they won't have the lock.
        slot_ref_copy.next_ptr = null;
        return slot_ref_copy;
    }
};

pub const AccountReferenceHead = struct {
    // TODO(fastload): remove
    ref_ptr: *AccountRef,
    ref_index: u64 = 0,

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

    pub const PtrToAccountRefField = union(enum) {
        null,
        head,
        parent: *AccountRef,
    };
    /// Returns a pointer to the account reference with a `next_ptr`
    /// field which is a pointer to the account reference pointer with
    /// a field `.slot` == `slot`.
    /// Returns `.null` if no account reference has said slot value.
    /// Returns `.head` if `head_ref.ref_ptr.slot == slot`.
    /// Returns `.parent = parent` if `parent.next_ptr.?.slot == slot`.
    pub inline fn getParentRefOf(
        head_ref: *const AccountReferenceHead,
        slot: Slot,
    ) PtrToAccountRefField {
        if (head_ref.ref_ptr.slot == slot) return .head;
        var curr_parent: *AccountRef = head_ref.ref_ptr;
        while (true) {
            const curr_ref = curr_parent.next_ptr orelse return .null;
            if (curr_ref.slot == slot) {
                return .{ .parent = curr_parent };
            }
            curr_parent = curr_ref;
        }
    }
};

pub const ShardedPubkeyRefMap = struct {
    allocator: std.mem.Allocator,
    // shard the pubkey map into shards to reduce lock contention
    shards: []RwPubkeyRefMap,
    shard_calculator: PubkeyShardCalculator,

    // map from pubkey -> account reference head (of linked list)
    pub const RwPubkeyRefMap = RwMux(PubkeyRefMap);
    pub const PubkeyRefMap = SwissMap(Pubkey, AccountReferenceHead, hash, eql);
    pub inline fn hash(key: Pubkey) u64 {
        return std.mem.readInt(u64, key.data[0..8], .little);
    }
    pub inline fn eql(key1: Pubkey, key2: Pubkey) bool {
        return key1.equals(&key2);
    }

    pub const ShardWriteLock = RwPubkeyRefMap.WLockGuard;
    pub const ShardReadLock = RwPubkeyRefMap.RLockGuard;

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, number_of_shards: u64) !Self {
        // shard the pubkey map into shards to reduce lock contention
        const shards = try allocator.alloc(RwPubkeyRefMap, number_of_shards);
        errdefer allocator.free(number_of_shards);
        @memset(shards, RwPubkeyRefMap.init(PubkeyRefMap.init(allocator)));

        const shard_calculator = PubkeyShardCalculator.init(number_of_shards);
        return .{
            .allocator = allocator,
            .shards = shards,
            .shard_calculator = shard_calculator,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.shards) |*shard_rw| {
            const shard, var shard_lg = shard_rw.writeWithLock();
            defer shard_lg.unlock();
            shard.deinit();
        }
        self.allocator.free(self.shards);
    }

    pub fn ensureTotalCapacity(self: *Self, shard_counts: []const u64) !void {
        if (shard_counts.len != self.shards.len) {
            return error.ShardSizeMismatch;
        }
        for (shard_counts, 0..) |count, index| {
            if (count > 0) {
                const shard_map, var lock = self.getShardFromIndex(index).writeWithLock();
                defer lock.unlock();
                try shard_map.ensureTotalCapacity(count);
            }
        }
    }

    pub fn ensureTotalAdditionalCapacity(self: *Self, shard_counts: []const u64) !void {
        if (shard_counts.len != self.shards.len) {
            return error.ShardSizeMismatch;
        }
        for (shard_counts, 0..) |count, index| {
            if (count > 0) {
                const shard_map, var lock = self.getShardFromIndex(index).writeWithLock();
                defer lock.unlock();
                // !
                try shard_map.ensureTotalCapacity(count + shard_map.count());
            }
        }
    }

    pub fn ensureTotalCapacityPerShard(self: *Self, size_per_shard: u32) !void {
        for (self.shards) |*shard_rw| {
            const shard, var shard_lg = shard_rw.writeWithLock();
            defer shard_lg.unlock();
            try shard.ensureTotalCapacity(size_per_shard);
        }
    }

    /// Get a read-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same shard is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).read*(){.get(pubkey)}` directly.
    pub fn getRead(self: *Self, pubkey: *const Pubkey) ?struct { *AccountReferenceHead, ShardReadLock } {
        const shard_map, var lock = self.getShard(pubkey).readWithLock();
        const ref_head_ptr = shard_map.getPtr(pubkey.*) orelse {
            lock.unlock();
            return null;
        };
        return .{ ref_head_ptr, lock };
    }

    /// Get a write-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same shard is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).write*(){.get(pubkey)}` directly.
    pub fn getWrite(self: *Self, pubkey: *const Pubkey) ?struct { *AccountReferenceHead, ShardWriteLock } {
        const shard_map, var lock = self.getShard(pubkey).writeWithLock();
        const ref_head_ptr = shard_map.getPtr(pubkey.*) orelse {
            lock.unlock();
            return null;
        };
        return .{ ref_head_ptr, lock };
    }

    pub fn getShardIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.shard_calculator.index(pubkey);
    }

    pub fn getShardFromIndex(self: *const Self, index: usize) *RwMux(PubkeyRefMap) {
        return &self.shards[index];
    }

    pub fn getShard(self: *const Self, pubkey: *const Pubkey) *RwMux(PubkeyRefMap) {
        return self.getShardFromIndex(self.getShardIndex(pubkey));
    }

    pub fn getShardCount(self: *const Self, index: u64) u64 {
        const shard, var lock = self.getShardFromIndex(index).readWithLock();
        defer lock.unlock();
        return shard.count();
    }

    pub fn numberOfShards(self: *const Self) usize {
        return self.shards.len;
    }
};

/// calculator to know which shard a pubkey belongs to
/// (since the index is sharded into shards).
///
/// Analogous to [PubkeyBinCalculator24](https://github.com/anza-xyz/agave/blob/c87f9cdfc98e80077f68a3d86aefbc404a1cb4d6/accounts-db/src/pubkey_bins.rs#L4)
pub const PubkeyShardCalculator = struct {
    n_shards: u64,
    shift_bits: u6,

    const Self = @This();

    pub fn init(n_shards: u64) Self {
        // u8 * 3 (ie, we consider on the first 3 bytes of a pubkey)
        const MAX_BITS: u32 = 24;
        // within bounds
        std.debug.assert(n_shards > 0);
        std.debug.assert(n_shards <= (1 << MAX_BITS));
        // power of two
        std.debug.assert((n_shards & (n_shards - 1)) == 0);
        // eg,
        // 8 shards
        // => leading zeros = 28
        // => shift_bits = (24 - (32 - 28 - 1)) = 21
        // ie,
        // if we have the first 24 bits set (u8 << 16, 8 + 16 = 24)
        // want to consider the first 3 bits of those 24
        // 0000 ... [100]0 0000 0000 0000 0000 0000
        // then we want to shift right by 21
        // 0000 ... 0000 0000 0000 0000 0000 0[100]
        // those 3 bits can represent 2^3 (= 8) shards
        const shift_bits = @as(u6, @intCast(MAX_BITS - (32 - @clz(@as(u32, @intCast(n_shards))) - 1)));

        return .{
            .n_shards = n_shards,
            .shift_bits = shift_bits,
        };
    }

    pub fn index(self: *const Self, pubkey: *const Pubkey) u64 {
        const data = &pubkey.data;
        return (@as(u64, data[0]) << 16 |
            @as(u64, data[1]) << 8 |
            @as(u64, data[2])) >> self.shift_bits;
    }
};

pub const ReferenceAllocator = union(enum) {
    /// Used to AccountRef mmapped data on disk in ./index/bin (see see accountsdb/readme.md)
    disk: struct {
        dma: *DiskMemoryAllocator,
        // used for deinit() purposes
        ptr_allocator: std.mem.Allocator,
    },
    ram: std.mem.Allocator,

    pub fn get(self: ReferenceAllocator) std.mem.Allocator {
        return switch (self) {
            .disk => self.disk.dma.allocator(),
            .ram => self.ram,
        };
    }

    pub fn deinit(self: *ReferenceAllocator) void {
        switch (self.*) {
            .disk => {
                self.disk.dma.dir.close();
                self.disk.ptr_allocator.destroy(self.disk.dma);
            },
            .ram => {},
        }
    }
};

test "account index update/remove reference" {
    const allocator = std.testing.allocator;

    var index = try AccountIndex.init(
        allocator,
        .noop,
        .{ .Ram = .{ .allocator = allocator } },
        8,
    );
    defer index.deinit();
    try index.ensureReferenceCapacity(100);
    try index.pubkey_ref_map.ensureTotalCapacityPerShard(100);

    // pubkey -> a
    var ref_a = AccountRef.DEFAULT;
    index.indexRefAssumeCapacity(&ref_a, 0);

    var ref_b = AccountRef.DEFAULT;
    ref_b.slot = 1;
    index.indexRefAssumeCapacity(&ref_b, 1);

    // make sure indexRef works
    {
        const ref_head, var ref_head_lg = index.pubkey_ref_map.getRead(&ref_a.pubkey).?;
        defer ref_head_lg.unlock();
        _, const ref_max = ref_head.highestRootedSlot(10);
        try std.testing.expectEqual(1, ref_max);
    }

    // update the tail
    try std.testing.expect(ref_b.location == .UnrootedMap);
    var ref_b2 = ref_b;
    ref_b2.location = .{ .File = .{
        .file_id = FileId.fromInt(@intCast(1)),
        .offset = 10,
    } };
    try index.updateReference(&ref_b.pubkey, 1, &ref_b2);
    {
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 1).?;
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
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 0).?;
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
