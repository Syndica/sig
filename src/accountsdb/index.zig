//! all index related structs (account ref, simd hashmap, …)
const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const DiskMemoryAllocator = sig.utils.allocators.DiskMemoryAllocator;
const Pubkey = sig.core.pubkey.Pubkey;
const RwMux = sig.sync.RwMux;
const Slot = sig.core.time.Slot;

const FileId = sig.accounts_db.accounts_file.FileId;
const SwissMap = sig.accounts_db.swiss_map.SwissMap;

const Logger = sig.trace.Logger("accounts_db.index");

/// reference to an account (either in a file or in the unrooted_map)
pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,
    next_ptr: ?*AccountRef,
    // NOTE: used purely so that we can realloc slices of AccountRefs and fix up the next ptr.
    prev_ptr: ?*AccountRef = null,

    pub const ZEROES: AccountRef = .{
        .pubkey = Pubkey.ZEROES,
        .slot = 0,
        .location = .{ .unrooted_map = .{ .index = 0 } },
        .next_ptr = null,
        .prev_ptr = null,
    };

    /// Analogous to [StorageLocation](https://github.com/anza-xyz/agave/blob/b47a4ec74d85dae0b6d5dd24a13a8923240e03af/accounts-db/src/account_info.rs#L23)
    pub const AccountLocation = union(enum(u8)) {
        file: struct {
            file_id: FileId,
            offset: u64,

            pub const @"!bincode-config:file_id" = FileId.BincodeConfig;
        },
        unrooted_map: struct {
            index: u64,
        },
    };
};

/// stores the mapping from Pubkey to the account location (AccountRef)
///
/// Analogous to [AccountsIndex](https://github.com/anza-xyz/agave/blob/a6b2283142192c5360ad0f53bec1eb4a9fb36154/accounts-db/src/accounts_index.rs#L644)
pub const AccountIndex = struct {
    allocator: std.mem.Allocator,
    logger: Logger,

    /// map from Pubkey -> AccountRefHead
    pubkey_ref_map: ShardedPubkeyRefMap,
    /// map from slot -> []AccountRef
    slot_reference_map: RwMux(SlotRefMap),

    /// this is the allocator used to allocate reference_memory
    reference_allocator: ReferenceAllocator,
    /// manages reference memory throughout the life of the program (ie, manages the state of free/used AccountRefs)
    reference_manager: *sig.utils.allocators.RecycleBuffer(
        AccountRef,
        AccountRef.ZEROES,
        .{},
    ),

    pub const SlotRefMapValue = struct {
        refs: std.ArrayListUnmanaged(AccountRef),
    };

    // NOTE: this arraylist's memory is managed by the ReferenceManger - cannot use the allocator interface
    pub const SlotRefMap = std.AutoHashMap(Slot, SlotRefMapValue);
    pub const AllocatorConfig = union(Tag) {
        pub const Tag = ReferenceAllocator.Tag;
        ram: struct { allocator: std.mem.Allocator },
        disk: struct { accountsdb_dir: std.fs.Dir },
        parent: *ReferenceAllocator,
    };
    pub const GetAccountRefError = error{ SlotNotFound, PubkeyNotFound };

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        allocator_config: AllocatorConfig,
        /// number of shards for the pubkey_ref_map
        number_of_shards: usize,
    ) !Self {
        const reference_allocator: ReferenceAllocator = switch (allocator_config) {
            .ram => |ram| blk: {
                logger.info().logf("using ram memory for account index", .{});
                break :blk .{ .ram = ram.allocator };
            },
            .disk => |disk| blk: {
                var index_dir = try disk.accountsdb_dir.makeOpenPath("index", .{});
                errdefer index_dir.close();

                logger.info().logf(
                    "using disk memory (@{f}) for account index",
                    .{sig.utils.fmt.tryRealPath(index_dir, ".")},
                );

                const disk_allocator = try allocator.create(DiskMemoryAllocator);
                errdefer allocator.destroy(disk_allocator);
                disk_allocator.* = .{
                    .dir = index_dir,
                    .logger = logger.withScope(@typeName(DiskMemoryAllocator)),
                };

                const tracing_disk_allocator = try allocator.create(tracy.TracingAllocator);
                errdefer allocator.destroy(tracing_disk_allocator);
                tracing_disk_allocator.* = .{
                    .parent = disk_allocator.allocator(),
                    .name = "index",
                };

                break :blk .{
                    .disk = .{
                        .dma = disk_allocator,
                        .ptr_allocator = allocator,
                        .tracing = tracing_disk_allocator,
                    },
                };
            },
            .parent => |parent| blk: {
                logger.info().log("using parent's reference allocator for account index");
                break :blk .{ .parent = parent };
            },
        };
        errdefer reference_allocator.deinit();

        const reference_manager = try sig.utils.allocators.RecycleBuffer(
            AccountRef,
            AccountRef.ZEROES,
            .{},
        ).create(.{
            .memory_allocator = reference_allocator.get(),
            .records_allocator = allocator,
        });
        errdefer reference_manager.destroy();

        var pubkey_ref_map =
            try ShardedPubkeyRefMap.init(reference_allocator.get(), number_of_shards);
        errdefer pubkey_ref_map.deinit();
        return .{
            .allocator = allocator,
            .logger = logger,
            .pubkey_ref_map = pubkey_ref_map,
            .slot_reference_map = RwMux(SlotRefMap).init(SlotRefMap.init(allocator)),
            .reference_allocator = reference_allocator,
            .reference_manager = reference_manager,
        };
    }

    pub fn deinit(self: *Self) void {
        self.pubkey_ref_map.deinit();

        {
            const slot_reference_map, var slot_reference_map_lg =
                self.slot_reference_map.writeWithLock();
            defer slot_reference_map_lg.unlock();
            slot_reference_map.deinit();
        }

        self.reference_manager.destroy();
        self.reference_allocator.deinit();
    }

    pub fn deinitLoadingThread(self: *Self) void {
        self.pubkey_ref_map.deinit();
        {
            const slot_reference_map, var slot_reference_map_lg =
                self.slot_reference_map.writeWithLock();
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
    }

    pub fn expandRefCapacity(self: *Self, n: u64) !void {
        const zone = tracy.Zone.init(@src(), .{
            .name = "accountsdb AccountIndex.expandRefCapacity",
        });
        defer zone.deinit();

        try self.reference_manager.expandCapacity(n);
    }

    pub const ReferenceParent = union(enum) {
        head: *AccountReferenceHead,
        parent: *AccountRef,
    };

    /// Get a pointer to the account reference pointer with slot `slot` and pubkey `pubkey`,
    /// alongside the write lock guard for the parent shard, and thus by extension the account
    /// reference; this also locks access to all other account references in the parent shard.
    /// This can be used to update an account reference (ie by replacing the `*AccountRef`).
    pub fn getReferenceParent(
        self: *Self,
        pubkey: *const Pubkey,
        slot: Slot,
    ) GetAccountRefError!struct {
        ReferenceParent,
        ShardedPubkeyRefMap.ShardWriteLock,
    } {
        const head_ref, var head_ref_lg = self.pubkey_ref_map.getWrite(pubkey) orelse
            return error.PubkeyNotFound;
        errdefer head_ref_lg.unlock();

        const ref_parent: ReferenceParent = switch (head_ref.getParentRefOf(slot)) {
            .null => return error.SlotNotFound,
            .head => .{ .head = head_ref },
            .parent => |parent| .{ .parent = parent },
        };
        return .{ ref_parent, head_ref_lg };
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

    /// adds the reference to the index if there is not a duplicate (ie, the same slot).
    /// returns if the reference was inserted.
    pub fn indexRefIfNotDuplicateSlot(
        self: *Self,
        account_ref: *AccountRef,
    ) std.mem.Allocator.Error!bool {
        // NOTE: the lock on the shard also locks the reference map
        const shard_map, var shard_map_lg =
            self.pubkey_ref_map.getShard(&account_ref.pubkey).writeWithLock();
        defer shard_map_lg.unlock();

        if (shard_map.capacity() < shard_map.count() + 1) {
            // caller is generally expected to ensure capacity first
            self.logger.info().log("index: shard growing unexpectedly");
            try shard_map.ensureTotalCapacity(shard_map.capacity() + 1);
        }

        const map_entry = shard_map.getOrPutAssumeCapacity(account_ref.pubkey);
        if (!map_entry.found_existing) {
            map_entry.value_ptr.* = .{ .ref_ptr = account_ref };
            return true;
        }

        // traverse until you find the end
        var curr_ref = map_entry.value_ptr.ref_ptr;

        while (true) {
            if (curr_ref.slot == account_ref.slot) {
                return false;
            }
            const next_ptr = curr_ref.next_ptr orelse {
                // end of the list => insert it here
                account_ref.prev_ptr = curr_ref;
                curr_ref.next_ptr = account_ref;
                return true;
            };
            // keep traversing
            curr_ref = next_ptr;
        }
    }

    /// adds a reference to the index
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRefAssumeCapacity(
        self: *const Self,
        account_ref: *AccountRef,
    ) void {
        // NOTE: the lock on the shard also locks the reference map
        const pubkey_ref_map, var pubkey_ref_map_lg =
            self.pubkey_ref_map.getShard(&account_ref.pubkey).writeWithLock();
        defer pubkey_ref_map_lg.unlock();

        // init value if dne or append to end of the linked-list
        const map_entry = pubkey_ref_map.getOrPutAssumeCapacity(account_ref.pubkey);
        if (!map_entry.found_existing) {
            map_entry.value_ptr.* = .{ .ref_ptr = account_ref };
            return;
        }

        // traverse until you find the end
        var curr_ref = map_entry.value_ptr.ref_ptr;
        while (curr_ref.next_ptr) |next_ref| {
            curr_ref = next_ref;
        }

        account_ref.prev_ptr = curr_ref;
        curr_ref.next_ptr = account_ref;
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

    pub fn removeReference(
        self: *Self,
        pubkey: *const Pubkey,
        slot: Slot,
    ) error{ SlotNotFound, PubkeyNotFound }!void {
        const pubkey_ref_map, var pubkey_ref_map_lg =
            self.pubkey_ref_map.getShard(pubkey).writeWithLock();
        defer pubkey_ref_map_lg.unlock();

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
};

pub const AccountReferenceHead = struct {
    ref_ptr: *AccountRef,

    pub fn highestRootedSlot(
        self: *const AccountReferenceHead,
        rooted_slot_max: Slot,
    ) struct { usize, Slot } {
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
        const zone = tracy.Zone.init(@src(), .{ .name = "ShardedPubkeyRefMap.init" });
        defer zone.deinit();

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
        const zone = tracy.Zone.init(@src(), .{
            .name = "ShardedPubkeyRefMap.ensureTotalAdditionalCapacity",
        });
        defer zone.deinit();

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
    pub fn getRead(
        self: *Self,
        pubkey: *const Pubkey,
    ) ?struct { *AccountReferenceHead, ShardReadLock } {
        const shard_map, var shard_map_lg = self.getShard(pubkey).readWithLock();
        const ref_head_ptr = shard_map.getPtr(pubkey.*) orelse {
            shard_map_lg.unlock();
            return null;
        };
        return .{ ref_head_ptr, shard_map_lg };
    }

    /// Get a write-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same shard is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).write*(){.get(pubkey)}` directly.
    pub fn getWrite(
        self: *Self,
        pubkey: *const Pubkey,
    ) ?struct { *AccountReferenceHead, ShardWriteLock } {
        const shard_map, var shard_map_lg = self.getShard(pubkey).writeWithLock();
        const ref_head_ptr = shard_map.getPtr(pubkey.*) orelse {
            shard_map_lg.unlock();
            return null;
        };
        return .{ ref_head_ptr, shard_map_lg };
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
        const n_shards_u32: u32 = @intCast(n_shards);
        const shift_bits: u6 = @intCast(MAX_BITS - (32 - @clz(n_shards_u32) - 1));

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

pub const ReferenceAllocator = union(Tag) {
    pub const Tag = enum { ram, disk, parent };
    pub const Disk = struct {
        dma: *DiskMemoryAllocator,
        tracing: *tracy.TracingAllocator,
        // used for deinit() purposes
        ptr_allocator: std.mem.Allocator,
    };

    /// Used to AccountRef mmapped data on disk in ./index/bin (see see accountsdb/readme.md)
    ram: std.mem.Allocator,
    disk: Disk,
    /// used for loading threads to access the parent's
    parent: *ReferenceAllocator,

    pub fn get(self: ReferenceAllocator) std.mem.Allocator {
        return switch (self) {
            .disk => self.disk.tracing.allocator(),
            .ram => self.ram,
            .parent => self.parent.get(),
        };
    }

    pub fn deinit(self: ReferenceAllocator) void {
        switch (self) {
            .disk => |disk| {
                var dir = disk.dma.dir;
                dir.close();
                disk.ptr_allocator.destroy(disk.dma);
                disk.ptr_allocator.destroy(disk.tracing);
            },
            .ram => {},
            .parent => {},
        }
    }
};

test "account index update/remove reference" {
    const allocator = std.testing.allocator;

    var index = try AccountIndex.init(allocator, .noop, .{ .ram = .{ .allocator = allocator } }, 8);
    defer index.deinit();
    try index.expandRefCapacity(100);
    try index.pubkey_ref_map.ensureTotalCapacityPerShard(100);

    // pubkey -> a
    var ref_a = AccountRef.ZEROES;
    index.indexRefAssumeCapacity(&ref_a);

    var ref_b = AccountRef.ZEROES;
    ref_b.slot = 1;
    index.indexRefAssumeCapacity(&ref_b);

    // make sure indexRef works
    {
        const ref_head, var ref_head_lg = index.pubkey_ref_map.getRead(&ref_a.pubkey).?;
        defer ref_head_lg.unlock();
        _, const ref_max = ref_head.highestRootedSlot(10);
        try std.testing.expectEqual(1, ref_max);
    }

    // update the tail
    try std.testing.expect(ref_b.location == .unrooted_map);
    var ref_b2 = ref_b;
    ref_b2.location = .{ .file = .{
        .file_id = FileId.fromInt(@intCast(1)),
        .offset = 10,
    } };
    try index.updateReference(&ref_b.pubkey, 1, &ref_b2);
    {
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 1).?;
        try std.testing.expect(ref.location == .file);
    }

    // update the head
    var ref_a2 = ref_a;
    ref_a2.location = .{ .file = .{
        .file_id = FileId.fromInt(1),
        .offset = 20,
    } };
    try index.updateReference(&ref_a.pubkey, 0, &ref_a2);
    {
        const ref = index.getReferenceSlotCopy(&ref_a.pubkey, 0).?;
        try std.testing.expect(ref.location == .file);
    }

    // remove the head
    try index.removeReference(&ref_a2.pubkey, 0);
    try std.testing.expect(!index.exists(&ref_a2.pubkey, 0));
    try std.testing.expect(index.exists(&ref_b2.pubkey, 1));

    // remove the tail
    try index.removeReference(&ref_b2.pubkey, 1);
    try std.testing.expect(!index.exists(&ref_b2.pubkey, 1));
}
