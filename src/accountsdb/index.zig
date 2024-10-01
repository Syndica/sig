//! all index related structs (account ref, simd hashmap, …)
const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const FileId = sig.accounts_db.accounts_file.FileId;
const RwMux = sig.sync.RwMux;

pub const SwissMap = sig.accounts_db.swiss_map.SwissMap;
pub const SwissMapUnmanaged = sig.accounts_db.swiss_map.SwissMapUnmanaged;
pub const BenchHashMap = sig.accounts_db.swiss_map.BenchHashMap;
pub const BenchmarkSwissMap = sig.accounts_db.swiss_map.BenchmarkSwissMap;

pub const AccountReferenceHead = struct {
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
        CachedInLru,
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
    pub const RefMap = SwissMap(Pubkey, AccountReferenceHead, pubkey_hash, pubkey_eql);

    pub const GetAccountRefError = error{ SlotNotFound, PubkeyNotFound };

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

        const removed_kv = reference_memory.fetchRemove(slot) orelse return error.MemoryNotFound;
        removed_kv.value.deinit();
    }

    /// Get a read-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same bin is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).read*(){.get(pubkey)}` directly.
    pub fn getReferenceHeadRead(self: *Self, pubkey: *const Pubkey) ?struct { AccountReferenceHead, RwMux(RefMap).RLockGuard } {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).readWithLock();
        const ref_head = bin.get(pubkey.*) orelse {
            bin_lg.unlock();
            return null;
        };
        return .{ ref_head, bin_lg };
    }

    /// Get a write-safe account reference head, and its associated lock guard.
    /// If access to many different account reference heads which are potentially in the same bin is
    /// required, prefer instead to use `getBinFromPubkey(pubkey).write*(){.get(pubkey)}` directly.
    pub fn getReferenceHeadWrite(self: *Self, pubkey: *const Pubkey) ?struct { AccountReferenceHead, RwMux(RefMap).WLockGuard } {
        const bin, const bin_lg = self.getBinFromPubkey(pubkey).writeWithLock();
        const ref_head = bin.get(pubkey.*) orelse return null;
        return .{ ref_head, bin_lg };
    }

    pub const ReferenceParent = union(enum) {
        head: *AccountReferenceHead,
        parent: *AccountRef,
    };

    /// Get a pointer to the account reference pointer with slot `slot` and pubkey `pubkey`,
    /// alongside the write lock guard for the parent bin, and thus by extension the account
    /// reference; this also locks access to all other account references in the parent bin.
    /// This can be used to update an account reference (ie by replacing the `*AccountRef`).
    pub fn getReferenceParent(
        self: *const Self,
        pubkey: *const Pubkey,
        slot: Slot,
    ) GetAccountRefError!struct { ReferenceParent, RwMux(RefMap).WLockGuard } {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).writeWithLock();
        errdefer bin_lg.unlock();

        const head_ref = bin.getPtr(pubkey.*) orelse return error.PubkeyNotFound;
        const ref_parent: ReferenceParent = switch (head_ref.getParentRefOf(slot)) {
            .null => return error.SlotNotFound,
            .head => .{ .head = head_ref },
            .parent => |parent| .{ .parent = parent },
        };
        return .{ ref_parent, bin_lg };
    }

    /// returns a reference to the slot in the index which is a local copy
    /// useful for reading the slot without holding the lock.
    /// NOTE: its not safe to read the underlying data without holding the lock
    pub fn getReferenceSlotCopy(self: *Self, pubkey: *const Pubkey, slot: Slot) ?AccountRef {
        const head_ref, var head_ref_lg = self.getReferenceHeadRead(pubkey) orelse return null;
        defer head_ref_lg.unlock();

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
        const head_ref, var bin_lg = self.getReferenceHeadRead(pubkey) orelse return false;
        defer bin_lg.unlock();

        // find the slot in the reference list
        var curr_ref: ?*AccountRef = head_ref.ref_ptr;
        const does_exist = while (curr_ref) |ref| : (curr_ref = ref.next_ptr) {
            if (ref.slot == slot) break true;
        } else false;

        return does_exist;
    }

    /// adds the reference to the index if there is not a duplicate (ie, the same slot).
    /// returns if the reference was inserted.
    pub fn indexRefIfNotDuplicateSlotAssumeCapacity(self: *Self, account_ref: *AccountRef) bool {
        const bin, var bin_lg = self.getBinFromPubkey(&account_ref.pubkey).writeWithLock();
        defer bin_lg.unlock(); // the lock on the bin also locks the reference map

        const gop = bin.getOrPutAssumeCapacity(account_ref.pubkey);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .ref_ptr = account_ref };
            return true;
        }

        // traverse until you find the end
        const head_ref = gop.value_ptr.*;

        var curr = head_ref.ref_ptr;
        while (true) {
            if (curr.slot == account_ref.slot) {
                // found a duplicate => dont do the insertion
                return false;
            }

            const next_ptr = curr.next_ptr orelse {
                // end of the list => insert it here
                curr.next_ptr = account_ref;
                return true;
            };

            // keep traversing
            curr = next_ptr;
        }
    }

    /// adds a reference to the index
    /// NOTE: this should only be used when you know the reference does not exist
    /// because we never want duplicate state references in the index
    pub fn indexRefAssumeCapacity(
        self: *const Self,
        account_ref: *AccountRef,
    ) void {
        const bin, var bin_lg = self.getBinFromPubkey(&account_ref.pubkey).writeWithLock();
        defer bin_lg.unlock(); // the lock on the bin also locks the reference map

        const gop = bin.getOrPutAssumeCapacity(account_ref.pubkey); // 1)
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .ref_ptr = account_ref };
            return;
        }

        // traverse until you find the end
        const head_ref = gop.value_ptr.*;

        var curr_ref = head_ref.ref_ptr;
        while (curr_ref.next_ptr) |next_ref| {
            curr_ref = next_ref;
        }
        curr_ref.next_ptr = account_ref;
    }

    pub fn updateReference(
        self: *const Self,
        pubkey: *const Pubkey,
        slot: Slot,
        new_ref: *AccountRef,
    ) GetAccountRefError!void {
        const ref_parent, var bin_lg = try self.getReferenceParent(pubkey, slot);
        defer bin_lg.unlock();
        const ptr_to_ref_field = switch (ref_parent) {
            .head => |head| &head.ref_ptr,
            .parent => |parent| &parent.next_ptr.?,
        };
        std.debug.assert(ptr_to_ref_field.*.slot == slot);
        std.debug.assert(ptr_to_ref_field.*.pubkey.equals(pubkey));
        ptr_to_ref_field.* = new_ref;
    }

    pub fn removeReference(self: *Self, pubkey: *const Pubkey, slot: Slot) error{ SlotNotFound, PubkeyNotFound }!void {
        const bin, var bin_lg = self.getBinFromPubkey(pubkey).writeWithLock();
        defer bin_lg.unlock();

        const head_ref = bin.getPtr(pubkey.*) orelse return error.PubkeyNotFound;
        switch (head_ref.getParentRefOf(slot)) {
            .null => return error.SlotNotFound,
            .head => head_ref.ref_ptr = head_ref.ref_ptr.next_ptr orelse {
                _ = bin.remove(pubkey.*) catch |err| return switch (err) {
                    error.KeyNotFound => error.PubkeyNotFound,
                };
                return;
            },
            .parent => |parent| parent.next_ptr = if (parent.next_ptr) |ref| ref.next_ptr else null,
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

test "account index update/remove reference" {
    const allocator = std.testing.allocator;

    var index = try AccountIndex.init(allocator, allocator, 8);
    defer index.deinit(true);
    try index.ensureTotalCapacity(100);

    // pubkey -> a
    var ref_a = AccountRef.default();
    index.indexRefAssumeCapacity(&ref_a);

    var ref_b = AccountRef.default();
    ref_b.slot = 1;
    index.indexRefAssumeCapacity(&ref_b);

    // make sure indexRef works
    {
        const ref_head, var ref_head_lg = index.getReferenceHeadRead(&ref_a.pubkey).?;
        defer ref_head_lg.unlock();
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
