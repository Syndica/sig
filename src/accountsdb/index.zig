//! all index related structs (account ref, simd hashmap, …)

const std = @import("std");
const lib = @import("../lib.zig");

const ArrayList = std.ArrayList;
const Slot = lib.core.time.Slot;
const Pubkey = lib.core.pubkey.Pubkey;
const AccountFile = lib.accounts_db.accounts_file.AccountFile;
const FileId = lib.accounts_db.accounts_file.FileId;
const RwMux = lib.sync.RwMux;
const AccountInFile = lib.accounts_db.accounts_file.AccountInFile;

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
    calculator: PubkeyBinCalculator,

    pub const ReferenceMemory = std.AutoHashMap(Slot, ArrayList(AccountRef));
    pub const RefMap = SwissMap(Pubkey, AccountReferenceHead, pubkey_hash, pubkey_eql);

    const Self = @This();

    pub fn init(
        // used to allocate the hashmap data
        allocator: std.mem.Allocator,
        // used to allocate the references
        reference_allocator: std.mem.Allocator,
        // number of bins to shard across
        number_of_bins: usize,
    ) !Self {
        const bins = try allocator.alloc(RwMux(RefMap), number_of_bins);
        for (bins) |*bin| {
            bin.* = RwMux(RefMap).init(RefMap.init(allocator));
        }
        const calculator = PubkeyBinCalculator.init(number_of_bins);

        return Self{
            .allocator = allocator,
            .reference_allocator = reference_allocator,
            .bins = bins,
            .calculator = calculator,
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
            var reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
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

    pub fn putReferenceBlock(self: *Self, slot: Slot, references: ArrayList(AccountRef)) !void {
        var reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();
        try reference_memory.putNoClobber(slot, references);
    }

    pub fn freeReferenceBlock(self: *Self, slot: Slot) error{MemoryNotFound}!void {
        var reference_memory, var reference_memory_lg = self.reference_memory.writeWithLock();
        defer reference_memory_lg.unlock();

        if (!reference_memory.remove(slot)) {
            return error.MemoryNotFound;
        }
    }

    pub fn getReference(self: *Self, pubkey: *const Pubkey) ?AccountReferenceHead {
        const bin_rw = self.getBinFromPubkey(pubkey);
        const bin, var bin_lg = bin_rw.readWithLock();
        defer bin_lg.unlock();

        const ref_head_rw = bin.get(pubkey.*);
        return ref_head_rw;
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

    pub const ValidateAccountFileError = error{
        BinCountMismatch,
        InvalidAccountFileLength,
        OutOfReferenceMemory,
    } || AccountInFile.ValidateError;

    pub fn validateAccountFile(
        self: *Self,
        accounts_file: *AccountFile,
        bin_counts: []usize,
        account_refs: *ArrayList(AccountRef),
    ) ValidateAccountFileError!void {
        var offset: usize = 0;
        var number_of_accounts: usize = 0;

        if (bin_counts.len != self.numberOfBins()) {
            return error.BinCountMismatch;
        }

        while (true) {
            const account = accounts_file.readAccount(offset) catch break;
            try account.validate();

            account_refs.append(.{
                .pubkey = account.store_info.pubkey,
                .slot = accounts_file.slot,
                .location = .{
                    .File = .{
                        .file_id = accounts_file.id,
                        .offset = offset,
                    },
                },
            }) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfReferenceMemory,
            };

            const pubkey = &account.store_info.pubkey;
            const bin_index = self.getBinIndex(pubkey);
            bin_counts[bin_index] += 1;

            offset = offset + account.len;
            number_of_accounts += 1;
        }

        if (offset != std.mem.alignForward(usize, accounts_file.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }

        accounts_file.number_of_accounts = number_of_accounts;
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *RwMux(RefMap) {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *RwMux(RefMap) {
        const bin_index = self.calculator.binIndex(pubkey);
        return self.getBin(bin_index);
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }
};

/// custom hashmap used for the index's map
/// based on google's swissmap
pub fn SwissMap(
    comptime Key: type,
    comptime Value: type,
    comptime hash_fn: fn (Key) callconv(.Inline) u64,
    comptime eq_fn: fn (Key, Key) callconv(.Inline) bool,
) type {
    return struct {
        groups: [][GROUP_SIZE]KeyValue,
        states: []@Vector(GROUP_SIZE, u8),
        bit_mask: usize,
        // underlying memory
        memory: []u8,
        allocator: std.mem.Allocator,
        _count: usize = 0,
        _capacity: usize = 0,

        const GROUP_SIZE = 16;

        pub const Self = @This();

        pub const State = packed struct(u8) {
            state: enum(u1) { empty_or_deleted, occupied },
            control_bytes: u7,
        };

        // specific state/control_bytes values
        pub const EMPTY_STATE = State{
            .state = .empty_or_deleted,
            .control_bytes = 0b0000000,
        };
        pub const DELETED_STATE = State{
            .state = .empty_or_deleted,
            .control_bytes = 0b1111111,
        };
        pub const OCCUPIED_STATE = State{
            .state = .occupied,
            .control_bytes = 0,
        };

        const EMPTY_STATE_VEC: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(EMPTY_STATE));
        const DELETED_STATE_VEC: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(DELETED_STATE));
        const OCCUPIED_STATE_VEC: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(OCCUPIED_STATE));

        pub const KeyValue = struct {
            key: Key,
            value: Value,
        };

        pub const KeyValuePtr = struct {
            key_ptr: *Key,
            value_ptr: *Value,
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return Self{
                .allocator = allocator,
                .groups = undefined,
                .states = undefined,
                .memory = undefined,
                .bit_mask = 0,
            };
        }

        pub fn initCapacity(allocator: std.mem.Allocator, n: usize) !Self {
            var self = init(allocator);
            try self.ensureTotalCapacity(n);
            return self;
        }

        pub fn ensureTotalCapacity(self: *Self, n: usize) !void {
            if (n <= self._capacity) {
                return;
            }

            if (self._capacity == 0) {
                const n_groups = @max(std.math.pow(u64, 2, std.math.log2(n) + 1) / GROUP_SIZE, 1);
                const group_size = n_groups * @sizeOf([GROUP_SIZE]KeyValue);
                const ctrl_size = n_groups * @sizeOf([GROUP_SIZE]State);
                const size = group_size + ctrl_size;

                const memory = try self.allocator.alloc(u8, size);
                @memset(memory, 0);

                const group_ptr: [*][GROUP_SIZE]KeyValue = @alignCast(@ptrCast(memory.ptr));
                const groups = group_ptr[0..n_groups];
                const states_ptr: [*]@Vector(GROUP_SIZE, u8) = @alignCast(@ptrCast(memory.ptr + group_size));
                const states = states_ptr[0..n_groups];

                self._capacity = n_groups * GROUP_SIZE;
                std.debug.assert(self._capacity >= n);
                self.groups = groups;
                self.states = states;
                self.memory = memory;
                self.bit_mask = n_groups - 1;
            } else {
                // recompute the size
                const n_groups = @max(std.math.pow(u64, 2, std.math.log2(n) + 1) / GROUP_SIZE, 1);

                const group_size = n_groups * @sizeOf([GROUP_SIZE]KeyValue);
                const ctrl_size = n_groups * @sizeOf([GROUP_SIZE]State);
                const size = group_size + ctrl_size;

                const memory = try self.allocator.alloc(u8, size);
                @memset(memory, 0);

                const group_ptr: [*][GROUP_SIZE]KeyValue = @alignCast(@ptrCast(memory.ptr));
                const groups = group_ptr[0..n_groups];
                const states_ptr: [*]@Vector(GROUP_SIZE, u8) = @alignCast(@ptrCast(memory.ptr + group_size));
                const states = states_ptr[0..n_groups];

                var new_self = Self{
                    .allocator = self.allocator,
                    .groups = groups,
                    .states = states,
                    .memory = memory,
                    .bit_mask = n_groups - 1,
                    ._capacity = n_groups * GROUP_SIZE,
                };

                var iter = self.iterator();
                while (iter.next()) |kv| {
                    new_self.putAssumeCapacity(kv.key_ptr.*, kv.value_ptr.*);
                }

                self.deinit(); // release old memory

                self._capacity = new_self._capacity;
                self.groups = new_self.groups;
                self.states = new_self.states;
                self.memory = new_self.memory;
                self.bit_mask = new_self.bit_mask;
            }
        }

        pub fn deinit(self: *Self) void {
            if (self._capacity > 0) {
                self.allocator.free(self.memory);
            }
        }

        pub const Iterator = struct {
            hm: *const Self,
            group_index: usize = 0,
            position: usize = 0,

            pub fn next(it: *Iterator) ?KeyValuePtr {
                const self = it.hm;

                if (self.capacity() == 0) return null;

                while (true) {
                    if (it.group_index == self.groups.len) {
                        return null;
                    }

                    const state_vec = self.states[it.group_index];

                    const occupied_states = state_vec & OCCUPIED_STATE_VEC;
                    if (@reduce(.Or, occupied_states) != 0) {
                        for (it.position..GROUP_SIZE) |j| {
                            defer it.position += 1;
                            if (occupied_states[j] != 0) {
                                return .{
                                    .key_ptr = &self.groups[it.group_index][j].key,
                                    .value_ptr = &self.groups[it.group_index][j].value,
                                };
                            }
                        }
                    }
                    it.position = 0;
                    it.group_index += 1;
                }
            }
        };

        /// simd helper function to OR two bool vectors
        pub fn orSIMD(a: @Vector(GROUP_SIZE, bool), b: @Vector(GROUP_SIZE, bool)) @Vector(GROUP_SIZE, bool) {
            const is_a: @Vector(GROUP_SIZE, u8) = @intFromBool(a);
            const is_b: @Vector(GROUP_SIZE, u8) = @intFromBool(b);
            const ones: @Vector(GROUP_SIZE, u8) = @splat(1);
            const a_or_b: @Vector(GROUP_SIZE, bool) = (is_a | is_b) == ones;
            return a_or_b;
        }

        /// simd helper function to AND two bool vectors
        pub fn andSIMD(a: @Vector(GROUP_SIZE, bool), b: @Vector(GROUP_SIZE, bool)) @Vector(GROUP_SIZE, bool) {
            const is_a: @Vector(GROUP_SIZE, u8) = @intFromBool(a);
            const is_b: @Vector(GROUP_SIZE, u8) = @intFromBool(b);
            const ones: @Vector(GROUP_SIZE, u8) = @splat(1);
            const a_and_b: @Vector(GROUP_SIZE, bool) = (is_a & is_b) == ones;
            return a_and_b;
        }

        pub fn iterator(self: *const @This()) Iterator {
            return .{ .hm = self };
        }

        pub inline fn count(self: *const @This()) usize {
            return self._count;
        }

        pub inline fn capacity(self: *const @This()) usize {
            return self._capacity;
        }

        pub const GetOrPutResult = struct {
            found_existing: bool,
            value_ptr: *Value,
        };

        pub fn remove(self: *@This(), key: Key) error{KeyNotFound}!void {
            if (self._capacity == 0) return error.KeyNotFound;
            const hash = hash_fn(key);
            var group_index = hash & self.bit_mask;

            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const key_vec: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));

            for (0..self.groups.len) |_| {
                const state_vec = self.states[group_index];

                const match_vec = key_vec == state_vec;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        // remove here
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            //
                            // search works by searching each group starting from group_index until an empty state is found
                            // because if theres an empty state, the key DNE
                            //
                            // if theres an empty state in this group already, then the search would early exit anyway,
                            // so we can change this state to 'empty' as well.
                            //
                            // if theres no empty state in this group, then there could be additional keys in a higher group,
                            // which if we changed this state to empty would cause the search to early exit,
                            // so we need to change this state to 'deleted'.
                            //
                            const new_state = if (@reduce(.Or, EMPTY_STATE_VEC == state_vec)) EMPTY_STATE else DELETED_STATE;
                            self.states[group_index][j] = @bitCast(new_state);
                            self._count -= 1;
                            return;
                        }
                    }
                }

                // if theres a free state, then the key DNE
                const is_empty_vec = EMPTY_STATE_VEC == state_vec;
                if (@reduce(.Or, is_empty_vec)) {
                    return error.KeyNotFound;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }

            return error.KeyNotFound;
        }

        pub fn get(self: *const @This(), key: Key) ?Value {
            if (self.getPtr(key)) |ptr| {
                return ptr.*;
            } else {
                return null;
            }
        }

        pub fn getPtr(self: *const @This(), key: Key) ?*Value {
            if (self._capacity == 0) return null;

            const hash = hash_fn(key);
            var group_index = hash & self.bit_mask;

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            // PERF: this struct is represented by a u8
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const key_vec: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));

            for (0..self.groups.len) |_| {
                const state_vec = self.states[group_index];

                // PERF: SIMD eq check: search for a match
                const match_vec = key_vec == state_vec;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        // PERF: SIMD eq check across pubkeys
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            return &self.groups[group_index][j].value;
                        }
                    }
                }

                // PERF: SIMD eq check: if theres a free state, then the key DNE
                const is_empty_vec = EMPTY_STATE_VEC == state_vec;
                if (@reduce(.Or, is_empty_vec)) {
                    return null;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            return null;
        }

        /// puts a key into the index with the value
        /// note: this assumes the key is not already in the index, if it is, then
        /// the map might contain two keys, and the behavior is undefined
        pub fn putAssumeCapacity(self: *Self, key: Key, value: Value) void {
            const hash = hash_fn(key);
            var group_index = hash & self.bit_mask;
            std.debug.assert(self._capacity > self._count);

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };

            for (0..self.groups.len) |_| {
                const state_vec = self.states[group_index];

                // if theres an free then insert
                // note: if theres atleast on empty state, then there wont be any deleted states
                // due to how remove works, so we dont need to prioritize deleted over empty
                const is_free_vec = ~state_vec & OCCUPIED_STATE_VEC;
                if (@reduce(.Or, is_free_vec) != 0) {
                    _ = self.fill(
                        key,
                        value,
                        key_state,
                        group_index,
                        is_free_vec == @as(@Vector(GROUP_SIZE, u8), @splat(1)),
                    );
                    return;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            unreachable;
        }

        /// fills a group with a key value and increments count
        /// where the fill index requires is_free_vec[index] == true
        fn fill(
            self: *Self,
            key: Key,
            value: Value,
            key_state: State,
            group_index: usize,
            is_free_vec: @Vector(GROUP_SIZE, bool),
        ) usize {
            const invalid_state: @Vector(GROUP_SIZE, u8) = @splat(GROUP_SIZE);
            const indices = @select(u8, is_free_vec, std.simd.iota(u8, GROUP_SIZE), invalid_state);
            const index = @reduce(.Min, indices);

            self.groups[group_index][index] = .{
                .key = key,
                .value = value,
            };
            self.states[group_index][index] = @bitCast(key_state);
            self._count += 1;

            return index;
        }

        pub fn getOrPutAssumeCapacity(self: *Self, key: Key) GetOrPutResult {
            const hash = hash_fn(key);
            var group_index = hash & self.bit_mask;

            std.debug.assert(self._capacity > self._count);

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const key_vec: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));

            for (0..self.groups.len) |_| {
                const state_vec = self.states[group_index];

                // SIMD eq search for a match (get)
                const match_vec = key_vec == state_vec;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            return .{
                                .found_existing = true,
                                .value_ptr = &self.groups[group_index][j].value,
                            };
                        }
                    }
                }

                // note: we cant insert into deleted states because
                // the value of the `get` part of this function - and
                // because the key might exist in another group
                const is_empty_vec = EMPTY_STATE_VEC == state_vec;
                if (@reduce(.Or, is_empty_vec)) {
                    const index = self.fill(
                        key,
                        undefined,
                        key_state,
                        group_index,
                        is_empty_vec,
                    );
                    return .{
                        .found_existing = false,
                        .value_ptr = &self.groups[group_index][index].value,
                    };
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            unreachable;
        }
    };
}

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

test "swissmap resize" {
    var map = SwissMap(Pubkey, AccountRef, pubkey_hash, pubkey_eql).init(std.testing.allocator);
    defer map.deinit();

    try map.ensureTotalCapacity(100);

    const ref = AccountRef.default();
    map.putAssumeCapacity(Pubkey.default(), ref);

    // this will resize the map with the key still in there
    try map.ensureTotalCapacity(200);
    const get_ref = map.get(Pubkey.default()) orelse return error.MissingAccount;
    try std.testing.expect(std.meta.eql(get_ref, ref));
}

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

    var disk_account_refs = try ArrayList(AccountRef).initCapacity(
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

test "swissmap read/write/delete" {
    const allocator = std.testing.allocator;

    const n_accounts = 10_000;
    const account_refs, const pubkeys = try generateData(allocator, n_accounts);
    defer {
        allocator.free(account_refs);
        allocator.free(pubkeys);
    }

    var map = try SwissMap(
        Pubkey,
        *AccountRef,
        pubkey_hash,
        pubkey_eql,
    ).initCapacity(allocator, n_accounts);
    defer map.deinit();

    // write all
    for (0..account_refs.len) |i| {
        const result = map.getOrPutAssumeCapacity(account_refs[i].pubkey);
        try std.testing.expect(!result.found_existing); // shouldnt be found
        result.value_ptr.* = &account_refs[i];
    }

    // read all - slots should be the same
    for (0..account_refs.len) |i| {
        const result = map.getOrPutAssumeCapacity(pubkeys[i]);
        try std.testing.expect(result.found_existing); // should be found
        try std.testing.expectEqual(result.value_ptr.*.slot, account_refs[i].slot);
    }

    // remove half
    for (0..account_refs.len / 2) |i| {
        try map.remove(pubkeys[i]);
    }

    // read removed half
    for (0..account_refs.len / 2) |i| {
        const result = map.get(pubkeys[i]);
        try std.testing.expect(result == null);
    }

    // read remaining half
    for (account_refs.len / 2..account_refs.len) |i| {
        const result = map.get(pubkeys[i]);
        try std.testing.expect(result != null);
        try std.testing.expectEqual(result.?.slot, account_refs[i].slot);
    }
}

test "swissmap read/write" {
    const allocator = std.testing.allocator;

    const n_accounts = 10_000;
    const account_refs, const pubkeys = try generateData(allocator, n_accounts);
    defer {
        allocator.free(account_refs);
        allocator.free(pubkeys);
    }

    var map = try SwissMap(
        Pubkey,
        *AccountRef,
        pubkey_hash,
        pubkey_eql,
    ).initCapacity(allocator, n_accounts);
    defer map.deinit();

    // write all
    for (0..account_refs.len) |i| {
        const result = map.getOrPutAssumeCapacity(account_refs[i].pubkey);
        try std.testing.expect(!result.found_existing); // shouldnt be found
        result.value_ptr.* = &account_refs[i];
    }

    // read all - slots should be the same
    for (0..account_refs.len) |i| {
        const result = map.getOrPutAssumeCapacity(pubkeys[i]);
        try std.testing.expect(result.found_existing); // should be found
        try std.testing.expectEqual(result.value_ptr.*.slot, account_refs[i].slot);
    }
}

fn generateData(allocator: std.mem.Allocator, n_accounts: usize) !struct {
    []AccountRef,
    []Pubkey,
} {
    var random = std.Random.DefaultPrng.init(0);
    const rng = random.random();

    const accounts = try allocator.alloc(AccountRef, n_accounts);
    const pubkeys = try allocator.alloc(Pubkey, n_accounts);
    for (0..n_accounts) |i| {
        rng.bytes(&pubkeys[i].data);
        accounts[i] = AccountRef.default();
        accounts[i].pubkey = pubkeys[i];
    }
    rng.shuffle(Pubkey, pubkeys);

    return .{ accounts, pubkeys };
}

pub const BenchmarkSwissMap = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 1;

    pub const BenchArgs = struct {
        n_accounts: usize,
        name: []const u8 = "",
    };

    pub const args = [_]BenchArgs{
        BenchArgs{
            .n_accounts = 100_000,
            .name = "100k accounts",
        },
        BenchArgs{
            .n_accounts = 500_000,
            .name = "500k accounts",
        },
        BenchArgs{
            .n_accounts = 1_000_000,
            .name = "1m accounts",
        },
    };

    pub fn swissmapReadWriteBenchmark(bench_args: BenchArgs) !u64 {
        const allocator = std.heap.page_allocator;
        const n_accounts = bench_args.n_accounts;

        const accounts, const pubkeys = try generateData(allocator, n_accounts);

        const write_time, const read_time = try benchGetOrPut(
            SwissMap(Pubkey, *AccountRef, pubkey_hash, pubkey_eql),
            allocator,
            accounts,
            pubkeys,
            null,
        );

        // this is what we compare the swiss map to
        // this type was the best one I could find
        const InnerT = std.HashMap(Pubkey, *AccountRef, struct {
            pub fn hash(self: @This(), key: Pubkey) u64 {
                _ = self;
                return pubkey_hash(key);
            }
            pub fn eql(self: @This(), key1: Pubkey, key2: Pubkey) bool {
                _ = self;
                return pubkey_eql(key1, key2);
            }
        }, std.hash_map.default_max_load_percentage);

        const std_write_time, const std_read_time = try benchGetOrPut(
            BenchHashMap(InnerT),
            allocator,
            accounts,
            pubkeys,
            null,
        );

        const write_speedup = @as(f32, @floatFromInt(std_write_time)) / @as(f32, @floatFromInt(write_time));
        const write_faster_or_slower = if (write_speedup < 1.0) "slower" else "faster";
        std.debug.print("\tWRITE: {} ({d:.2}x {s} than std)\n", .{
            std.fmt.fmtDuration(write_time),
            write_speedup,
            write_faster_or_slower,
        });

        const read_speedup = @as(f32, @floatFromInt(std_read_time)) / @as(f32, @floatFromInt(read_time));
        const read_faster_or_slower = if (read_speedup < 1.0) "slower" else "faster";
        std.debug.print("\tREAD: {} ({d:.2}x {s} than std)\n", .{
            std.fmt.fmtDuration(read_time),
            read_speedup,
            read_faster_or_slower,
        });

        return write_time;
    }
};

fn benchGetOrPut(
    comptime T: type,
    allocator: std.mem.Allocator,
    accounts: []AccountRef,
    pubkeys: []Pubkey,
    read_amount: ?usize,
) !struct { usize, usize } {
    var t = try T.initCapacity(allocator, accounts.len);

    var timer = try std.time.Timer.start();
    for (0..accounts.len) |i| {
        const result = t.getOrPutAssumeCapacity(accounts[i].pubkey);
        if (!result.found_existing) {
            result.value_ptr.* = &accounts[i];
        } else {
            std.debug.panic("found something that shouldn't exist", .{});
        }
    }
    const write_time = timer.read();
    timer.reset();

    var count: usize = 0;
    const read_len = read_amount orelse accounts.len;
    for (0..read_len) |i| {
        const result = t.getOrPutAssumeCapacity(pubkeys[i]);
        if (result.found_existing) {
            count += result.value_ptr.*.slot;
        } else {
            std.debug.panic("not found", .{});
        }
    }
    std.mem.doNotOptimizeAway(count);
    const read_time = timer.read();

    return .{ write_time, read_time };
}

pub fn BenchHashMap(T: type) type {
    return struct {
        inner: T,

        // other T types that might be useful
        // const T = std.AutoHashMap(Pubkey, *AccountRef);
        // const T = std.AutoArrayHashMap(Pubkey, *AccountRef);
        // const T = std.ArrayHashMap(Pubkey, *AccountRef, struct {
        //     pub fn hash(self: @This(), key: Pubkey) u32 {
        //         _ = self;
        //         return std.mem.readIntLittle(u32, key[0..4]);
        //     }
        //     pub fn eql(self: @This(), key1: Pubkey, key2: Pubkey, b_index: usize) bool {
        //         _ = b_index;
        //         _ = self;
        //         return equals(key1, key2);
        //     }
        // }, false);

        pub fn initCapacity(allocator: std.mem.Allocator, n: usize) !@This() {
            var refs = T.init(allocator);
            try refs.ensureTotalCapacity(@intCast(n));
            return @This(){ .inner = refs };
        }

        pub fn write(self: *@This(), accounts: []AccountRef) !void {
            for (0..accounts.len) |i| {
                self.inner.putAssumeCapacity(accounts[i].pubkey, accounts[i]);
            }
        }

        pub fn read(self: *@This(), pubkey: *Pubkey) !usize {
            if (self.inner.get(pubkey.*)) |acc| {
                return 1 + @as(usize, @intCast(acc.offset));
            } else {
                unreachable;
            }
        }

        pub fn getOrPutAssumeCapacity(self: *@This(), pubkey: Pubkey) T.GetOrPutResult {
            const result = self.inner.getOrPutAssumeCapacity(pubkey);
            return result;
        }
    };
}
