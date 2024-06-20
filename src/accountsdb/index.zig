//! all index related structs (account ref, simd hashmap, …)

const std = @import("std");
const ArrayList = std.ArrayList;
const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const AccountFile = @import("accounts_file.zig").AccountFile;
const FileId = @import("accounts_file.zig").FileId;

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
    bins: []RefMap,
    calculator: PubkeyBinCalculator,
    // TODO: use arena allocator ontop of reference allocator ...
    memory_linked_list: ?*RefMemoryLinkedList = null,

    pub const RefMap = SwissMap(Pubkey, *AccountRef, pubkey_hash, pubkey_eql);

    const Self = @This();

    pub fn init(
        // used to allocate the hashmap data
        allocator: std.mem.Allocator,
        // used to allocate the references
        reference_allocator: std.mem.Allocator,
        // number of bins to shard across
        number_of_bins: usize,
    ) !Self {
        const bins = try allocator.alloc(RefMap, number_of_bins);
        for (bins) |*bin| {
            bin.* = RefMap.init(allocator);
        }
        const calculator = PubkeyBinCalculator.init(number_of_bins);

        return Self{
            .allocator = allocator,
            .reference_allocator = reference_allocator,
            .bins = bins,
            .calculator = calculator,
        };
    }

    pub fn deinit(self: *Self, free_memory: bool) void {
        for (self.bins) |*bin| {
            bin.deinit();
        }
        self.allocator.free(self.bins);

        var maybe_curr = self.memory_linked_list;
        while (maybe_curr) |curr| {
            if (free_memory) {
                curr.memory.deinit();
            }
            maybe_curr = curr.next_ptr;
            self.allocator.destroy(curr);
        }
    }

    pub fn addMemoryBlock(self: *Self, refs: ArrayList(AccountRef)) !*ArrayList(AccountRef) {
        var node = try self.allocator.create(RefMemoryLinkedList);
        node.* = .{ .memory = refs };
        if (self.memory_linked_list == null) {
            self.memory_linked_list = node;
        } else {
            var tail = self.memory_linked_list.?;
            while (tail.next_ptr) |ptr| {
                tail = ptr;
            }
            tail.next_ptr = node;
        }

        return &node.memory;
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *RefMap {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *RefMap {
        const bin_index = self.calculator.binIndex(pubkey);
        return &self.bins[bin_index];
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }

    /// adds the reference to the index if there is not a duplicate (ie, the same slot)
    pub fn indexRefIfNotDuplicateSlot(self: *Self, account_ref: *AccountRef) bool {
        const bin = self.getBinFromPubkey(&account_ref.pubkey);
        const result = bin.getOrPutAssumeCapacity(account_ref.pubkey);
        if (result.found_existing) {
            // traverse until you find the end
            var curr: *AccountRef = result.value_ptr.*;
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
            result.value_ptr.* = account_ref;
            return true;
        }
    }

    /// adds a reference to the index
    pub fn indexRef(self: *Self, account_ref: *AccountRef) void {
        const bin = self.getBinFromPubkey(&account_ref.pubkey);
        const result = bin.getOrPutAssumeCapacity(account_ref.pubkey); // 1)
        if (result.found_existing) {
            // traverse until you find the end
            var curr: *AccountRef = result.value_ptr.*;
            while (true) {
                if (curr.next_ptr == null) { // 2)
                    curr.next_ptr = account_ref;
                    break;
                } else {
                    curr = curr.next_ptr.?;
                }
            }
        } else {
            result.value_ptr.* = account_ref;
        }
    }

    pub fn validateAccountFile(
        self: *Self,
        accounts_file: *AccountFile,
        bin_counts: []usize,
        account_refs: *ArrayList(AccountRef),
    ) !void {
        var offset: usize = 0;
        var number_of_accounts: usize = 0;

        if (bin_counts.len != self.numberOfBins()) {
            return error.BinCountMismatch;
        }

        while (true) {
            const account = accounts_file.readAccount(offset) catch break;
            try account.validate();

            try account_refs.append(.{
                .pubkey = account.store_info.pubkey,
                .slot = accounts_file.slot,
                .location = .{
                    .File = .{
                        .file_id = FileId.fromInt(@intCast(accounts_file.id)),
                        .offset = offset,
                    },
                },
            });

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
            state: enum(u1) { empty, occupied },
            control_bytes: u7,
        };

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
                const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

                if (self.capacity() == 0) return null;

                while (true) {
                    if (it.group_index == self.groups.len) {
                        return null;
                    }

                    const states = self.states[it.group_index];
                    const occupied_states = free_state != states;

                    if (@reduce(.Or, occupied_states)) {
                        for (it.position..GROUP_SIZE) |j| {
                            defer it.position += 1;
                            if (occupied_states[j]) {
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

        pub fn get(self: *const @This(), key: Key) ?Value {
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
            const search_state: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                const states = self.states[group_index];

                // PERF: SIMD eq check: search for a match
                const match_vec = search_state == states;
                if (@reduce(.Or, match_vec)) {
                    inline for (0..GROUP_SIZE) |j| {
                        // PERF: SIMD eq check across pubkeys
                        if (match_vec[j] and eq_fn(self.groups[group_index][j].key, key)) {
                            return self.groups[group_index][j].value;
                        }
                    }
                }

                // PERF: SIMD eq check: if theres a free state, then the key DNE
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    return null;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            return null;
        }

        pub fn putAssumeCapacity(self: *Self, key: Key, value: Value) void {
            const hash = hash_fn(key);
            var group_index = hash & self.bit_mask;
            std.debug.assert(self._capacity > self._count);

            // what we are searching for (get)
            const control_bytes: u7 = @intCast(hash >> (64 - 7));
            // PERF: this struct is represented by a u8
            const key_state = State{
                .state = .occupied,
                .control_bytes = control_bytes,
            };
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                const states = self.states[group_index];

                // if theres an free then insert
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    const invalid_state: @Vector(GROUP_SIZE, u8) = @splat(16);
                    const indices = @select(u8, free_vec, std.simd.iota(u8, GROUP_SIZE), invalid_state);
                    const free_index = @reduce(.Min, indices);

                    // occupy it
                    self.groups[group_index][free_index] = .{
                        .key = key,
                        .value = value,
                    };
                    self.states[group_index][free_index] = @bitCast(key_state);
                    self._count += 1;
                    return;
                }

                // otherwise try the next group
                group_index = (group_index + 1) & self.bit_mask;
            }
            unreachable;
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
            const search_state: @Vector(GROUP_SIZE, u8) = @splat(@bitCast(key_state));
            // or looking for an empty space (ie, put)
            const free_state: @Vector(GROUP_SIZE, u8) = @splat(0);

            for (0..self.groups.len) |_| {
                const states = self.states[group_index];

                // SIMD eq search for a match (get)
                const match_vec = search_state == states;
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

                // if theres an free then insert (put)
                const free_vec = free_state == states;
                if (@reduce(.Or, free_vec)) {
                    const invalid_state: @Vector(GROUP_SIZE, u8) = @splat(16);
                    const indices = @select(u8, free_vec, std.simd.iota(u8, GROUP_SIZE), invalid_state);
                    const free_index = @reduce(.Min, indices);

                    // occupy it
                    self.groups[group_index][free_index].key = key; // 2)
                    self.states[group_index][free_index] = @bitCast(key_state);
                    self._count += 1;
                    return .{
                        .found_existing = false,
                        .value_ptr = &self.groups[group_index][free_index].value,
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

/// used to track account reference data. This architechture allows
/// us to allocate memory blocks of references in one go and then link them
/// together for deallocation.
pub const RefMemoryLinkedList = struct {
    memory: ArrayList(AccountRef),
    next_ptr: ?*RefMemoryLinkedList = null,

    // TODO: be able to re-use this backing memory (whats free/occupied?)
    // will likely just need a quick simd bitvec
};

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

    pub fn init(filepath: []const u8) !Self {
        return Self{
            .filepath = filepath,
        };
    }

    /// deletes all allocated files + optionally frees the filepath
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
        // TODO: remove
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

test "core.accounts_db.index: tests disk allocator on hashmaps" {
    var allocator = try DiskMemoryAllocator.init("test_data/tmp");
    defer allocator.deinit(null);

    var refs = std.AutoHashMap(Pubkey, AccountRef).init(allocator.allocator());
    try refs.ensureTotalCapacity(100);

    const ref = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 2 },
        },
        .slot = 144,
    };

    try refs.put(Pubkey.default(), ref);

    const r = refs.get(Pubkey.default()) orelse return error.MissingAccount;
    try std.testing.expect(std.meta.eql(r, ref));
}

test "core.accounts_db.index: tests disk allocator" {
    var allocator = try DiskMemoryAllocator.init("test_data/tmp");

    var disk_account_refs = try ArrayList(AccountRef).initCapacity(
        allocator.allocator(),
        1,
    );
    defer disk_account_refs.deinit();

    const ref = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 2 },
        },
        .slot = 10,
    };
    disk_account_refs.appendAssumeCapacity(ref);

    try std.testing.expect(std.meta.eql(disk_account_refs.items[0], ref));

    const ref2 = AccountRef{
        .pubkey = Pubkey.default(),
        .location = .{
            .Cache = .{ .index = 4 },
        },
        .slot = 14,
    };
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
