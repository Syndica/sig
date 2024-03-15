const std = @import("std");
const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const Account = @import("../core/account.zig").Account;
const hashAccount = @import("../core/account.zig").hashAccount;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Pubkey = @import("../core/pubkey.zig").Pubkey;

const AccountFile = @import("accounts_file.zig").AccountFile;

const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

pub const AccountRef = struct {
    pubkey: Pubkey,
    slot: Slot,
    location: AccountLocation,
    next_ptr: ?*AccountRef = null,

    pub const AccountLocation = union(enum(u8)) {
        File: struct {
            file_id: u32,
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

pub fn FastMap(
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

        pub fn init(allocator: std.mem.Allocator) @This() {
            return @This(){
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

        pub fn ensureTotalCapacity(self: *@This(), n: usize) !void {
            if (n == 0) {
                // something is wrong
                return error.ZeroCapacityNotSupported;
            }
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

        pub fn deinit(self: *@This()) void {
            if (self._capacity > 0)
                self.allocator.free(self.memory);
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

            var hash = hash_fn(key);
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
                var match_vec = search_state == states;
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

        pub fn putAssumeCapacity(self: *@This(), key: Key, value: Value) void {
            var hash = hash_fn(key);
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

        pub fn getOrPutAssumeCapacity(self: *@This(), key: Key) GetOrPutResult {
            var hash = hash_fn(key);
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
                var match_vec = search_state == states;
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
    return std.mem.readIntLittle(u64, key.data[0..8]);
}

pub inline fn pubkey_eql(key1: Pubkey, key2: Pubkey) bool {
    return key1.equals(&key2);
}

pub const AccountIndexBin = struct {
    account_refs: RefMap,
    disk_memory: ?DiskMemory,
    allocator: std.mem.Allocator,

    pub const DiskMemory = struct {
        account_refs: RefMap,
        allocator: *DiskMemoryAllocator,
    };

    const RefMap = FastMap(Pubkey, *AccountRef, pubkey_hash, pubkey_eql);

    pub fn initCapacity(
        allocator: std.mem.Allocator,
        ram_memory_config: RamMemoryConfig,
        maybe_disk_memory_config: ?DiskMemoryConfig,
        bin_index: usize,
    ) !AccountIndexBin {
        // setup ram references
        var account_refs = RefMap.init(ram_memory_config.allocator);
        if (ram_memory_config.capacity > 0) {
            try account_refs.ensureTotalCapacity(ram_memory_config.capacity);
        }

        // setup disk references
        var disk_memory: ?DiskMemory = null;
        if (maybe_disk_memory_config) |*disk_memory_config| {
            std.fs.cwd().access(disk_memory_config.dir_path, .{}) catch {
                try std.fs.cwd().makeDir(disk_memory_config.dir_path);
            };

            const disk_filepath = try std.fmt.allocPrint(
                allocator,
                "{s}/bin{d}_index_data",
                .{ disk_memory_config.dir_path, bin_index },
            );

            // need to store on heap so `ptr.allocator()` is always correct
            var ptr = try allocator.create(DiskMemoryAllocator);
            ptr.* = try DiskMemoryAllocator.init(disk_filepath);

            var disk_account_refs = RefMap.init(ptr.allocator());
            if (disk_memory_config.capacity > 0) {
                try account_refs.ensureTotalCapacity(disk_memory_config.capacity);
            }

            disk_memory = .{
                .account_refs = disk_account_refs,
                .allocator = ptr,
            };
        }

        return AccountIndexBin{
            .account_refs = account_refs,
            .disk_memory = disk_memory,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *AccountIndexBin) void {
        self.account_refs.deinit();
        if (self.disk_memory) |*disk_memory| {
            disk_memory.account_refs.deinit();
            disk_memory.allocator.deinit(self.allocator);
            self.allocator.destroy(disk_memory.allocator);
        }
    }

    pub inline fn getInMemRefs(self: *AccountIndexBin) *RefMap {
        return &self.account_refs;
    }

    pub inline fn getDiskRefs(self: *AccountIndexBin) ?*RefMap {
        if (self.disk_memory) |*disk_memory| {
            return &disk_memory.account_refs;
        } else {
            return null;
        }
    }

    pub inline fn getRefs(self: *AccountIndexBin) *RefMap {
        if (self.disk_memory) |*disk_memory| {
            return &disk_memory.account_refs;
        } else {
            return &self.account_refs;
        }
    }
};

// TODO: be able to re-use this backing memory (whats free/occupied?)
// will likely just need a quick simd bitvec
pub const RefMemoryLinkedList = struct {
    memory: ArrayList(AccountRef),
    next_ptr: ?*RefMemoryLinkedList = null,
};

/// stores the mapping from Pubkey to the account location (AccountRef)
pub const AccountIndex = struct {
    bins: []AccountIndexBin,
    calculator: PubkeyBinCalculator,
    allocator: std.mem.Allocator,
    use_disk: bool,
    memory_linked_list: ?*RefMemoryLinkedList = null,

    const Self = @This();

    pub fn init(
        // used to allocate the bin slice and other bin metadata
        allocator: std.mem.Allocator,
        // number of bins to shard pubkeys across
        n_bins: usize,
        ram_config: RamMemoryConfig,
        disk_config: ?DiskMemoryConfig,
    ) !Self {
        const calculator = PubkeyBinCalculator.init(n_bins);

        var bins = try allocator.alloc(AccountIndexBin, n_bins);
        for (bins, 0..) |*bin, bin_i| {
            bin.* = try AccountIndexBin.initCapacity(
                allocator,
                ram_config,
                disk_config,
                bin_i,
            );
        }
        const use_disk = disk_config != null;

        return Self{
            .bins = bins,
            .calculator = calculator,
            .allocator = allocator,
            .use_disk = use_disk,
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

    pub fn addMemoryBlock(self: *Self, refs: ArrayList(AccountRef)) !void {
        var node = try self.allocator.create(RefMemoryLinkedList);
        node.* = .{
            .memory = refs,
        };
        if (self.memory_linked_list == null) {
            self.memory_linked_list = node;
        } else {
            var tail = self.memory_linked_list.?;
            while (tail.next_ptr) |ptr| {
                tail = ptr;
            }
            tail.next_ptr = node;
        }
    }

    pub inline fn getBinIndex(self: *const Self, pubkey: *const Pubkey) usize {
        return self.calculator.binIndex(pubkey);
    }

    pub inline fn getBin(self: *const Self, index: usize) *AccountIndexBin {
        return &self.bins[index];
    }

    pub inline fn getBinFromPubkey(
        self: *const Self,
        pubkey: *const Pubkey,
    ) *AccountIndexBin {
        const bin_index = self.calculator.binIndex(pubkey);
        return &self.bins[bin_index];
    }

    pub inline fn numberOfBins(self: *const Self) usize {
        return self.bins.len;
    }

    /// adds the reference to the index if there is not a duplicate (ie, the same slot)
    pub fn indexRefIfNotDuplicate(self: *Self, account_ref: *AccountRef) void {
        const bin = self.getBinFromPubkey(&account_ref.pubkey);
        var result = bin.getRefs().getOrPutAssumeCapacity(account_ref.pubkey);
        if (result.found_existing) {
            // traverse until you find the end
            var curr: *AccountRef = result.value_ptr.*;
            while (true) {
                if (curr.slot == account_ref.slot) {
                    // found a duplicate => dont do the insertion
                    break;
                } else if (curr.next_ptr == null) {
                    // end of the list => insert it here
                    curr.next_ptr = account_ref;
                    break;
                } else {
                    // keep traversing
                    curr = curr.next_ptr.?;
                }
            }
        } else {
            result.value_ptr.* = account_ref;
        }
    }

    /// adds a reference to the index
    pub fn indexRef(self: *Self, account_ref: *AccountRef) void {
        const bin = self.getBinFromPubkey(&account_ref.pubkey);
        var result = bin.getRefs().getOrPutAssumeCapacity(account_ref.pubkey); // 1)
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

    /// indexes and accounts file by parsing out the accounts.
    pub fn indexAccountFile(self: *Self, allocator: std.mem.Allocator, accounts_file: *AccountFile) !void {
        var offset: usize = 0;

        while (true) {
            var account = accounts_file.readAccount(offset) catch break;
            const pubkey = account.store_info.pubkey;

            const hash_is_missing = std.mem.eql(u8, &account.hash().data, &Hash.default().data);
            if (hash_is_missing) {
                const hash = hashAccount(
                    account.account_info.lamports,
                    account.data,
                    &account.account_info.owner.data,
                    account.account_info.executable,
                    account.account_info.rent_epoch,
                    &pubkey.data,
                );
                account.hash_ptr.* = hash;
            }

            const account_ref = AccountRef{
                .pubkey = pubkey,
                .slot = accounts_file.slot,
                .location = .{
                    .File = .{
                        .file_id = @as(u32, @intCast(accounts_file.id)),
                        .offset = offset,
                    },
                },
            };

            // put this in a per bin vector []Vec(AccountRef)
            const index_bin = self.getBinFromPubkey(&pubkey);
            const refs = index_bin.getRefs();
            try AccountIndexBin.put(refs, allocator, account_ref);

            offset = offset + account.len;
        }
    }

    pub fn validateAccountFile(
        self: *Self,
        accounts_file: *AccountFile,
        bin_counts: []usize,
        account_refs: *ArrayList(AccountRef),
    ) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

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
                        .file_id = @as(u32, @intCast(accounts_file.id)),
                        .offset = offset,
                    },
                },
            });

            const pubkey = &account.store_info.pubkey;
            const bin_index = self.getBinIndex(pubkey);
            bin_counts[bin_index] += 1;

            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != std.mem.alignForward(usize, accounts_file.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }

        accounts_file.n_accounts = n_accounts;
    }
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

pub const DiskMemoryAllocator = struct {
    filepath: []const u8,
    count: usize = 0,

    const Self = @This();

    pub fn init(filepath: []const u8) !Self {
        return Self{
            .filepath = filepath,
        };
    }

    /// deletes all allocated files + optionally frees the filepath
    pub fn deinit(self: *Self, str_allocator: ?std.mem.Allocator) void {
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

        var buf: [1024]u8 = undefined;
        const filepath = std.fmt.bufPrint(&buf, "{s}_{d}", .{ self.filepath, self.count }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {}\n", .{err});
            return null;
        };

        var file = std.fs.cwd().createFile(filepath, .{ .read = true }) catch |err| {
            std.debug.print("Disk Memory Allocator error: {} filepath: {s}\n", .{ err, filepath });
            return null;
        };
        defer file.close();
        self.count += 1;

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

        var memory = std.os.mmap(
            null,
            aligned_size,
            std.os.PROT.READ | std.os.PROT.WRITE,
            std.os.MAP.SHARED,
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
        std.os.munmap(@alignCast(buf.ptr[0..buf_aligned_len]));
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
