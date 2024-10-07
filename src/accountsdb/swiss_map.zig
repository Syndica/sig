//! custom hashmap used for the index's map
//! based on google's swissmap

const std = @import("std");
const sig = @import("../sig.zig");
const accounts_db = sig.accounts_db;

pub fn SwissMap(
    comptime Key: type,
    comptime Value: type,
    comptime hash_fn: fn (Key) callconv(.Inline) u64,
    comptime eq_fn: fn (Key, Key) callconv(.Inline) bool,
) type {
    return struct {
        allocator: std.mem.Allocator,
        unmanaged: Unmanaged,
        const Self = @This();

        pub const Unmanaged = SwissMapUnmanaged(Key, Value, hash_fn, eq_fn);

        pub inline fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .unmanaged = Unmanaged.init(),
            };
        }

        pub fn initCapacity(allocator: std.mem.Allocator, n: usize) !Self {
            var unmanaged = Unmanaged.init();
            try unmanaged.ensureTotalCapacity(allocator, n);
            return .{
                .allocator = allocator,
                .unmanaged = unmanaged,
            };
        }

        pub fn ensureTotalCapacity(self: *Self, n: usize) std.mem.Allocator.Error!void {
            return @call(.always_inline, Unmanaged.ensureTotalCapacity, .{ &self.unmanaged, self.allocator, n });
        }

        pub fn deinit(self: *Self) void {
            return @call(.always_inline, Unmanaged.deinit, .{ &self.unmanaged, self.allocator });
        }

        pub const Iterator = Unmanaged.Iterator;

        pub inline fn iterator(self: *const @This()) Iterator {
            return self.unmanaged.iterator();
        }

        pub inline fn count(self: *const @This()) usize {
            return self.unmanaged.count();
        }

        pub inline fn capacity(self: *const @This()) usize {
            return self.unmanaged.capacity();
        }

        pub const GetOrPutResult = Unmanaged.GetOrPutResult;

        pub fn remove(self: *@This(), key: Key) error{KeyNotFound}!Value {
            return @call(.always_inline, Unmanaged.remove, .{ &self.unmanaged, key });
        }

        pub fn get(self: *const @This(), key: Key) ?Value {
            return @call(.always_inline, Unmanaged.get, .{ &self.unmanaged, key });
        }

        pub fn getPtr(self: *const @This(), key: Key) ?*Value {
            return @call(.always_inline, Unmanaged.getPtr, .{ &self.unmanaged, key });
        }

        /// puts a key into the index with the value
        /// note: this assumes the key is not already in the index, if it is, then
        /// the map might contain two keys, and the behavior is undefined
        pub fn putAssumeCapacity(self: *Self, key: Key, value: Value) void {
            return @call(.always_inline, Unmanaged.putAssumeCapacity, .{ &self.unmanaged, key, value });
        }

        pub fn getOrPutAssumeCapacity(self: *Self, key: Key) GetOrPutResult {
            return @call(.always_inline, Unmanaged.getOrPutAssumeCapacity, .{ &self.unmanaged, key });
        }
    };
}

pub fn SwissMapUnmanaged(
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
        _count: usize = 0,
        _capacity: usize = 0,
        const Self = @This();

        const GROUP_SIZE = 16;

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

        pub inline fn init() Self {
            return Self{
                .groups = undefined,
                .states = undefined,
                .memory = undefined,
                .bit_mask = 0,
            };
        }

        pub fn initCapacity(allocator: std.mem.Allocator, n: usize) std.mem.Allocator.Error!Self {
            var self = init(allocator);
            try self.ensureTotalCapacity(allocator, n);
            return self;
        }

        pub fn ensureTotalCapacity(self: *Self, allocator: std.mem.Allocator, n: usize) std.mem.Allocator.Error!void {
            if (n <= self._capacity) {
                return;
            }

            if (self._capacity == 0) {
                const n_groups = @max(std.math.pow(u64, 2, std.math.log2(n) + 1) / GROUP_SIZE, 1);
                const group_size = n_groups * @sizeOf([GROUP_SIZE]KeyValue);
                const ctrl_size = n_groups * @sizeOf([GROUP_SIZE]State);
                const size = group_size + ctrl_size;

                const memory = try allocator.alloc(u8, size);
                errdefer comptime unreachable;
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

                const memory = try allocator.alloc(u8, size);
                errdefer comptime unreachable;
                @memset(memory, 0);

                const group_ptr: [*][GROUP_SIZE]KeyValue = @alignCast(@ptrCast(memory.ptr));
                const groups = group_ptr[0..n_groups];
                const states_ptr: [*]@Vector(GROUP_SIZE, u8) = @alignCast(@ptrCast(memory.ptr + group_size));
                const states = states_ptr[0..n_groups];

                var new_self = Self{
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

                self.deinit(allocator); // release old memory

                self._capacity = new_self._capacity;
                self.groups = new_self.groups;
                self.states = new_self.states;
                self.memory = new_self.memory;
                self.bit_mask = new_self.bit_mask;
            }
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            if (self._capacity > 0) {
                allocator.free(self.memory);
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

        pub inline fn iterator(self: *const @This()) Iterator {
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

        pub fn remove(
            self: *@This(),
            key: Key,
        ) error{KeyNotFound}!Value {
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
                            const result = self.groups[group_index][j].value;

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
                            return result;
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

test "swissmap resize" {
    var map = SwissMap(sig.core.Pubkey, accounts_db.index.AccountRef, accounts_db.index.pubkey_hash, accounts_db.index.pubkey_eql).init(std.testing.allocator);
    defer map.deinit();

    try map.ensureTotalCapacity(100);

    const ref = accounts_db.index.AccountRef.default();
    map.putAssumeCapacity(sig.core.Pubkey.default(), ref);

    // this will resize the map with the key still in there
    try map.ensureTotalCapacity(200);
    const get_ref = map.get(sig.core.Pubkey.default()) orelse return error.MissingAccount;
    try std.testing.expect(std.meta.eql(get_ref, ref));
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
        sig.core.Pubkey,
        *accounts_db.index.AccountRef,
        accounts_db.index.pubkey_hash,
        accounts_db.index.pubkey_eql,
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
        _ = try map.remove(pubkeys[i]);
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
        sig.core.Pubkey,
        *accounts_db.index.AccountRef,
        accounts_db.index.pubkey_hash,
        accounts_db.index.pubkey_eql,
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
    []accounts_db.index.AccountRef,
    []sig.core.Pubkey,
} {
    var random = std.Random.DefaultPrng.init(0);
    const rng = random.random();

    const accounts = try allocator.alloc(accounts_db.index.AccountRef, n_accounts);
    const pubkeys = try allocator.alloc(sig.core.Pubkey, n_accounts);
    for (0..n_accounts) |i| {
        rng.bytes(&pubkeys[i].data);
        accounts[i] = accounts_db.index.AccountRef.default();
        accounts[i].pubkey = pubkeys[i];
    }
    rng.shuffle(sig.core.Pubkey, pubkeys);

    return .{ accounts, pubkeys };
}

pub const BenchmarkSwissMap = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;

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
        const allocator = std.heap.c_allocator;
        const n_accounts = bench_args.n_accounts;

        const accounts, const pubkeys = try generateData(allocator, n_accounts);

        const write_time, const read_time = try benchGetOrPut(
            SwissMap(
                sig.core.Pubkey,
                *accounts_db.index.AccountRef,
                accounts_db.index.pubkey_hash,
                accounts_db.index.pubkey_eql,
            ),
            allocator,
            accounts,
            pubkeys,
            null,
        );

        // this is what we compare the swiss map to
        // this type was the best one I could find
        const InnerT = std.HashMap(sig.core.Pubkey, *accounts_db.index.AccountRef, struct {
            pub fn hash(self: @This(), key: sig.core.Pubkey) u64 {
                _ = self;
                return accounts_db.index.pubkey_hash(key);
            }
            pub fn eql(self: @This(), key1: sig.core.Pubkey, key2: sig.core.Pubkey) bool {
                _ = self;
                return accounts_db.index.pubkey_eql(key1, key2);
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
        std.log.debug("\tWRITE: {} ({d:.2}x {s} than std)\n", .{
            std.fmt.fmtDuration(write_time),
            write_speedup,
            write_faster_or_slower,
        });

        const read_speedup = @as(f32, @floatFromInt(std_read_time)) / @as(f32, @floatFromInt(read_time));
        const read_faster_or_slower = if (read_speedup < 1.0) "slower" else "faster";
        std.log.debug("\tREAD: {} ({d:.2}x {s} than std)\n", .{
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
    accounts: []accounts_db.index.AccountRef,
    pubkeys: []sig.core.Pubkey,
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

        pub fn write(self: *@This(), accounts: []accounts_db.index.AccountRef) !void {
            for (0..accounts.len) |i| {
                self.inner.putAssumeCapacity(accounts[i].pubkey, accounts[i]);
            }
        }

        pub fn read(self: *@This(), pubkey: *sig.core.Pubkey) !usize {
            if (self.inner.get(pubkey.*)) |acc| {
                return 1 + @as(usize, @intCast(acc.offset));
            } else {
                unreachable;
            }
        }

        pub fn getOrPutAssumeCapacity(self: *@This(), pubkey: sig.core.Pubkey) T.GetOrPutResult {
            const result = self.inner.getOrPutAssumeCapacity(pubkey);
            return result;
        }
    };
}
