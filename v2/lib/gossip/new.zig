const std = @import("std");
const lib = @import("lib/lib.zig");

const Hash = lib.solana.Hash;
const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;
const Packet = lib.net.Packet;

const MTU = 1232;
// message_type + push_message/pull_response(from: Pubkey, n_values:u64)
const MAX_VALUE_SIZE = MTU - 4 - 32 - 8;

const PRUNE_PREFIX = "\xffSOLANA_PRUNE_DATA";
const PING_PONG_PREFIX = "SOLANA_PING_PONG";

const MAX_WALLCLOCK = 1_000_000_000_000_000;

const MAX_BLOOM_KEYS = 8;
const MAX_BLOOM_BYTES = 928;
const MAX_BLOOM_FALSE_RATE = 0.1;

// coerce LLVM into emitting a cmov
inline fn select(cond: bool, a: anytype, b: anytype) @TypeOf(a, b) {
    if (cond) {
        @branchHint(.unpredictable);
        return a;
    } else {
        @branchHint(.unpredictable);
        return b;
    }
}

inline fn sub(a: anytype, b: @TypeOf(a)) ?@TypeOf(a) {
    const res = a -% b;
    return if (res <= a) res else null;
}

inline fn readShortVecLen(sv_mem: u32) struct{ u32, u16 } {
    const len = @as(u32, @ctz(sv_mem & 0x8080) / 8) + 1;

    // TODO: branchless
    return .{ len, };
}

inline fn readContactInfoWallclock(wc_mem: u64) struct { u32, u64 } {
    const high_bits: u64 = 0x8080808080808080;
    const len = @as(u32, @ctz(wc_mem & high_bits) / 8) + 1;

    const used_mask = (@as(u64, 1) << @intCast(len * 8)) - 1;
    const used = wc_mem & ~high_bits & used_mask;

    var vec: @Vector(8, u64) = @as(@Vector(8, u8), @bitCast(used));
    vec >>= std.simd.iota(u6, 8);
    return .{ len, @reduce(.Add, vec) };
}

const GossipMessageType = enum(u16) {
    pull_request,
    pull_response,
    push_message,
    prune_message,
    ping_message,
    pong_message,
};

const GossipDataType = enum(u8) {
    legacy_contact_info,
    vote,
    lowest_slot,
    legacy_snapshot_hashes,
    account_hashes,
    epoch_slots,
    legacy_version,
    version,
    node_instance,
    duplicate_shred,
    snapshot_hashes,
    contact_info,
    restart_last_voted_fork,
    restart_heaviest_fork,

    fn isDeprecated(dt: GossipDataType) bool {
        comptime var lut: [std.meta.fields(GossipDataType).len]bool = undefined;
        inline for (0..lut.len) |i| lut[i] = switch (@as(GossipDataType, @enumFromInt(i))) {
            .vote,
            .lowest_slot,
            .epoch_slots,
            .duplicate_shred,
            .snapshot_hashes,
            .contact_info,
            => false,
            else => true,
        };
        return lut[@intFromEnum(dt)];
    }

    fn getWallclock(dt: GossipDataType, bytes: []const u8) u64 {
        const wc_offset_after_pubkey = 4 + 32;
        if (dt != .contact_info) {
            @branchHint(.likely);
            const is_restart =
                @intFromEnum(dt) >= @intFromEnum(GossipDataType.restart_last_voted_fork);
            const wc_offset = select(is_restart, wc_offset_after_pubkey, bytes.len - 8);
            return std.mem.readInt(u64, bytes[wc_offset..][0..8], .little);
        }

        const wc_mem = std.mem.readInt(u64, bytes[wc_offset_after_pubkey..][0..8], .little);
        _, const wc = readContactInfoWallclock(wc_mem);
        return wc;
    }
};

fn minHeapAppend(min_heap: anytype, new_value: @TypeOf(min_heap[0])) void {
    var idx = min_heap.len - 1;
    min_heap[idx] = new_value;
    while (true) {
        const parent = (sub(idx, 1) orelse return) / 2;
        if (min_heap[parent].wallclock <= min_heap[idx].wallclock) return;
        std.mem.swap(@TypeOf(min_heap[0]), &min_heap[parent], &min_heap[idx]);
        idx = parent;
    }
}

fn minHeapReplaceOldest(min_heap: anytype, new_value: @TypeOf(min_heap[0])) void {
    var idx: usize = 0;
    min_heap[idx] = new_value;
    while (true) {
        var smallest = idx;
        inline for (.{ 1, 2 }) |child_offset| {
            const child = idx * 2 + child_offset;
            const child_idx = select(child < min_heap.len, child, smallest);
            const smaller = min_heap[child_idx].wallclock < min_heap[smallest].wallclock;
            smallest = select(smaller, child_idx, smallest);
        }
        if (smallest == idx) break;
        std.mem.swap(@TypeOf(min_heap[0]), &min_heap[smallest], &min_heap[idx]);
        idx = smallest;
    }
}

const HashWindow = extern struct {
    len: usize,
    values: [capacity]Value,

    const capacity = 8 * 1024;
    const Self = @This();
    const Value = struct {
        wallclock: u64,
        hash: Hash,
    };

    fn init(self: *Self) void {
        self.len = 0;
    }

    fn getHashes(self: *const Self) []const Hash {
        return self.hashes[0..self.len];
    }

    fn insert(self: *Self, wallclock: u64, hash: *const Hash) void {
        if (self.len < capacity) {
            @branchHint(.unlikely); // optimize instead for the HashWindow being constantly full.
            self.len += 1;
            minHeapAppend(self.values[0..self.len], .{ .wallclock = wallclock, .hash = hash.* });
        } else {
            // replace top (oldest) with new value
            minHeapReplaceOldest(self.values[0..self.len], .{
                .wallclock = wallclock,
                .hash = hash.*,
            });
        }
    }
};

inline fn hashPubkey(pk: *const Pubkey, maybe_aux: ?u64) u64 {
    const sk = [_]u64{
        0x2d358dccaa6c78a5,
        0x8bb84b93962eacc9,
        0x4b33a62ed433d4a3,
        0x4d5a2da51de1aa47,
        0xa0761d6478bd642f,
        0xe7037ed1a0b428db,
    };
    const in: [4]u64 = @bitCast(pk.data);
    const a: [2]u64 = @bitCast(@as(u128, in[0] ^ sk[0]) * (in[1] ^ sk[1]));
    const b: [2]u64 = @bitCast(@as(u128, in[2] ^ sk[2]) * (in[3] ^ sk[3]));
    var ab: [2]u64 = @bitCast(@as(u128, a[0] ^ a[1] ^ sk[4]) * (b[0] ^ b[1] ^ sk[5]));
    if (maybe_aux) |aux| ab = @bitCast(@as(u128, ab[0] ^ ab[1] ^ sk[0]) * (aux ^ sk[1]));
    return ab[0] ^ ab[1];
}

const Key = struct {
    dt: GossipDataType,
    idx: u16,
    from: Pubkey,

    fn hash(self: *const Key) u64 {
        const aux: u32 = @bitCast([_]u16{ @intFromEnum(self.dt), self.idx });
        return hashPubkey(self.from, aux);
    }

    fn eql(self: *const Key, other: *const Key) bool {
        const vec: [2]@Vector(32, u8) = @bitCast([_][32]u8{ self.from.data, other.from.data });
        const meta: [2]u32 = @bitCast([_][2]u16{
            [_]u16{ @intFromEnum(self.dt), self.idx },
            [_]u16{ @intFromEnum(other.dt), other.idx },
        });

        const meta_eq = @intFromBool(meta[0] == meta[1]);
        const from_eq = @intFromBool(@reduce(.And, vec[0] == vec[0]));
        return (meta_eq & from_eq) > 0;
    }

    fn fromBytes(bytes: []const u8) Key {
        const dt: GossipDataType = @enumFromInt(std.mem.readInt(u32, bytes[0..4], .little));
        const idx_len: u5 = switch (std.math.order(
            @intFromEnum(dt),
            @intFromEnum(GossipDataType.duplicate_shred),
        )) {
            .eq => 2,
            .lt => 1,
            .gt => 0,
        };

        const idx_mem: u32 = std.mem.readInt(u16, bytes[4..][0..2], .little);
        return .{
            .dt = dt,
            .idx = @truncate((idx_mem >> (idx_len * 8)) << (idx_len * 8)),
            .from = .{ .data = bytes[idx_len..][0..32].* },
        };
    }
};

const ValueWindow = extern struct {
    len: u32,
    map: [capacity * 2]MapEntry,
    min_heap: [capacity]HeapEntry,
    values: [capacity]Value,

    const capacity = 8 * 1024;
    const Self = @This();

    const MapEntry = enum(u16) {
        empty = 0,
        tombstone = 1,
        _,

        fn canInsert(self: MapEntry) bool {
            return @intFromEnum(self) <= @intFromEnum(MapEntry.tombstone);
        }

        inline fn valid(idx: u64) MapEntry {
            return @enumFromInt(idx + 2);
        }

        inline fn getValid(self: MapEntry) ?u32 {
            return sub(@as(u32, @intFromEnum(self)), 2);
        }
    };

    const HeapEntry = extern struct {
        wallclock: u64,
        map_idx: u64,
    };

    const Value = extern struct {
        size: u16,
        duplicates: u16,
        hash: Hash,
        bytes: [MAX_VALUE_SIZE]u8,
    };

    fn init(self: *Self) void {
        self.len = 0;
        @memset(&self.map, .empty);
    }

    const ValuePtr = extern struct {
        ptr: usize,

        fn init(maybe_value: ?*Value, tag: enum(u1){ normal = 0, duplicate = 1 }) ValuePtr {
            comptime std.debug.assert(@alignOf(Value) > 1);
            return .{ .ptr = @intFromPtr(maybe_value) + @intFromEnum(tag) };
        }

        fn isEmpty(self: ValuePtr) bool {
            return self.ptr == 0;
        }

        fn isDuplicate(self: ValuePtr) bool {
            return self.ptr & 1 > 0;
        }

        inline fn getPtr(self: ValuePtr) ?*Value {
            return @ptrFromInt(self.ptr & ~@as(usize, 1));
        }
    };

    // If returns .empty, the given key/hash/wallclock were too old
    // If returns .initDuplicates, the given key/hash/wallclock already exists
    // If returns .initValue, a new entry was added (expire *Value Hash if not eq, init the *Value)
    fn insert(self: *Self, key: *const Key, hash: *const Hash, wallclock: u64) ValuePtr {
        const map_hash = key.hash();
        comptime std.debug.assert(std.math.isPowerOfTwo(self.map.len));

        var map_insert_idx: u64 = 0;
        var map_idx: u64 = map_hash >> (comptime @intCast(@as(u7, 64) - @ctz(self.map.len)));
        while (true) {
            const e = self.map[map_idx];
            const maybe_insert_idx = select(e.canInsert(), map_idx +% (1 << 32), 0);
            map_insert_idx = select(map_insert_idx == 0, maybe_insert_idx, map_insert_idx);
            map_idx = (map_idx +% 1) % self.map.len;
            if (e == .empty) break;
            if (e.getValid()) |value_idx| {
                // check if this is the right value.
                const value = &self.values[value_idx];
                const value_key = Key.fromBytes(value.bytes[0..value.size]);
                if (!value_key.eql(key)) continue;

                // extract the wallclock (should this be stored instead?)
                _, const value_wallclock = key.dt.getWallclock(value.bytes[0..value.size]);

                // hash == v.hash (duplicate)
                const vec: [2]@Vector(32, u8) = @bitCast([_][32]u8{ hash.data, value.hash.data });
                const diff_mask: u32 = @bitCast(vec[0] != vec[1]);
                if (diff_mask == 0) {
                    return .init(value, .duplicate);
                }

                // if (wc < v.wc or (wc == v.wc and hash < v.hash)) { expire(incoming) }
                const diff_eq = @ctz(diff_mask);
                const hash_lt = hash.data[diff_eq] < value.hash.data[diff_eq];
                const wc_hash_lt = select(wallclock == value_wallclock, hash_lt, false);
                if (select(wallclock < value_wallclock, true, wc_hash_lt)) {
                    return .init(null, .duplicate);
                }

                // Inserted value. Leave old hash (caller should expire it if they differ)
                return .init(value, .normal);
            }
        }

        // map_insert_idx is either 0 or (insert_idx | (1 << 32))
        const insert_idx: u32 = @truncate(map_insert_idx);

        var value_idx = self.len;
        if (value_idx < capacity) {
            @branchHint(.unlikely); // optimize instead for the ValueWindow being constantly full.
            self.len += 1;

            // insert into map & append to min-heap
            self.map[insert_idx] = .valid(value_idx);
            minHeapAppend(self.min_heap[0..self.len], .{
                .wallclock = wallclock,
                .map_idx = insert_idx,
            });

            // Insert new value with new hash
            const value = &self.values[value_idx];
            value.hash = hash.*;
            return .init(value, .normal);
        }
        
        // Older than current oldest. Dont insert.
        if (wallclock < self.min_heap[0].wallclock) {
            return .init(null, .normal);
        }

        // remove existing oldest & reuse its value_idx
        const removed = &self.map[self.min_heap[0].map_idx];
        value_idx = removed.getValid().?;
        removed.* = .tombstone;

        // insert into map & replace oldest in min-heap
        self.map[insert_idx] = .valid(value_idx);
        minHeapReplaceOldest(self.min_heap[0..self.len], .{
            .wallclock = wallclock,
            .map_idx = insert_idx,
        });

        // Inserted value. Leave old hash (caller should expire it if they differ)
        return .init(&self.values[value_idx], .normal);
    }
};

const PingMessage = extern struct {
    from: Pubkey,
    token: [32]u8,
    signature: Signature,
};
const PongMessage = extern struct {
    from: Pubkey,
    hash: Hash,
    signature: Signature,
};

const PingWindow = extern struct {
    old_hash: Hash,
    hash: Hash,
    token: [32]u8,
    signature: Signature,

    const Self = @This();

    fn init(self: *PingWindow, prng: std.Random, effects: anytype) void {
        prng.bytes(&self.hash.data);
        self.refresh(prng, effects);
    }

    fn refresh(self: *PingWindow, prng: std.Random, effects: anytype) void {
        self.old_hash = self.hash;
        prng.bytes(&self.token);
        self.hash = Hash.initMany(&.{ PING_PONG_PREFIX, &self.token });
        effects.sign(&self.token, &self.new_signature);
    }
    
    fn contains(self: *const Self, hash: *const Hash) bool {
        const old_eq = @intFromBool(self.old_hash.eql(hash));
        const curr_eq = @intFromBool(self.hash.eql(hash));
        return (old_eq | curr_eq) > 0;
    }
};

const Address = extern struct {
    version: enum(u8){ v4, v6 },
    port: u16,
    ip: [16]u8,

    fn fromNetAddr(self: *@This(), net_addr: *const std.net.Address) void {
        switch (net_addr.any.family) {
            std.posix.AF.INET => {
                self.version = .v4;
                self.port = net_addr.in.getPort();
                self.ip[0..4].* = @bitCast(net_addr.in.sa.addr);
            },
            std.posix.AF.INET6 => {
                self.version = .v6;
                self.port = net_addr.in6.getPort();
                self.ip = net_addr.in6.sa.addr;
            },
            else => unreachable,
        }
    }
};

const BloomFilter = struct {
    num_bits: u32,
    keys: []align(1) u64,
    words: []align(1) u64,

    fn init(keys: []align(1) u64, words: []align(1) u64, num_bits: u32) BloomFilter {
        std.debug.assert(num_bits <= words.len * 8);
        return .{
            .num_bits = num_bits,
            .keys = keys,
            .words = words,
        };
    }

    fn getBitPos(self: *const BloomFilter, key: u64, bytes: *const [32]u8) u64 {
        var fnv1a = key;
        for (bytes) |b| fnv1a = (fnv1a ^ @as(u64, b)) *% 0xcbf29ce484222325;
        return fnv1a % self.num_bits;
    }

    fn add(self: *const BloomFilter, bytes: *const [32]u8) void {
        const pre_read = bytes.*;
        for (self.keys) |key| {
            const bit = self.getBitPos(key, &pre_read);
            self.words[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
        }
    }

    fn contains(self: *const BloomFilter, bytes: *const [32]u8) bool {
        const pre_read = bytes.*;
        for (self.keys) |key| {
            const bit = self.getBitPos(key, &pre_read);
            if ((self.words[bit / 64] >> @intCast(bit % 64)) & 1 == 0) return false;
        }
        return true;
    }
};

const PeerTable = extern struct {
    values: [capacity]Value,

    const capacity = 64 * 1024;
    const Self = @This();

    fn init(self: *Self) void {
        
    }

    const Value = extern struct {
        last_pong: u64,
        last_ping: u64,
        addr: Address,
    };

    fn get(self: *const Self, pubkey: *const Pubkey) ?*Value {

    }

    const ValuePtr = extern struct {
        ptr: usize,
        
        fn exists(self: ValuePtr) bool {

        }

        fn getPtr(self: ValuePtr) *Value {

        }
    };

    fn getOrPut(self: *const Self, pubkey: *const Pubkey) ValuePtr {

    }
};

const PushActiveSet = extern struct {
    len: u32,
    targets: [MAX_FANOUT]Target,

    const MAX_FANOUT = 9;
    const BloomFilterStorage = extern struct {
        keys: [MAX_BLOOM_KEYS]u64,
        words: [@divExact(MAX_BLOOM_BYTES, 8)]u64,

        fn init(self: *BloomFilterStorage, prng: std.Random) void {
            prng.bytes(std.mem.asBytes(&self.keys));
            @memset(&self.words, 0);
        }

        fn asBloomFilter(self: *const BloomFilterStorage) BloomFilter {
            return .init(&self.keys, &self.words, MAX_BLOOM_BYTES * 8);
        }
    };

    const Self = @This();
    const Target = extern struct {
        pubkey: Pubkey,
        addr: Address,
        pruned: BloomFilterStorage,
    };

    fn init(self: *Self) void {
        self.len = 0;
    }

    fn tryAppend(self: *Self) ?*Target {
        if (self.len < self.targets.len) return null;
        defer self.len += 1;
        return &self.targets[self.len];
    }

    fn getSlice(self: *const Self) []Target {
        return self.targets[0..self.len];
    }
};

const Node = extern struct {
    identity: Pubkey,
    hash_window: HashWindow,
    value_window: ValueWindow,
    ping_window: PingWindow,
    peer_table: PeerTable,
    push_active_set: PushActiveSet,

    const DUPLICATE_THRESHOLD_UNTIL_PRUNE = 20;

    const Self = @This();

    fn init(self: *Node) void {
        self.hash_window.init();
        self.value_window.init();
        self.ping_window.init();
        self.peer_table.init();
        // self.push_active_set.init();
    }

    fn onMessage(self: *Self, now: u64, addr: *const std.net.Address, data: []const u8) !void {
        var r: std.Io.Reader = .fixed(data);

        const mt_mem = r.takeInt(u32, .little) catch return error.InvalidMessage;
        const mt = std.meta.intToEnum(GossipMessageType, mt_mem) catch 
            return error.InvalidMessageType;

        switch (mt) {
            .pull_request => {
                const num_keys = r.takeInt(u64, .little) catch return error.InvalidBloomFilter;
                const k_mem = r.take(num_keys * @sizeOf(u64)) catch return error.InvalidBloomFilter;
                const keys = std.mem.bytesAsSlice(u64, k_mem);

                const has_vec = r.takeByte() catch return error.InvalidBitVec;
                if (has_vec > 1) return error.InvalidBitVec;
                const words = if (has_vec == 0) &.{} else blk: {
                    const num_words = r.takeInt(u64, .little) catch return error.InvalidBitVec;
                    const w_mem = r.take(num_words * @sizeOf(u64)) catch return error.InvalidBitVec;
                    break :blk std.mem.bytesAsSlice(u64, w_mem);
                };

                const bit_cap = r.takeInt(u64, .little) catch return error.InvalidBitVec;
                if (bit_cap > words.len * @sizeOf(u64)) return error.InvalidBitVec;
                
                var bits_set = r.takeInt(u64, .little) catch return error.InvalidBloomFilter;
                for (words) |w| {
                    bits_set = sub(bits_set, @popCount(w)) orelse return error.InvalidBloomFilter;
                }

                const mask = r.takeInt(u64, .little) catch return error.InvalidBloomMask;
                const mask_bits = std.math.cast(
                    u6,
                    r.takeInt(u32, .little) catch return error.InvalidBloomMask,
                ) catch return error.InvalidBloomMask;

                // TODO: verify ContactInfo

                // Scan through our values to find one that matches the mask & is not in the bloom.
                const ignore_bloom: BloomFilter = .init(keys, words, @intCast(bit_cap));
                for (self.value_window.values[0..self.value_window.len]) |*value| {
                    const lsb_mask = (~@as(u64, 0)) >> mask_bits;
                    const h: u64 = std.mem.readInt(u64, value.hash.data[0..8], .little);
                    if ((h | lsb_mask) != (mask | lsb_mask)) continue;
                    if (ignore_bloom.contains(&value.hash.data)) continue;

                    // Found one. No need to buffer them up (other nodes do this for unstaked).
                    const p = self.prepPacket();
                    p.size = 4 + 8 + value.size;
                    p.addr = addr.*;

                    const pr_hdr = @intFromEnum(GossipMessageType.pull_response);
                    std.mem.writeInt(u32, p.data[0..4], pr_hdr, .little);
                    std.mem.writeInt(u64, p.data[4..][0..8], 1, .little);
                    @memcpy(p.data[4 + 8..][0..value.size], value.bytes[0..value.size]);

                    try self.submitPackets();
                    return;
                }
            },
            .pull_response, .push_message => {
                const from: *const Pubkey = 
                    @ptrCast(r.takeArray(@sizeOf(Pubkey)) catch return error.InvalidValues);

                var num_values = r.takeInt(u64, .little) catch return error.InvalidValues;
                while (num_values > 0) : (num_values -= 1) {
                    const dt = std.meta.intToEnum(
                        GossipDataType,
                        r.takeInt(u32, .little) catch return error.InvalidValue,
                    ) catch return error.InvalidValue;

                    switch (dt) {
                        .legacy_contact_info => return error.Deprecated,
                        .vote => {
                            const idx_and_pk = r.takeArray(1 + 32) catch return error.InvalidVote;
                            if (idx_and_pk[0] > 12) return error.InvalidVote;

                            const num_signatures, const consumed = 
                                readShortVecLen(r.buffer[r.seek..]);
                            r.seek += consumed;
                        },
                        .lowest_slot => {

                        },
                        .legacy_snapshot_hashes, .account_hashes => return error.Deprecated,
                        .epoch_slots => {

                        },
                        .legacy_version, .version, .node_instance => return error.Deprecated,
                        .duplicate_shred => {

                        },
                        .snapshot_hashes => {

                        },
                        .contact_info => {

                        },
                        .restart_last_voted_fork => {

                        },
                        .restart_heaviest_fork => {

                        },
                    }
                }
            },
            .prune_message => {
                // read PrueMessage{ from: Pubkey, data: PruneData{ from: Pubkey 
                const pk_mem = r.takeArray(2 * @sizeOf(Pubkey)) catch return error.InvalidPrune;
                const pubkeys: *const [2]Pubkey = @ptrCast(pk_mem);
                if (!pubkeys[0].equals(&pubkeys[1])) return error.InvalidPrune;

                const num_prunes = r.takeInt(u64, .little) catch return error.InvalidPruneData;
                const prunes: []const Pubkey = std.mem.bytesAsSlice(
                    Pubkey,
                    r.take(num_prunes * @sizeOf(Pubkey)) catch return error.InvalidPruneData,
                );

                // Get signature in place.
                const signature: *const Signature = 
                    @ptrCast(r.takeArray(@sizeOf(Signature)) catch return error.InvalidPruneData);

                const destination: *const Pubkey = 
                    @ptrCast(r.takeArray(@sizeOf(Pubkey)) catch return error.InvalidPruneData);
                if (!self.identity.equals(destination)) return error.InvalidPruneSender;

                const wallclock = r.takeInt(u64, .little) catch return error.InvalidPruneData;
                if (wallclock > MAX_WALLCLOCK) return error.InvalidPruneData;

                // right before the PruneData, write a bincode.Vec(u8){ .items = PRUNE_PREFIX }
                const prefix_offset = 32 - PRUNE_PREFIX.len - 8;
                const prefix = pk_mem[0..32][prefix_offset..];
                std.mem.writeInt(u64, prefix[0..8], PRUNE_PREFIX.len, .little);
                @memcpy(prefix[8..], PRUNE_PREFIX);

                const pubkey = &pubkeys[1]; // the untouched one after the prefix
                signature.verify(pubkey, r.buffer[4 + prefix_offset .. r.seek]) catch {
                    signature.verify(pubkey, r.buffer[4 + 32 .. r.seek]) catch {
                        return error.InvalidPruneSignature;
                    };
                };

                // Find the node in the active set (if any) & update its prune bloom filter
                for (self.push_active_set.getSlice()) |target| {
                    if (!target.pubkey.equals(pubkey)) continue;
                    for (prunes) |*p| target.pruned.asBloomFilter().add(&p.data);
                    break;
                }
            },
            .ping_message => {
                const msg_buf = r.takeArray(@sizeOf(PingMessage)) catch return error.InvalidPing;
                const msg: *PingMessage = @ptrCast(msg_buf);
                msg.signature.verify(&msg.from, &msg.token) catch return error.InvalidPingSignature;

                const p = self.prepPacket();
                p.addr = addr.*;
                p.size = 4 + @sizeOf(PongMessage);

                const pong_hdr = @intFromEnum(GossipMessageType.pong_message);
                std.mem.writeInt(u32, p.data[0..4], pong_hdr, .little);

                const pong_msg: *PongMessage = @ptrCast(p.data[4..][0..@sizeOf(PongMessage)]);
                pong_msg.from = self.identity;
                pong_msg.hash = Hash.initMany(&.{ PING_PONG_PREFIX, &msg.token });
                self.sign(&pong_msg.hash.data, &pong_msg.signature);

                try self.submitPackets();
            },
            .pong_message => {
                const msg_buf = r.takeArray(@sizeOf(PongMessage)) catch return error.InvalidPong;
                const msg: *PongMessage = @ptrCast(msg_buf);

                // check ping hash window first before trying to verify
                if (!self.ping_window.contains(&msg.hash)) return error.ExpiredPong;
                msg.signature.verify(&msg.from, &msg.hash) catch return error.InvalidPongSignature;

                const peer = self.peer_window.get(&msg.from) orelse return;
                peer.last_pong = now;
            },
        }
    }
    
    fn sign(self: *const Self, msg: []const u8, out_sig: *Signature) void {

    }

    fn prepPacket(self: *Self) *Packet {

    }

    fn submitPackets(self: *Self) !void {

    }

    fn insert(self: *Self, key: *const Key, wallclock: u64, value_bytes: []const u8) void {
        const hash = Hash.init(value_bytes);
        const value_ptr = self.value_window.insert(key, &hash, wallclock);

        const value = value_ptr.getPtr() orelse { // didnt insert
            self.hash_window.insert(now, &hash);
            return;
        };

        if (value_ptr.isDuplicate()) {

        }

        if (value_ptr.isEmpty()) {
            return self.hash_window.insert(wallclock, hash);
        } else if (value_ptr.getDuplicates()) |duplicates| {
            if (duplicates >= DUPLICATE_THRESHOLD_UNTIL_PRUNE) {
                // send prune
            }
        } else {
            const value = value_ptr.getPtr();
            if (!hash.eql(&value.hash)) {
                self.hash_window.insert(wallclock, &value.hash);
            }

            value.hash = hash;
            value.duplicates = 0;
            value.size = @intCast(value_bytes.len);
            @memcpy(value.bytes[0..value.size], value_bytes);
        }
    }
};
