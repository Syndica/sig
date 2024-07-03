const std = @import("std");
const Hash = @import("../core/hash.zig").Hash;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const GossipTable = @import("table.zig").GossipTable;
const _gossip_data = @import("data.zig");
const SignedGossipData = _gossip_data.SignedGossipData;
const getWallclockMs = _gossip_data.getWallclockMs;
const RwMux = @import("../sync/mux.zig").RwMux;

pub const MAX_BLOOM_SIZE: usize = 928;
pub const MAX_NUM_PULL_REQUESTS: usize = 20; // labs - 1024;
pub const FALSE_RATE: f64 = 0.1;
pub const KEYS: f64 = 8;

/// parses all the values in the gossip table and returns a list of
/// corresponding filters. Note: make sure to call deinit_gossip_filters.
pub fn buildGossipPullFilters(
    alloc: std.mem.Allocator,
    rand: std.Random,
    gossip_table_rw: *RwMux(GossipTable),
    failed_pull_hashes: *const ArrayList(Hash),
    bloom_size: usize,
    max_n_filters: usize,
) error{ NotEnoughSignedGossipDatas, OutOfMemory }!ArrayList(GossipPullFilter) {
    var filter_set = blk: {
        var gossip_table_lock = gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();

        const num_items = gossip_table.len() + gossip_table.purged.len() + failed_pull_hashes.items.len;

        var filter_set = try GossipPullFilterSet.init(alloc, rand, num_items, bloom_size);
        errdefer filter_set.deinit();

        // add all gossip values
        const gossip_values = gossip_table.store.iterator().values;
        for (0..gossip_table.len()) |i| {
            const hash = gossip_values[i].value_hash;
            filter_set.add(&hash);
        }
        // add purged values
        const purged_values = try gossip_table.purged.getValues();
        for (purged_values.items) |hash| {
            filter_set.add(&hash);
        }
        // add failed inserts
        for (failed_pull_hashes.items) |hash| {
            filter_set.add(&hash);
        }

        break :blk filter_set;
    };
    errdefer filter_set.deinit();

    // note: filter set is deinit() in this fcn
    const filters = try filter_set.consumeForGossipPullFilters(alloc, rand, max_n_filters);
    return filters;
}

pub fn deinitGossipPullFilters(filters: *ArrayList(GossipPullFilter)) void {
    for (filters.items) |*filter| {
        filter.deinit();
    }
    filters.deinit();
}

pub fn shuffleFirstN(rng: std.rand.Random, comptime T: type, buf: []T, n: usize) void {
    for (0..n) |i| {
        const j = rng.intRangeLessThan(usize, 0, buf.len);
        std.mem.swap(T, &buf[i], &buf[j]);
    }
}

pub const GossipPullFilterSet = struct {
    filters: ArrayList(Bloom),

    // mask bits represents the number of bits required to represent the number of
    // filters.
    mask_bits: u32, // todo: make this a u6

    const Self = @This();

    pub fn init(
        alloc: std.mem.Allocator,
        rand: std.Random,
        num_items: usize,
        bloom_size_bytes: usize,
    ) error{ NotEnoughSignedGossipDatas, OutOfMemory }!Self {
        const bloom_size_bits: f64 = @floatFromInt(bloom_size_bytes * 8);
        // mask_bits = log2(..) number of filters
        const mask_bits = GossipPullFilter.computeMaskBits(@floatFromInt(num_items), bloom_size_bits);
        const n_filters: usize = @intCast(@as(u64, 1) << @as(u6, @intCast(mask_bits)));

        // TODO; add errdefer handling here
        const max_items = GossipPullFilter.computeMaxItems(bloom_size_bits, FALSE_RATE, KEYS);
        var filters = try ArrayList(Bloom).initCapacity(alloc, n_filters);
        for (0..n_filters) |_| {
            const filter = try Bloom.random(
                alloc,
                rand,
                @intFromFloat(max_items),
                FALSE_RATE,
                @intFromFloat(bloom_size_bits),
            );
            filters.appendAssumeCapacity(filter);
        }

        return Self{
            .filters = filters,
            .mask_bits = mask_bits,
        };
    }

    pub fn initTest(alloc: std.mem.Allocator, rand: std.Random, mask_bits: u32) error{ NotEnoughSignedGossipDatas, OutOfMemory }!Self {
        const n_filters: usize = @intCast(@as(u64, 1) << @as(u6, @intCast(mask_bits)));

        var filters = try ArrayList(Bloom).initCapacity(alloc, n_filters);
        for (0..n_filters) |_| {
            const filter = try Bloom.random(alloc, rand, 1000, FALSE_RATE, MAX_BLOOM_SIZE);
            filters.appendAssumeCapacity(filter);
        }
        return Self{
            .filters = filters,
            .mask_bits = mask_bits,
        };
    }

    /// note: does not free filter values bc we take ownership of them in
    /// getGossipPullFilters
    pub fn deinit(self: *Self) void {
        self.filters.deinit();
    }

    pub fn hashIndex(mask_bits: u32, hash: *const Hash) usize {
        if (mask_bits == 0) {
            return 0;
        }
        // 64 = u64 bits
        const shift_bits: u6 = @intCast(64 - mask_bits);
        // only look at the first `mask_bits` bits
        // which represents `n_filters` number of indexs
        const index = @as(usize, hashToU64(hash) >> shift_bits);
        return index;
    }

    pub fn add(self: *Self, hash: *const Hash) void {
        const index = GossipPullFilterSet.hashIndex(self.mask_bits, hash);
        self.filters.items[index].add(&hash.data);
    }

    pub fn len(self: Self) usize {
        return self.filters.items.len;
    }

    /// returns a list of GossipPullFilters and consumes Self by calling deinit.
    pub fn consumeForGossipPullFilters(self: *Self, alloc: std.mem.Allocator, rand: std.Random, max_size: usize) error{OutOfMemory}!ArrayList(GossipPullFilter) {
        defer self.deinit(); // !

        const set_size = self.len();
        var indexs = try ArrayList(usize).initCapacity(alloc, set_size);
        defer indexs.deinit();
        for (0..set_size) |i| {
            indexs.appendAssumeCapacity(i);
        }

        const n_filters = @min(set_size, max_size);
        const can_consume_all = max_size >= set_size;

        if (!can_consume_all) {
            // shuffle the indexs
            shuffleFirstN(rand, usize, indexs.items, n_filters);

            // release others
            for (n_filters..set_size) |i| {
                const index = indexs.items[i];
                self.filters.items[index].deinit();
            }
        }

        var filters = try ArrayList(GossipPullFilter).initCapacity(alloc, n_filters);
        for (0..n_filters) |i| {
            const index = indexs.items[i];

            const filter = GossipPullFilter{
                .filter = self.filters.items[index], // take ownership of filter
                .mask = GossipPullFilter.computeMask(index, self.mask_bits),
                .mask_bits = self.mask_bits,
            };
            filters.appendAssumeCapacity(filter);
        }

        return filters;
    }
};

/// Analogous to [CrdsFilter](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_gossip_pull.rs#L60)
pub const GossipPullFilter = struct {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,

    const Self = @This();

    /// only used in tests
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .filter = Bloom.init(allocator, 0, null),
            .mask = 18_446_744_073_709_551_615,
            .mask_bits = 0,
        };
    }

    pub fn computeMask(index: u64, mask_bits: u32) u64 {
        if (mask_bits == 0) {
            return ~@as(u64, 0);
        }

        std.debug.assert(index <= std.math.pow(u64, 2, mask_bits));
        // eg, with index = 2 and mask_bits = 3
        // shift_bits = 61 (ie, only look at first 2 bits)
        const shift_bits: u6 = @intCast(64 - mask_bits);
        // 2 << 61 = 100...000
        const shifted_index = index << shift_bits;
        // OR with all the other zeros
        //  10                 111111..11111
        //   ^                         ^
        // index (mask_bits length) | rest
        return shifted_index | (~@as(u64, 0) >> @as(u6, @intCast(mask_bits)));
    }

    pub fn computeMaskBits(num_items: f64, max: f64) u32 {
        return @intFromFloat(@max(0, (std.math.ceil(std.math.log2(num_items / max)))));
    }

    pub fn computeMaxItems(max_bits: f64, false_rate: f64, num_keys: f64) f64 {
        const m = max_bits;
        const p = false_rate;
        const k = num_keys;
        return std.math.ceil(m / (-k / @log(@as(f64, 1) - exp(@log(p) / k))));
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

pub fn hashToU64(hash: *const Hash) u64 {
    const buf = hash.data[0..8];
    return std.mem.readInt(u64, buf, .little);
}

const LegacyContactInfo = _gossip_data.LegacyContactInfo;

test "gossip.pull_request: test building filters" {
    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    var tp = ThreadPool.init(.{});
    var gossip_table = try GossipTable.init(std.testing.allocator, &tp);
    defer gossip_table.deinit();

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    for (0..64) |_| {
        const id = Pubkey.random(rng);
        var legacy_contact_info = LegacyContactInfo.default(id);
        legacy_contact_info.id = id;
        const gossip_value = try SignedGossipData.initSigned(.{
            .LegacyContactInfo = legacy_contact_info,
        }, &kp);

        try gossip_table.insert(gossip_value, 0);
    }

    const max_bytes = 2;
    const num_items = gossip_table.len();

    // build filters
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);

    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try buildGossipPullFilters(
        std.testing.allocator,
        rng,
        &gossip_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer deinitGossipPullFilters(&filters);

    const mask_bits = filters.items[0].mask_bits;

    // assert value is in the filter
    const gossip_values = gossip_table.store.iterator().values;
    for (0..num_items) |i| {
        const versioned_value = gossip_values[i];
        const hash = versioned_value.value_hash;

        const index = GossipPullFilterSet.hashIndex(mask_bits, &hash);
        const filter = filters.items[index].filter;
        try std.testing.expect(filter.contains(&hash.data));
    }
}

test "gossip.pull_request: filter set deinits correct" {
    var prng = std.Random.Xoshiro256.init(@intCast(std.time.milliTimestamp()));
    const rand = prng.random();

    var filter_set = try GossipPullFilterSet.init(std.testing.allocator, rand, 10000, 200);

    const hash = Hash.random(rand);
    filter_set.add(&hash);

    const index = GossipPullFilterSet.hashIndex(filter_set.mask_bits, &hash);
    var bloom = filter_set.filters.items[index];

    const v = bloom.contains(&hash.data);
    try std.testing.expect(v);

    var f = try filter_set.consumeForGossipPullFilters(std.testing.allocator, rand, 10);
    defer deinitGossipPullFilters(&f);

    try std.testing.expect(f.capacity == filter_set.len());

    const x = f.items[index];
    try std.testing.expect(x.filter.contains(&hash.data));
}

test "gossip.pull_request: helper functions are correct" {
    {
        const v = GossipPullFilter.computeMaxItems(100.5, 0.1, 10.0);
        try std.testing.expectEqual(@as(f64, 16), v);
    }

    {
        const v = GossipPullFilter.computeMaskBits(800, 100);
        try std.testing.expectEqual(@as(usize, 3), v);
    }

    {
        const v = Hash{ .data = .{1} ++ .{0} ** 31 };
        try std.testing.expectEqual(@as(u64, 1), hashToU64(&v));
    }

    {
        const v = GossipPullFilter.computeMask(2, 3);
        // 101111111111111111111111111111111111111111111111111111111111111
        try std.testing.expectEqual(@as(u64, 6917529027641081855), v);
    }
}

test "gossip.pull_request: gossip filter matches rust bytes" {
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0 };
    var filter = GossipPullFilter.init(std.testing.allocator);
    defer filter.deinit();

    var buf = [_]u8{0} ** 1024;
    const bytes = try bincode.writeToSlice(buf[0..], filter, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes);
}
