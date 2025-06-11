const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Bloom = sig.bloom.Bloom;
const GossipTable = sig.gossip.GossipTable;
const SignedGossipData = sig.gossip.SignedGossipData;
const RwMux = sig.sync.RwMux;

pub const MAX_BLOOM_SIZE: usize = 928;
pub const MAX_NUM_PULL_REQUESTS: usize = 20; // labs - 1024;
pub const FALSE_RATE: f64 = 0.1;
pub const KEYS: f64 = 8;

/// parses all the values in the gossip table and returns a list of
/// corresponding filters. Note: make sure to call deinit_gossip_filters.
pub fn buildGossipPullFilters(
    allocator: std.mem.Allocator,
    random: std.Random,
    gossip_table_rw: *RwMux(GossipTable),
    failed_pull_hashes: []const Hash,
    bloom_size: usize,
    max_n_filters: usize,
) error{ NotEnoughSignedGossipDatas, OutOfMemory }![]GossipPullFilter {
    var filter_set = blk: {
        var gossip_table_lock = gossip_table_rw.read();
        defer gossip_table_lock.unlock();
        const gossip_table: *const GossipTable = gossip_table_lock.get();

        const num_items = gossip_table.length() +
            gossip_table.purged.length() +
            failed_pull_hashes.len;

        var filter_set = try GossipPullFilterSet.init(allocator, random, num_items, bloom_size);
        errdefer filter_set.deinit(allocator);

        // add all gossip values
        for (gossip_table.store.metadata.items) |metadata| {
            filter_set.add(&metadata.value_hash);
        }

        // add purged values
        for (gossip_table.purged.queue.items(.hash)) |hash| {
            filter_set.add(&hash);
        }

        // add failed inserts
        for (failed_pull_hashes) |hash| {
            filter_set.add(&hash);
        }

        break :blk filter_set;
    };

    // note: filter set is deinit() in this fcn
    return try filter_set.getFiltersAndDeinit(
        allocator,
        random,
        max_n_filters,
    );
}

/// Takes ownership and de-allocates the input `filters` slice.
pub fn deinitGossipPullFilters(filters: []GossipPullFilter, allocator: std.mem.Allocator) void {
    for (filters) |*filter| filter.deinit(allocator);
    allocator.free(filters);
}

pub const GossipPullFilterSet = struct {
    filters: std.ArrayListUnmanaged(Bloom),
    /// The number of bits required to represent the number of filters.
    mask_bits: u6,

    pub fn init(
        allocator: std.mem.Allocator,
        random: std.Random,
        num_items: usize,
        bloom_size_bytes: usize,
    ) error{ NotEnoughSignedGossipDatas, OutOfMemory }!GossipPullFilterSet {
        const bloom_size_bits: f64 = @floatFromInt(bloom_size_bytes * 8);
        // mask_bits = log2(..) number of filters
        const mask_bits = GossipPullFilter.computeMaskBits(
            @floatFromInt(num_items),
            bloom_size_bits,
        );
        const n_filters = @as(u64, 1) << mask_bits;

        const max_items = GossipPullFilter.computeMaxItems(bloom_size_bits, FALSE_RATE, KEYS);

        const filters = try allocator.alloc(Bloom, n_filters);
        errdefer allocator.free(filters);

        for (filters, 0..) |*filter, i| {
            errdefer for (filters[0..i]) |*f| f.deinit(allocator);
            filter.* = try Bloom.initRandom(
                allocator,
                random,
                @intFromFloat(max_items),
                FALSE_RATE,
                @intFromFloat(bloom_size_bits),
            );
        }

        return .{
            .filters = .fromOwnedSlice(filters),
            .mask_bits = mask_bits,
        };
    }

    pub fn initTest(
        allocator: std.mem.Allocator,
        random: std.Random,
        mask_bits: u6,
    ) error{ NotEnoughSignedGossipDatas, OutOfMemory }!GossipPullFilterSet {
        const n_filters = @as(u64, 1) << mask_bits;
        const filters = try allocator.alloc(Bloom, n_filters);

        for (filters) |*filter| {
            filter.* = try Bloom.initRandom(
                allocator,
                random,
                1000,
                FALSE_RATE,
                MAX_BLOOM_SIZE,
            );
        }

        return .{
            .filters = .fromOwnedSlice(filters),
            .mask_bits = mask_bits,
        };
    }

    /// NOTE: there are only a few select usecases for this function. It should only be
    /// used in an `errdefer`, since the main usecase is `getFiltersAndDeinit` which
    /// has its own de-allocation scheme. For cases where we want to handle failures
    /// before `getFiltersAndDeinit` is called, we use this `deinit` function.
    pub fn deinit(self: *GossipPullFilterSet, allocator: std.mem.Allocator) void {
        for (self.filters.items) |*filter| filter.deinit(allocator);
        self.filters.deinit(allocator);
    }

    pub fn hashIndex(mask_bits: u32, hash: *const Hash) usize {
        if (mask_bits == 0) {
            return 0;
        }
        // 64 = u64 bits
        const shift_bits: u6 = @intCast(64 - mask_bits);
        // only look at the first `mask_bits` bits
        // which represents `n_filters` number of indices
        return hashToU64(hash) >> shift_bits;
    }

    pub fn add(self: *GossipPullFilterSet, hash: *const Hash) void {
        const index = GossipPullFilterSet.hashIndex(self.mask_bits, hash);
        self.filters.items[index].add(&hash.data);
    }

    pub fn length(self: GossipPullFilterSet) usize {
        return self.filters.items.len;
    }

    /// Caller owns the returned slice of `GossipPullFilters` and the allocated data within the
    /// bloom filters inside of the filters.
    ///
    /// This function is equivalent to calling `deinit` on other data structuers, but is designed
    /// to better handle incremental de-allocation of the filters and avoid cloning the filters.
    pub fn getFiltersAndDeinit(
        self: *GossipPullFilterSet,
        allocator: std.mem.Allocator,
        random: std.Random,
        max_size: usize,
    ) error{OutOfMemory}![]GossipPullFilter {
        // run the deinit iff we're not returning an error, since we expect there to be an `errdefer`
        // about the callsite to handle the error case.
        var is_ok: bool = true;
        defer if (is_ok) {
            // we don't deinit the filters themselves, since the callee of this function owns them now.
            self.filters.deinit(allocator);
            self.* = undefined;
        };
        errdefer is_ok = false;

        const set_size = self.length();
        const indices = try allocator.alloc(u64, set_size);
        defer allocator.free(indices);
        for (indices, 0..) |*i, j| i.* = j;

        const n_filters = @min(set_size, max_size);
        const can_consume_all = max_size >= set_size;

        if (!can_consume_all) {
            // shuffle the indices
            sig.rand.shuffleFocusedRange(random, usize, indices, 0, n_filters);

            // release others
            for (n_filters..set_size) |i| {
                const index = indices[i];
                self.filters.items[index].deinit(allocator);
            }
        }

        const filters = try allocator.alloc(GossipPullFilter, n_filters);
        errdefer allocator.free(filters);

        for (filters, 0..) |*filter, i| {
            errdefer for (filters[0..i]) |*f| f.deinit(allocator);
            const index = indices[i];
            filter.* = .{
                .bloom = self.filters.items[index],
                .mask = GossipPullFilter.computeMask(index, self.mask_bits),
                .mask_bits = self.mask_bits,
            };
        }

        return filters;
    }
};

/// Analogous to [CrdsFilter](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_gossip_pull.rs#L60)
pub const GossipPullFilter = struct {
    bloom: Bloom,
    mask: u64,
    mask_bits: u32,

    /// only used in tests
    pub fn init(allocator: std.mem.Allocator) !GossipPullFilter {
        return .{
            .bloom = try Bloom.init(allocator, 0, .empty),
            .mask = std.math.maxInt(u64),
            .mask_bits = 0,
        };
    }

    pub fn deinit(self: *GossipPullFilter, allocator: std.mem.Allocator) void {
        self.bloom.deinit(allocator);
    }

    pub fn computeMask(index: u64, mask_bits: u6) u64 {
        if (mask_bits == 0) return std.math.maxInt(u64);

        std.debug.assert(index <= std.math.pow(u64, 2, mask_bits));
        // eg, with index = 2 and mask_bits = 3
        // shift_bits = 61 (ie, only look at first 2 bits)
        const shift_bits: u6 = @intCast(@as(u7, 64) - mask_bits);
        // 2 << 61 = 100...000
        const shifted_index = index << shift_bits;
        // OR with all the other zeros
        //  10                 111111..11111
        //   ^                         ^
        // index (mask_bits length) | rest
        return shifted_index | (~@as(u64, 0) >> mask_bits);
    }

    pub fn computeMaskBits(num_items: f64, max: f64) u6 {
        const bottom = std.math.ceil(std.math.log2(num_items / max));
        return @intFromFloat(@max(0, bottom));
    }

    pub fn computeMaxItems(max_bits: f64, false_rate: f64, num_keys: f64) f64 {
        const m = max_bits;
        const p = false_rate;
        const k = num_keys;
        return std.math.ceil(m / (-k / @log(@as(f64, 1) - std.math.exp(@log(p) / k))));
    }
};

pub fn hashToU64(hash: *const Hash) u64 {
    const buf = hash.data[0..8];
    return std.mem.readInt(u64, buf, .little);
}

test "building pull filters" {
    const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
    const allocator = std.testing.allocator;

    var gossip_table = try GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    // insert a some value
    const kp = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    for (0..64) |_| {
        const id = Pubkey.initRandom(random);
        var legacy_contact_info = LegacyContactInfo.default(id);
        legacy_contact_info.id = id;
        const gossip_value = SignedGossipData.initSigned(
            &kp,
            .{ .LegacyContactInfo = legacy_contact_info },
        );
        _ = try gossip_table.insert(gossip_value, 0);
    }

    const max_bytes = 2;
    const num_items = gossip_table.length();

    // build filters
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);

    const filters = try buildGossipPullFilters(
        allocator,
        random,
        &gossip_table_rw,
        &.{},
        max_bytes,
        100,
    );
    defer deinitGossipPullFilters(filters, allocator);

    const mask_bits = filters[0].mask_bits;

    // assert value is in the filter
    try std.testing.expectEqual(num_items, gossip_table.store.count());
    for (gossip_table.store.metadata.items) |metadata| {
        const index = GossipPullFilterSet.hashIndex(mask_bits, &metadata.value_hash);
        const bloom = filters[index].bloom;
        try std.testing.expect(bloom.contains(&metadata.value_hash.data));
    }
}

test "filter set deinits correct" {
    const allocator = std.testing.allocator;

    var prng = std.Random.Xoshiro256.init(123);
    const random = prng.random();

    var filter_set = try GossipPullFilterSet.init(allocator, random, 10000, 200);

    const hash = Hash.initRandom(random);
    filter_set.add(&hash);

    const index = GossipPullFilterSet.hashIndex(filter_set.mask_bits, &hash);
    var bloom = filter_set.filters.items[index];
    try std.testing.expect(bloom.contains(&hash.data));

    // get the length before calling deinit
    const filter_set_length = filter_set.length();
    const f = try filter_set.getFiltersAndDeinit(
        allocator,
        random,
        10,
    );
    defer deinitGossipPullFilters(f, allocator);

    try std.testing.expectEqual(filter_set_length, f.len);
    try std.testing.expect(f[index].bloom.contains(&hash.data));
}

test "helper functions are correct" {
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
        // 0b101111111111111111111111111111111111111111111111111111111111111
        try std.testing.expectEqual(@as(u64, 6917529027641081855), v);
    }
}

test "filter matches rust bytes" {
    const allocator = std.testing.allocator;

    var filter = try GossipPullFilter.init(allocator);
    defer filter.deinit(allocator);

    var buffer: [1024]u8 = undefined;
    const bytes = try bincode.writeToSlice(&buffer, filter, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, &.{
        0, 0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
        0, 0,   0,   0,   0,   0,   0,   0,   0,   0, 0, 0,
        0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0,
        0,
    }, bytes);
}

test "filter set init checkAllocations" {
    const S = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var prng = std.Random.Xoshiro256.init(123);
            const random = prng.random();

            var filter_set = try GossipPullFilterSet.init(allocator, random, 10000, 200);
            errdefer filter_set.deinit(allocator);

            const filters = try filter_set.getFiltersAndDeinit(allocator, random, 200);
            defer deinitGossipPullFilters(filters, allocator);
        }
    };

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        S.run,
        .{},
    );
}
