const std = @import("std");
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const ContactInfo = @import("node.zig").ContactInfo;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const CrdsTable = @import("crds_table.zig").CrdsTable;
const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;

const RwMux = @import("../sync/mux.zig").RwMux;

pub const MAX_CRDS_OBJECT_SIZE: usize = 928;
pub const MAX_BLOOM_SIZE: usize = MAX_CRDS_OBJECT_SIZE;

pub const MAX_NUM_PULL_REQUESTS: usize = 20; // labs - 1024;
pub const FALSE_RATE: f64 = 0.1;
pub const KEYS: f64 = 8;

/// parses all the values in the crds table and returns a list of
/// corresponding filters. Note: make sure to call deinit_crds_filters.
pub fn build_crds_filters(
    alloc: std.mem.Allocator,
    crds_table_rw: *RwMux(CrdsTable),
    failed_pull_hashes: *const ArrayList(Hash),
    bloom_size: usize,
    max_n_filters: usize,
) error{ NotEnoughCrdsValues, OutOfMemory }!ArrayList(CrdsFilter) {
    var filter_set = blk: {
        var crds_table_lock = crds_table_rw.read();
        const crds_table: *const CrdsTable = crds_table_lock.get();
        defer crds_table_lock.unlock();

        const num_items = crds_table.len() + crds_table.purged.len() + failed_pull_hashes.items.len;

        var filter_set = try CrdsFilterSet.init(alloc, num_items, bloom_size);
        errdefer filter_set.deinit();

        // add all crds values
        const crds_values = crds_table.store.iterator().values;
        for (0..crds_table.len()) |i| {
            const hash = crds_values[i].value_hash;
            filter_set.add(&hash);
        }
        // add purged values
        const purged_values = try crds_table.purged.get_values(alloc);
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
    const filters = try filter_set.consume_for_crds_filters(alloc, max_n_filters);
    return filters;
}

pub fn deinit_crds_filters(filters: *ArrayList(CrdsFilter)) void {
    for (filters.items) |*filter| {
        filter.deinit();
    }
    filters.deinit();
}

pub fn shuffle_first_n(rng: std.rand.Random, comptime T: type, buf: []T, n: usize) void {
    for (0..n) |i| {
        const j = rng.intRangeLessThan(usize, 0, buf.len);
        std.mem.swap(T, &buf[i], &buf[j]);
    }
}

pub const CrdsFilterSet = struct {
    filters: ArrayList(Bloom),

    // mask bits represents the number of bits required to represent the number of
    // filters.
    mask_bits: u32, // todo: make this a u6

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, num_items: usize, bloom_size_bytes: usize) error{ NotEnoughCrdsValues, OutOfMemory }!Self {
        var bloom_size_bits: f64 = @floatFromInt(bloom_size_bytes * 8);
        // mask_bits = log2(..) number of filters
        var mask_bits = CrdsFilter.compute_mask_bits(@floatFromInt(num_items), bloom_size_bits);
        if (mask_bits == 0) return error.NotEnoughCrdsValues;

        const n_filters: usize = @intCast(@as(u64, 1) << @as(u6, @intCast(mask_bits)));

        // TODO; add errdefer handling here
        var max_items = CrdsFilter.compute_max_items(bloom_size_bits, FALSE_RATE, KEYS);
        var filters = try ArrayList(Bloom).initCapacity(alloc, n_filters);
        for (0..n_filters) |_| {
            var filter = try Bloom.random(alloc, @intFromFloat(max_items), FALSE_RATE, @intFromFloat(bloom_size_bits));
            filters.appendAssumeCapacity(filter);
        }

        return Self{
            .filters = filters,
            .mask_bits = mask_bits,
        };
    }

    /// note: does not free filter values bc we take ownership of them in
    /// getCrdsFilters
    pub fn deinit(self: *Self) void {
        self.filters.deinit();
    }

    pub fn hash_index(mask_bits: u32, hash: *const Hash) usize {
        // 64 = u64 bits
        const shift_bits: u6 = @intCast(64 - mask_bits);
        // only look at the first `mask_bits` bits
        // which represents `n_filters` number of indexs
        const index = @as(usize, hash_to_u64(hash) >> shift_bits);
        return index;
    }

    pub fn add(self: *Self, hash: *const Hash) void {
        const index = CrdsFilterSet.hash_index(self.mask_bits, hash);
        self.filters.items[index].add(&hash.data);
    }

    pub fn len(self: Self) usize {
        return self.filters.items.len;
    }

    /// returns a list of CrdsFilters and consumes Self by calling deinit.
    pub fn consume_for_crds_filters(self: *Self, alloc: std.mem.Allocator, max_size: usize) error{OutOfMemory}!ArrayList(CrdsFilter) {
        defer self.deinit(); // !

        const set_size = self.len();
        var indexs = try ArrayList(usize).initCapacity(alloc, set_size);
        defer indexs.deinit();
        for (0..set_size) |i| {
            indexs.appendAssumeCapacity(i);
        }

        const output_size = @min(set_size, max_size);
        const can_consume_all = max_size >= set_size;

        if (!can_consume_all) {

            // shuffle the indexs
            var rng = std.rand.DefaultPrng.init(crds.get_wallclock_ms());
            shuffle_first_n(rng.random(), usize, indexs.items, output_size);

            // release others
            for (output_size..set_size) |i| {
                const index = indexs.items[i];
                self.filters.items[index].deinit();
            }
        }

        var output = try ArrayList(CrdsFilter).initCapacity(alloc, output_size);
        for (0..output_size) |i| {
            const index = indexs.items[i];

            var output_item = CrdsFilter{
                .filter = self.filters.items[index], // take ownership of filter
                .mask = CrdsFilter.compute_mask(index, self.mask_bits),
                .mask_bits = self.mask_bits,
            };
            output.appendAssumeCapacity(output_item);
        }

        return output;
    }
};

pub const CrdsFilter = struct {
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

    pub fn compute_mask(index: u64, mask_bits: u32) u64 {
        std.debug.assert(mask_bits > 0);
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

    pub fn compute_mask_bits(num_items: f64, max: f64) u32 {
        return @intFromFloat(@max(0, (std.math.ceil(std.math.log2(num_items / max)))));
    }

    pub fn compute_max_items(max_bits: f64, false_rate: f64, num_keys: f64) f64 {
        const m = max_bits;
        const p = false_rate;
        const k = num_keys;
        return std.math.ceil(m / (-k / @log(@as(f64, 1) - exp(@log(p) / k))));
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

pub fn hash_to_u64(hash: *const Hash) u64 {
    const buf = hash.data[0..8];
    return std.mem.readIntLittle(u64, buf);
}

test "gossip.pull: test build_crds_filters" {
    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    for (0..64) |_| {
        var id = Pubkey.random(rng, .{});
        var legacy_contact_info = crds.LegacyContactInfo.default(id);
        legacy_contact_info.id = id;
        var crds_value = try crds.CrdsValue.initSigned(crds.CrdsData{
            .LegacyContactInfo = legacy_contact_info,
        }, &kp);

        try crds_table.insert(crds_value, 0);
    }

    const max_bytes = 2;
    const num_items = crds_table.len();

    // build filters
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);

    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try build_crds_filters(
        std.testing.allocator,
        &crds_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer deinit_crds_filters(&filters);

    const mask_bits = filters.items[0].mask_bits;

    // assert value is in the filter
    const crds_values = crds_table.store.iterator().values;
    for (0..num_items) |i| {
        const versioned_value = crds_values[i];
        const hash = versioned_value.value_hash;

        const index = CrdsFilterSet.hash_index(mask_bits, &hash);
        const filter = filters.items[index].filter;
        try std.testing.expect(filter.contains(&hash.data));
    }
}

test "gossip.pull: CrdsFilterSet deinits correct" {
    var filter_set = try CrdsFilterSet.init(std.testing.allocator, 10000, 200);

    const hash = Hash.random();
    filter_set.add(&hash);

    const index = CrdsFilterSet.hash_index(filter_set.mask_bits, &hash);
    var bloom = filter_set.filters.items[index];

    const v = bloom.contains(&hash.data);
    try std.testing.expect(v);

    var f = try filter_set.consume_for_crds_filters(std.testing.allocator, 10);
    defer deinit_crds_filters(&f);

    try std.testing.expect(f.capacity == filter_set.len());

    const x = f.items[index];
    try std.testing.expect(x.filter.contains(&hash.data));
}

test "gossip.pull: helper functions are correct" {
    {
        const v = CrdsFilter.compute_max_items(100.5, 0.1, 10.0);
        try std.testing.expectEqual(@as(f64, 16), v);
    }

    {
        const v = CrdsFilter.compute_mask_bits(800, 100);
        try std.testing.expectEqual(@as(usize, 3), v);
    }

    {
        const v = Hash{ .data = .{1} ++ .{0} ** 31 };
        try std.testing.expectEqual(@as(u64, 1), hash_to_u64(&v));
    }

    {
        const v = CrdsFilter.compute_mask(2, 3);
        // 101111111111111111111111111111111111111111111111111111111111111
        try std.testing.expectEqual(@as(u64, 6917529027641081855), v);
    }
}

test "gossip.pull: crds filter matches rust bytes" {
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0 };
    var filter = CrdsFilter.init(std.testing.allocator);
    defer filter.deinit();

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], filter, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes);
}
