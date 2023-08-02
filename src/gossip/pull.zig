const std = @import("std");
const SocketAddr = @import("net.zig").SocketAddr;
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const Transaction = @import("../core/transaction.zig").Transaction;
const Slot = @import("../core/slot.zig").Slot;
const Option = @import("../option.zig").Option;
const ContactInfo = @import("node.zig").ContactInfo;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const ln = std.math.ln;
const exp = std.math.exp;

const CrdsTable = @import("crds_table.zig").CrdsTable;
const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;

pub const MAX_NUM_PULL_REQUESTS: usize = 20; // labs - 1024;
pub const FALSE_RATE: f64 = 0.1;
pub const KEYS: f64 = 8;

// TODO: make it batch
pub fn filter_crds_values(
    alloc: std.mem.Allocator,
    crds_table: *CrdsTable,
    value: *CrdsValue,
    filter: *CrdsFilter,
    output_size_limit: usize,
    now: u64,
) !?ArrayList(CrdsValue) {
    crds_table.read();
    defer crds_table.release_read();

    if (output_size_limit == 0) {
        return null;
    }

    var caller_wallclock = value.wallclock();
    const is_too_old = caller_wallclock < now -| CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS;
    const is_too_new = caller_wallclock > now +| CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS;
    if (is_too_old or is_too_new) {
        return null;
    }

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const jitter = rng.intRangeAtMost(u64, 0, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 4);
    caller_wallclock = caller_wallclock + jitter;

    var output = ArrayList(CrdsValue).init(alloc);
    var bloom = filter.filter;

    var match_indexs = try crds_table.get_bitmask_matches(alloc, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

    for (match_indexs.items) |entry_index| {
        var entry = crds_table.store.iterator().values[entry_index];

        // entry is too new
        if (entry.value.wallclock() > caller_wallclock) {
            continue;
        }
        // entry is already contained in the bloom
        if (bloom.contains(&entry.value_hash.data)) {
            continue;
        }
        // exclude contact info (? not sure why - labs does it)
        if (entry.value.data == crds.CrdsData.ContactInfo) {
            continue;
        }

        // good
        try output.append(entry.value);
        if (output.items.len == output_size_limit) {
            break;
        }
    }

    return output;
}

pub fn deinit_crds_filters(filters: *ArrayList(CrdsFilter)) void {
    for (filters.items) |*filter| {
        filter.deinit();
    }
    filters.deinit();
}

/// parses all the values in the crds table and returns a list of
/// corresponding filters. Note: make sure to call deinit_crds_filters.
pub fn build_crds_filters(
    alloc: std.mem.Allocator,
    crds_table: *CrdsTable,
    bloom_size: usize,
) !ArrayList(CrdsFilter) {
    crds_table.read();
    defer crds_table.release_read();

    const num_items = crds_table.len();
    // TODO: purged + failed inserts

    var filter_set = try CrdsFilterSet.init(alloc, num_items, bloom_size);

    const crds_values = crds_table.store.iterator().values;
    for (0..num_items) |i| {
        const hash = crds_values[i].value_hash;
        filter_set.add(&hash);
    }

    // note: filter set is deinit() in this fcn
    const filters = try filter_set.consumeForCrdsFilters(alloc, MAX_NUM_PULL_REQUESTS);
    return filters;
}

pub const CrdsFilterSet = struct {
    filters: ArrayList(Bloom),

    // mask bits represents the number of bits required to represent the number of
    // filters.
    mask_bits: u32, // todo: make this a u6

    const Self = @This();

    pub fn init(alloc: std.mem.Allocator, num_items: usize, max_bytes: usize) !Self {
        var max_bits: f64 = @floatFromInt(max_bytes * 8);
        var max_items = CrdsFilter.compute_max_items(max_bits, FALSE_RATE, KEYS);
        // mask_bits = log2(..) number of filters
        var mask_bits = CrdsFilter.compute_mask_bits(@floatFromInt(num_items), max_bits);
        std.debug.assert(mask_bits > 0);

        const n_filters: usize = @intCast(@as(u64, 1) << @as(u6, @intCast(mask_bits)));
        std.debug.assert(n_filters > 0);

        // TODO; add errdefer handling here
        var filters = try ArrayList(Bloom).initCapacity(alloc, n_filters);
        for (0..n_filters) |_| {
            var filter = try Bloom.random(alloc, @intFromFloat(max_items), FALSE_RATE, @intFromFloat(max_bits));
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
    pub fn consumeForCrdsFilters(self: *Self, alloc: std.mem.Allocator, max_size: usize) !ArrayList(CrdsFilter) {
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
            var seed = @as(u64, @intCast(std.time.milliTimestamp()));
            var rand = std.rand.DefaultPrng.init(seed);
            for (0..output_size) |i| {
                const j = @min(set_size, @max(0, rand.random().int(usize)));
                std.mem.swap(usize, &indexs.items[i], &indexs.items[j]);
            }

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

    // only used in tests
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
        return std.math.ceil(m / (-k / ln(@as(f64, 1) - exp(ln(p) / k))));
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

pub fn hash_to_u64(hash: *const Hash) u64 {
    const buf = hash.data[0..8];
    return std.mem.readIntLittle(u64, buf);
}

test "gossip.pull: test filter_crds_values" {
    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    for (0..100) |_| {
        // var id = Pubkey.random(rng, .{});
        // var legacy_contact_info = crds.LegacyContactInfo.default();
        // legacy_contact_info.wallclock = 40;
        // legacy_contact_info.id = id;
        // var crds_value = try crds.CrdsValue.initSigned(crds.CrdsData{
        //     .LegacyContactInfo = legacy_contact_info,
        // }, kp);

        var crds_value = try crds.CrdsValue.random(rng, kp);
        try crds_table.insert(crds_value, 0);
    }

    const max_bytes = 10;

    // recver
    var filters = try build_crds_filters(std.testing.allocator, &crds_table, max_bytes);
    defer deinit_crds_filters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    var legacy_contact_info = crds.LegacyContactInfo.default();
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var crds_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, kp);

    // insert more values which the filters should be missing
    for (0..64) |_| {
        var v2 = try crds.CrdsValue.random(rng, kp);
        try crds_table.insert(v2, 0);
    }

    var values = (try filter_crds_values(
        std.testing.allocator,
        &crds_table,
        &crds_value,
        &filter,
        100,
        @intCast(std.time.milliTimestamp()),
    )).?;
    defer values.deinit();

    try std.testing.expect(values.items.len > 0);
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
        var legacy_contact_info = crds.LegacyContactInfo.default();
        legacy_contact_info.id = id;
        var crds_value = try crds.CrdsValue.initSigned(crds.CrdsData{
            .LegacyContactInfo = legacy_contact_info,
        }, kp);

        try crds_table.insert(crds_value, 0);
    }

    const max_bytes = 2;
    const num_items = crds_table.len();

    // build filters
    var filters = try build_crds_filters(std.testing.allocator, &crds_table, max_bytes);
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

    var f = try filter_set.consumeForCrdsFilters(std.testing.allocator, 10);
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
