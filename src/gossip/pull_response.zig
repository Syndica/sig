const std = @import("std");
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const RwMux = @import("../sync/mux.zig").RwMux;
const GossipTable = @import("table.zig").GossipTable;
const _gossip_data = @import("data.zig");
const GossipData = _gossip_data.GossipData;
const GossipDataWithSignature = _gossip_data.GossipDataWithSignature;

const _pull_request = @import("pull_request.zig");
const GossipFilter = _pull_request.GossipFilter;
const buildGossipFilters = _pull_request.buildGossipFilters;
const deinitGossipFilters = _pull_request.deinitGossipFilters;

pub const GOSSIP_PULL_TIMEOUT_MS: u64 = 15000;

pub fn filterGossipDataWithSignatures(
    allocator: std.mem.Allocator,
    gossip_table: *const GossipTable,
    filter: *const GossipFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}!ArrayList(GossipDataWithSignature) {
    if (max_number_values == 0) {
        return ArrayList(GossipDataWithSignature).init(allocator);
    }

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const jitter = rng.intRangeAtMost(u64, 0, GOSSIP_PULL_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    var bloom = filter.filter;

    var match_indexs = try gossip_table.getBitmaskMatches(allocator, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

    const output_size = @min(max_number_values, match_indexs.items.len);
    var output = try ArrayList(GossipDataWithSignature).initCapacity(allocator, output_size);
    errdefer output.deinit();

    for (match_indexs.items) |entry_index| {
        var entry = gossip_table.store.iterator().values[entry_index];

        // entry is too new
        if (entry.value.wallclock() > caller_wallclock_with_jitter) {
            continue;
        }
        // entry is already contained in the bloom
        if (bloom.contains(&entry.value_hash.data)) {
            continue;
        }
        // exclude contact info (? not sure why - labs does it)
        if (entry.value.data == GossipData.ContactInfo) {
            continue;
        }

        // good
        try output.append(entry.value);
        if (output.items.len == max_number_values) {
            break;
        }
    }

    return output;
}

const LegacyContactInfo = _gossip_data.LegacyContactInfo;

test "gossip.pull_response: test filtering values works" {
    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    var tp = ThreadPool.init(.{});
    var gossip_table = try GossipTable.init(std.testing.allocator, &tp);
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);
    defer {
        var lg = gossip_table_rw.write();
        lg.mut().deinit();
    }

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = 18;
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var lg = gossip_table_rw.write();
    for (0..100) |_| {
        var gossip_value = try GossipDataWithSignature.random(rng, &kp);
        try lg.mut().insert(gossip_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try buildGossipFilters(
        std.testing.allocator,
        &gossip_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer deinitGossipFilters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    // TODO: make this consistent across tests
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var gossip_value = try GossipDataWithSignature.initSigned(.{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    // insert more values which the filters should be missing
    lg = gossip_table_rw.write();
    for (0..64) |_| {
        var v2 = try GossipDataWithSignature.random(rng, &kp);
        try lg.mut().insert(v2, 0);
    }

    var values = try filterGossipDataWithSignatures(
        std.testing.allocator,
        lg.get(),
        &filter,
        gossip_value.wallclock(),
        100,
    );
    defer values.deinit();
    lg.unlock();

    try std.testing.expect(values.items.len > 0);
}
