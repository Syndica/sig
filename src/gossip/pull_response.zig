const std = @import("std");
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const ContactInfo = @import("node.zig").ContactInfo;
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const RwMux = @import("../sync/mux.zig").RwMux;
const GossipTable = @import("table.zig").GossipTable;
const crds = @import("data.zig");
const GossipDataWithSignature = crds.GossipDataWithSignature;

const crds_pull_req = @import("./pull_request.zig");
const GossipFilter = crds_pull_req.GossipFilter;

pub const GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;

pub fn filterGossipDataWithSignatures(
    alloc: std.mem.Allocator,
    crds_table: *const GossipTable,
    filter: *const GossipFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}!ArrayList(GossipDataWithSignature) {
    if (max_number_values == 0) {
        return ArrayList(GossipDataWithSignature).init(alloc);
    }

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const jitter = rng.intRangeAtMost(u64, 0, GOSSIP_PULL_CRDS_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    var bloom = filter.filter;

    var match_indexs = try crds_table.getBitmaskMatches(alloc, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

    const output_size = @min(max_number_values, match_indexs.items.len);
    var output = try ArrayList(GossipDataWithSignature).initCapacity(alloc, output_size);
    errdefer output.deinit();

    for (match_indexs.items) |entry_index| {
        var entry = crds_table.store.iterator().values[entry_index];

        // entry is too new
        if (entry.value.wallclock() > caller_wallclock_with_jitter) {
            continue;
        }
        // entry is already contained in the bloom
        if (bloom.contains(&entry.value_hash.data)) {
            continue;
        }
        // exclude contact info (? not sure why - labs does it)
        if (entry.value.data == crds.GossipData.ContactInfo) {
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

test "gossip.pull: test filter_crds_values" {
    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    var tp = ThreadPool.init(.{});
    var crds_table = try GossipTable.init(std.testing.allocator, &tp);
    var crds_table_rw = RwMux(GossipTable).init(crds_table);
    defer {
        var lg = crds_table_rw.write();
        lg.mut().deinit();
    }

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = 18;
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var lg = crds_table_rw.write();
    for (0..100) |_| {
        var crds_value = try crds.GossipDataWithSignature.random(rng, &kp);
        try lg.mut().insert(crds_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try crds_pull_req.buildGossipFilters(
        std.testing.allocator,
        &crds_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer crds_pull_req.deinitGossipFilters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    var legacy_contact_info = crds.LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    // TODO: make this consistent across tests
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var crds_value = try GossipDataWithSignature.initSigned(crds.GossipData{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    // insert more values which the filters should be missing
    lg = crds_table_rw.write();
    for (0..64) |_| {
        var v2 = try crds.GossipDataWithSignature.random(rng, &kp);
        try lg.mut().insert(v2, 0);
    }

    var values = try filterGossipDataWithSignatures(
        std.testing.allocator,
        lg.get(),
        &filter,
        crds_value.wallclock(),
        100,
    );
    defer values.deinit();
    lg.unlock();

    try std.testing.expect(values.items.len > 0);
}
