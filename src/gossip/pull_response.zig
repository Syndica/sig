const std = @import("std");
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const ContactInfo = @import("node.zig").ContactInfo;
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const exp = std.math.exp;

const RwMux = @import("../sync/mux.zig").RwMux;
const CrdsTable = @import("crds_table.zig").CrdsTable;
const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;

const crds_pull_req = @import("./pull_request.zig");
const CrdsFilter = crds_pull_req.CrdsFilter;

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;

// TODO: make it batch
pub fn filter_crds_values(
    alloc: std.mem.Allocator,
    crds_table: *const CrdsTable,
    filter: *const CrdsFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}!ArrayList(CrdsValue) {
    if (max_number_values == 0) {
        return ArrayList(CrdsValue).init(alloc);
    }

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const jitter = rng.intRangeAtMost(u64, 0, CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    var output = ArrayList(CrdsValue).init(alloc);
    errdefer output.deinit();

    var bloom = filter.filter;

    var match_indexs = try crds_table.get_bitmask_matches(alloc, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

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
        if (entry.value.data == crds.CrdsData.ContactInfo) {
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
    var crds_table = try CrdsTable.init(std.testing.allocator);
    var crds_table_rw = RwMux(CrdsTable).init(crds_table);
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
        var crds_value = try crds.CrdsValue.random(rng, &kp);
        try lg.mut().insert(crds_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try crds_pull_req.build_crds_filters(
        std.testing.allocator,
        &crds_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer crds_pull_req.deinit_crds_filters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);
    var legacy_contact_info = crds.LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var crds_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    // insert more values which the filters should be missing
    lg = crds_table_rw.write();
    for (0..64) |_| {
        var v2 = try crds.CrdsValue.random(rng, &kp);
        try lg.mut().insert(v2, 0);
    }

    var values = try filter_crds_values(
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
