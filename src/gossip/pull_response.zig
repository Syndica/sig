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
const exp = std.math.exp;

const CrdsTable = @import("crds_table.zig").CrdsTable;
const crds = @import("crds.zig");
const CrdsValue = crds.CrdsValue;

const crds_pull_req = @import("./pull_request.zig");
const CrdsFilter = crds_pull_req.CrdsFilter;

pub const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;

// TODO: make it batch
pub fn filter_crds_values(
    alloc: std.mem.Allocator,
    crds_table: *CrdsTable,
    value: *CrdsValue,
    filter: *CrdsFilter,
    output_size_limit: usize,
    now: u64,
) !ArrayList(CrdsValue) {
    crds_table.read();
    defer crds_table.release_read();

    if (output_size_limit == 0) {
        return ArrayList(CrdsValue).init(alloc);
    }

    var caller_wallclock = value.wallclock();
    const is_too_old = caller_wallclock < now -| CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS;
    const is_too_new = caller_wallclock > now +| CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS;
    if (is_too_old or is_too_new) {
        return ArrayList(CrdsValue).init(alloc);
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
        try crds_table.insert(crds_value, 0, null);
    }

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try crds_pull_req.build_crds_filters(
        std.testing.allocator,
        &crds_table,
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
    }, kp);

    // insert more values which the filters should be missing
    for (0..64) |_| {
        var v2 = try crds.CrdsValue.random(rng, kp);
        try crds_table.insert(v2, 0, null);
    }

    var values = try filter_crds_values(
        std.testing.allocator,
        &crds_table,
        &crds_value,
        &filter,
        100,
        @intCast(std.time.milliTimestamp()),
    );
    defer values.deinit();

    try std.testing.expect(values.items.len > 0);
}
