const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.mux.RwMux;
const GossipTable = sig.gossip.table.GossipTable;
const GossipData = sig.gossip.data.GossipData;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;

const buildGossipPullFilters = sig.gossip.pull_request.buildGossipPullFilters;
const deinitGossipPullFilters = sig.gossip.pull_request.deinitGossipPullFilters;

pub const GOSSIP_PULL_TIMEOUT_MS: u64 = 15000;

pub fn filterSignedGossipDatas(
    /// It is advised to use a PRNG, and not a true RNG, otherwise
    /// the runtime of this function may be unbounded.
    rand: std.Random,
    allocator: std.mem.Allocator,
    gossip_table: *const GossipTable,
    filter: *const GossipPullFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}!ArrayList(SignedGossipData) {
    if (max_number_values == 0) {
        return ArrayList(SignedGossipData).init(allocator);
    }

    const jitter = rand.intRangeAtMost(u64, 0, GOSSIP_PULL_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    var bloom = filter.filter;

    var match_indexs = try gossip_table.getBitmaskMatches(allocator, filter.mask, filter.mask_bits);
    defer match_indexs.deinit();

    const output_size = @min(max_number_values, match_indexs.items.len);
    var output = try ArrayList(SignedGossipData).initCapacity(allocator, output_size);
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

const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;

test "gossip.pull_response: test filtering values works" {
    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    var tp = ThreadPool.init(.{});
    const gossip_table = try GossipTable.init(std.testing.allocator, &tp);
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);
    defer {
        var lg = gossip_table_rw.write();
        lg.mut().deinit();
    }

    // insert a some value
    const kp = try KeyPair.create([_]u8{1} ** 32);

    var prng = std.rand.DefaultPrng.init(18);
    const random = prng.random();

    var lg = gossip_table_rw.write();
    for (0..100) |_| {
        const gossip_value = try SignedGossipData.random(random, &kp);
        _ = try lg.mut().insert(gossip_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(std.testing.allocator);
    var filters = try buildGossipPullFilters(
        std.testing.allocator,
        random,
        &gossip_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer deinitGossipPullFilters(&filters);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);
    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    // TODO: make this consistent across tests
    legacy_contact_info.wallclock = @intCast(std.time.milliTimestamp());
    var gossip_value = try SignedGossipData.initSigned(.{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    // insert more values which the filters should be missing
    lg = gossip_table_rw.write();
    for (0..64) |_| {
        const v2 = try SignedGossipData.random(random, &kp);
        _ = try lg.mut().insert(v2, 0);
    }

    const maybe_failing_seed: u64 = @intCast(std.time.milliTimestamp());
    var maybe_failing_prng = std.Random.Xoshiro256.init(maybe_failing_seed);
    var values = try filterSignedGossipDatas(
        maybe_failing_prng.random(),
        std.testing.allocator,
        lg.get(),
        &filter,
        gossip_value.wallclock(),
        100,
    );
    defer values.deinit();
    lg.unlock();

    std.testing.expect(values.items.len > 0) catch |err| {
        std.log.err("\nThe failing seed is: '{d}'\n", .{maybe_failing_seed});
        return err;
    };
}
