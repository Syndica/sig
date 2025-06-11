const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.mux.RwMux;
const GossipTable = sig.gossip.table.GossipTable;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;

const buildGossipPullFilters = sig.gossip.pull_request.buildGossipPullFilters;
const deinitGossipPullFilters = sig.gossip.pull_request.deinitGossipPullFilters;

pub const GOSSIP_PULL_TIMEOUT_MS: u64 = 15000;

pub fn filterSignedGossipDatas(
    /// It is advised to use a PRNG, and not a true RNG, otherwise
    /// the runtime of this function may be unbounded.
    random: std.Random,
    allocator: std.mem.Allocator,
    gossip_table: *const GossipTable,
    filter: *const GossipPullFilter,
    caller_wallclock: u64,
    max_number_values: usize,
) error{OutOfMemory}![]SignedGossipData {
    if (max_number_values == 0) return &.{};

    const jitter = random.intRangeAtMost(u64, 0, GOSSIP_PULL_TIMEOUT_MS / 4);
    const caller_wallclock_with_jitter = caller_wallclock + jitter;

    const match_indices = try gossip_table.getBitmaskMatches(
        allocator,
        filter.mask,
        filter.mask_bits,
    );
    defer allocator.free(match_indices);

    var output: std.ArrayListUnmanaged(SignedGossipData) = try .initCapacity(
        allocator,
        max_number_values,
    );
    errdefer output.deinit(allocator);

    for (match_indices) |entry_index| {
        var entry = gossip_table.store.getByIndex(entry_index);

        // entry is too new
        if (entry.data.wallclock() > caller_wallclock_with_jitter) {
            continue;
        }
        // entry is already contained in the bloom
        if (filter.bloom.contains(&entry.metadata.value_hash.data)) {
            continue;
        }
        // exclude contact info (? not sure why - labs does it)
        if (entry.data == .ContactInfo) {
            continue;
        }

        // good
        output.appendAssumeCapacity(entry.signedData());
        if (output.items.len == max_number_values) break;
    }

    return try output.toOwnedSlice(allocator);
}

const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;

test "gossip.pull_response: test filtering values works" {
    if (true) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    const gossip_table = try GossipTable.init(allocator, allocator);
    var gossip_table_rw = RwMux(GossipTable).init(gossip_table);
    defer {
        var lg = gossip_table_rw.write();
        lg.mut().deinit();
    }

    // insert a some value
    const kp = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(18);
    const random = prng.random();

    var lg = gossip_table_rw.write();
    for (0..100) |_| {
        const gossip_value = SignedGossipData.initRandom(random, &kp);
        _ = try lg.mut().insert(gossip_value, 0);
    }
    lg.unlock();

    const max_bytes = 10;

    // recver
    const failed_pull_hashes = std.ArrayList(Hash).init(allocator);
    var filters = try buildGossipPullFilters(
        allocator,
        random,
        &gossip_table_rw,
        &failed_pull_hashes,
        max_bytes,
        100,
    );
    defer deinitGossipPullFilters(filters.toOwnedSlice() catch unreachable, allocator);
    var filter = filters.items[0];

    // corresponding value
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);
    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = random.int(u64);

    var gossip_value = SignedGossipData.initSigned(
        &kp,
        .{ .LegacyContactInfo = legacy_contact_info },
    );

    // insert more values which the filters should be missing
    lg = gossip_table_rw.write();
    for (0..64) |_| {
        const v2 = SignedGossipData.initRandom(random, &kp);
        _ = try lg.mut().insert(v2, 0);
    }

    const maybe_failing_seed: u64 = random.int(u64);
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

    try std.testing.expect(values.items.len > 0);
}
