const std = @import("std");
const sig = @import("../sig.zig");
const network = @import("zig-network");

const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const ContactInfo = sig.gossip.data.ContactInfo;
const Pubkey = sig.core.pubkey.Pubkey;
const GossipTable = sig.gossip.GossipTable;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipKey = sig.gossip.data.GossipKey;
const Signature = sig.core.Signature;
const Duration = sig.time.Duration;

const TRIM_INTERVAL = Duration.fromSecs(2);

pub fn run(seed: u64, args: []const []const u8) !void {
    const maybe_max_actions_string: ?[]const u8 = if (args.len == 0) null else args[0];
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    // setup
    var gpa_state: std.heap.DebugAllocator(.{ .safety = true }) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    // NOTE: change to trace for full logs
    const logger = sig.trace.direct_print.logger("gossip_table.fuzz", .debug);

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    // init gossip table
    var gossip_table = try GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    var put_count: u64 = 0;
    var get_count: u64 = 0;
    var total_action_count: u64 = 0;
    var now: u64 = 100;

    var insertion_times = try std.ArrayList(u64).initCapacity(allocator, 100);
    defer insertion_times.deinit();

    var pubkeys = try std.ArrayList(Pubkey).initCapacity(allocator, 100);
    defer pubkeys.deinit();

    var keypairs = try std.ArrayList(KeyPair).initCapacity(allocator, 100);
    defer keypairs.deinit();

    var signatures = sig.utils.collections.PubkeyMapManaged(Signature).init(allocator);
    defer signatures.deinit();

    var keys = try std.ArrayList(GossipKey).initCapacity(allocator, 100);
    defer keys.deinit();

    var timer = sig.time.Timer.start();

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_actions) |max_actions| {
            if (total_action_count >= max_actions) {
                logger.info().logf("reached max actions: {}", .{max_actions});
                break;
            }
        }
        defer {
            now += 1;
            total_action_count += 1;
        }

        const action = random.enumValue(enum { put, get });
        switch (action) {
            .put => {
                defer put_count += 1;
                const new_keypair = random.boolean();

                var data = GossipData{
                    .ContactInfo = try ContactInfo
                        .initRandom(allocator, random, Pubkey.initRandom(random), 0, 0, 0),
                };

                if (new_keypair) {
                    var seed_buf: [32]u8 = undefined;
                    random.bytes(&seed_buf);
                    const keypair = try KeyPair.generateDeterministic(seed_buf);
                    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

                    data.setId(pubkey);
                    data.wallclockPtr().* = now;
                    const signed_data = SignedGossipData.initSigned(&keypair, data);

                    // !
                    logger.trace().logf("putting pubkey: {}", .{pubkey});
                    const result = try gossip_table.insert(signed_data, now);
                    std.debug.assert(result == .success);

                    try keys.append(GossipKey{ .ContactInfo = pubkey });
                    try keypairs.append(keypair);
                    try pubkeys.append(pubkey);
                    try signatures.put(pubkey, signed_data.signature);
                    try insertion_times.append(now);
                } else {
                    if (pubkeys.items.len == 0) {
                        data.deinit(allocator);
                        continue;
                    }

                    const index = random.intRangeAtMost(usize, 0, pubkeys.items.len - 1);
                    const keypair = keypairs.items[index];
                    const pubkey = pubkeys.items[index];

                    data.setId(pubkey);
                    data.wallclockPtr().* = now;

                    const should_overwrite = random.boolean();
                    if (should_overwrite) {
                        logger.trace().logf("overwriting pubkey: {}", .{pubkey});
                        data.wallclockPtr().* = now;
                    } else {
                        logger.trace().logf("writing old pubkey: {}", .{pubkey});
                        const old_value = random.boolean();
                        const other_insertion_time = insertion_times.items[index];
                        if (old_value) {
                            // ignored old value
                            data.wallclockPtr().* = other_insertion_time -| random.intRangeAtMost(u64, 10, 100);
                        } else {
                            // will be a duplicate value
                            data.wallclockPtr().* = other_insertion_time;
                        }
                    }

                    const signed_data = SignedGossipData.initSigned(&keypair, data);

                    // !
                    const result = try gossip_table.insert(signed_data, now);
                    defer if (result == .fail) data.deinit(allocator);
                    if (result == .fail and result.fail == .too_old) {
                        logger.trace().logf("ignored old value: {}", .{pubkey});
                        std.debug.assert(!should_overwrite);
                    }
                    if (result == .fail and result.fail == .duplicate) {
                        logger.trace().logf("duplicate value: {}", .{pubkey});
                    }

                    if (result == .success) {
                        keys.items[index] = GossipKey{ .ContactInfo = pubkey };
                        // should over-write the old value
                        insertion_times.items[index] = now;
                        try signatures.put(pubkey, signed_data.signature);
                    }
                }
            },
            .get => {
                if (pubkeys.items.len == 0) {
                    continue;
                }

                const index = random.intRangeAtMost(usize, 0, pubkeys.items.len - 1);
                const pubkey = pubkeys.items[index];
                const search_key = keys.items[index];

                errdefer {
                    logger.err().logf("pubkey failed: {} with key: {}", .{ pubkey, search_key });
                }

                const metadata = gossip_table.getMetadata(search_key) orelse {
                    logger.err().logf("failed to get pubkey: {}", .{search_key});
                    return error.PubkeyNotFound;
                };

                if (!metadata.signature.eql(&signatures.get(pubkey).?)) {
                    logger.err().logf("signature mismatch: {}", .{pubkey});
                    return error.SignatureMismatch;
                }

                // via direct method
                if (gossip_table.getThreadSafeContactInfo(pubkey) == null) {
                    logger.err().logf("failed to get contact info: {}", .{pubkey});
                    return error.ContactInfoNotFound;
                }

                // via iter
                var iter = gossip_table.contactInfoIterator(0);
                const found = while (iter.next()) |contact_info| {
                    if (contact_info.pubkey.equals(&pubkey)) {
                        break true;
                    }
                } else false;
                if (!found) {
                    logger.err().logf("failed to find pubkey: {}", .{pubkey});
                    return error.ContactInfoNotFound;
                }

                get_count += 1;
            },
        }

        if (timer.read().gt(TRIM_INTERVAL)) {
            defer timer.reset();
            const size = gossip_table.len();

            if (random.boolean()) {
                // trim the table in half
                const max_pubkey_capacity = size / 2;
                const pubkeys_droppped_count = try gossip_table.attemptTrim(now, max_pubkey_capacity);
                if (pubkeys_droppped_count == 0) continue;

                logger.info().logf("op(trim): table size: {} -> {}", .{ size, gossip_table.len() });
            } else {
                // NOTE: not completely accurate, but good enough
                const middle_index = insertion_times.items.len / 2;
                const middle_insert_time = insertion_times.items[middle_index];
                _ = try gossip_table.removeOldLabels(middle_insert_time, 0);

                logger.info().logf("op(remove-old-labels): table size: {} -> {}", .{ size, gossip_table.len() });
            }

            // reset the pubkey list
            const available_keys = gossip_table.pubkey_to_values.keys();
            var index: u64 = 0;
            while (index < pubkeys.items.len) {
                const pubkey = pubkeys.items[index];
                const still_exists = for (available_keys) |*key| {
                    if (key.equals(&pubkey)) {
                        break true;
                    }
                } else false;

                if (!still_exists) {
                    const pk_removed = pubkeys.swapRemove(index);
                    _ = insertion_times.swapRemove(index);
                    _ = signatures.swapRemove(pubkey);
                    _ = keys.swapRemove(index);

                    std.debug.assert(pk_removed.equals(&pubkey));
                } else {
                    index += 1;
                }
            }

            logger.info().logf("put: {}, get: {}", .{ put_count, get_count });
            put_count = 0;
            get_count = 0;

            if (maybe_max_actions) |max_actions| {
                const percent_int = (total_action_count * 100) / max_actions;
                logger.info().logf("total actions: {} / {} ({}%)", .{ total_action_count, max_actions, percent_int });
            }
        }
    }
}
