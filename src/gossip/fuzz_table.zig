const std = @import("std");
const sig = @import("../lib.zig");
const network = @import("zig-network");
const bincode = sig.bincode.bincode;

const AtomicBool = std.atomic.Value(bool);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const GossipService = sig.gossip.service.GossipService;
const ChunkType = sig.gossip.service.ChunkType;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const gossipDataToPackets = sig.gossip.service.gossipDataToPackets;
const getWallclockMs = sig.gossip.data.getWallclockMs;
const Logger = sig.trace.log.Logger;
const SocketAddr = sig.net.net.SocketAddr;
const Pubkey = sig.core.pubkey.Pubkey;
const Bloom = sig.bloom.bloom.Bloom;
const EndPoint = network.EndPoint;
const Packet = sig.net.packet.Packet;
const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const GossipMessage = sig.gossip.message.GossipMessage;
const Ping = sig.gossip.ping_pong.Ping;
const Pong = sig.gossip.ping_pong.Pong;
const GossipTable = sig.gossip.GossipTable;

const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipKey = sig.gossip.data.GossipKey;
const Signature = sig.core.Signature;

const GossipPullFilterSet = sig.gossip.pull_request.GossipPullFilterSet;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;
const Hash = sig.core.hash.Hash;
const ThreadPool = sig.sync.thread_pool.ThreadPool;

const TRIM_INTERVAL = 2 * std.time.ns_per_s;
const MAX_N_THREADS = 2;

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    // setup
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    // init gossip table
    // MAX: 2 threads
    const n_threads = @min(@as(u32, @truncate(std.Thread.getCpuCount() catch 1)), MAX_N_THREADS);
    const thread_pool = try allocator.create(ThreadPool);
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
        allocator.destroy(thread_pool);
    }
    thread_pool.* = ThreadPool.init(.{
        .max_threads = n_threads,
        .stack_size = 2 * 1024 * 1024,
    });

    const gossip_table = try allocator.create(GossipTable);
    gossip_table.* = try GossipTable.init(allocator, thread_pool);
    defer {
        gossip_table.deinit();
        allocator.destroy(gossip_table);
    }

    const Actions = enum { put, get };
    var put_count: u64 = 0;
    var get_count: u64 = 0;
    var total_action_count: u64 = 0;
    var now: u64 = 0;

    var insertion_times = try std.ArrayList(u64).initCapacity(allocator, 100);
    defer insertion_times.deinit();

    var pubkeys = try std.ArrayList(Pubkey).initCapacity(allocator, 100);
    defer pubkeys.deinit();

    var keypairs = try std.ArrayList(KeyPair).initCapacity(allocator, 100);
    defer keypairs.deinit();

    var signatures = std.AutoArrayHashMap(Pubkey, Signature).init(allocator);
    defer signatures.deinit();

    var keys = try std.ArrayList(GossipKey).initCapacity(allocator, 100);
    defer keys.deinit();

    var timer = std.time.Timer.start() catch unreachable;

    var seed_buf: [32]u8 = undefined;

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_actions) |max_actions| {
            if (total_action_count >= max_actions) {
                std.debug.print("reached max actions: {}\n", .{max_actions});
                break;
            }
        }
        defer {
            now += 1;
            total_action_count += 1;
        }

        const action_int = rand.intRangeAtMost(u8, 0, 1);
        const action: Actions = @enumFromInt(action_int);
        switch (action) {
            .put => {
                const new_keypair = rand.boolean();
                var data = GossipData.randomFromIndex(rand, 0);

                const new_contact_info = rand.boolean();
                if (new_contact_info) {
                    data = GossipData{
                        .ContactInfo = try ContactInfo.random(allocator, rand, Pubkey.random(rand), 0, 0, 0),
                    };
                }

                if (new_keypair) {
                    rand.bytes(&seed_buf);
                    const keypair = try KeyPair.create(seed_buf);
                    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

                    data.setId(pubkey);
                    var signed_data = try SignedGossipData.initSigned(data, &keypair);
                    signed_data.wallclockPtr().* = now;

                    // !
                    try gossip_table.insert(signed_data, now);

                    if (new_contact_info) {
                        try keys.append(GossipKey{ .ContactInfo = pubkey });
                    } else {
                        try keys.append(GossipKey{ .LegacyContactInfo = pubkey });
                    }

                    try keypairs.append(keypair);
                    try pubkeys.append(pubkey);
                    try signatures.put(pubkey, signed_data.signature);
                    try insertion_times.append(now);
                } else {
                    const index = rand.intRangeAtMost(usize, 0, pubkeys.items.len - 1);
                    const keypair = keypairs.items[index];
                    const pubkey = pubkeys.items[index];

                    data.setId(pubkey);
                    var signed_data = try SignedGossipData.initSigned(data, &keypair);
                    signed_data.wallclockPtr().* = now;

                    const should_overwrite = rand.boolean();
                    if (should_overwrite) {
                        signed_data.wallclockPtr().* = now;
                    } else {
                        const other_insertion_time = insertion_times.items[index];
                        signed_data.wallclockPtr().* = other_insertion_time -| rand.intRangeAtMost(u64, 0, 100);
                    }

                    // !
                    gossip_table.insert(signed_data, now) catch |err| {
                        switch (err) {
                            GossipTable.InsertionError.OldValue => {
                                // std.debug.assert(!should_overwrite);
                            },
                            GossipTable.InsertionError.DuplicateValue => {},
                            else => {
                                return err;
                            },
                        }
                    };

                    if (should_overwrite) {
                        if (new_contact_info) {
                            keys.items[index] = GossipKey{ .ContactInfo = pubkey };
                        } else {
                            keys.items[index] = GossipKey{ .LegacyContactInfo = pubkey };
                        }
                        // should over-write the old value
                        insertion_times.items[index] = now;
                        try signatures.put(pubkey, signed_data.signature);
                    }
                }

                put_count += 1;
            },
            .get => {
                if (pubkeys.items.len == 0) {
                    continue;
                }

                const index = rand.intRangeAtMost(usize, 0, pubkeys.items.len - 1);
                const pubkey = pubkeys.items[index];
                // general search
                const search_key = keys.items[index];

                const versioned_data = gossip_table.get(search_key) orelse {
                    logger.errf("failed to get pubkey: {}\n", .{search_key});
                    return;
                };

                if (!versioned_data.value.signature.eql(&signatures.get(pubkey).?)) {
                    logger.errf("hash mismatch: {}\n", .{pubkey});
                    return;
                }

                // via direct method
                _ = gossip_table.getThreadSafeContactInfo(pubkey) orelse {
                    logger.errf("failed to get contact info: {}\n", .{pubkey});
                    return;
                };

                // via iter
                var found = false;
                var iter = gossip_table.contactInfoIterator(0);
                while (iter.next()) |contact_info| {
                    if (contact_info.pubkey.equals(&pubkey)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    logger.errf("failed to find pubkey: {}\n", .{pubkey});
                    return;
                }

                get_count += 1;
            },
        }

        if (timer.read() > TRIM_INTERVAL) {
            defer timer.reset();
            const size = gossip_table.len();

            if (rand.boolean()) {
                // trim the table in half
                const max_pubkey_capacity = size / 2;
                const did_trim = try gossip_table.attemptTrim(max_pubkey_capacity);
                if (!did_trim) continue;

                logger.infof("op(trim): table size: {} -> {}", .{ size, gossip_table.len() });
            } else {
                // NOTE: not completely accurate, but good enough
                const middle_index = insertion_times.items.len / 2;
                const middle_insert_time = insertion_times.items[middle_index];
                try gossip_table.removeOldLabels(middle_insert_time, 0);

                logger.infof("op(remove-old-labels): table size: {} -> {}", .{ size, gossip_table.len() });
            }

            // reset the pubkey list
            const available_keys = gossip_table.pubkey_to_values.keys();
            var index: u64 = 0;
            while (index < pubkeys.items.len) {
                const pubkey = pubkeys.items[index];
                const still_exists = blk: for (available_keys) |*key| {
                    if (key.equals(&pubkey)) {
                        break :blk true;
                    }
                } else false;

                if (!still_exists) {
                    _ = pubkeys.swapRemove(index);
                    _ = insertion_times.swapRemove(index);
                    _ = signatures.swapRemove(pubkey);
                } else {
                    index += 1;
                }
            }

            logger.infof("put: {}, get: {}", .{ put_count, get_count });
            put_count = 0;
            get_count = 0;

            if (maybe_max_actions) |max_actions| {
                const percent_int = (total_action_count * 100) / max_actions;
                logger.infof("total actions: {} / {} ({}%)", .{ total_action_count, max_actions, percent_int });
            }
        }
    }
}
