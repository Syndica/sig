//! how to run the fuzzer:
//!     `zig build fuzz_gossip`
//! to stop the fuzzer write any input to stdin and press enter

const std = @import("std");

const _gossip_service = @import("./service.zig");
const GossipService = _gossip_service.GossipService;
const ChunkType = _gossip_service.ChunkType;
const gossipDataToPackets = _gossip_service.gossipDataToPackets;

const Logger = @import("../trace/log.zig").Logger;
const _gossip_data = @import("data.zig");
const LegacyContactInfo = _gossip_data.LegacyContactInfo;
const SignedGossipData = _gossip_data.SignedGossipData;
const ContactInfo = _gossip_data.ContactInfo;
const AtomicBool = std.atomic.Value(bool);

const SocketAddr = @import("../net/net.zig").SocketAddr;

const Pubkey = @import("../core/pubkey.zig").Pubkey;
const getWallclockMs = @import("data.zig").getWallclockMs;

const Bloom = @import("../bloom/bloom.zig").Bloom;
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("../net/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../net/packet.zig").PACKET_DATA_SIZE;
const NonBlockingChannel = @import("../sync/channel.zig").NonBlockingChannel;

const _gossip_message = @import("message.zig");
const GossipMessage = _gossip_message.GossipMessage;

const Ping = @import("ping_pong.zig").Ping;
const Pong = @import("ping_pong.zig").Pong;
const bincode = @import("../bincode/bincode.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const _gossip_table = @import("../gossip/table.zig");

const _pull_request = @import("../gossip/pull_request.zig");
const GossipPullFilterSet = _pull_request.GossipPullFilterSet;
const GossipPullFilter = _pull_request.GossipPullFilter;

const Hash = @import("../core/hash.zig").Hash;

const PacketChannel = NonBlockingChannel(Packet);
const GossipChannel = NonBlockingChannel(GossipMessage);

pub fn serializeToPacket(d: anytype, to_addr: EndPoint) !Packet {
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    const msg_slice = try bincode.writeToSlice(&packet_buf, d, bincode.Params{});
    const packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn randomPing(rng: std.rand.Random, keypair: *const KeyPair) !GossipMessage {
    const ping = GossipMessage{
        .PingMessage = try Ping.random(rng, keypair),
    };
    return ping;
}

pub fn randomPingPacket(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    const ping = try randomPing(rng, keypair);
    const packet = try serializeToPacket(ping, to_addr);
    return packet;
}

pub fn randomPong(rng: std.rand.Random, keypair: *const KeyPair) !GossipMessage {
    const pong = GossipMessage{
        .PongMessage = try Pong.random(rng, keypair),
    };
    return pong;
}

pub fn randomPongPacket(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    const pong = try randomPong(rng, keypair);
    const packet = try serializeToPacket(pong, to_addr);
    return packet;
}

pub fn randomSignedGossipData(rng: std.rand.Random, maybe_should_pass_sig_verification: ?bool) !SignedGossipData {
    var keypair = try KeyPair.create(null);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    // will have random id
    // var value = try SignedGossipData.random(rng, &keypair);
    var value = try SignedGossipData.randomWithIndex(rng, &keypair, 0);
    value.data.LegacyContactInfo = LegacyContactInfo.default(Pubkey.fromPublicKey(&keypair.public_key));
    try value.sign(&keypair);

    const should_pass_sig_verification = maybe_should_pass_sig_verification orelse rng.boolean();
    if (should_pass_sig_verification) {
        value.data.setId(pubkey);
        try value.sign(&keypair);
    }

    return value;
}

pub fn randomPushMessage(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !std.ArrayList(Packet) {
    const size: comptime_int = 5;
    var values: [size]SignedGossipData = undefined;
    const should_pass_sig_verification = rng.boolean();
    for (0..size) |i| {
        const value = try randomSignedGossipData(rng, should_pass_sig_verification);
        values[i] = value;
    }

    const allocator = std.heap.page_allocator;
    const packets = try gossipDataToPackets(
        allocator,
        &Pubkey.fromPublicKey(&keypair.public_key),
        &values,
        &to_addr,
        ChunkType.PushMessage,
    );
    return packets;
}

pub fn randomPullResponse(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !std.ArrayList(Packet) {
    const size: comptime_int = 5;
    var values: [size]SignedGossipData = undefined;
    const should_pass_sig_verification = rng.boolean();
    for (0..size) |i| {
        const value = try randomSignedGossipData(rng, should_pass_sig_verification);
        values[i] = value;
    }

    const allocator = std.heap.page_allocator;
    const packets = try gossipDataToPackets(
        allocator,
        &Pubkey.fromPublicKey(&keypair.public_key),
        &values,
        &to_addr,
        ChunkType.PullResponse,
    );
    return packets;
}

pub fn randomPullRequest(
    allocator: std.mem.Allocator,
    rng: std.rand.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !Packet {
    const value = try SignedGossipData.initSigned(.{
        .LegacyContactInfo = LegacyContactInfo.default(
            Pubkey.fromPublicKey(&keypair.public_key),
        ),
    }, keypair);

    return randomPullRequestWithContactInfo(
        allocator,
        rng,
        to_addr,
        value,
    );
}

pub fn randomPullRequestWithContactInfo(
    allocator: std.mem.Allocator,
    rng: std.rand.Random,
    to_addr: EndPoint,
    contact_info: SignedGossipData,
) !Packet {
    const N_FILTER_BITS = rng.intRangeAtMost(u6, 1, 10);

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, rng, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    var filter = GossipPullFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    // const invalid_filter = rng.boolean();
    const invalid_filter = false;
    if (invalid_filter) {
        filter.mask = (~@as(usize, 0)) >> rng.intRangeAtMost(u6, 1, 10);
        filter.mask_bits = rng.intRangeAtMost(u6, 1, 10);

        // add more random hashes
        for (0..5) |_| {
            const rand_value = try randomSignedGossipData(rng, true);
            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buf, rand_value, bincode.Params.standard);
            const value_hash = Hash.generateSha256Hash(bytes);
            filter.filter.add(&value_hash.data);
        }
    } else {
        // add some valid hashes
        var filter_set = try GossipPullFilterSet.initTest(allocator, rng, filter.mask_bits);

        for (0..5) |_| {
            const rand_value = try randomSignedGossipData(rng, true);
            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buf, rand_value, bincode.Params.standard);
            const value_hash = Hash.generateSha256Hash(bytes);
            filter_set.add(&value_hash);
        }

        var filters = try filter_set.consumeForGossipPullFilters(allocator, rng, 1);
        filter.filter = filters.items[0].filter;
        filter.mask = filters.items[0].mask;
        filter.mask_bits = filters.items[0].mask_bits;

        for (filters.items[1..]) |*filter_i| {
            filter_i.filter.deinit();
        }
        filters.deinit();
    }

    // serialize and send as packet
    const msg = GossipMessage{ .PullRequest = .{ filter, contact_info } };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    const msg_slice = try bincode.writeToSlice(&packet_buf, msg, bincode.Params{});
    const packet = Packet.init(to_addr, packet_buf, msg_slice.len);

    if (!invalid_filter) {
        filter.filter.deinit();
    }

    return packet;
}

pub fn waitForExit(exit: *AtomicBool) void {
    const reader = std.io.getStdOut().reader();
    var buf: [1]u8 = undefined;
    _ = reader.read(&buf) catch unreachable;

    exit.store(true, .unordered);
}

pub fn run(args: *std.process.ArgIterator) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator(); // use std.testing.allocator to detect leaks

    // parse cli args to define where to send packets
    // zig build fuzz -- <entrypoint> <seed> <max_messages>
    const maybe_entrypoint = args.next();
    const maybe_seed = args.next();
    const maybe_max_messages_string = args.next();

    const entrypoint = blk: {
        if (maybe_entrypoint) |entrypoint| {
            const addr = SocketAddr.parse(entrypoint) catch @panic("invalid entrypoint");
            break :blk addr;
        } else {
            @panic("usage: zig build fuzz -- <entrypoint> <seed> <num_messages>");
        }
    };
    const to_endpoint = entrypoint.toEndpoint();

    const seed = blk: {
        if (maybe_seed) |seed_str| {
            break :blk try std.fmt.parseInt(u64, seed_str, 10);
        } else {
            break :blk getWallclockMs();
        }
    };

    const maybe_max_messages = blk: {
        if (maybe_max_messages_string) |max_messages_str| {
            break :blk try std.fmt.parseInt(usize, max_messages_str, 10);
        } else {
            break :blk null;
        }
    };

    std.debug.print("using seed: {d}\n", .{seed});
    var rng = std.rand.DefaultPrng.init(seed);

    // var logger = Logger.init(gpa.allocator(), .debug);
    // defer logger.deinit();
    // logger.spawn();

    // setup sending socket
    var fuzz_keypair = try KeyPair.create(null);
    const fuzz_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 9998);

    const fuzz_pubkey = Pubkey.fromPublicKey(&fuzz_keypair.public_key);
    var fuzz_contact_info = ContactInfo.init(allocator, fuzz_pubkey, 0, 19);
    try fuzz_contact_info.setSocket(.gossip, fuzz_address);

    var fuzz_exit = AtomicBool.init(false);
    var gossip_service_fuzzer = try GossipService.init(
        allocator,
        allocator,
        fuzz_contact_info,
        fuzz_keypair,
        (&entrypoint)[0..1],
        &fuzz_exit,
        .noop,
    );

    const fuzz_handle = try std.Thread.spawn(.{}, GossipService.run, .{
        &gossip_service_fuzzer, .{
            .spy_node = true,
            .dump = false,
        },
    });

    const SLEEP_TIME = 0;
    // const SLEEP_TIME = std.time.ns_per_ms * 10;
    // const SLEEP_TIME = std.time.ns_per_s;

    // wait for keyboard input to exit
    var loop_exit = AtomicBool.init(false);
    var exit_handle = try std.Thread.spawn(.{}, waitForExit, .{&loop_exit});

    var msg_count: usize = 0;
    while (!loop_exit.load(.unordered)) {
        if (maybe_max_messages) |max_messages| {
            if (msg_count >= max_messages) {
                break;
            }
        }

        const command = rng.random().intRangeAtMost(u8, 0, 4);
        // var command: usize = if (msg_count % 2 == 0) 2 else 4;
        // var command: usize = 4;

        const packet = switch (command) {
            0 => blk: {
                // send ping message
                const packet = randomPingPacket(rng.random(), &fuzz_keypair, to_endpoint);
                break :blk packet;
            },
            1 => blk: {
                // send pong message
                const packet = randomPongPacket(rng.random(), &fuzz_keypair, to_endpoint);
                break :blk packet;
            },
            2 => blk: {
                // send push message
                const packets = randomPushMessage(rng.random(), &fuzz_keypair, to_endpoint) catch |err| {
                    std.debug.print("ERROR: {s}\n", .{@errorName(err)});
                    continue;
                };
                defer packets.deinit();

                const packet = packets.items[0];
                break :blk packet;
            },
            3 => blk: {
                // send pull response
                const packets = randomPullResponse(rng.random(), &fuzz_keypair, to_endpoint) catch |err| {
                    std.debug.print("ERROR: {s}\n", .{@errorName(err)});
                    continue;
                };
                defer packets.deinit();

                const packet = packets.items[0];
                break :blk packet;
            },
            4 => blk: {
                // send pull request
                const packet = randomPullRequest(
                    allocator,
                    rng.random(),
                    &fuzz_keypair,
                    to_endpoint,
                );
                break :blk packet;
            },
            else => unreachable,
        };
        const send_packet = packet catch |err| {
            std.debug.print("ERROR: {s}\n", .{@errorName(err)});
            continue;
        };

        // batch it
        var packet_batch = std.ArrayList(Packet).init(allocator);
        try packet_batch.append(send_packet);
        msg_count +|= 1;

        const send_duplicate = rng.random().boolean();
        if (send_duplicate) {
            msg_count +|= 1;
            try packet_batch.append(send_packet);
        }

        // send it
        try gossip_service_fuzzer.packet_outgoing_channel.send(packet_batch);

        std.time.sleep(SLEEP_TIME);

        if (msg_count % 1000 == 0) {
            std.debug.print("{d} messages sent\n", .{msg_count});
        }
    }

    // cleanup
    std.debug.print("\t=> shutting down...\n", .{});
    fuzz_exit.store(true, .unordered);
    fuzz_handle.join();
    gossip_service_fuzzer.deinit();
    std.debug.print("\t=>fuzzy gossip service shutdown\n", .{});

    exit_handle.join();
    std.debug.print("fuzzing done\n", .{});
}
