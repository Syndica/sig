//! to use the fuzzer run the following command:
//!     ./zig-out/bin/fuzz <seed> <num_messages> ?<entrypoint>
//! to stop the fuzzer write any input to stdin and press enter

const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

const GossipService = sig.gossip.service.GossipService;
const ChunkType = sig.gossip.service.ChunkType;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const ContactInfo = sig.gossip.data.ContactInfo;
const GossipMessage = sig.gossip.message.GossipMessage;
const GossipPullFilterSet = sig.gossip.pull_request.GossipPullFilterSet;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;
const Ping = sig.gossip.ping_pong.Ping;
const Pong = sig.gossip.ping_pong.Pong;
const SocketAddr = sig.net.net.SocketAddr;
const Pubkey = sig.core.pubkey.Pubkey;
const Bloom = sig.bloom.bloom.Bloom;
const Packet = sig.net.packet.Packet;
const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const Hash = sig.core.hash.Hash;
const EndPoint = @import("zig-network").EndPoint;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const AtomicBool = std.atomic.Value(bool);

const gossipDataToPackets = sig.gossip.service.gossipDataToPackets;

const Duration = sig.time.Duration;

const SLEEP_TIME = Duration.zero();
// const SLEEP_TIME = Duration.fromMillis(10);
// const SLEEP_TIME = Duration.fromSecs(10);

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

/// note the contact info must have responded to a ping
/// for a valid pull response to be generated
pub fn randomPullRequest(
    allocator: std.mem.Allocator,
    contact_info: LegacyContactInfo,
    rng: std.rand.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !Packet {
    const value = try SignedGossipData.initSigned(.{
        .LegacyContactInfo = contact_info,
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

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator(); // use std.testing.allocator to detect leaks

    var rng = std.rand.DefaultPrng.init(seed);

    // parse cli args to define where to send packets
    const maybe_max_messages_string = args.next();
    const maybe_entrypoint = args.next();

    const to_entrypoint, const fuzz_sig = blk: {
        if (maybe_entrypoint) |entrypoint| {
            const addr = SocketAddr.parse(entrypoint) catch @panic("invalid entrypoint");
            break :blk .{ addr.toEndpoint(), false };
        } else {
            // default to localhost (wont actually send anything)
            break :blk .{ try EndPoint.parse("127.0.0.1:8001"), true };
        }
    };

    const maybe_max_messages = blk: {
        if (maybe_max_messages_string) |max_messages_str| {
            break :blk try std.fmt.parseInt(usize, max_messages_str, 10);
        } else {
            break :blk null;
        }
    };

    // setup sending socket
    var fuzz_keypair = try KeyPair.create(null);
    const fuzz_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 9998);
    const fuzz_pubkey = Pubkey.fromPublicKey(&fuzz_keypair.public_key);
    var fuzz_contact_info = ContactInfo.init(allocator, fuzz_pubkey, 0, 19);
    try fuzz_contact_info.setSocket(.gossip, fuzz_address);

    var exit = AtomicBool.init(false);

    var gossip_client, const packet_channel, var handle = blk: {
        if (fuzz_sig) {
            // this is who we blast messages at
            var client_keypair = try KeyPair.create(null);
            const client_address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 9988);
            const client_pubkey = Pubkey.fromPublicKey(&client_keypair.public_key);
            var client_contact_info = ContactInfo.init(allocator, client_pubkey, 0, 19);
            try client_contact_info.setSocket(.gossip, client_address);

            var gossip_service_client = try GossipService.init(
                allocator,
                allocator,
                client_contact_info,
                client_keypair,
                null, // we will only recv packets
                &exit,
                .noop, // no logs
            );

            const client_handle = try std.Thread.spawn(.{}, GossipService.run, .{
                &gossip_service_client, .{
                    .spy_node = true,
                    .dump = false,
                },
            });

            // this is used to respond to pings
            var gossip_service_fuzzer = try GossipService.init(
                allocator,
                allocator,
                fuzz_contact_info,
                fuzz_keypair,
                (&SocketAddr.fromEndpoint(&to_entrypoint))[0..1], // we only want to communicate with one node
                &exit,
                .noop, // no logs
            );

            // this is mainly used to just send packets through the fuzzer
            // but we also want to respond to pings so we need to run the full gossip service
            const fuzz_handle = try std.Thread.spawn(.{}, GossipService.run, .{
                &gossip_service_fuzzer, .{
                    .spy_node = true,
                    .dump = false,
                },
            });
            fuzz_handle.detach();

            break :blk .{ gossip_service_client, gossip_service_client.packet_incoming_channel, client_handle };
        } else {
            var gossip_service_fuzzer = try GossipService.init(
                allocator,
                allocator,
                fuzz_contact_info,
                fuzz_keypair,
                (&SocketAddr.fromEndpoint(&to_entrypoint))[0..1], // we only want to communicate with one node
                &exit,
                .noop, // no logs
            );

            // this is mainly used to just send packets through the fuzzer
            // but we also want to respond to pings so we need to run the full gossip service
            const fuzz_handle = try std.Thread.spawn(.{}, GossipService.run, .{
                &gossip_service_fuzzer, .{
                    .spy_node = true,
                    .dump = false,
                },
            });

            break :blk .{ gossip_service_fuzzer, gossip_service_fuzzer.packet_outgoing_channel, fuzz_handle };
        }
    };

    // NOTE: this is useful when we want to run for an inf amount of time and want to
    // early exit at some point without killing the process
    var fuzzing_loop_exit = AtomicBool.init(false);
    // wait for any keyboard input to exit early
    var exit_handle = try std.Thread.spawn(.{}, waitForExit, .{&fuzzing_loop_exit});
    exit_handle.detach();

    // start fuzzing
    try fuzz(
        allocator,
        &fuzzing_loop_exit,
        maybe_max_messages,
        rng.random(),
        &fuzz_keypair,
        LegacyContactInfo.fromContactInfo(&fuzz_contact_info),
        to_entrypoint,
        packet_channel,
    );

    // cleanup
    std.debug.print("\t=> shutting down...\n", .{});
    exit.store(true, .unordered);
    handle.join();
    gossip_client.deinit();
    std.debug.print("\t=> done.\n", .{});
}

pub fn fuzz(
    allocator: std.mem.Allocator,
    loop_exit: *AtomicBool,
    maybe_max_messages: ?usize,
    rng: std.Random,
    keypair: *const KeyPair,
    contact_info: LegacyContactInfo,
    to_endpoint: EndPoint,
    outgoing_channel: *sig.sync.Channel(std.ArrayList(Packet)),
) !void {
    var msg_count: usize = 0;

    while (!loop_exit.load(.unordered)) {
        if (maybe_max_messages) |max_messages| {
            if (msg_count >= max_messages) {
                std.debug.print("reached max messages: {d}\n", .{msg_count});
                break;
            }
        }

        const action = rng.enumValue(enum {
            ping,
            pong,
            push,
            pull_request,
            pull_response,
        });
        const packet = switch (action) {
            .ping => blk: {
                // send ping message
                const packet = randomPingPacket(rng, keypair, to_endpoint);
                break :blk packet;
            },
            .pong => blk: {
                // send pong message
                const packet = randomPongPacket(rng, keypair, to_endpoint);
                break :blk packet;
            },
            .push => blk: {
                // send push message
                const packets = randomPushMessage(rng, keypair, to_endpoint) catch |err| {
                    std.debug.print("ERROR: {s}\n", .{@errorName(err)});
                    continue;
                };
                defer packets.deinit();

                const packet = packets.items[0];
                break :blk packet;
            },
            .pull_request => blk: {
                // send pull response
                const packets = randomPullResponse(rng, keypair, to_endpoint) catch |err| {
                    std.debug.print("ERROR: {s}\n", .{@errorName(err)});
                    continue;
                };
                defer packets.deinit();

                const packet = packets.items[0];
                break :blk packet;
            },
            .pull_response => blk: {
                // send pull request
                const packet = randomPullRequest(
                    allocator,
                    contact_info,
                    rng,
                    keypair,
                    to_endpoint,
                );
                break :blk packet;
            },
        };
        const send_packet = packet catch |err| {
            std.debug.print("ERROR: {s}\n", .{@errorName(err)});
            continue;
        };

        // batch it
        var packet_batch = std.ArrayList(Packet).init(allocator);
        try packet_batch.append(send_packet);
        msg_count +|= 1;

        const send_duplicate = rng.boolean();
        if (send_duplicate) {
            msg_count +|= 1;
            try packet_batch.append(send_packet);
        }

        // send it
        try outgoing_channel.send(packet_batch);

        std.time.sleep(SLEEP_TIME.asNanos());

        if (msg_count % 1000 == 0) {
            std.debug.print("{d} messages sent\n", .{msg_count});
        }
    }
}
