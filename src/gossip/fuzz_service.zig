//! to use the fuzzer run the following command:
//!     ./zig-out/bin/fuzz <seed> <num_messages>
const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const EndPoint = @import("zig-network").EndPoint;
const GossipService = sig.gossip.service.GossipService;
const ChunkType = sig.gossip.service.ChunkType;
const ContactInfo = sig.gossip.data.ContactInfo;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipMessage = sig.gossip.message.GossipMessage;
const GossipPullFilterSet = sig.gossip.pull_request.GossipPullFilterSet;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;
const Ping = sig.gossip.ping_pong.Ping;
const Pong = sig.gossip.ping_pong.Pong;
const SocketAddr = sig.net.net.SocketAddr;
const Pubkey = sig.core.pubkey.Pubkey;
const Bloom = sig.bloom.bloom.Bloom;
const Packet = sig.net.packet.Packet;
const Hash = sig.core.hash.Hash;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Duration = sig.time.Duration;
const Channel = sig.sync.Channel;

const getWallclockMs = sig.time.getWallclockMs;
const gossipDataToPackets = sig.gossip.service.gossipDataToPackets;

const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;

const SHRED_VERSION = 19;
const SLEEP_TIME = Duration.zero();
// const SLEEP_TIME = Duration.fromMillis(10);
// const SLEEP_TIME = Duration.fromSecs(10);

const Logger = sig.trace.Logger("gossip.fuzz_service");

pub fn run(seed: u64, args: []const []const u8) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // logs
    var std_logger = try sig.trace.ChannelPrintLogger.init(.{
        .allocator = std.heap.c_allocator,
        .max_level = sig.trace.Level.debug,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    // setup randomness
    var prng = std.Random.DefaultPrng.init(seed);

    // parse cli args to define where to send packets
    const maybe_max_messages_string: ?[]const u8 = if (args.len == 0) null else args[0];
    const maybe_max_messages = blk: {
        if (maybe_max_messages_string) |max_messages_str| {
            break :blk try std.fmt.parseInt(u64, max_messages_str, 10);
        } else {
            break :blk null;
        }
    };

    // we need two clients:
    //  1) fuzz_client: attacker
    //  2) gossip_client: victim
    // fuzz_client --rand-messages-> client (fuzz client sends random messages to client)
    // fuzz_client <-pings/pongs-> client (fuzz responds to pings from the client to maintain a valid connection)

    const CLIENT_PORT = 9988;
    const FUZZER_PORT = 9989;

    const gossip_client = try newGossipClient(
        allocator,
        CLIENT_PORT,
        SHRED_VERSION,
        null, // no entrypoints
        .noop,
    );
    try gossip_client.start(.{
        .spy_node = false, // build out going messages too
        .dump = false,
    });
    const client_address = gossip_client.my_contact_info.getSocket(.gossip).?;
    defer {
        gossip_client.shutdown();
        gossip_client.deinit();
        allocator.destroy(gossip_client);
    }

    // dont care about these allocs rn -- they can leak
    // since we only care about the standard/receiving gossip client
    const dirty_allocator = std.heap.c_allocator;

    // TODO: figure out how to only collect the metrics for the client,
    // rn, we will collect double metrics
    const fuzz_client = try newGossipClient(
        dirty_allocator,
        FUZZER_PORT,
        SHRED_VERSION,
        &.{client_address}, // talk to the client
        .noop, // no logs
    );
    try fuzz_client.start(.{
        .spy_node = false, // build outgoing messages
        .dump = false,
    });
    defer {
        fuzz_client.shutdown();
        fuzz_client.deinit();
        dirty_allocator.destroy(fuzz_client);
    }

    // start fuzzing
    try fuzz(
        dirty_allocator,
        maybe_max_messages,
        prng.random(),
        fuzz_client,
    );
}

pub fn fuzz(
    allocator: std.mem.Allocator,
    maybe_max_messages: ?usize,
    random: std.Random,
    fuzz_client: *GossipService,
) !void {
    std.debug.assert(fuzz_client.entrypoints.len > 0);

    const keypair = &fuzz_client.my_keypair;
    const to_endpoint = fuzz_client.entrypoints[0].addr.toEndpoint();
    const contact_info = fuzz_client.my_contact_info;
    const outgoing_channel = fuzz_client.packet_outgoing_channel;

    var last_print_msg_count: u64 = 0;
    var msg_count: u64 = 0;
    while (true) {
        if (maybe_max_messages) |max_messages| {
            if (msg_count >= max_messages) {
                std.debug.print("reached max messages: {d}\n", .{msg_count});
                break;
            }
        }

        const action = random.enumValue(enum {
            ping,
            pong,
            push,
            pull_request,
            pull_response,
        });
        switch (action) {
            .ping => {

                // send ping message
                const packet = try randomPingPacket(
                    random,
                    keypair,
                    to_endpoint,
                );
                try sendPacket(
                    &msg_count,
                    outgoing_channel,
                    packet,
                    random.boolean(),
                );
            },
            .pong => {

                // send pong message
                const packet = try randomPongPacket(
                    random,
                    keypair,
                    to_endpoint,
                );
                try sendPacket(
                    &msg_count,
                    outgoing_channel,
                    packet,
                    random.boolean(),
                );
            },
            .push => {

                // send push message
                const packets = try randomPushMessage(
                    allocator,
                    random,
                    keypair,
                    to_endpoint,
                );
                defer packets.deinit();
                try sendPackets(
                    &msg_count,
                    outgoing_channel,
                    packets.items,
                    random,
                );
            },
            .pull_response => {

                // send pull response
                const packets = try randomPullResponse(
                    allocator,
                    random,
                    keypair,
                    to_endpoint,
                );
                defer packets.deinit();
                try sendPackets(
                    &msg_count,
                    outgoing_channel,
                    packets.items,
                    random,
                );
            },
            .pull_request => {

                // send pull request
                const packet = try randomPullRequest(
                    allocator,
                    contact_info,
                    random,
                    keypair,
                    to_endpoint,
                );
                try sendPacket(
                    &msg_count,
                    outgoing_channel,
                    packet,
                    random.boolean(),
                );
            },
        }

        if ((msg_count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} messages sent\n", .{msg_count});
            last_print_msg_count = msg_count;
        }
        std.Thread.sleep(SLEEP_TIME.asNanos());
    }
}

pub fn sendPackets(
    msg_count: *u64,
    outgoing_channel: *Channel(Packet),
    packets: []Packet,
    random: std.Random,
) !void {
    for (packets) |packet| {
        try sendPacket(
            msg_count,
            outgoing_channel,
            packet,
            random.boolean(),
        );
    }
}

pub fn sendPacket(
    msg_count: *u64,
    outgoing_channel: *Channel(Packet),
    packet: Packet,
    send_duplicate: bool,
) !void {
    try outgoing_channel.send(packet);
    msg_count.* +|= 1;

    if (send_duplicate) {
        try outgoing_channel.send(packet);
        msg_count.* +|= 1;
    }
}

pub fn newGossipClient(
    allocator: std.mem.Allocator,
    port: u16,
    shred_version: u16,
    entrypoints: ?[]const SocketAddr,
    logger: Logger,
) !*GossipService {
    const address = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, port);
    var keypair = KeyPair.generate();

    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const now = getWallclockMs();
    var contact_info = ContactInfo.init(allocator, pubkey, now, shred_version);
    try contact_info.setSocket(.gossip, address);

    return try GossipService.create(
        allocator,
        allocator,
        contact_info,
        keypair,
        entrypoints,
        .from(logger),
    );
}

pub fn serializeToPacket(d: anytype, to_addr: EndPoint) !Packet {
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    const msg_slice = try bincode.writeToSlice(&packet_buf, d, bincode.Params{});
    return Packet.init(to_addr, packet_buf, msg_slice.len);
}

pub fn randomPing(random: std.Random, keypair: *const KeyPair) !GossipMessage {
    return .{ .PingMessage = try Ping.initRandom(random, keypair) };
}

pub fn randomPingPacket(
    random: std.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !Packet {
    const ping = try randomPing(random, keypair);
    return try serializeToPacket(ping, to_addr);
}

pub fn randomPong(random: std.Random, keypair: *const KeyPair) !GossipMessage {
    return .{ .PongMessage = try Pong.initRandom(random, keypair) };
}

pub fn randomPongPacket(
    random: std.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !Packet {
    const pong = try randomPong(random, keypair);
    return try serializeToPacket(pong, to_addr);
}

pub fn randomSignedGossipData(
    allocator: std.mem.Allocator,
    random: std.Random,
    should_pass_sig_verification: bool,
) !SignedGossipData {
    const keypair = KeyPair.generate();
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    const now = getWallclockMs();
    const info_pubkey = if (should_pass_sig_verification) pubkey else Pubkey.initRandom(random);
    // TODO: support other types of gossip data
    const info = ContactInfo.init(allocator, info_pubkey, now, SHRED_VERSION);

    return SignedGossipData.initSigned(&keypair, .{ .ContactInfo = info });
}

pub fn randomPushMessage(
    allocator: std.mem.Allocator,
    random: std.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !std.ArrayList(Packet) {
    const size: comptime_int = 5;
    var values: [size]SignedGossipData = undefined;
    const should_pass_sig_verification = random.boolean();
    for (0..size) |i| {
        const value = try randomSignedGossipData(
            allocator,
            random,
            should_pass_sig_verification,
        );
        values[i] = value;
    }

    return try gossipDataToPackets(
        allocator,
        &Pubkey.fromPublicKey(&keypair.public_key),
        &values,
        &to_addr,
        ChunkType.PushMessage,
    );
}

pub fn randomPullResponse(
    allocator: std.mem.Allocator,
    random: std.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !std.ArrayList(Packet) {
    const size: comptime_int = 5;
    var values: [size]SignedGossipData = undefined;
    const should_pass_sig_verification = random.boolean();
    for (0..size) |i| {
        const value = try randomSignedGossipData(
            allocator,
            random,
            should_pass_sig_verification,
        );
        values[i] = value;
    }

    return try gossipDataToPackets(
        allocator,
        &Pubkey.fromPublicKey(&keypair.public_key),
        &values,
        &to_addr,
        ChunkType.PullResponse,
    );
}

/// note the contact info must have responded to a ping
/// for a valid pull response to be generated
pub fn randomPullRequest(
    allocator: std.mem.Allocator,
    contact_info: ContactInfo,
    random: std.Random,
    keypair: *const KeyPair,
    to_addr: EndPoint,
) !Packet {
    const value = SignedGossipData.initSigned(
        keypair,
        .{ .ContactInfo = contact_info },
    );
    return randomPullRequestWithContactInfo(
        allocator,
        random,
        to_addr,
        value,
    );
}

pub fn randomPullRequestWithContactInfo(
    allocator: std.mem.Allocator,
    random: std.Random,
    to_addr: EndPoint,
    contact_info: SignedGossipData,
) !Packet {
    const N_FILTER_BITS = random.intRangeAtMost(u6, 1, 10);

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.initRandom(allocator, random, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    var filter = GossipPullFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    // const invalid_filter = rng.boolean();
    const invalid_filter = false;
    if (invalid_filter) {
        filter.mask = (~@as(usize, 0)) >> random.intRangeAtMost(u6, 1, 10);
        filter.mask_bits = random.intRangeAtMost(u6, 1, 10);

        // add more random hashes
        for (0..5) |_| {
            const rand_value = try randomSignedGossipData(allocator, random, true);
            var buffer: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buffer, rand_value, bincode.Params.standard);
            const value_hash = Hash.init(bytes);
            filter.filter.add(&value_hash.data);
        }
    } else {
        // add some valid hashes
        var filter_set = try GossipPullFilterSet.initTest(allocator, random, filter.mask_bits);

        for (0..5) |_| {
            const rand_value = try randomSignedGossipData(allocator, random, true);
            var buffer: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buffer, rand_value, bincode.Params.standard);
            const value_hash = Hash.init(bytes);
            filter_set.add(&value_hash);
        }

        var filters = try filter_set.consumeForGossipPullFilters(allocator, random, 1);
        filter.filter = filters.items[0].filter;
        filter.mask = filters.items[0].mask;
        filter.mask_bits = filters.items[0].mask_bits;

        for (filters.items[1..]) |*filter_i| {
            filter_i.filter.deinit();
        }
        filters.deinit();
    }
    defer if (!invalid_filter) filter.filter.deinit();

    // serialize and send as packet
    const msg = GossipMessage{ .PullRequest = .{ filter, contact_info } };
    return try serializeToPacket(msg, to_addr);
}
