const std = @import("std");
const GossipService = @import("gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;

const crds = @import("crds.zig");
const LegacyContactInfo = crds.LegacyContactInfo;
const AtomicBool = std.atomic.Atomic(bool);

const SocketAddr = @import("net.zig").SocketAddr;
const UdpSocket = @import("zig-network").Socket;

const Pubkey = @import("../core/pubkey.zig").Pubkey;
const get_wallclock = @import("crds.zig").get_wallclock;

const Bloom = @import("../bloom/bloom.zig").Bloom;
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;
const NonBlockingChannel = @import("../sync/channel.zig").NonBlockingChannel;

const Thread = std.Thread;
const Tuple = std.meta.Tuple;
const _protocol = @import("protocol.zig");
const Protocol = _protocol.Protocol;
const PruneData = _protocol.PruneData;

const Mux = @import("../sync/mux.zig").Mux;
const RwMux = @import("../sync/mux.zig").RwMux;

const Ping = @import("ping_pong.zig").Ping;
const Pong = @import("ping_pong.zig").Pong;
const bincode = @import("../bincode/bincode.zig");
const CrdsValue = crds.CrdsValue;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const HashTimeQueue = _crds_table.HashTimeQueue;
const CRDS_UNIQUE_PUBKEY_CAPACITY = _crds_table.CRDS_UNIQUE_PUBKEY_CAPACITY;

const pull_request = @import("../gossip/pull_request.zig");
const CrdsFilter = pull_request.CrdsFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;

const pull_response = @import("../gossip/pull_response.zig");
const ActiveSet = @import("../gossip/active_set.zig").ActiveSet;

const Hash = @import("../core/hash.zig").Hash;

const socket_utils = @import("socket_utils.zig");

const PacketChannel = NonBlockingChannel(Packet);
const ProtocolMessage = struct { from_endpoint: EndPoint, message: Protocol };
const ProtocolChannel = NonBlockingChannel(ProtocolMessage);

pub fn random_ping(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    var ping_buf: [32]u8 = undefined;
    rng.bytes(&ping_buf);
    const ping = Protocol{
        .PingMessage = try Ping.init(ping_buf, keypair),
    };

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, ping, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn random_pong(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    var ping_buf: [32]u8 = undefined;
    rng.bytes(&ping_buf);
    const ping = try Ping.init(ping_buf, keypair);

    const pong = Protocol{
        .PongMessage = try Pong.init(&ping, keypair),
    };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, pong, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn random_crds_value(rng: std.rand.Random, maybe_should_pass_sig_verification: ?bool) !CrdsValue {
    var keypair = try KeyPair.create(null);
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);

    // will have random id
    var value = try CrdsValue.random(rng, &keypair);

    const should_pass_sig_verification = maybe_should_pass_sig_verification orelse rng.boolean();
    if (should_pass_sig_verification) {
        value.data.set_id(pubkey);
        try value.sign(&keypair);
    }

    return value;
}

pub fn random_push_message(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    var crds_values: [1]CrdsValue = undefined;
    var should_pass_sig_verification = rng.boolean();
    for (0..1) |i| {
        var value = try random_crds_value(rng, should_pass_sig_verification);
        crds_values[i] = value;
    }

    // serialize and send as packet
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
    var msg = Protocol{ .PushMessage = .{ pubkey, crds_values[0..1] } };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, msg, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn random_pull_response(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    var crds_values: [5]CrdsValue = undefined;
    var should_pass_sig_verification = rng.boolean();
    for (0..5) |i| {
        var value = try random_crds_value(rng, should_pass_sig_verification);
        crds_values[i] = value;
    }

    // serialize and send as packet
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
    var msg = Protocol{ .PullResponse = .{ pubkey, crds_values[0..5] } };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, msg, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn random_pull_request(allocator: std.mem.Allocator, rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    const N_FILTER_BITS = rng.intRangeAtMost(u6, 1, 10);

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    const crds_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = LegacyContactInfo.random(rng),
    }, keypair);

    const filter = CrdsFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    // serialize and send as packet
    var msg = Protocol{ .PullRequest = .{ filter, crds_value } };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, msg, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator(); // use std.testing.allocator to detect leaks

    var logger = Logger.init(gpa.allocator(), .debug);
    defer logger.deinit();
    logger.spawn();

    // setup the gossip service
    var gossip_port: u16 = 8001;
    var gossip_address = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, gossip_port);

    var my_keypair = try KeyPair.create(null);
    var exit = AtomicBool.init(false);

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = LegacyContactInfo.default(my_pubkey);
    contact_info.shred_version = 0;
    contact_info.gossip = gossip_address;

    // start running gossip
    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair,
        &exit,
    );
    defer gossip_service.deinit();

    var handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ &gossip_service, logger },
    );
    std.debug.print("gossip service started on port {d}\n", .{gossip_port});

    // setup sending socket
    var fuzz_keypair = try KeyPair.create(null);
    var fuzz_address = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 9998);

    var fuzz_pubkey = Pubkey.fromPublicKey(&fuzz_keypair.public_key, false);
    var fuzz_contact_info = LegacyContactInfo.default(fuzz_pubkey);
    fuzz_contact_info.shred_version = 19;
    fuzz_contact_info.gossip = fuzz_address;

    var fuzz_exit = AtomicBool.init(false);
    var gossip_service_fuzzer = try GossipService.init(
        allocator,
        fuzz_contact_info,
        fuzz_keypair,
        &fuzz_exit,
    );
    var fuzz_handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ &gossip_service_fuzzer, logger },
    );

    // blast it
    // var seed = get_wallclock();
    var seed: u64 = 1693494238796;
    std.debug.print("SEED: {d}\n", .{seed});
    var rng = std.rand.DefaultPrng.init(seed);

    // send ping
    {
        const ping = try random_ping(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
        try gossip_service_fuzzer.responder_channel.send(ping);
    }

    // send pong message
    {
        const pong = try random_pong(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
        try gossip_service_fuzzer.responder_channel.send(pong);
    }

    for (0..5) |_| {
        // send push message
        {
            var packet = try random_push_message(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
            try gossip_service_fuzzer.responder_channel.send(packet);
        }

        // send as pull response
        {
            var packet = try random_pull_response(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
            try gossip_service_fuzzer.responder_channel.send(packet);
        }
        std.time.sleep(std.time.ns_per_s);
    }

    // send pull request
    {
        for (0..5) |_| {
            var packet = try random_pull_request(
                allocator,
                rng.random(),
                &fuzz_keypair,
                gossip_address.toEndpoint(),
            );
            try gossip_service_fuzzer.responder_channel.send(packet);
        }
    }

    while (true) {}

    // // TODO: wait for cancel keyboard input
    // const reader = std.io.getStdOut().reader();
    // var buf: [1]u8 = undefined;
    // _ = reader.read(&buf) catch unreachable;

    // cleanup
    std.debug.print("\t=> shutting down...\n", .{});
    exit.store(true, std.atomic.Ordering.Unordered);
    handle.join();
    std.debug.print("\t=> gossip service shutdown\n", .{});

    fuzz_exit.store(true, std.atomic.Ordering.Unordered);
    fuzz_handle.join();
    gossip_service_fuzzer.deinit();
    std.debug.print("\t=>fuzzy gossip service shutdown\n", .{});

    std.debug.print("fuzzing done\n", .{});
}
