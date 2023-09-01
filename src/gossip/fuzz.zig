//! how to run the fuzzer:
//!     `zig build fuzz_gossip`
//! to stop the fuzzer write any input to stdin and press enter

const std = @import("std");
const GossipService = @import("gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;

const crds = @import("crds.zig");
const LegacyContactInfo = crds.LegacyContactInfo;
const AtomicBool = std.atomic.Atomic(bool);

const SocketAddr = @import("net.zig").SocketAddr;

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

const Hash = @import("../core/hash.zig").Hash;

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
    const size: comptime_int = 5;
    var crds_values: [size]CrdsValue = undefined;
    var should_pass_sig_verification = rng.boolean();
    for (0..size) |i| {
        var value = try random_crds_value(rng, should_pass_sig_verification);
        crds_values[i] = value;
    }

    // serialize and send as packet
    var size_for_packet = @as(usize, size);
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    while (size_for_packet > 0) {
        var msg = Protocol{ .PushMessage = .{ pubkey, crds_values[0..size_for_packet] } };
        var msg_slice = bincode.writeToSlice(&packet_buf, msg, bincode.Params{}) catch |err| {
            if (err == error.OutOfMemory) {
                // TODO: optimize
                size_for_packet -= 1;
                continue;
            } else {
                return err;
            }
        };

        var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
        return packet;
    }

    return error.FailedToBuildRandomPushPacket;
}

pub fn random_pull_response(rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    const size: comptime_int = 5;
    var crds_values: [size]CrdsValue = undefined;
    var should_pass_sig_verification = rng.boolean();
    for (0..size) |i| {
        var value = try random_crds_value(rng, should_pass_sig_verification);
        crds_values[i] = value;
    }

    // serialize and send as packet
    var size_for_packet = @as(usize, size);
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key, false);
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    while (size_for_packet > 0) {
        var msg = Protocol{ .PullResponse = .{ pubkey, crds_values[0..size_for_packet] } };
        var msg_slice = bincode.writeToSlice(&packet_buf, msg, bincode.Params{}) catch |err| {
            if (err == error.OutOfMemory) {
                // TODO: optimize
                size_for_packet -= 1;
                continue;
            } else {
                return err;
            }
        };

        var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
        return packet;
    }

    return error.FailedToBuildRandomPullResponsePacket;
}

pub fn random_pull_request(allocator: std.mem.Allocator, rng: std.rand.Random, keypair: *const KeyPair, to_addr: EndPoint) !Packet {
    const N_FILTER_BITS = rng.intRangeAtMost(u6, 1, 10);

    // only consider the first bit so we know well get matches
    var bloom = try Bloom.random(allocator, 100, 0.1, N_FILTER_BITS);
    defer bloom.deinit();

    const crds_value = try CrdsValue.initSigned(crds.CrdsData{
        .LegacyContactInfo = LegacyContactInfo.random(rng),
    }, keypair);

    var filter = CrdsFilter{
        .filter = bloom,
        .mask = (~@as(usize, 0)) >> N_FILTER_BITS,
        .mask_bits = N_FILTER_BITS,
    };

    const invalid_filter = rng.boolean();
    if (invalid_filter) {
        filter.mask = (~@as(usize, 0)) >> rng.intRangeAtMost(u6, 1, 10);
        filter.mask_bits = rng.intRangeAtMost(u6, 1, 10);

        // add more random hashes
        for (0..5) |_| {
            var value = try random_crds_value(rng, true);
            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
            const value_hash = Hash.generateSha256Hash(bytes);
            filter.filter.add(&value_hash.data);
        }
    } else {
        // add some valid hashes
        var filter_set = try pull_request.CrdsFilterSet.init_test(allocator, filter.mask_bits);
        for (0..5) |_| {
            var value = try random_crds_value(rng, true);
            var buf: [PACKET_DATA_SIZE]u8 = undefined;
            const bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
            const value_hash = Hash.generateSha256Hash(bytes);
            filter_set.add(&value_hash);
        }

        var filters = try filter_set.consume_for_crds_filters(allocator, 1);
        filter.filter = filters.items[0].filter;
        filter.mask = filters.items[0].mask;
        filter.mask_bits = filters.items[0].mask_bits;

        filters.deinit();
    }

    // serialize and send as packet
    var msg = Protocol{ .PullRequest = .{ filter, crds_value } };
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var msg_slice = try bincode.writeToSlice(&packet_buf, msg, bincode.Params{});
    var packet = Packet.init(to_addr, packet_buf, msg_slice.len);
    return packet;
}

pub fn wait_for_exit(exit: *AtomicBool) void {
    const reader = std.io.getStdOut().reader();
    var buf: [1]u8 = undefined;
    _ = reader.read(&buf) catch unreachable;

    exit.store(true, std.atomic.Ordering.Unordered);
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
    var seed = get_wallclock();
    // var seed: u64 = 1693494238796;
    std.debug.print("SEED: {d}\n", .{seed});
    var rng = std.rand.DefaultPrng.init(seed);

    // wait for keyboard input to exit
    var loop_exit = AtomicBool.init(false);
    var exit_handle = try std.Thread.spawn(.{}, wait_for_exit, .{&loop_exit});

    while (!loop_exit.load(std.atomic.Ordering.Unordered)) {
        var command = rng.random().intRangeAtMost(u8, 0, 4);
        var packet = switch (command) {
            0 => blk: {
                // send ping message
                const packet = random_ping(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
                break :blk packet;
            },
            1 => blk: {
                // send pong message
                const packet = random_pong(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
                break :blk packet;
            },
            2 => blk: {
                // send push message
                const packet = random_push_message(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
                break :blk packet;
            },
            3 => blk: {
                // send pull response
                const packet = random_pull_response(rng.random(), &fuzz_keypair, gossip_address.toEndpoint());
                break :blk packet;
            },
            4 => blk: {
                // send pull request
                var packet = random_pull_request(
                    allocator,
                    rng.random(),
                    &fuzz_keypair,
                    gossip_address.toEndpoint(),
                );
                break :blk packet;
            },
            else => unreachable,
        };
        var send_packet = packet catch |err| {
            std.debug.print("ERROR: {s}\n", .{@errorName(err)});
            continue;
        };

        try gossip_service_fuzzer.responder_channel.send(send_packet);

        var send_duplicate = rng.random().boolean();
        if (send_duplicate) {
            try gossip_service_fuzzer.responder_channel.send(send_packet);
        }

        std.time.sleep(std.time.ns_per_ms * 10);
        // std.time.sleep(std.time.ns_per_s);
    }

    // cleanup
    std.debug.print("\t=> shutting down...\n", .{});
    exit.store(true, std.atomic.Ordering.Unordered);
    handle.join();
    std.debug.print("\t=> gossip service shutdown\n", .{});

    fuzz_exit.store(true, std.atomic.Ordering.Unordered);
    fuzz_handle.join();
    gossip_service_fuzzer.deinit();
    std.debug.print("\t=>fuzzy gossip service shutdown\n", .{});

    exit_handle.join();
    std.debug.print("fuzzing done\n", .{});
}
