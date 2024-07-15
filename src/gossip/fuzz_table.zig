const std = @import("std");
const sig = @import("../lib.zig");

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

const GossipTable = sig.gossip.GossipTable;
const _gossip_table = @import("../gossip/table.zig");

const _pull_request = @import("../gossip/pull_request.zig");
const GossipPullFilterSet = _pull_request.GossipPullFilterSet;
const GossipPullFilter = _pull_request.GossipPullFilter;

const Hash = @import("../core/hash.zig").Hash;
const ThreadPool = sig.sync.ThreadPool;

const PacketChannel = NonBlockingChannel(Packet);
const GossipChannel = NonBlockingChannel(GossipMessage);

pub fn run(args: *std.process.ArgIterator) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator(); // use std.testing.allocator to detect leaks

    const maybe_seed = args.next();
    const maybe_max_actions_string = args.next();

    // threadpool 
    const n_threads = @min(@as(u32, @truncate(std.Thread.getCpuCount() catch 1)), 8);
    const thread_pool = try allocator.create(ThreadPool);
    thread_pool.* = ThreadPool.init(.{
        .max_threads = n_threads,
        .stack_size = 2 * 1024 * 1024,
    });

    const gossip_table = try allocator.create(GossipTable);
    gossip_table.* = GossipTable.init(allocator, )
    defer { 
    }

}