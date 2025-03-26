const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

const bincode = sig.bincode;

const ArrayList = std.ArrayList;
const Thread = std.Thread;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const EndPoint = network.EndPoint;
const UdpSocket = network.Socket;

const Bloom = sig.bloom.Bloom;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Logger = sig.trace.log.Logger;
const Packet = sig.net.Packet;
const EchoServer = sig.net.echo.Server;
const SocketAddr = sig.net.SocketAddr;
const Counter = sig.prometheus.Counter;
const Gauge = sig.prometheus.Gauge;
const Histogram = sig.prometheus.Histogram;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const ThreadPoolTask = sig.utils.thread.ThreadPoolTask;
const ThreadPool = sig.sync.ThreadPool;
const Task = sig.sync.ThreadPool.Task;
const Batch = sig.sync.ThreadPool.Batch;
const Mux = sig.sync.Mux;
const RwMux = sig.sync.RwMux;
const Channel = sig.sync.Channel;
const ActiveSet = sig.gossip.active_set.ActiveSet;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipDumpService = sig.gossip.dump_service.GossipDumpService;
const GossipMessage = sig.gossip.message.GossipMessage;
const PruneData = sig.gossip.PruneData;
const GossipTable = sig.gossip.table.GossipTable;
const HashTimeQueue = sig.gossip.table.HashTimeQueue;
const AutoArrayHashSet = sig.gossip.table.AutoArrayHashSet;
const GossipPullFilter = sig.gossip.pull_request.GossipPullFilter;
const Ping = sig.gossip.ping_pong.Ping;
const Pong = sig.gossip.ping_pong.Pong;
const PingCache = sig.gossip.ping_pong.PingCache;
const PingAndSocketAddr = sig.gossip.ping_pong.PingAndSocketAddr;
const ServiceManager = sig.utils.service_manager.ServiceManager;
const Duration = sig.time.Duration;
const ExitCondition = sig.sync.ExitCondition;
const SocketThread = sig.net.SocketThread;

const endpointToString = sig.net.endpointToString;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;
const deinitMux = sig.sync.mux.deinitMux;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const UNIQUE_PUBKEY_CAPACITY = sig.gossip.table.UNIQUE_PUBKEY_CAPACITY;
const MAX_NUM_PULL_REQUESTS = sig.gossip.pull_request.MAX_NUM_PULL_REQUESTS;

pub const PULL_REQUEST_RATE = Duration.fromSecs(5);
pub const PULL_RESPONSE_TIMEOUT = Duration.fromSecs(5);
pub const ACTIVE_SET_REFRESH_RATE = Duration.fromSecs(15);
pub const DATA_TIMEOUT = Duration.fromSecs(15);
pub const TABLE_TRIM_RATE = Duration.fromSecs(10);
pub const BUILD_MESSAGE_LOOP_MIN = Duration.fromSecs(1);
pub const PUBLISH_STATS_INTERVAL = Duration.fromSecs(2);

pub const PUSH_MSG_TIMEOUT = Duration.fromSecs(30);
pub const PRUNE_MSG_TIMEOUT = Duration.fromMillis(500);
pub const FAILED_INSERTS_RETENTION = Duration.fromSecs(20);
pub const PURGED_RETENTION = Duration.fromSecs(PULL_REQUEST_RATE.asSecs() * 5);

pub const MAX_PACKETS_PER_PUSH: usize = 64;
pub const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * @as(u64, MAX_PACKETS_PER_PUSH);
// 4 (enum) + 32 (pubkey) + 8 (len) = 44
pub const MAX_PUSH_MESSAGE_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

pub const MAX_NUM_VALUES_PER_PULL_RESPONSE = 20; // TODO: this is approx the rust one -- should tune
pub const NUM_ACTIVE_SET_ENTRIES: usize = 25;
/// Maximum number of origin nodes that a PruneData may contain, such that the
/// serialized size of the PruneMessage stays below PACKET_DATA_SIZE.
pub const MAX_PRUNE_DATA_NODES: usize = 32;

pub const PING_CACHE_CAPACITY: usize = 65_536;
pub const PING_CACHE_TTL = Duration.fromSecs(1280);
pub const PING_CACHE_RATE_LIMIT_DELAY = Duration.fromSecs(1280 / 64);

// TODO: replace with get_epoch_duration when BankForks is supported
const DEFAULT_EPOCH_DURATION = Duration.fromMillis(172_800_000);

pub const VERIFY_PACKET_PARALLEL_TASKS = 4;
const THREAD_POOL_SIZE = 4;
const MAX_PROCESS_BATCH_SIZE = 64;
const GOSSIP_PRNG_SEED = 19;

pub const ScopedLogger = sig.trace.log.ScopedLogger("gossip-svc");

pub const GossipMessageWithEndpoint = struct { from_endpoint: EndPoint, message: GossipMessage };

pub fn getClusterEntrypoints(cluster: sig.core.Cluster) []const []const u8 {
    return switch (cluster) {
        .mainnet => &.{
            "entrypoint.mainnet-beta.solana.com:8001",
            "entrypoint2.mainnet-beta.solana.com:8001",
            "entrypoint3.mainnet-beta.solana.com:8001",
            "entrypoint4.mainnet-beta.solana.com:8001",
            "entrypoint5.mainnet-beta.solana.com:8001",
        },
        .testnet => &.{
            "entrypoint.testnet.solana.com:8001",
            "entrypoint2.testnet.solana.com:8001",
            "entrypoint3.testnet.solana.com:8001",
        },
        .devnet => &.{
            "entrypoint.devnet.solana.com:8001",
            "entrypoint2.devnet.solana.com:8001",
            "entrypoint3.devnet.solana.com:8001",
            "entrypoint4.devnet.solana.com:8001",
            "entrypoint5.devnet.solana.com:8001",
        },
        .localnet => &.{
            "127.0.0.1:1024", // agave test-validator default
            "127.0.0.1:8001", // sig validator default
        },
    };
}

pub fn localhostTestContactInfo(id: Pubkey) !ContactInfo {
    comptime std.debug.assert(@import("builtin").is_test); // should only be used for testin
    var contact_info = try LegacyContactInfo.default(id).toContactInfo(std.testing.allocator);
    try contact_info.setSocket(.gossip, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0));
    return contact_info;
}

/// uses a read lock to first check if the gossip table should be trimmed,
/// then acquires a write lock to perform the trim.
/// NOTE: in practice, trim is rare because the number of global validators is much <10k (the global constant
/// used is UNIQUE_PUBKEY_CAPACITY)
pub fn attemptGossipTableTrim(
    logger: ScopedLogger,
    gossip_table_rw: *RwMux(GossipTable),
    metrics: GossipTableTrimMetrics,
) !void {
    // first check with a read lock
    const should_trim = blk: {
        const gossip_table, var gossip_table_lock = gossip_table_rw.readWithLock();
        defer gossip_table_lock.unlock();

        const should_trim = gossip_table.shouldTrim(UNIQUE_PUBKEY_CAPACITY);
        break :blk should_trim;
    };

    // then trim with write lock
    const n_pubkeys_dropped: u64 = if (should_trim) blk: {
        var gossip_table, var gossip_table_lock = gossip_table_rw.writeWithLock();
        defer gossip_table_lock.unlock();

        var x_timer = sig.time.Timer.start() catch unreachable;
        const now = getWallclockMs();
        const n_pubkeys_dropped = gossip_table.attemptTrim(now, UNIQUE_PUBKEY_CAPACITY) catch |err| err_blk: {
            logger.err().logf("gossip_table.attemptTrim failed: {s}", .{@errorName(err)});
            break :err_blk 0;
        };
        const elapsed = x_timer.read().asMillis();
        metrics.handle_trim_table_time.observe(elapsed);

        break :blk n_pubkeys_dropped;
    } else 0;

    metrics.table_pubkeys_dropped.add(n_pubkeys_dropped);
}

pub const GossipTableTrimMetrics = struct {
    handle_trim_table_time: *Histogram,
    table_pubkeys_dropped: *Counter,
};

/// serializes a list of ping messages into Packets and sends them out
pub fn sendPings(
    packet_outgoing_channel: *Channel(Packet),
    ping_messages_sent: *Counter(u64),
    pings: []const PingAndSocketAddr,
) error{ OutOfMemory, ChannelClosed, SerializationError }!void {
    for (pings) |ping_and_addr| {
        const message = GossipMessage{ .PingMessage = ping_and_addr.ping };

        var packet = Packet.default();
        const serialized_ping = bincode.writeToSlice(&packet.data, message, .{}) catch return error.SerializationError;
        packet.size = serialized_ping.len;
        packet.addr = ping_and_addr.socket.toEndpoint();

        try packet_outgoing_channel.send(packet);
        ping_messages_sent.add(1);
    }
}

pub const ChunkType = enum(u8) {
    PushMessage,
    PullResponse,
};

pub fn gossipDataToPackets(
    allocator: std.mem.Allocator,
    my_pubkey: *const Pubkey,
    gossip_values: []SignedGossipData,
    to_endpoint: *const EndPoint,
    chunk_type: ChunkType,
) error{ OutOfMemory, SerializationError }!ArrayList(Packet) {
    if (gossip_values.len == 0)
        return ArrayList(Packet).init(allocator);

    const indexs = try chunkValuesIntoPacketIndexes(
        allocator,
        gossip_values,
        MAX_PUSH_MESSAGE_PAYLOAD_SIZE,
    );
    defer indexs.deinit();
    var chunk_iter = std.mem.window(usize, indexs.items, 2, 1);

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var packets = try ArrayList(Packet).initCapacity(allocator, indexs.items.len -| 1);
    errdefer packets.deinit();

    while (chunk_iter.next()) |window| {
        const start_index = window[0];
        const end_index = window[1];
        const values = gossip_values[start_index..end_index];

        const message = switch (chunk_type) {
            .PushMessage => GossipMessage{ .PushMessage = .{ my_pubkey.*, values } },
            .PullResponse => GossipMessage{ .PullResponse = .{ my_pubkey.*, values } },
        };
        const msg_slice = bincode.writeToSlice(&packet_buf, message, bincode.Params{}) catch {
            return error.SerializationError;
        };
        const packet = Packet.init(to_endpoint.*, packet_buf, msg_slice.len);
        packets.appendAssumeCapacity(packet);
    }

    return packets;
}

fn chunkValuesIntoPacketIndexes(
    allocator: std.mem.Allocator,
    gossip_values: []const SignedGossipData,
    max_chunk_bytes: usize,
) error{ OutOfMemory, SerializationError }!ArrayList(usize) {
    var packet_indexs = try ArrayList(usize).initCapacity(allocator, 1);
    errdefer packet_indexs.deinit();
    packet_indexs.appendAssumeCapacity(0);

    if (gossip_values.len == 0) {
        return packet_indexs;
    }

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var buf_byte_size: u64 = 0;

    for (gossip_values, 0..) |gossip_value, i| {
        const data_byte_size = bincode.getSerializedSizeWithSlice(
            &packet_buf,
            gossip_value,
            bincode.Params{},
        ) catch {
            return error.SerializationError;
        };
        const new_chunk_size = buf_byte_size + data_byte_size;
        const is_last_iter = i == gossip_values.len - 1;

        if (new_chunk_size > max_chunk_bytes or is_last_iter) {
            try packet_indexs.append(i);
            buf_byte_size = data_byte_size;
        } else {
            buf_byte_size = new_chunk_size;
        }
    }

    return packet_indexs;
}
