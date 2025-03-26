const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

const bincode = sig.bincode;
const socket_utils = sig.net.socket_utils;
const pull_request = sig.gossip.pull_request;
const pull_response = sig.gossip.pull_response;

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

const GossipMessageWithEndpoint = gossip.svc.GossipMessageWithEndpoint;

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

pub const ScopedLogger = sig.trace.log.ScopedLogger("gossip-verify");


            

pub const GossipVerifyService = struct {
    gossip_data_allocator: std.mem.Allocator,
    logger: ScopedLogger,
    packet_incoming_channel: *Channel(Packet),
    verified_incoming_channel: *Channel(gossip.svc.GossipMessageWithEndpoint),
    thread_pool: ThreadPool,
    gossip_packets_received_total: *Counter,

    /// main logic for deserializing Packets into GossipMessage messages
    /// and verifing they have valid values, and have valid signatures.
    /// Verified GossipMessagemessages are then sent to the verified_channel.
    pub fn verifyPackets(self: *GossipVerifyService, exit_condition: ExitCondition) !void {
        defer {
            // empty the channel
            while (self.packet_incoming_channel.tryReceive()) |_| {}
            // trigger the next service in the chain to close
            exit_condition.afterExit();
            self.logger.debug().log("verifyPackets loop closed");
        }

        const tasks = try VerifyMessageTask.init(self.allocator, VERIFY_PACKET_PARALLEL_TASKS);
        defer self.allocator.free(tasks);

        // pre-allocate all the tasks
        for (tasks) |*task| {
            task.entry = .{
                .gossip_data_allocator = self.gossip_data_allocator,
                .verified_incoming_channel = self.verified_incoming_channel,
                .packet = undefined,
                .logger = self.logger,
            };
        }

        // loop until the previous service closes and triggers us to close
        while (true) {
            self.packet_incoming_channel.waitToReceive(exit_condition) catch break;

            // verify in parallel using the threadpool
            // PERF: investigate CPU pinning
            var task_search_start_idx: usize = 0;
            while (self.packet_incoming_channel.tryReceive()) |packet| {
                defer self.gossip_packets_received_total.inc();

                const acquired_task_idx = VerifyMessageTask.awaitAndAcquireFirstAvailableTask(tasks, task_search_start_idx);
                task_search_start_idx = (acquired_task_idx + 1) % tasks.len;

                const task_ptr = &tasks[acquired_task_idx];
                task_ptr.entry.packet = packet;
                task_ptr.result catch |err| self.logger.err().logf("VerifyMessageTask encountered error: {s}", .{@errorName(err)});

                const batch = Batch.from(&task_ptr.task);
                self.thread_pool.schedule(batch);
            }
        }

        for (tasks) |*task| {
            task.blockUntilCompletion();
            task.result catch |err| self.logger.err().logf("VerifyMessageTask encountered error: {s}", .{@errorName(err)});
        }
    }
};

const VerifyMessageTask = ThreadPoolTask(VerifyMessageEntry);
const VerifyMessageEntry = struct {
    gossip_data_allocator: std.mem.Allocator,
    packet: Packet,
    verified_incoming_channel: *Channel(GossipMessageWithEndpoint),
    logger: ScopedLogger,

    pub fn callback(self: *VerifyMessageEntry) !void {
        const packet = self.packet;
        var message = bincode.readFromSlice(
            self.gossip_data_allocator,
            GossipMessage,
            packet.data[0..packet.size],
            bincode.Params.standard,
        ) catch |e| {
            self.logger.err().logf("packet_verify: failed to deserialize: {s}", .{@errorName(e)});
            return;
        };

        message.sanitize() catch |e| {
            self.logger.err().logf("packet_verify: failed to sanitize: {s}", .{@errorName(e)});
            bincode.free(self.gossip_data_allocator, message);
            return;
        };

        message.verifySignature() catch |e| {
            self.logger.err().logf(
                "packet_verify: failed to verify signature from {}: {s}",
                .{ packet.addr, @errorName(e) },
            );
            bincode.free(self.gossip_data_allocator, message);
            return;
        };

        const msg: GossipMessageWithEndpoint = .{
            .from_endpoint = packet.addr,
            .message = message,
        };
        try self.verified_incoming_channel.send(msg);
    }
};

// test "test packet verification" {
//     const allocator = std.testing.allocator;
//     var keypair = try KeyPair.create([_]u8{1} ** 32);
//     const id = Pubkey.fromPublicKey(&keypair.public_key);
//     const contact_info = try gossip.svc.localhostTestContactInfo(id);

//     var packet_incoming_channel = try Channel(Packet).create(allocator);
//     defer packet_incoming_channel.destroy();

//     var verified_incoming_channel = try Channel(GossipMessageWithEndpoint).create(allocator);
//     defer verified_incoming_channel.destroy();

//     // setup the threadpool for processing messages
//     const n_threads: usize = @min(std.Thread.getCpuCount() catch 1, THREAD_POOL_SIZE);
//     const thread_pool = ThreadPool.init(.{
//         .max_threads = @intCast(n_threads),
//         .stack_size = 2 * 1024 * 1024,
//     });
//     defer thread_pool.deinit();

//     const verify_service = GossipVerifyService{
//         .gossip_data_allocator = allocator,
//         .logger = .noop,
//         .packet_incoming_channel = packet_incoming_channel,
//         .verified_incoming_channel = verified_incoming_channel,
//         .thread_pool = thread_pool,
//         .gossip_packets_received_total = allocator,
//     };
//     _ = verify_service; // autofix

//     // noop for this case because this tests error failed verification
//     var verify_service = try GossipVerifyService.create(
//         allocator,
//         allocator,
//         contact_info,
//         keypair,
//         null,
//         .noop,
//     );
//     defer {
//         verify_service.deinit();
//         allocator.destroy(verify_service);
//     }

//     var packet_channel = verify_service.packet_incoming_channel;
//     var verified_channel = verify_service.verified_incoming_channel;

//     const packet_verifier_handle = try Thread.spawn(
//         .{},
//         GossipVerifyService.verifyPackets,
//         .{ verify_service, .{ .unordered = verify_service.service_manager.exit } },
//     );
//     defer {
//         verify_service.shutdown();
//         packet_verifier_handle.join();
//     }

//     var prng = std.rand.DefaultPrng.init(91);
//     var data = GossipData.randomFromIndex(prng.random(), 0);
//     data.LegacyContactInfo.id = id;
//     data.LegacyContactInfo.wallclock = 0;
//     var value = SignedGossipData.initSigned(&keypair, data);

//     try std.testing.expect(try value.verify(id));

//     var values = [_]SignedGossipData{value};
//     const message = GossipMessage{
//         .PushMessage = .{ id, &values },
//     };

//     var peer = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 0);
//     const from = peer.toEndpoint();

//     var buf = [_]u8{0} ** PACKET_DATA_SIZE;
//     const out = try bincode.writeToSlice(buf[0..], message, bincode.Params{});
//     const packet = Packet.init(from, buf, out.len);
//     for (0..3) |_| {
//         try packet_channel.send(packet);
//     }

//     // send one which fails sanitization
//     var value_v2 = SignedGossipData.initSigned(&keypair, GossipData.randomFromIndex(prng.random(), 2));
//     value_v2.data.EpochSlots[0] = sig.gossip.data.MAX_EPOCH_SLOTS;
//     var values_v2 = [_]SignedGossipData{value_v2};
//     const message_v2 = GossipMessage{
//         .PushMessage = .{ id, &values_v2 },
//     };
//     var buf_v2 = [_]u8{0} ** PACKET_DATA_SIZE;
//     const out_v2 = try bincode.writeToSlice(buf_v2[0..], message_v2, bincode.Params{});
//     const packet_v2 = Packet.init(from, buf_v2, out_v2.len);
//     try packet_channel.send(packet_v2);

//     // send one with a incorrect signature
//     var rand_keypair = try KeyPair.create([_]u8{3} ** 32);
//     const value2 = SignedGossipData.initSigned(&rand_keypair, GossipData.randomFromIndex(prng.random(), 0));
//     var values2 = [_]SignedGossipData{value2};
//     const message2 = GossipMessage{
//         .PushMessage = .{ id, &values2 },
//     };
//     var buf2 = [_]u8{0} ** PACKET_DATA_SIZE;
//     const out2 = try bincode.writeToSlice(buf2[0..], message2, bincode.Params{});
//     const packet2 = Packet.init(from, buf2, out2.len);
//     try packet_channel.send(packet2);

//     // send it with a SignedGossipData which hash a slice
//     {
//         const rand_pubkey = Pubkey.fromPublicKey(&rand_keypair.public_key);
//         var dshred = sig.gossip.data.DuplicateShred.initRandom(prng.random());
//         var chunk: [32]u8 = .{1} ** 32;
//         dshred.chunk = &chunk;
//         dshred.wallclock = 1714155765121;
//         dshred.slot = 16592333628234015598;
//         dshred.shred_index = 3853562894;
//         dshred.shred_type = sig.gossip.data.ShredType.Data;
//         dshred.num_chunks = 99;
//         dshred.chunk_index = 69;
//         dshred.from = rand_pubkey;
//         const dshred_data = GossipData{
//             .DuplicateShred = .{ 1, dshred },
//         };
//         const dshred_value = SignedGossipData.initSigned(&rand_keypair, dshred_data);
//         var values3 = [_]SignedGossipData{dshred_value};
//         const message3 = GossipMessage{
//             .PushMessage = .{ id, &values3 },
//         };
//         var buf3 = [_]u8{0} ** PACKET_DATA_SIZE;
//         const out3 = try bincode.writeToSlice(buf3[0..], message3, bincode.Params{});
//         const packet3 = Packet.init(from, buf3, out3.len);
//         try packet_channel.send(packet3);
//     }

//     var msg_count: usize = 0;
//     while (msg_count < 4) {
//         if (verified_channel.tryReceive()) |msg| {
//             defer bincode.free(verify_service.allocator, msg);
//             try std.testing.expect(msg.message.PushMessage[0].equals(&id));
//             msg_count += 1;
//         }
//     }
// }
