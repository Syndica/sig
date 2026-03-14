const std = @import("std");
const sig = @import("sig");

const Allocator = std.mem.Allocator;
const KeyPair = sig.identity.KeyPair;

const bincode = sig.bincode;
const mock = sig.transaction_sender_v2.mock;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Hash = sig.core.Hash;
const Transaction = sig.core.Transaction;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;
const Status = sig.core.status_cache.Status;

const Packet = sig.net.Packet;
const SocketAddr = sig.net.SocketAddr;
const QuicClientLogger = sig.net.quic_client.Logger;
const runQuicClient = sig.net.quic_client.runClient;

const RpcClient = sig.rpc.Client;
const Commitment = sig.rpc.methods.common.Commitment;

const SYSTEM_PROGRAM_ID = sig.runtime.program.system.ID;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

const TransactionInfo = sig.TransactionSenderService.TransactionInfo;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const PubkeyMap = sig.utils.collections.PubkeyMap;

const Logger = sig.trace.log.Logger("test_send_transactions");

const LEADER_WINDOW: u64 = 4;
const FORWARD_TO_LEADERS: usize = 5;
const DEFAULT_RPC_URL = "https://api.testnet.solana.com";

pub fn main() !void {
    const logger = Logger{
        .impl = .direct_print,
        .max_level = .debug,
        .filters = .debug,
    };

    var exit_flag = std.atomic.Value(bool).init(false);
    const exit = ExitCondition{ .unordered = &exit_flag };
    errdefer |err| {
        logger.err().logf("exiting with error: {any}\n", .{err});
        exit.setExit();
    }

    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const args = try std.process.argsAlloc(arena);
    defer std.process.argsFree(arena, args);

    if (args.len > 2) {
        std.debug.print(
            "Usage:\n" ++
                "  quic-repro [rpc_url]\n\n" ++
                "Example:\n" ++
                "  quic-repro\n" ++
                "  quic-repro https://api.testnet.solana.com\n",
            .{},
        );
        return error.InvalidArgs;
    }

    const rpc_url = if (args.len == 2) args[1] else DEFAULT_RPC_URL;

    var mock_sender_service = try MockSenderService.init(
        arena,
        exit,
        .from(logger),
        rpc_url,
        .fromSecs(5), // Approx every 2 leaders
    );
    const mock_sender_handle = try std.Thread.spawn(
        .{},
        MockSenderService.run,
        .{&mock_sender_service},
    );
    defer mock_sender_handle.join();

    var mock_transfer_service = sig.MockTransferService{
        .exit = exit,
        .logger = .from(logger),
        .mode = try .initRpc(gpa, rpc_url, .noop),
        .sender = mock_sender_service.receiver,
        .transfers = 100,
    };
    try mock_transfer_service.run(arena);
    exit.setExit();
}

const MockSenderService = struct {
    arena: Allocator,
    exit: ExitCondition,
    logger: Logger,
    client: RpcClient,
    receiver: *Channel(TransactionInfo),

    epoch_start_slot: u64,
    epoch_leaders: []?SocketAddr,
    send_interval: Duration,

    pub fn init(
        arena: Allocator,
        exit: ExitCondition,
        logger: Logger,
        rpc_url: []const u8,
        send_interval: Duration,
    ) !MockSenderService {
        const receiver = try Channel(TransactionInfo).create(arena);
        receiver.name = "TransactionSenderService: TransactionInfo Receiver";

        var rpc_client = try RpcClient.init(
            arena,
            rpc_url,
            .{ .max_retries = 2, .logger = .noop },
        );

        const epoch_start_slot, const epoch_leaders = try resolveLeadersFromRpc(
            arena,
            &rpc_client,
        );

        return .{
            .arena = arena,
            .exit = exit,
            .logger = logger,
            .client = rpc_client,
            .receiver = receiver,
            .epoch_start_slot = epoch_start_slot,
            .epoch_leaders = epoch_leaders,
            .send_interval = send_interval,
        };
    }

    pub fn run(self: *MockSenderService) !void {
        const quic_sender = try Channel(Packet).create(self.arena);
        quic_sender.name = "TransactionSenderService: Packet Sender";

        const quic_handle = try std.Thread.spawn(
            .{},
            sig.net.quic_client.runClient,
            .{
                self.arena,
                quic_sender,
                sig.net.quic_client.Logger.from(self.logger),
                self.exit,
            },
        );
        defer quic_handle.join();

        try self.handleTransactions(quic_sender);
    }

    fn handleTransactions(
        self: *MockSenderService,
        quic_sender: *Channel(Packet),
    ) !void {
        var last_sent_time = Instant.EPOCH_ZERO;
        var txn_info = try self.receiver.receive(self.exit);

        while (self.exit.shouldRun()) {
            if (self.receiver.tryReceive()) |new_info| {
                self.logger.info().logf("Received TransactionInfo: signature={f}", .{new_info.signature});
                txn_info = new_info;
                last_sent_time = Instant.EPOCH_ZERO;
            }

            if (last_sent_time.elapsed().gt(self.send_interval)) {
                self.logger.info().logf("Sending Transaction: signature={f}", .{txn_info.signature});
                try self.sendToLeaders(quic_sender, &txn_info);
                last_sent_time = Instant.now();
            }

            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    fn sendToLeaders(
        self: *MockSenderService,
        quic_sender: *Channel(Packet),
        txn_info: *TransactionInfo,
    ) !void {
        var slot_response = try self.client.getSlot(.{ .config = .{ .commitment = .processed } });
        const slot = try slot_response.result();

        const leader_idx = slot - self.epoch_start_slot;
        for (0..FORWARD_TO_LEADERS) |leader_i| {
            const idx = leader_idx + leader_i * LEADER_WINDOW;
            if (idx >= self.epoch_leaders.len) return error.EndOfEpoch;
            if (self.epoch_leaders[idx]) |leader| {
                self.logger.info().logf("Sending {f} leader {d}", .{ txn_info.signature, idx });
                try quic_sender.send(Packet.init(
                    leader,
                    txn_info.wire_transaction,
                    txn_info.wire_transaction_size,
                ));
            } else self.logger.info().logf("No address for leader {d}", .{idx});
        }
    }
};

fn resolveLeadersFromRpc(
    arena: Allocator,
    client: *RpcClient,
) !struct { u64, []?SocketAddr } {
    var slot_response = try client.getSlot(.{
        .config = .{ .commitment = .processed },
    });
    defer slot_response.deinit();
    const current_slot = try slot_response.result();

    var epoch_info_response = try client.getEpochInfo(
        .{ .config = .{ .commitment = .processed } },
    );
    defer epoch_info_response.deinit();
    const epoch_info = try epoch_info_response.result();
    const epoch_start_slot = current_slot - epoch_info.slotIndex;

    var schedule_response = try client.getLeaderSchedule(.{ .slot = current_slot });
    defer schedule_response.deinit();
    var rpc_leader_schedule = try schedule_response.result();

    var cluster_nodes_response = try client.getClusterNodes(.{});
    defer cluster_nodes_response.deinit();
    const cluster_nodes = try cluster_nodes_response.result();

    var pubkey_to_tpu_quic = std.AutoArrayHashMapUnmanaged(Pubkey, SocketAddr).empty;
    defer pubkey_to_tpu_quic.deinit(arena);

    for (cluster_nodes) |node| {
        const tpu_quic = node.tpuQuic orelse continue;

        const addr = SocketAddr.parse(tpu_quic) catch blk: {
            const gossip = node.gossip orelse continue;
            const port = std.fmt.parseUnsigned(u16, tpu_quic, 10) catch continue;

            var gossip_addr = SocketAddr.parse(gossip) catch continue;
            gossip_addr.setPort(port);
            break :blk gossip_addr;
        };

        try pubkey_to_tpu_quic.put(arena, try Pubkey.parseRuntime(node.pubkey), addr);
    }

    var leader_by_slot = std.AutoArrayHashMapUnmanaged(u64, Pubkey).empty;
    defer leader_by_slot.deinit(arena);

    var it = rpc_leader_schedule.value.iterator();
    while (it.next()) |entry| {
        const leader = entry.key_ptr.*;
        for (entry.value_ptr.*) |slot_in_epoch| {
            try leader_by_slot.put(arena, epoch_start_slot + slot_in_epoch, leader);
        }
    }

    var selected = PubkeyMap(void){};
    defer selected.deinit(arena);

    var leaders: std.ArrayListUnmanaged(SocketAddr) = .empty;
    errdefer leaders.deinit(arena);

    const start = std.mem.min(u64, leader_by_slot.keys());
    const end = std.mem.max(u64, leader_by_slot.keys());
    const addresses = try arena.alloc(?SocketAddr, end - start + 1);
    var has_address_count: usize = 0;
    for (start..end + 1, 0..) |slot, i| {
        const leader = leader_by_slot.get(slot) orelse return error.MissingLeaderForSlot;
        addresses[i] = pubkey_to_tpu_quic.get(leader);
        if (addresses[i] != null) has_address_count += 1;
    }

    return .{ epoch_start_slot, addresses };
}
