const std = @import("std");
const sig = @import("sig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

const Packet = sig.net.Packet;
const SocketAddr = sig.net.SocketAddr;
const QuicClient = sig.net.QuicClient;

const RpcClient = sig.rpc.Client;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

const TransactionInfo = sig.TransactionSenderService.TransactionInfo;

const Instant = sig.time.Instant;
const Duration = sig.time.Duration;

const Logger = sig.trace.log.Logger("test_send_transactions");

const LEADER_WINDOW: u64 = 4;
const FORWARD_TO_LEADERS: usize = 5;
const DEFAULT_RPC_URL = "https://api.testnet.solana.com";

fn printUsage() void {
    std.debug.print(
        "Usage:\n" ++
            "  test-send-transactions <num_transactions> [--rpc-url <url>]\n\n" ++
            "Arguments:\n" ++
            "  <num_transactions>    Number of transactions to send (required)\n\n" ++
            "Options:\n" ++
            "  --rpc-url <url>       RPC URL to use (default: {s})\n\n" ++
            "Example:\n" ++
            "  test-send-transactions 10\n" ++
            "  test-send-transactions 10 --rpc-url https://api.testnet.solana.com\n",
        .{DEFAULT_RPC_URL},
    );
}

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
    defer if (gpa_state.deinit() == .leak) {
        logger.err().log("Memory leak detected");
    };
    const gpa = gpa_state.allocator();

    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    if (args.len < 2 or args.len == 3 or args.len > 4) {
        printUsage();
        return error.InvalidArgs;
    }

    const transfers = std.fmt.parseUnsigned(u64, args[1], 10) catch {
        std.debug.print("Error: invalid number of transactions '{s}'\n", .{args[1]});
        printUsage();
        return error.InvalidArgs;
    };

    var rpc_url: []const u8 = DEFAULT_RPC_URL;

    if (args.len == 4) {
        if (!std.mem.eql(u8, args[2], "--rpc-url")) {
            std.debug.print("Error: unexpected argument '{s}'\n", .{args[2]});
            printUsage();
            return error.InvalidArgs;
        }
        rpc_url = args[3];
    }

    if (std.mem.indexOf(u8, rpc_url, "mainnet") != null) {
        @panic("Refusing to run against mainnet. Use a testnet or devnet RPC URL instead.");
    }

    logger.info().logf("Starting test with {d} transactions, RPC URL: {s}", .{ transfers, rpc_url });

    var mock_sender_service = try MockSenderService.init(
        gpa,
        exit,
        .from(logger),
        rpc_url,
        .fromSecs(5), // Approx every 2 leaders
    );
    defer mock_sender_service.deinit();

    const mock_sender_handle = try std.Thread.spawn(
        .{},
        MockSenderService.run,
        .{ &mock_sender_service, gpa },
    );
    defer mock_sender_handle.join();

    var mock_transfer_service = sig.MockTransferService{
        .exit = exit,
        .logger = .from(logger),
        .mode = try .initRpc(gpa, rpc_url, .noop),
        .sender = mock_sender_service.receiver,
        .transfers = transfers,
    };
    defer mock_transfer_service.deinit();

    try mock_transfer_service.run(gpa);

    exit.setExit();
}

const MockSenderService = struct {
    exit: ExitCondition,
    logger: Logger,
    client: RpcClient,
    receiver: *Channel(TransactionInfo),
    send_interval: Duration,

    pub fn deinit(self: *MockSenderService) void {
        self.client.deinit();
        self.receiver.destroy();
    }

    pub fn init(
        gpa: Allocator,
        exit: ExitCondition,
        logger: Logger,
        rpc_url: []const u8,
        send_interval: Duration,
    ) !MockSenderService {
        const receiver = try Channel(TransactionInfo).create(gpa);
        receiver.name = "TransactionSenderService: TransactionInfo Receiver";
        errdefer receiver.destroy();

        var client = try RpcClient.init(
            gpa,
            rpc_url,
            .{ .max_retries = 3, .logger = .noop },
        );
        errdefer client.deinit();

        return .{
            .exit = exit,
            .logger = logger,
            .client = client,
            .receiver = receiver,
            .send_interval = send_interval,
        };
    }

    pub fn run(self: *MockSenderService, gpa: Allocator) !void {
        const quic_client = try QuicClient.create(
            gpa,
            .from(self.logger),
            self.exit,
            .{ .log_metrics_interval = .fromSecs(1) },
        );
        defer quic_client.destroy();

        const quic_handle = try std.Thread.spawn(.{}, QuicClient.run, .{quic_client});
        defer quic_handle.join();

        try self.handleTransactions(gpa, quic_client.receiver);
    }

    fn handleTransactions(
        self: *MockSenderService,
        gpa: Allocator,
        quic_sender: *Channel(Packet),
    ) !void {
        const epoch_start_slot, const epoch_leaders = try resolveLeadersFromRpc(
            gpa,
            &self.client,
        );
        defer gpa.free(epoch_leaders);

        var last_sent_time = Instant.EPOCH_ZERO;
        var txn_info = try self.receiver.receive(self.exit);

        while (self.exit.shouldRun()) {
            if (self.receiver.tryReceive()) |new_info| {
                self.logger.info().logf("Received TransactionInfo: signature={f}", .{
                    new_info.signature,
                });
                txn_info = new_info;
                last_sent_time = Instant.EPOCH_ZERO;
            }

            if (last_sent_time.elapsed().gt(self.send_interval)) {
                self.logger.info().logf("Sending Transaction: signature={f}", .{
                    txn_info.signature,
                });
                try self.sendToLeaders(quic_sender, &txn_info, epoch_start_slot, epoch_leaders);
                last_sent_time = Instant.now();
            }

            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    fn sendToLeaders(
        self: *MockSenderService,
        quic_sender: *Channel(Packet),
        txn_info: *TransactionInfo,
        epoch_start_slot: u64,
        epoch_leaders: []?SocketAddr,
    ) !void {
        var slot_response = try self.client.getSlot(.{ .config = .{ .commitment = .processed } });
        defer slot_response.deinit();
        const slot = try slot_response.result();

        const leader_idx = slot - epoch_start_slot;
        for (0..FORWARD_TO_LEADERS) |leader_i| {
            const idx = leader_idx + leader_i * LEADER_WINDOW;
            if (idx >= epoch_leaders.len) return error.EndOfEpoch;
            if (epoch_leaders[idx]) |leader| {
                try quic_sender.send(Packet.init(
                    leader,
                    txn_info.wire_transaction,
                    txn_info.wire_transaction_size,
                ));
            }
        }
    }
};

fn resolveLeadersFromRpc(gpa: Allocator, client: *RpcClient) !struct { u64, []?SocketAddr } {
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
    var rpc_leader_schedule = try schedule_response.result() orelse
        return error.MissingLeaderSchedule;

    var cluster_nodes_response = try client.getClusterNodes(.{});
    defer cluster_nodes_response.deinit();
    const cluster_nodes = try cluster_nodes_response.result();

    var pubkey_to_tpu_quic = std.AutoArrayHashMapUnmanaged(Pubkey, SocketAddr).empty;
    defer pubkey_to_tpu_quic.deinit(gpa);

    for (cluster_nodes) |node| {
        const tpu_quic = node.tpuQuic orelse continue;

        const addr = SocketAddr.parse(tpu_quic) catch blk: {
            const gossip = node.gossip orelse continue;
            const port = std.fmt.parseUnsigned(u16, tpu_quic, 10) catch continue;

            var gossip_addr = SocketAddr.parse(gossip) catch continue;
            gossip_addr.setPort(port);
            break :blk gossip_addr;
        };

        try pubkey_to_tpu_quic.put(gpa, try Pubkey.parseRuntime(node.pubkey), addr);
    }

    var leader_by_slot = std.AutoArrayHashMapUnmanaged(u64, Pubkey).empty;
    defer leader_by_slot.deinit(gpa);

    var it = rpc_leader_schedule.value.iterator();
    while (it.next()) |entry| {
        const leader = entry.key_ptr.*;
        for (entry.value_ptr.*) |slot_in_epoch| {
            try leader_by_slot.put(gpa, epoch_start_slot + slot_in_epoch, leader);
        }
    }

    const start = std.mem.min(u64, leader_by_slot.keys());
    const end = std.mem.max(u64, leader_by_slot.keys());
    const addresses = try gpa.alloc(?SocketAddr, end - start + 1);
    errdefer gpa.free(addresses);
    var has_address_count: usize = 0;
    for (start..end + 1, 0..) |slot, i| {
        const leader = leader_by_slot.get(slot) orelse return error.MissingLeaderForSlot;
        addresses[i] = pubkey_to_tpu_quic.get(leader);
        if (addresses[i] != null) has_address_count += 1;
    }

    return .{ epoch_start_slot, addresses };
}
