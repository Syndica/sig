const std = @import("std");
const sig = @import("sig");

const KeyPair = sig.identity.KeyPair;

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Hash = sig.core.Hash;
const Transaction = sig.core.Transaction;
const TransactionMessage = sig.core.transaction.Message;
const TransactionInstruction = sig.core.transaction.Instruction;

const Packet = sig.net.Packet;
const SocketAddr = sig.net.SocketAddr;
const QuicClientLogger = sig.net.quic_client.Logger;
const runQuicClient = sig.net.quic_client.runClient;

const RpcClient = sig.rpc.Client;

const SYSTEM_PROGRAM_ID = sig.runtime.program.system.ID;

const Channel = sig.sync.Channel;
const ExitCondition = sig.sync.ExitCondition;

const PubkeyMap = sig.utils.collections.PubkeyMap;

const Logger = sig.trace.log.Logger("test_send_transactions");

const DEFAULT_RPC_URL = "https://api.testnet.solana.com";
const LEADER_WINDOW: u64 = 4;
const FORWARD_TO_LEADERS: usize = 5;

const TRANSFER_AMOUNT: u64 = 1e6;
const TRANSFER_FEE: u64 = 5000;
const TRANSFER_COST: u64 = TRANSFER_AMOUNT + TRANSFER_FEE;

const MockAccount = struct {
    keypair: KeyPair,
    pubkey: Pubkey,
    balance: u64,

    fn init(keypair: KeyPair) MockAccount {
        return .{
            .keypair = keypair,
            .pubkey = Pubkey.fromPublicKey(&keypair.public_key),
            .balance = 0,
        };
    }
};

const MockAccounts = struct {
    alice: MockAccount,
    bob: MockAccount,

    const DEFAULT: MockAccounts = .{
        // H67JSziFxAZR1KSQshWfa8Rdpr7LSv1VkT2cFQHL79rd
        .bob = MockAccount.init(.{
            .public_key = .{ .bytes = .{
                239, 10,  4,   236, 219, 237, 69,  197, 199, 60, 117, 184, 223, 215, 132, 73,
                93,  248, 200, 254, 212, 239, 251, 120, 223, 25, 201, 196, 20,  58,  163, 62,
            } },
            .secret_key = .{ .bytes = .{
                208, 26,  255, 64,  164, 52,  99,  120, 92,  227, 25,  240, 222, 245, 70,  77,
                171, 89,  129, 64,  110, 73,  159, 230, 38,  212, 150, 202, 57,  157, 151, 175,
                239, 10,  4,   236, 219, 237, 69,  197, 199, 60,  117, 184, 223, 215, 132, 73,
                93,  248, 200, 254, 212, 239, 251, 120, 223, 25,  201, 196, 20,  58,  163, 62,
            } },
        }),
        // ErnDW7vq2XmzstretUJ7NhT95PV6zeXeyXwLssowF6i
        .alice = MockAccount.init(.{
            .public_key = .{ .bytes = .{
                3,  140, 214, 34, 176, 145, 149, 13,  169, 145, 117, 3, 98, 140, 206, 183,
                20, 52,  35,  97, 89,  82,  55,  162, 13,  26,  172, 9, 77, 242, 217, 211,
            } },
            .secret_key = .{ .bytes = .{
                28, 57,  92,  177, 192, 198, 0,   137, 66,  122, 128, 0,   112, 193, 184, 209,
                72, 187, 109, 65,  115, 173, 181, 139, 194, 185, 253, 182, 173, 110, 184, 124,
                3,  140, 214, 34,  176, 145, 149, 13,  169, 145, 117, 3,   98,  140, 206, 183,
                20, 52,  35,  97,  89,  82,  55,  162, 13,  26,  172, 9,   77,  242, 217, 211,
            } },
        }),
    };
};

fn usage() void {
    std.debug.print(
        "Usage:\n" ++
            "  quic-repro [rpc_url]\n\n" ++
            "Example:\n" ++
            "  quic-repro\n" ++
            "  quic-repro https://api.testnet.solana.com\n",
        .{},
    );
}

fn getBalanceLamports(rpc_client: *RpcClient, pubkey: Pubkey) !u64 {
    var response = try rpc_client.getBalance(
        .{ .pubkey = pubkey, .config = .{ .commitment = .processed } },
    );
    defer response.deinit();
    const result = try response.result();
    return result.value;
}

fn getLatestBlockhash(rpc_client: *RpcClient) !Hash {
    var response = try rpc_client.getLatestBlockhash(
        .{ .config = .{ .commitment = .processed } },
    );
    defer response.deinit();
    const result = try response.result();
    return try Hash.parseRuntime(result.value.blockhash);
}

const SignatureState = enum {
    pending,
    succeeded,
    failed,
};

fn getSignatureState(rpc_client: *RpcClient, signature: Signature) !SignatureState {
    var response = try rpc_client.getSignatureStatuses(.{
        .signatures = &.{signature},
        .config = .{ .searchTransactionHistory = true },
    });
    defer response.deinit();
    const result = try response.result();
    if (result.value.len == 0) return .pending;

    const maybe_status = result.value[0] orelse return .pending;
    if (maybe_status.err != null) return .failed;
    return .succeeded;
}

fn resolveLeadersFromRpc(
    arena: std.mem.Allocator,
    rpc_client: *RpcClient,
) !struct { u64, []?SocketAddr } {
    var slot_response = try rpc_client.getSlot(.{
        .config = .{ .commitment = .processed },
    });
    defer slot_response.deinit();
    const current_slot = try slot_response.result();

    var epoch_info_response = try rpc_client.getEpochInfo(
        .{ .config = .{ .commitment = .processed } },
    );
    defer epoch_info_response.deinit();
    const epoch_info = try epoch_info_response.result();
    const epoch_start_slot = current_slot - epoch_info.slotIndex;

    var schedule_response = try rpc_client.getLeaderSchedule(.{ .slot = current_slot });
    defer schedule_response.deinit();
    var rpc_leader_schedule = try schedule_response.result();

    var cluster_nodes_response = try rpc_client.getClusterNodes(.{});
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

fn buildTransferTransaction(
    gpa: std.mem.Allocator,
    from_keypair: KeyPair,
    to_pubkey: Pubkey,
    lamports: u64,
    recent_blockhash: Hash,
) !Transaction {
    const from_pubkey = Pubkey.fromPublicKey(&from_keypair.public_key);

    const account_keys = try gpa.dupe(Pubkey, &.{
        from_pubkey,
        to_pubkey,
        SYSTEM_PROGRAM_ID,
    });
    errdefer gpa.free(account_keys);

    const account_indexes = try gpa.dupe(u8, &.{ 0, 1 });
    errdefer gpa.free(account_indexes);

    var transfer_data = [_]u8{0} ** 12;
    var fbs = std.io.fixedBufferStream(&transfer_data);
    const writer = fbs.writer();
    try writer.writeInt(u32, 2, .little);
    try writer.writeInt(u64, lamports, .little);

    const instruction_data = try gpa.dupe(u8, &transfer_data);
    errdefer gpa.free(instruction_data);

    const instructions = try gpa.alloc(TransactionInstruction, 1);
    errdefer gpa.free(instructions);
    instructions[0] = .{
        .program_index = 2,
        .account_indexes = account_indexes,
        .data = instruction_data,
    };

    const msg: TransactionMessage = .{
        .signature_count = 1,
        .readonly_signed_count = 0,
        .readonly_unsigned_count = 1,
        .account_keys = account_keys,
        .recent_blockhash = recent_blockhash,
        .instructions = instructions,
    };

    return try Transaction.initOwnedMessageWithSigningKeypairs(
        gpa,
        .legacy,
        msg,
        &.{from_keypair},
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
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var arena_allocator = std.heap.ArenaAllocator.init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    const args = try std.process.argsAlloc(arena);
    defer std.process.argsFree(arena, args);

    if (args.len > 2) {
        usage();
        return error.InvalidArgs;
    }

    const rpc_url = if (args.len == 2) args[1] else DEFAULT_RPC_URL;
    var rpc_client = try sig.rpc.Client.init(arena, rpc_url, .{ .max_retries = 2, .logger = .noop });
    defer rpc_client.deinit();

    const epoch_start_slot, const leaders = try resolveLeadersFromRpc(arena, &rpc_client);
    defer arena.free(leaders);

    const channel = try Channel(Packet).create(arena);
    defer channel.destroy();

    const client_thread = try std.Thread.spawn(
        .{},
        runQuicClient,
        .{ arena, channel, QuicClientLogger.from(logger), exit },
    );
    defer client_thread.join();

    var accounts = MockAccounts.DEFAULT;
    accounts.alice.balance = try getBalanceLamports(&rpc_client, accounts.alice.pubkey);
    accounts.bob.balance = try getBalanceLamports(&rpc_client, accounts.bob.pubkey);

    var from_account, var to_account = if (accounts.alice.balance > accounts.bob.balance)
        .{ &accounts.alice, &accounts.bob }
    else
        .{ &accounts.bob, &accounts.alice };

    var successful_transactions: usize = 0;

    while (exit.shouldRun() and successful_transactions < 10) {
        if (from_account.balance < TRANSFER_COST and to_account.balance < TRANSFER_COST) {
            logger.err().logf(
                "both accounts have insufficient balance (alice={d} bob={d}), exiting",
                .{ accounts.alice.balance, accounts.bob.balance },
            );
            return error.InsufficientBalance;
        } else if (from_account.balance < TRANSFER_COST) {
            logger.info().logf(
                "from_account has insufficient balance (balance={d}), switching accounts",
                .{from_account.balance},
            );
            const temp = from_account;
            from_account = to_account;
            to_account = temp;
        }

        logger.info().logf(
            "Attempting transfer ({}/{} succesful transactions)",
            .{ successful_transactions + 1, 10 },
        );
        const start_slot = blk: {
            var slot_response = try rpc_client.getSlot(
                .{ .config = .{ .commitment = .processed } },
            );
            defer slot_response.deinit();
            break :blk try slot_response.result();
        };
        var current_slot = start_slot;

        const blockhash = try getLatestBlockhash(&rpc_client);
        var tx = try buildTransferTransaction(
            arena,
            from_account.keypair,
            to_account.pubkey,
            TRANSFER_AMOUNT,
            blockhash,
        );
        defer tx.deinit(arena);

        var tx_wire: [Packet.DATA_SIZE]u8 = @splat(0);
        const tx_len = (try bincode.writeToSlice(&tx_wire, tx, .{})).len;
        if (tx_len == 0 or tx_len > Packet.DATA_SIZE) return error.InvalidTransactionSize;

        const signature = tx.signatures[0];
        var landed = false;

        while (exit.shouldRun() and current_slot < start_slot + 150 and !landed) {
            const last_send_slot = current_slot;
            const leader_start_index = current_slot - epoch_start_slot;
            for (0..FORWARD_TO_LEADERS) |leader_num| {
                const leader_idx = leader_start_index + leader_num * LEADER_WINDOW;
                if (leader_idx >= leaders.len) return error.EndOfEpoch;
                if (leaders[leader_idx]) |leader| {
                    logger.info().logf(
                        "sending tx={f} slot={d} leader_num={}",
                        .{ signature, current_slot, leader_num },
                    );
                    try channel.send(Packet.init(leader, tx_wire, tx_len));
                } else {
                    logger.info().logf(
                        "sending tx={f} slot={d} leader_num={} (no address)",
                        .{ signature, current_slot, leader_num },
                    );
                }
            }

            while (exit.shouldRun() and
                current_slot < last_send_slot + FORWARD_TO_LEADERS * LEADER_WINDOW)
            {
                switch (try getSignatureState(&rpc_client, signature)) {
                    .succeeded => {
                        logger.info().logf(
                            "succeeded tx={f} slot={d}",
                            .{ signature, current_slot },
                        );
                        successful_transactions += 1;
                        landed = true;
                        break;
                    },
                    .failed => {
                        logger.err().logf(
                            "failed tx={f} slot={d}",
                            .{ signature, current_slot },
                        );
                        landed = true;
                        break;
                    },
                    .pending => {
                        logger.info().logf(
                            "pending tx={f} slot={d}",
                            .{ signature, current_slot },
                        );
                        std.Thread.sleep(std.time.ns_per_s);
                    },
                }

                current_slot = blk: {
                    var slot_response = try rpc_client.getSlot(
                        .{ .config = .{ .commitment = .processed } },
                    );
                    defer slot_response.deinit();
                    break :blk try slot_response.result();
                };
            }

            if (landed) {
                accounts.alice.balance = try getBalanceLamports(&rpc_client, accounts.alice.pubkey);
                accounts.bob.balance = try getBalanceLamports(&rpc_client, accounts.bob.pubkey);
                logger.info().logf(
                    "current balances: alice={d} bob={d}",
                    .{ accounts.alice.balance, accounts.bob.balance },
                );
                break;
            } else logger.info().log("pending for too long, retry...");
        }
    }

    logger.info().logf("done (successful transactions: {})", .{successful_transactions});
    exit.setExit();
}
