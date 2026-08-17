const std = @import("std");
const sig = @import("sig");

const Allocator = std.mem.Allocator;
const Entry = sig.core.Entry;
const GenesisConfig = sig.core.GenesisConfig;
const Hash = sig.core.Hash;
const Ledger = sig.ledger.Ledger;
const Shred = sig.ledger.shred.Shred;
const Slot = sig.core.Slot;
const SlotMeta = sig.ledger.meta.SlotMeta;
const Transaction = sig.core.Transaction;

const schema = sig.ledger.schema.schema;
const DATA_SHRED_CAPACITY = sig.ledger.shred.DataShred.constants.payload_size -
    sig.ledger.shred.DataShred.constants.headers_size;
const DATA_SHREDS_PER_FEC_SET: u32 = 32;
const MERKLE_PROOF_ENTRY_SIZE: usize = 20;
const MAX_RPC_ATTEMPTS = 6;
const RPC_SKIPPED_SLOT_CODE: i64 = -32007;
const RPC_LONG_TERM_STORAGE_SKIPPED_SLOT_CODE: i64 = -32009;

const Args = struct {
    write: bool,
    udp_target: ?[]const u8,
    shred_version: ?u16,
    hashes_per_tick_override: ?u64,
    ledger_path: []const u8,
    rpc_url: []const u8,
    genesis_path: []const u8,
    root_slot: Slot,
    end_slot: Slot,
};

const RpcEncodedTransaction = struct {
    transaction: struct { []const u8, []const u8 },
};

const RpcBlock = struct {
    previousBlockhash: Hash,
    blockhash: Hash,
    parentSlot: Slot,
    transactions: ?[]const RpcEncodedTransaction = null,
    blockTime: ?i64 = null,
    blockHeight: ?u64 = null,
};

const RpcError = struct {
    code: i64,
    message: []const u8,
};

const RpcEnvelope = struct {
    result: ?RpcBlock = null,
    @"error": ?RpcError = null,
};

const BlockResponse = struct {
    arena: *std.heap.ArenaAllocator,
    block: RpcBlock,

    fn deinit(self: BlockResponse) void {
        const allocator = self.arena.child_allocator;
        self.arena.deinit();
        allocator.destroy(self.arena);
    }
};

pub fn main() !void {
    var gpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const raw_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, raw_args);

    if (raw_args.len == 2 and
        (std.mem.eql(u8, raw_args[1], "--help") or std.mem.eql(u8, raw_args[1], "-h")))
    {
        printUsage();
        return;
    }

    const args = parseArgs(raw_args) catch |err| {
        printUsage();
        std.debug.print("error: {s}\n", .{@errorName(err)});
        return err;
    };

    if (args.write) try requireIsolatedClonePath(args.ledger_path);

    var genesis = try GenesisConfig.init(allocator, args.genesis_path);
    defer genesis.deinit(allocator);
    const genesis_hashes_per_tick = genesis.poh_config.hashes_per_tick orelse
        return error.HashesPerTickDisabled;
    const hashes_per_tick = args.hashes_per_tick_override orelse genesis_hashes_per_tick;
    if (hashes_per_tick == 0) return error.HashesPerTickDisabled;
    if (genesis.ticks_per_slot == 0) return error.TicksPerSlotDisabled;
    if (args.write and args.hashes_per_tick_override == null) {
        std.debug.print(
            "refusing_write=true reason=missing_effective_hashes_per_tick genesis_hashes_per_tick={}\n",
            .{genesis_hashes_per_tick},
        );
        return error.WriteRequiresHashesPerTick;
    }
    if (args.udp_target != null and args.hashes_per_tick_override == null) {
        std.debug.print(
            "refusing_udp=true reason=missing_effective_hashes_per_tick genesis_hashes_per_tick={}\n",
            .{genesis_hashes_per_tick},
        );
        return error.UdpRequiresHashesPerTick;
    }

    std.debug.print(
        "mode={s} ledger_path={s} root_slot={} end_slot={} ticks_per_slot={} genesis_hashes_per_tick={} hashes_per_tick={} hashes_per_tick_source={s}\n",
        .{
            if (args.write) "write" else if (args.udp_target != null) "udp" else "dry-run",
            args.ledger_path,
            args.root_slot,
            args.end_slot,
            genesis.ticks_per_slot,
            genesis_hashes_per_tick,
            hashes_per_tick,
            if (args.hashes_per_tick_override != null) "override" else "genesis",
        },
    );
    std.debug.print(
        "bridge_kind=synthetic_entry_framing official_rpc_transactions=true authentic_shreds=false runtime_verifier_bypass=false\n",
        .{},
    );

    var rpc_client = try sig.rpc.Client.init(allocator, args.rpc_url, .{
        .max_retries = 3,
    });
    defer rpc_client.deinit();

    var root_response = try fetchBlock(&rpc_client, args.root_slot, false);
    defer root_response.deinit();
    const root_block = root_response.block;
    std.debug.print("root_slot={} root_blockhash={f}\n", .{ args.root_slot, root_block.blockhash });

    if (!args.write and args.udp_target == null) {
        var slot = args.root_slot + 1;
        while (slot <= args.end_slot) : (slot += 1) {
            processDryRunSlot(
                allocator,
                &rpc_client,
                genesis.ticks_per_slot,
                hashes_per_tick,
                slot,
                args.root_slot,
                root_block.blockhash,
            ) catch |err| switch (err) {
                error.SkippedSlot => {
                    std.debug.print("slot={} dry_run=skipped rpc_status=skipped\n", .{slot});
                    continue;
                },
                else => return err,
            };
            std.debug.print(
                "dry_run=pass ledger_opened=false ledger_mutated=false probed_slot={} requested_end_slot={}\n",
                .{ slot, args.end_slot },
            );
            return;
        }
        return error.NoProducedSlots;
    }

    if (args.udp_target) |target_text| {
        const target = try sig.net.SocketAddr.parse(target_text);
        var socket = try sig.net.UdpSocket.create(switch (target) {
            .V4 => .ipv4,
            .V6 => .ipv6,
        });
        defer socket.close();

        var previous_slot = args.root_slot;
        var previous_hash = root_block.blockhash;
        var slot = args.root_slot + 1;
        var sent_slots: usize = 0;
        var skipped_slots: usize = 0;
        var total_transactions: usize = 0;
        var total_shreds: usize = 0;
        var total_bytes: usize = 0;
        var first_sent_slot: ?Slot = null;
        while (slot <= args.end_slot) : (slot += 1) {
            const stats = fetchBuildAndSendSlot(
                allocator,
                &rpc_client,
                genesis.ticks_per_slot,
                hashes_per_tick,
                &socket,
                target.toAddress(),
                args.shred_version orelse return error.UdpRequiresShredVersion,
                slot,
                previous_slot,
                previous_hash,
            ) catch |err| switch (err) {
                error.SkippedSlot => {
                    skipped_slots += 1;
                    std.debug.print(
                        "slot={} udp=skipped rpc_status=skipped previous_produced_slot={}\n",
                        .{ slot, previous_slot },
                    );
                    continue;
                },
                else => return err,
            };
            if (first_sent_slot == null) first_sent_slot = slot;
            previous_slot = slot;
            previous_hash = stats.blockhash;
            sent_slots += 1;
            total_transactions += stats.transaction_count;
            total_shreds += stats.shred_count;
            total_bytes += stats.sent_bytes;
        }

        std.debug.print(
            "bridge_udp=pass target={s} shred_version={} slots={} skipped_slots={} transactions={} data_shreds={} bytes={} first_slot={} last_slot={} requested_end_slot={} final_blockhash={f}\n",
            .{
                target_text,
                args.shred_version.?,
                sent_slots,
                skipped_slots,
                total_transactions,
                total_shreds,
                total_bytes,
                first_sent_slot orelse return error.NoProducedSlots,
                previous_slot,
                args.end_slot,
                previous_hash,
            },
        );
        return;
    }

    var ledger = try Ledger.init(
        allocator,
        sig.trace.Logger("ledger").noop,
        args.ledger_path,
        null,
    );
    defer ledger.deinit();

    const did_purge = try sig.ledger.cleanup_service.purgeSlots(
        &ledger.db,
        args.root_slot + 1,
        args.end_slot,
    );
    try installRootStub(allocator, &ledger, args.root_slot);
    std.debug.print(
        "ledger_prepare=pass purged_existing_bridge_range={} root_stub_installed=true\n",
        .{did_purge},
    );

    var previous_slot = args.root_slot;
    var previous_hash = root_block.blockhash;
    var slot = args.root_slot + 1;
    var written_slots: usize = 0;
    var skipped_slots: usize = 0;
    var total_transactions: usize = 0;
    var total_shreds: usize = 0;
    var first_written_slot: ?Slot = null;
    while (slot <= args.end_slot) : (slot += 1) {
        const stats = fetchBuildAndInsertSlot(
            allocator,
            &rpc_client,
            genesis.ticks_per_slot,
            hashes_per_tick,
            &ledger,
            slot,
            previous_slot,
            previous_hash,
        ) catch |err| switch (err) {
            error.SkippedSlot => {
                skipped_slots += 1;
                std.debug.print(
                    "slot={} insert=skipped rpc_status=skipped previous_produced_slot={}\n",
                    .{ slot, previous_slot },
                );
                continue;
            },
            else => return err,
        };
        if (first_written_slot == null) first_written_slot = slot;
        previous_slot = slot;
        previous_hash = stats.blockhash;
        written_slots += 1;
        total_transactions += stats.transaction_count;
        total_shreds += stats.shred_count;
    }

    std.debug.print(
        "bridge_write=pass slots={} skipped_slots={} transactions={} data_shreds={} first_slot={} last_slot={} requested_end_slot={} final_blockhash={f}\n",
        .{
            written_slots,
            skipped_slots,
            total_transactions,
            total_shreds,
            first_written_slot orelse return error.NoProducedSlots,
            previous_slot,
            args.end_slot,
            previous_hash,
        },
    );
}

fn printUsage() void {
    std.debug.print(
        "usage: rpc-ledger-bridge [--write | --udp-target <ip:port> --shred-version <version>] [--hashes-per-tick <count>] <ledger-path> <rpc-url> <genesis-path> <root-slot> <end-slot>\n" ++
            "  default: fetch and validate root+first slot without opening the ledger\n" ++
            "  --write: purge and replace root+1..end in an isolated clone path containing 'rpc-bridge'\n" ++
            "  --udp-target: send canonical RPC transactions in synthetic data shreds to a live Sig UDP receiver\n" ++
            "  --shred-version: required with --udp-target and must match the live cluster\n" ++
            "  --hashes-per-tick: effective runtime-bank value; required with --write or --udp-target\n",
        .{},
    );
}

fn parseArgs(raw_args: []const []const u8) !Args {
    var write = false;
    var udp_target: ?[]const u8 = null;
    var shred_version: ?u16 = null;
    var hashes_per_tick_override: ?u64 = null;
    var positional: [5][]const u8 = undefined;
    var positional_count: usize = 0;

    var arg_index: usize = 1;
    while (arg_index < raw_args.len) {
        const arg = raw_args[arg_index];
        if (std.mem.eql(u8, arg, "--write")) {
            if (write) return error.DuplicateWriteFlag;
            if (udp_target != null) return error.ConflictingOutputModes;
            write = true;
            arg_index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--udp-target")) {
            if (udp_target != null) return error.DuplicateUdpTarget;
            if (write) return error.ConflictingOutputModes;
            arg_index += 1;
            if (arg_index >= raw_args.len) return error.MissingUdpTarget;
            udp_target = raw_args[arg_index];
            arg_index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--shred-version")) {
            if (shred_version != null) return error.DuplicateShredVersion;
            arg_index += 1;
            if (arg_index >= raw_args.len) return error.MissingShredVersion;
            shred_version = try std.fmt.parseUnsigned(u16, raw_args[arg_index], 10);
            arg_index += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--hashes-per-tick")) {
            if (hashes_per_tick_override != null)
                return error.DuplicateHashesPerTick;
            arg_index += 1;
            if (arg_index >= raw_args.len)
                return error.MissingHashesPerTick;
            const value = try std.fmt.parseUnsigned(u64, raw_args[arg_index], 10);
            if (value == 0) return error.HashesPerTickDisabled;
            hashes_per_tick_override = value;
            arg_index += 1;
            continue;
        }
        if (std.mem.startsWith(u8, arg, "--")) return error.UnknownArgument;
        if (positional_count == positional.len) return error.TooManyArguments;
        positional[positional_count] = arg;
        positional_count += 1;
        arg_index += 1;
    }
    if (positional_count != positional.len) return error.MissingArgument;

    const root_slot = try std.fmt.parseUnsigned(Slot, positional[3], 10);
    const end_slot = try std.fmt.parseUnsigned(Slot, positional[4], 10);
    if (root_slot == std.math.maxInt(Slot)) return error.RootSlotOverflow;
    if (end_slot < root_slot + 1) return error.EmptyBridgeRange;
    if (udp_target != null and shred_version == null) return error.UdpRequiresShredVersion;
    if (udp_target == null and shred_version != null) return error.ShredVersionRequiresUdp;

    return .{
        .write = write,
        .udp_target = udp_target,
        .shred_version = shred_version,
        .hashes_per_tick_override = hashes_per_tick_override,
        .ledger_path = positional[0],
        .rpc_url = positional[1],
        .genesis_path = positional[2],
        .root_slot = root_slot,
        .end_slot = end_slot,
    };
}

fn requireIsolatedClonePath(ledger_path: []const u8) !void {
    if (std.mem.indexOf(u8, ledger_path, "rpc-bridge") == null) {
        std.debug.print(
            "refusing_write=true reason=ledger_path_missing_rpc_bridge ledger_path={s}\n",
            .{ledger_path},
        );
        return error.UnsafeLedgerPath;
    }
}

fn fetchBlock(
    client: *sig.rpc.Client,
    slot: Slot,
    include_transactions: bool,
) !BlockResponse {
    const allocator = client.fetcher.http_client.allocator;
    var attempt: usize = 1;
    while (attempt <= MAX_RPC_ATTEMPTS) : (attempt += 1) {
        const request = sig.rpc.Request{
            .id = .{ .int = 1 },
            .method = .{ .getBlock = .{
                .slot = slot,
                .encoding_or_config = .{ .config = .{
                    .commitment = .finalized,
                    .encoding = .base64,
                    .transactionDetails = if (include_transactions) .full else .none,
                    .maxSupportedTransactionVersion = 0,
                    .rewards = false,
                } },
            } },
        };
        var request_writer = std.io.Writer.Allocating.init(allocator);
        defer request_writer.deinit();
        try std.json.fmt(request, .{}).format(&request_writer.writer);

        const response_json = client.fetcher.fetchWithRetries(
            allocator,
            request_writer.written(),
        ) catch |err| {
            std.debug.print(
                "rpc_fetch_retry slot={} attempt={}/{} transport_error={s}\n",
                .{ slot, attempt, MAX_RPC_ATTEMPTS, @errorName(err) },
            );
            if (attempt == MAX_RPC_ATTEMPTS) return err;
            std.Thread.sleep(@as(u64, @intCast(@min(attempt, 5))) * std.time.ns_per_s);
            continue;
        };
        defer allocator.free(response_json);

        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const envelope = std.json.parseFromSliceLeaky(
            RpcEnvelope,
            arena.allocator(),
            response_json,
            .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            },
        ) catch |err| {
            std.debug.print(
                "rpc_fetch_retry slot={} attempt={}/{} minimal_parse_error={s} response_bytes={}\n",
                .{ slot, attempt, MAX_RPC_ATTEMPTS, @errorName(err), response_json.len },
            );
            arena.deinit();
            allocator.destroy(arena);
            if (attempt == MAX_RPC_ATTEMPTS) return err;
            std.Thread.sleep(@as(u64, @intCast(@min(attempt, 5))) * std.time.ns_per_s);
            continue;
        };
        if (envelope.result) |block| return .{ .arena = arena, .block = block };

        if (envelope.@"error") |rpc_error| {
            if (isSkippedSlotRpcCode(rpc_error.code)) {
                std.debug.print(
                    "rpc_fetch_skipped slot={} rpc_code={} message={s}\n",
                    .{ slot, rpc_error.code, rpc_error.message },
                );
                arena.deinit();
                allocator.destroy(arena);
                return error.SkippedSlot;
            }
            std.debug.print(
                "rpc_fetch_retry slot={} attempt={}/{} rpc_code={} message={s}\n",
                .{ slot, attempt, MAX_RPC_ATTEMPTS, rpc_error.code, rpc_error.message },
            );
        } else {
            std.debug.print(
                "rpc_fetch_retry slot={} attempt={}/{} missing_result=true\n",
                .{ slot, attempt, MAX_RPC_ATTEMPTS },
            );
        }
        arena.deinit();
        allocator.destroy(arena);
        if (attempt == MAX_RPC_ATTEMPTS) return error.RpcRequestFailed;
        std.Thread.sleep(@as(u64, @intCast(@min(attempt, 5))) * std.time.ns_per_s);
    }
    unreachable;
}

fn isSkippedSlotRpcCode(code: i64) bool {
    return code == RPC_SKIPPED_SLOT_CODE or
        code == RPC_LONG_TERM_STORAGE_SKIPPED_SLOT_CODE;
}

fn processDryRunSlot(
    allocator: Allocator,
    rpc_client: *sig.rpc.Client,
    ticks_per_slot: u64,
    hashes_per_tick: u64,
    slot: Slot,
    expected_parent_slot: Slot,
    expected_previous_hash: Hash,
) !void {
    var response = try fetchBlock(rpc_client, slot, true);
    defer response.deinit();
    const block = response.block;
    try validateBlockChain(slot, block, expected_parent_slot, expected_previous_hash);

    const transactions = try decodeTransactions(
        allocator,
        block.transactions orelse return error.MissingTransactions,
    );
    defer deinitTransactions(allocator, transactions);

    const expected_ticks = try expectedTicksForProducedSlot(
        ticks_per_slot,
        slot,
        expected_parent_slot,
    );
    const entries = try buildSyntheticEntries(
        allocator,
        expected_ticks,
        hashes_per_tick,
        expected_previous_hash,
        block.blockhash,
        transactions,
    );
    defer allocator.free(entries);

    const serialized_entries = try sig.bincode.writeAlloc(allocator, entries, .{});
    defer allocator.free(serialized_entries);
    const shreds = try buildDataShreds(
        allocator,
        slot,
        expected_parent_slot,
        0,
        0,
        DATA_SHREDS_PER_FEC_SET,
        serialized_entries,
    );
    defer deinitShreds(allocator, shreds);

    std.debug.print(
        "slot={} dry_run=pass parent={} slot_span={} transactions={} entries={} ticks={} serialized_entry_bytes={} data_shreds={} previous_blockhash={f} blockhash={f}\n",
        .{
            slot,
            block.parentSlot,
            slot - block.parentSlot,
            transactions.len,
            entries.len,
            sig.core.entry.tickCount(entries),
            serialized_entries.len,
            shreds.len,
            block.previousBlockhash,
            block.blockhash,
        },
    );
}

const InsertStats = struct {
    blockhash: Hash,
    transaction_count: usize,
    shred_count: usize,
    sent_bytes: usize = 0,
};

fn fetchBuildAndSendSlot(
    allocator: Allocator,
    rpc_client: *sig.rpc.Client,
    ticks_per_slot: u64,
    hashes_per_tick: u64,
    socket: *const sig.net.UdpSocket,
    target: std.net.Address,
    shred_version: u16,
    slot: Slot,
    expected_parent_slot: Slot,
    expected_previous_hash: Hash,
) !InsertStats {
    var timer = try std.time.Timer.start();
    var response = try fetchBlock(rpc_client, slot, true);
    defer response.deinit();
    const fetch_ms = timer.read() / std.time.ns_per_ms;
    const block = response.block;
    try validateBlockChain(slot, block, expected_parent_slot, expected_previous_hash);

    const transactions = try decodeTransactions(
        allocator,
        block.transactions orelse return error.MissingTransactions,
    );
    defer deinitTransactions(allocator, transactions);

    const expected_ticks = try expectedTicksForProducedSlot(
        ticks_per_slot,
        slot,
        expected_parent_slot,
    );
    const entries = try buildSyntheticEntries(
        allocator,
        expected_ticks,
        hashes_per_tick,
        expected_previous_hash,
        block.blockhash,
        transactions,
    );
    defer allocator.free(entries);

    const serialized_entries = try sig.bincode.writeAlloc(allocator, entries, .{});
    defer allocator.free(serialized_entries);
    const shreds = try buildDataShreds(
        allocator,
        slot,
        expected_parent_slot,
        shred_version,
        0,
        1,
        serialized_entries,
    );
    defer deinitShreds(allocator, shreds);

    var sent_bytes: usize = 0;
    for (shreds, 0..) |shred, i| {
        const payload = shred.payload();
        _ = sig.ledger.shred.layout.merkleRoot(payload) orelse
            return error.MissingUdpMerkleRoot;
        const sent = try socket.sendTo(target, payload);
        if (sent != payload.len) return error.PartialUdpShredSend;
        sent_bytes += sent;

        // Avoid overflowing the live receiver's packet batch with a single local burst.
        if ((i + 1) % 128 == 0) std.Thread.sleep(std.time.ns_per_ms);
    }

    const total_ms = timer.read() / std.time.ns_per_ms;
    std.debug.print(
        "slot={} udp=sent parent={} slot_span={} shred_version={} transactions={} entries={} ticks={} serialized_entry_bytes={} data_shreds={} bytes={} fetch_ms={} total_ms={} previous_blockhash={f} blockhash={f}\n",
        .{
            slot,
            block.parentSlot,
            slot - block.parentSlot,
            shred_version,
            transactions.len,
            entries.len,
            sig.core.entry.tickCount(entries),
            serialized_entries.len,
            shreds.len,
            sent_bytes,
            fetch_ms,
            total_ms,
            block.previousBlockhash,
            block.blockhash,
        },
    );

    return .{
        .blockhash = block.blockhash,
        .transaction_count = transactions.len,
        .shred_count = shreds.len,
        .sent_bytes = sent_bytes,
    };
}

fn fetchBuildAndInsertSlot(
    allocator: Allocator,
    rpc_client: *sig.rpc.Client,
    ticks_per_slot: u64,
    hashes_per_tick: u64,
    ledger: *Ledger,
    slot: Slot,
    expected_parent_slot: Slot,
    expected_previous_hash: Hash,
) !InsertStats {
    var timer = try std.time.Timer.start();
    var response = try fetchBlock(rpc_client, slot, true);
    defer response.deinit();
    const fetch_ms = timer.read() / std.time.ns_per_ms;
    const block = response.block;
    try validateBlockChain(slot, block, expected_parent_slot, expected_previous_hash);

    const transactions = try decodeTransactions(
        allocator,
        block.transactions orelse return error.MissingTransactions,
    );
    defer deinitTransactions(allocator, transactions);

    const expected_ticks = try expectedTicksForProducedSlot(
        ticks_per_slot,
        slot,
        expected_parent_slot,
    );
    const entries = try buildSyntheticEntries(
        allocator,
        expected_ticks,
        hashes_per_tick,
        expected_previous_hash,
        block.blockhash,
        transactions,
    );
    defer allocator.free(entries);

    const serialized_entries = try sig.bincode.writeAlloc(allocator, entries, .{});
    defer allocator.free(serialized_entries);
    const shreds = try buildDataShreds(
        allocator,
        slot,
        expected_parent_slot,
        0,
        0,
        DATA_SHREDS_PER_FEC_SET,
        serialized_entries,
    );
    defer deinitShreds(allocator, shreds);

    const repaired = try allocator.alloc(bool, shreds.len);
    defer allocator.free(repaired);
    @memset(repaired, false);

    var insertion = try ledger.shredInserter().insertShreds(
        allocator,
        shreds,
        repaired,
        .{
            .is_trusted = true,
            .skip_recovery = true,
            .skip_shred_tracker = true,
            .skip_data_recovery_meta_load = true,
        },
    );
    defer insertion.deinit();

    if (block.blockTime) |blocktime| try ledger.db.put(schema.blocktime, slot, blocktime);
    if (block.blockHeight) |height| try ledger.db.put(schema.block_height, slot, height);

    const total_ms = timer.read() / std.time.ns_per_ms;
    std.debug.print(
        "slot={} insert=pass parent={} slot_span={} transactions={} entries={} ticks={} serialized_entry_bytes={} data_shreds={} completed_sets={} duplicates={} fetch_ms={} total_ms={} previous_blockhash={f} blockhash={f}\n",
        .{
            slot,
            block.parentSlot,
            slot - block.parentSlot,
            transactions.len,
            entries.len,
            sig.core.entry.tickCount(entries),
            serialized_entries.len,
            shreds.len,
            insertion.completed_data_set_infos.items.len,
            insertion.duplicate_shreds.items.len,
            fetch_ms,
            total_ms,
            block.previousBlockhash,
            block.blockhash,
        },
    );

    return .{
        .blockhash = block.blockhash,
        .transaction_count = transactions.len,
        .shred_count = shreds.len,
    };
}

fn validateBlockChain(
    slot: Slot,
    block: RpcBlock,
    expected_parent_slot: Slot,
    expected_previous_hash: Hash,
) !void {
    if (block.parentSlot != expected_parent_slot) {
        std.debug.print(
            "chain_validation=fail slot={} expected_parent={} actual_parent={}\n",
            .{ slot, expected_parent_slot, block.parentSlot },
        );
        return error.ParentSlotMismatch;
    }
    if (!block.previousBlockhash.eql(expected_previous_hash)) {
        std.debug.print(
            "chain_validation=fail slot={} expected_previous_blockhash={f} actual_previous_blockhash={f}\n",
            .{ slot, expected_previous_hash, block.previousBlockhash },
        );
        return error.PreviousBlockhashMismatch;
    }
}

fn decodeTransactions(
    allocator: Allocator,
    encoded_transactions: []const RpcEncodedTransaction,
) ![]Transaction {
    const transactions = try allocator.alloc(Transaction, encoded_transactions.len);
    errdefer allocator.free(transactions);
    var initialized: usize = 0;
    errdefer for (transactions[0..initialized]) |transaction| transaction.deinit(allocator);

    for (encoded_transactions, 0..) |encoded_with_meta, i| {
        const binary = encoded_with_meta.transaction;
        if (!std.mem.eql(u8, binary[1], "base64"))
            return error.UnexpectedTransactionEncoding;
        const encoded = binary[0];

        const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
        const decoded = try allocator.alloc(u8, decoded_len);
        defer allocator.free(decoded);
        try std.base64.standard.Decoder.decode(decoded, encoded);
        transactions[i] = try sig.bincode.readFromSlice(allocator, Transaction, decoded, .{});
        initialized += 1;
    }
    return transactions;
}

fn deinitTransactions(allocator: Allocator, transactions: []Transaction) void {
    for (transactions) |transaction| transaction.deinit(allocator);
    allocator.free(transactions);
}

fn buildSyntheticEntries(
    allocator: Allocator,
    expected_tick_count_value: u64,
    hashes_per_tick: u64,
    previous_blockhash: Hash,
    official_blockhash: Hash,
    transactions: []const Transaction,
) ![]Entry {
    if (transactions.len == 0) return error.EmptyTransactionBlock;
    if (hashes_per_tick == 0) return error.HashesPerTickDisabled;
    const expected_tick_count: usize = @intCast(expected_tick_count_value);
    if (expected_tick_count == 0) return error.TicksPerSlotDisabled;
    const hash_count: usize = @intCast(hashes_per_tick);

    const entries = try allocator.alloc(Entry, expected_tick_count + 1);
    errdefer allocator.free(entries);
    var current_hash = previous_blockhash;
    var entry_index: usize = 0;

    for (0..expected_tick_count - 1) |_| {
        Hash.hashRepeated(&current_hash, &current_hash, hash_count);
        entries[entry_index] = .{
            .num_hashes = hashes_per_tick,
            .hash = current_hash,
            .transactions = &.{},
        };
        entry_index += 1;
    }

    if (hash_count > 1) Hash.hashRepeated(&current_hash, &current_hash, hash_count - 1);
    const transaction_mixin = sig.core.entry.hashTransactions(transactions);
    current_hash = current_hash.extend(&transaction_mixin.data);
    entries[entry_index] = .{
        .num_hashes = hashes_per_tick,
        .hash = current_hash,
        .transactions = transactions,
    };
    entry_index += 1;

    entries[entry_index] = .{
        .num_hashes = 0,
        .hash = official_blockhash,
        .transactions = &.{},
    };
    entry_index += 1;
    std.debug.assert(entry_index == entries.len);

    var tick_hash_count: u64 = 0;
    if (!sig.core.entry.verifyTickHashCount(
        entries,
        sig.trace.Logger("rpc_ledger_bridge").noop,
        &tick_hash_count,
        hashes_per_tick,
    )) return error.InvalidSyntheticTickHashCount;
    if (tick_hash_count != 0) return error.IncompleteSyntheticTickHashCount;
    if (sig.core.entry.tickCount(entries) != expected_tick_count_value)
        return error.InvalidSyntheticTickCount;
    if (!sig.core.entry.verifyPoh(entries, previous_blockhash))
        return error.InvalidSyntheticPoh;
    if (!entries[entries.len - 1].hash.eql(official_blockhash))
        return error.OfficialBlockhashNotPreserved;

    return entries;
}

fn expectedTicksForProducedSlot(
    ticks_per_slot: u64,
    slot: Slot,
    parent_slot: Slot,
) !u64 {
    if (slot <= parent_slot) return error.InvalidParentSlotOffset;
    return std.math.mul(u64, ticks_per_slot, slot - parent_slot) catch
        return error.TickCountOverflow;
}

fn buildDataShreds(
    allocator: Allocator,
    slot: Slot,
    parent_slot: Slot,
    shred_version: u16,
    proof_size: u8,
    data_shreds_per_fec_set: u32,
    serialized_entries: []const u8,
) ![]Shred {
    if (serialized_entries.len == 0) return error.EmptySerializedEntries;
    const parent_offset_value = slot - parent_slot;
    const parent_offset = std.math.cast(u16, parent_offset_value) orelse
        return error.ParentSlotOffsetOverflow;
    if (parent_offset == 0) return error.InvalidParentSlotOffset;
    if (data_shreds_per_fec_set == 0) return error.InvalidFecSetSize;

    const proof_bytes = std.math.mul(usize, proof_size, MERKLE_PROOF_ENTRY_SIZE) catch
        return error.InvalidProofSize;
    const data_shred_capacity = std.math.sub(usize, DATA_SHRED_CAPACITY, proof_bytes) catch
        return error.InvalidProofSize;
    if (data_shred_capacity == 0) return error.InvalidProofSize;

    const shred_count = (serialized_entries.len + data_shred_capacity - 1) /
        data_shred_capacity;
    if (shred_count > sig.ledger.shred.DataShred.constants.max_per_slot)
        return error.TooManyDataShreds;

    const shreds = try allocator.alloc(Shred, shred_count);
    errdefer allocator.free(shreds);
    var initialized: usize = 0;
    errdefer for (shreds[0..initialized]) |shred| shred.deinit();

    const variant = sig.ledger.shred.ShredVariant{
        .shred_type = .data,
        .proof_size = proof_size,
        .chained = false,
        .resigned = false,
    };

    for (shreds, 0..) |*out, i| {
        const start = i * data_shred_capacity;
        const end = @min(serialized_entries.len, start + data_shred_capacity);
        const data = serialized_entries[start..end];
        const is_last = i + 1 == shred_count;
        const index: u32 = @intCast(i);
        const common_header = sig.ledger.shred.CommonHeader{
            .leader_signature = .ZEROES,
            .variant = variant,
            .slot = slot,
            .index = index,
            .version = shred_version,
            .erasure_set_index = (index / data_shreds_per_fec_set) *
                data_shreds_per_fec_set,
        };
        const data_header = sig.ledger.shred.DataHeader{
            .parent_slot_offset = parent_offset,
            .flags = .{ .state = if (is_last) 0xff else 0x3f },
            .size = @intCast(sig.ledger.shred.DataShred.constants.headers_size + data.len),
        };

        const payload = try allocator.alloc(
            u8,
            sig.ledger.shred.DataShred.constants.payload_size,
        );
        @memset(payload, 0);
        var stream = std.io.fixedBufferStream(payload);
        sig.bincode.write(stream.writer(), common_header, .{}) catch |err| {
            allocator.free(payload);
            return err;
        };
        sig.bincode.write(stream.writer(), data_header, .{}) catch |err| {
            allocator.free(payload);
            return err;
        };
        if (stream.pos != sig.ledger.shred.DataShred.constants.headers_size) {
            allocator.free(payload);
            return error.UnexpectedDataShredHeaderSize;
        }
        @memcpy(payload[stream.pos..][0..data.len], data);

        const data_shred = sig.ledger.shred.DataShred{
            .common = common_header,
            .custom = data_header,
            .allocator = allocator,
            .payload = payload,
        };
        data_shred.sanitize() catch |err| {
            allocator.free(payload);
            return err;
        };
        out.* = .{ .data = data_shred };
        initialized += 1;
    }
    return shreds;
}

fn deinitShreds(allocator: Allocator, shreds: []Shred) void {
    for (shreds) |shred| shred.deinit();
    allocator.free(shreds);
}

fn installRootStub(allocator: Allocator, ledger: *Ledger, root_slot: Slot) !void {
    var root_meta = SlotMeta.init(allocator, root_slot, null);
    defer root_meta.deinit();
    root_meta.connected_flags.set(.parent_connected);
    root_meta.setConnected();
    try ledger.db.put(schema.slot_meta, root_slot, root_meta);
    try ledger.db.put(schema.rooted_slots, root_slot, true);
}
