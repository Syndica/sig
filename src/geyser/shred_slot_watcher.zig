/// Slot watcher for the shred_network subcommand.
///
/// Polls the ledger for completed slots and runs the PumpFun instruction
/// parser on every transaction. Emits TradeEventV1 payloads via the geyser
/// pipe — no snapshot, no SVM needed.
///
/// Usage:
///   const thread = try std.Thread.spawn(.{}, run, .{ allocator, &ledger, geyser_writer, exit, start_slot });
///   defer thread.join();

const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Slot = sig.core.Slot;
const GeyserWriter = sig.geyser.GeyserWriter;
const pumpfun_parser = sig.geyser.pumpfun_parser;
const pumpswap_parser = sig.geyser.pumpswap_parser;

/// Poll interval when live (slot watcher has already processed at least one real slot).
const LIVE_POLL_INTERVAL_NS: u64 = 100 * std.time.ns_per_ms;

/// Poll interval during initial catchup (ledger is empty, burning through dead slots).
/// 5ms per poll keeps CPU usage low while advancing ~200 slots/second.
const CATCHUP_POLL_INTERVAL_NS: u64 = 5 * std.time.ns_per_ms;

/// Max polls before declaring a slot dead and advancing — live mode.
/// 50 × 100ms = 5 seconds per dead slot.
const LIVE_DEAD_SLOT_POLLS: u32 = 50;

/// Max polls before declaring a slot dead during catchup.
/// 3 × 5ms = 15ms per dead slot → ~67 slots/second advancement.
/// At 15ms/slot, a 1000-slot gap is closed in ~15 seconds.
const CATCHUP_DEAD_SLOT_POLLS: u32 = 3;

pub fn run(
    allocator: Allocator,
    ledger: *sig.ledger.Ledger,
    geyser_writer: ?*GeyserWriter,
    exit: *std.atomic.Value(bool),
    start_slot: Slot,
) void {
    runInner(allocator, ledger, geyser_writer, exit, start_slot) catch |err| {
        std.log.err("shred_slot_watcher: fatal error: {}", .{err});
    };
}

fn runInner(
    allocator: Allocator,
    ledger: *sig.ledger.Ledger,
    geyser_writer: ?*GeyserWriter,
    exit: *std.atomic.Value(bool),
    start_slot: Slot,
) !void {
    std.log.info("shred_slot_watcher: starting from slot {}", .{start_slot});

    var next_slot: Slot = start_slot;
    var stall_count: u32 = 0;
    var slots_parsed: u64 = 0;
    var trade_events: u64 = 0;

    while (!exit.load(.acquire)) {
        const reader = ledger.reader();

        // Use fast catchup timing only when we're still behind the start slot.
        // Once we reach start_slot without seeing a real slot, switch to live timing
        // to avoid overshooting the tip and skipping real turbine data.
        const caught_up = slots_parsed > 0;
        const past_start = next_slot >= start_slot;
        const in_live_mode = caught_up or past_start;
        const poll_interval = if (in_live_mode) LIVE_POLL_INTERVAL_NS else CATCHUP_POLL_INTERVAL_NS;
        const dead_slot_limit = if (in_live_mode) LIVE_DEAD_SLOT_POLLS else CATCHUP_DEAD_SLOT_POLLS;

        const is_full = reader.isFull(allocator, next_slot) catch |err| {
            std.log.warn("shred_slot_watcher: isFull({}) error: {} — retrying", .{ next_slot, err });
            std.Thread.sleep(poll_interval);
            continue;
        };

        if (!is_full) {
            stall_count += 1;
            if (stall_count >= dead_slot_limit) {
                if (!caught_up) {
                    std.log.debug("shred_slot_watcher: catchup advance slot {}", .{next_slot});
                } else {
                    std.log.debug("shred_slot_watcher: slot {} timed out (dead/skipped), advancing", .{next_slot});
                }
                next_slot += 1;
                stall_count = 0;
            } else {
                std.Thread.sleep(poll_interval);
            }
            continue;
        }

        // Slot is complete — read entries
        stall_count = 0;
        const entries = reader.getSlotEntries(allocator, next_slot, 0) catch |err| {
            std.log.warn("shred_slot_watcher: getSlotEntries({}) error: {} — skipping", .{ next_slot, err });
            next_slot += 1;
            continue;
        };
        defer {
            for (entries) |entry| entry.deinit(allocator);
            allocator.free(entries);
        }

        // Parse each transaction for PumpFun and PumpSwap instructions
        for (entries) |entry| {
            for (entry.transactions) |*tx| {
                pumpfun_parser.parseTransaction(tx, next_slot, geyser_writer);
                pumpswap_parser.parseTransaction(tx, next_slot, geyser_writer);
                trade_events += 1; // approximate — parsers only emit on match
            }
        }

        if (slots_parsed == 0) {
            std.log.info("shred_slot_watcher: caught up — first live slot {} processed", .{next_slot});
        }

        slots_parsed += 1;
        if (slots_parsed % 100 == 0) {
            std.log.info(
                "shred_slot_watcher: slot={} slots_parsed={} tx_seen_approx={}",
                .{ next_slot, slots_parsed, trade_events },
            );
        }

        next_slot += 1;
    }

    std.log.info("shred_slot_watcher: exit — last slot processed {}", .{next_slot - 1});
}
