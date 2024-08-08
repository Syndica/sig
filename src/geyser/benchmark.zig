const std = @import("std");
const sig = @import("../lib.zig");
const geyser = sig.geyser;

const bincode = sig.bincode;
const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const GeyserWriter = sig.geyser.GeyserWriter;
const VersionedAccountPayload = sig.geyser.core.VersionedAccountPayload;

const MEASURE_RATE = sig.time.Duration.fromSecs(2);
const PIPE_PATH = "../sig/test_data/accountsdb_fuzz.pipe";

pub fn streamWriter(exit: *std.atomic.Value(bool)) !void {
    const allocator = std.heap.page_allocator;

    // 4gb
    var geyser_writer = try GeyserWriter.init(allocator, PIPE_PATH, exit, 1 << 32);
    defer geyser_writer.deinit();

    try geyser_writer.spawnIOLoop();

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // PERF: one allocation slice
    const N_ACCOUNTS_PER_SLOT = 700;
    const accounts = try allocator.alloc(Account, N_ACCOUNTS_PER_SLOT);
    const pubkeys = try allocator.alloc(Pubkey, N_ACCOUNTS_PER_SLOT);
    for (0..N_ACCOUNTS_PER_SLOT) |i| {
        const data_len = rng.intRangeAtMost(u64, 2000, 10_000);
        accounts[i] = try Account.random(allocator, rng, data_len);
        pubkeys[i] = Pubkey.random(rng);
    }
    var slot: Slot = 0;

    while (!exit.load(.unordered)) {
        // since the i/o happens in another thread, we cant easily track bytes/second here
        try geyser_writer.writePayloadToPipe(
            VersionedAccountPayload{
                .AccountPayloadV1 = .{
                    .accounts = accounts,
                    .pubkeys = pubkeys,
                    .slot = slot,
                },
            },
        );
        slot += 1;
    }
}

pub fn runBenchmark() !void {
    const allocator = std.heap.page_allocator;

    const exit = try allocator.create(std.atomic.Value(bool));
    defer allocator.destroy(exit);

    exit.* = std.atomic.Value(bool).init(false);

    const reader_handle = try std.Thread.spawn(.{}, geyser.core.streamReader, .{
        exit,
        PIPE_PATH,
        MEASURE_RATE,
        null,
    });
    const writer_handle = try std.Thread.spawn(.{}, streamWriter, .{exit});

    // let it run for ~4 measurements
    std.time.sleep(MEASURE_RATE.asNanos() * 100);
    exit.store(true, .unordered);

    reader_handle.join();
    writer_handle.join();
}
