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

pub fn streamReader(exit: *std.atomic.Value(bool)) !void {
    const allocator = std.heap.page_allocator;

    var reader = try sig.geyser.GeyserReader.init(allocator, PIPE_PATH, exit, .{});
    defer reader.deinit();

    var bytes_read: usize = 0;
    var timer = try sig.time.Timer.start();

    while (!exit.load(.unordered)) {
        const n, const payload = try reader.readPayload();
        bytes_read += n;

        // just drop the data
        std.mem.doNotOptimizeAway(payload);
        reader.resetMemory();

        // mb/sec reading
        if (timer.read().asNanos() > MEASURE_RATE.asNanos()) {
            // print mb/sec
            const elapsed = timer.read().asSecs();
            const bytes_per_sec = bytes_read / elapsed;
            const mb_per_sec = bytes_per_sec / 1_000_000;
            const mb_per_sec_dec = (bytes_per_sec - mb_per_sec * 1_000_000) / (1_000_000 / 100);
            std.debug.print("read mb/sec: {}.{}\n", .{ mb_per_sec, mb_per_sec_dec });

            bytes_read = 0;
            timer.reset();
        }
    }
}

pub fn streamWriter(exit: *std.atomic.Value(bool)) !void {
    const allocator = std.heap.page_allocator;

    var geyser_writer = try GeyserWriter.init(allocator, PIPE_PATH, exit, 1 << 32);
    defer geyser_writer.deinit();

    try geyser_writer.spawnIOLoop();

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // PERF: one allocation slice
    // const N_ACCOUNTS_PER_SLOT = 10_000_000; // based on testnet data
    const N_ACCOUNTS_PER_SLOT = 100;
    const accounts = try allocator.alloc(Account, N_ACCOUNTS_PER_SLOT);
    const pubkeys = try allocator.alloc(Pubkey, N_ACCOUNTS_PER_SLOT);
    for (0..N_ACCOUNTS_PER_SLOT) |i| {
        // const data_len = rng.intRangeAtMost(u64, 2000, 10_000_000); // based on testnet data
        // const data_len = 10_000_000;
        // const data_len = 1;
        const data_len = rng.intRangeAtMost(u64, 2000, 10_000);
        // const is_large = rng.intRangeAtMost(u8, 0, 10) < 1; // 10% chance of large data
        // if (is_large) {
        //     data_len = rng.intRangeAtMost(u64, 2000, 10_000_000);
        // }
        // const data_len = 32;
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

    const reader_handle = try std.Thread.spawn(.{}, streamReader, .{exit});
    const writer_handle = try std.Thread.spawn(.{}, streamWriter, .{exit});

    // let it run for ~4 measurements
    std.time.sleep(MEASURE_RATE.asNanos() * 100);
    exit.store(true, .unordered);

    reader_handle.join();
    writer_handle.join();
}
