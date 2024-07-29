const std = @import("std");
const sig = @import("../lib.zig");

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const GeyserWriter = sig.geyser.GeyserWriter;

pub fn streamReader() !void {
    const allocator = std.heap.page_allocator;
    var reader = try sig.geyser.GeyserReader.init(allocator, "../sig/test_data/accountsdb_fuzz.pipe");
    defer reader.deinit();

    var bytes_read: usize = 0;
    var timer = try sig.time.Timer.start();

    while (true) {
        const data = try reader.read();

        var bytes: usize = 0;
        for (data.accounts, data.pubkeys) |*account, _| {
            bytes += account.data.len;
        }
        bytes_read += bytes;

        // mb/sec reading
        if (timer.read().asSecs() > 5) {
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

pub fn streamWriter() !void {
    const allocator = std.heap.page_allocator;

    var geyser = try GeyserWriter.init(allocator, "test_data/accountsdb_fuzz.pipe");
    defer geyser.deinit();

    var random = std.rand.DefaultPrng.init(19);
    const rng = random.random();

    // PERF: one allocation slice
    const N_ACCOUNTS_PER_SLOT = 100;
    const accounts = try allocator.alloc(Account, N_ACCOUNTS_PER_SLOT);
    const pubkeys = try allocator.alloc(Pubkey, N_ACCOUNTS_PER_SLOT);

    var bytes_per_batch: u64 = 0;
    for (0..N_ACCOUNTS_PER_SLOT) |i| {
        accounts[i] = try Account.random(allocator, rng, 32);
        pubkeys[i] = Pubkey.random(rng);

        bytes_per_batch += accounts[i].data.len;
    }

    var timer = try sig.time.Timer.start();
    var bytes_written: u64 = 0;
    var slot: Slot = 0;

    while (true) {
        try geyser.write(slot, accounts, pubkeys);
        bytes_written += bytes_per_batch;

        if (timer.read().asSecs() > 5) {
            // print mb/sec
            const elapsed = timer.read().asSecs();
            const bytes_per_sec = bytes_written / elapsed;
            const mb_per_sec = bytes_per_sec / 1_000_000;
            const mb_per_sec_dec = (bytes_per_sec - mb_per_sec * 1_000_000) / (1_000_000 / 100);
            std.debug.print("write mb/sec: {}.{}\n", .{ mb_per_sec, mb_per_sec_dec });

            bytes_written = 0;
            timer.reset();
        }
        slot += 1;
    }
}

pub fn main() !void {
    const reader_handle = try std.Thread.spawn(.{}, streamReader, .{});
    reader_handle.detach();

    try streamWriter();
}
