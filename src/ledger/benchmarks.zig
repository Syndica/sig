const std = @import("std");
const sig = @import("../sig.zig");
const ledger_tests = @import("./tests.zig");
const ledger = @import("lib.zig");

const Reward = ledger.transaction_status.Reward;
const Rewards = ledger.transaction_status.Rewards;
const RewardType = ledger.transaction_status.RewardType;
const Pubkey = sig.core.Pubkey;
const TestState = ledger_tests.TestState;

const schema = ledger.schema.schema;
const deinitShreds = ledger_tests.deinitShreds;
const testShreds = ledger_tests.testShreds;

fn createRewards(allocator: std.mem.Allocator, count: usize) !Rewards {
    var rng = std.Random.DefaultPrng.init(100);
    const rand = rng.random();
    var rewards: Rewards = Rewards.init(allocator);
    for (0..count) |i| {
        try rewards.append(Reward{
            .pubkey = &Pubkey.initRandom(rand).data,
            .lamports = @intCast(42 + i),
            .post_balance = std.math.maxInt(u64),
            .reward_type = RewardType.Fee,
            .commission = null,
        });
    }
    return rewards;
}

pub const BenchmarkLedger = struct {
    const Slot = sig.core.Slot;
    const SlotMeta = ledger.meta.SlotMeta;

    pub const min_iterations = 25;
    pub const max_iterations = 25;

    /// Analogous to [bench_write_small](https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L59)
    ///
    /// There is a notable difference from agave: This does not measure the
    /// creation of shreds from entries. But even if you remove that from
    /// the agave benchmark, the benchmark result is the same.
    pub fn @"ShredInserter.insertShreds - 1751 shreds"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();

        const shreds_path = "agave.blockstore.bench_write_small.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const is_repairs = try inserter.allocator.alloc(bool, shreds.len);
        defer inserter.allocator.free(is_repairs);
        for (0..shreds.len) |i| {
            is_repairs[i] = false;
        }

        var timer = try sig.time.Timer.start();
        _ = try inserter.insertShreds(shreds, is_repairs, null, false, null);
        return timer.read();
    }

    /// Analogous to [bench_serialize_write_bincode](https://github.com/anza-xyz/agave/blob/9c2098450ca7e5271e3690277992fbc910be27d0/ledger/benches/protobuf.rs#L88)
    pub fn @"Database.put Rewards"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        const slot: u32 = 0;

        var rewards: Rewards = try createRewards(allocator, 100);
        const rewards_slice = try rewards.toOwnedSlice();
        var timer = try sig.time.Timer.start();
        try state.db.put(schema.rewards, slot, .{
            .rewards = rewards_slice,
            .num_partitions = null,
        });
        return timer.read();
    }

    /// Analogous to [bench_read_bincode](https://github.com/anza-xyz/agave/blob/9c2098450ca7e5271e3690277992fbc910be27d0/ledger/benches/protobuf.rs#L100)
    pub fn @"Database.get Rewards"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        const slot: u32 = 1;

        var rewards: Rewards = try createRewards(allocator, 100);
        try state.db.put(schema.rewards, slot, .{
            .rewards = try rewards.toOwnedSlice(),
            .num_partitions = null,
        });
        var timer = try sig.time.Timer.start();
        _ = try state.db.get(allocator, schema.rewards, slot);
        return timer.read();
    }

    /// Benchmarks for BlockstoreReader.
    ///
    /// Analogous to [bench_read_sequential]https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L78
    pub fn @"BlockstoreReader.getDataShred - Sequential"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const total_shreds = shreds.len;

        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);

        const slot: u32 = 0;
        const num_reads = total_shreds / 15;

        var rng = std.Random.DefaultPrng.init(100);

        var timer = try sig.time.Timer.start();
        const start_index = rng.random().intRangeAtMost(u32, 0, @intCast(total_shreds));
        for (start_index..start_index + num_reads) |i| {
            const shred_index = i % total_shreds;
            _ = try reader.getDataShred(slot, shred_index) orelse return error.MissingShred;
        }
        return timer.read();
    }

    /// Analogous to [bench_read_random]https://github.com/anza-xyz/agave/blob/92eca1192b055d896558a78759d4e79ab4721ff1/ledger/benches/blockstore.rs#L103
    pub fn @"BlockstoreReader.getDataShred - Random"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const total_shreds = shreds.len;
        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);
        const num_reads = total_shreds / 15;

        const slot: u32 = 0;

        var rng = std.Random.DefaultPrng.init(100);

        var indices = try std.ArrayList(u32).initCapacity(inserter.allocator, num_reads);
        defer indices.deinit();
        for (num_reads) |_| {
            indices.appendAssumeCapacity(rng.random().uintAtMost(u32, @intCast(total_shreds)));
        }

        var timer = try sig.time.Timer.start();
        for (indices.items) |shred_index| {
            _ = try reader.getDataShred(slot, shred_index) orelse return error.MissingShred;
        }
        return timer.read();
    }

    pub fn @"BlockstoreReader.getCompleteBlock"() !sig.time.Duration {
        const state = try TestState.init(std.heap.c_allocator, @src(), .noop);
        defer state.deinit();
        var reader = try state.reader();
        const result = try ledger_tests.insertDataForBlockTest(state);
        defer result.deinit();

        var timer = try sig.time.Timer.start();
        _ = try reader.getCompleteBlock(result.slot + 2, true);
        return timer.read();
    }

    pub fn @"BlockstoreReader.getDataShredsForSlot"() !sig.time.Duration {
        const state = try TestState.init(std.heap.c_allocator, @src(), .noop);
        defer state.deinit();
        var reader = try state.reader();
        const result = try ledger_tests.insertDataForBlockTest(state);
        defer result.deinit();

        var timer = try sig.time.Timer.start();
        const shreds = try reader.getDataShredsForSlot(result.slot + 2, 0);
        const duration = timer.read();
        try std.testing.expect(shreds.items.len > 0);
        return duration;
    }

    pub fn @"BlockstoreReader.getSlotEntriesWithShredInfo"() !sig.time.Duration {
        const state = try TestState.init(std.heap.c_allocator, @src(), .noop);
        defer state.deinit();
        var reader = try state.reader();
        const result = try ledger_tests.insertDataForBlockTest(state);
        defer result.deinit();

        var timer = try sig.time.Timer.start();
        const items = try reader.getSlotEntriesWithShredInfo(result.slot + 2, 0, true);
        const duration = timer.read();
        try std.testing.expect(items[0].items.len > 0);
        return duration;
    }

    pub fn @"BlockstoreReader.getCodeShred"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.code_shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        const total_shreds = shreds.len;
        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);

        const slot: u32 = 1;

        var rng = std.Random.DefaultPrng.init(100);

        var indices = try std.ArrayList(u32).initCapacity(inserter.allocator, total_shreds);
        defer indices.deinit();
        for (total_shreds) |_| {
            indices.appendAssumeCapacity(rng.random().uintAtMost(u32, @intCast(total_shreds)));
        }

        var timer = try sig.time.Timer.start();
        for (indices.items) |shred_index| {
            _ = try reader.getCodeShred(slot, shred_index) orelse return error.MissingShred;
        }
        return timer.read();
    }

    pub fn @"BlockstoreReader.getCodeShredsForSlot"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const shreds_path = "agave.blockstore.bench_read.code_shreds.bin";
        const shreds = try testShreds(std.heap.c_allocator, shreds_path);
        defer deinitShreds(allocator, shreds);

        _ = try ledger.shred_inserter.shred_inserter.insertShredsForTest(&inserter, shreds);

        const slot = 1;
        const start_index = 0;

        var timer = try sig.time.Timer.start();
        const code_shreds = try reader.getCodeShredsForSlot(slot, start_index);
        const duration = timer.read();
        try std.testing.expect(code_shreds.items.len > 0);
        return duration;
    }

    /// Benchmarks for LedgerResultWriter.
    ///
    /// Analogous to [bench_write_transaction_status]https://github.com/anza-xyz/agave/blob/ff1b22007c34669768c5b676cac491f580b39e0b/ledger/benches/blockstore.rs#L206
    pub fn @"LedgerResultWriter.writeTransactionStatus"() !sig.time.Duration {
        const Signature = sig.core.Signature;
        const TransactionStatusMeta = ledger.transaction_status.TransactionStatusMeta;

        const state = try TestState.init(std.heap.c_allocator, @src(), .noop);
        defer state.deinit();
        var writer = try state.writer();
        var rng = std.rand.DefaultPrng.init(100);

        var signatures: std.ArrayList(Signature) = try std.ArrayList(Signature).initCapacity(state.allocator, 64);
        defer signatures.deinit();
        var writable_keys = try std.ArrayList(std.ArrayList(Pubkey)).initCapacity(state.allocator, 64);
        defer {
            for (writable_keys.items) |l| l.deinit();
            writable_keys.deinit();
        }
        var readonly_keys = try std.ArrayList(std.ArrayList(Pubkey)).initCapacity(state.allocator, 64);
        defer {
            for (readonly_keys.items) |l| l.deinit();
            readonly_keys.deinit();
        }

        for (0..64) |_| {
            // Two writable keys
            var w_keys = try std.ArrayList(Pubkey).initCapacity(state.allocator, 2);
            try w_keys.append(Pubkey.initRandom(rng.random()));
            try w_keys.append(Pubkey.initRandom(rng.random()));
            writable_keys.appendAssumeCapacity(w_keys);

            // Two readonly keys
            var r_keys = try std.ArrayList(Pubkey).initCapacity(state.allocator, 2);
            try r_keys.append(Pubkey.initRandom(rng.random()));
            try r_keys.append(Pubkey.initRandom(rng.random()));
            readonly_keys.appendAssumeCapacity(r_keys);

            var random_bytes: [64]u8 = undefined;
            for (random_bytes[0..]) |*byte| {
                byte.* = rng.random().int(u8);
            }
            signatures.appendAssumeCapacity(Signature.init(random_bytes));
        }

        const slot = 5;

        var timer = try sig.time.Timer.start();
        for (signatures.items, 0..) |signature, tx_idx| {
            const status = TransactionStatusMeta.EMPTY_FOR_TEST;
            const w_keys = writable_keys.items[tx_idx];
            const r_keys = readonly_keys.items[tx_idx];
            _ = try writer.writeTransactionStatus(slot, signature, w_keys, r_keys, status, tx_idx);
        }
        return timer.read();
    }
};

pub const BenchmarkLedgerSlow = struct {
    const Slot = sig.core.Slot;
    const SlotMeta = ledger.meta.SlotMeta;

    pub const min_iterations = 5;
    pub const max_iterations = 5;

    pub fn @"BlockstoreReader.slotRangeConnected"() !sig.time.Duration {
        const allocator = std.heap.c_allocator;
        var state = try TestState.init(allocator, @src(), .noop);
        defer state.deinit();
        var reader = try state.reader();
        var db = state.db;

        var write_batch = try db.initWriteBatch();
        defer write_batch.deinit();

        // TODO this is essentially slots with little or no data consturcted manually
        // Will it be more realistic to not manually construct the benchmarking data?
        const slot_per_epoch = 432_000;
        var parent_slot: ?Slot = null;
        for (1..(slot_per_epoch + 1)) |slot| {
            var slot_meta = SlotMeta.init(allocator, slot, parent_slot);
            defer slot_meta.deinit();
            // ensure isFull() is true
            slot_meta.last_index = 1;
            slot_meta.consecutive_received_from_0 = slot_meta.last_index.? + 1;
            // update next slots
            if (slot < (slot_per_epoch + 1)) {
                try slot_meta.child_slots.append(slot + 1);
            }
            try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
            // connect the chain
            parent_slot = slot;
        }
        try db.commit(&write_batch);

        var timer = try sig.time.Timer.start();
        const is_connected = try reader.slotRangeConnected(1, slot_per_epoch);
        const duration = timer.read();

        try std.testing.expectEqual(true, is_connected);

        return duration;
    }
};
