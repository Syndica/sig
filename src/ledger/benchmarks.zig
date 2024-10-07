const std = @import("std");
const sig = @import("../sig.zig");
const ledger_tests = @import("./tests.zig");
const ledger = @import("lib.zig");

const Reward = ledger.transaction_status.Reward;
const Rewards = ledger.transaction_status.Rewards;
const RewardType = ledger.transaction_status.RewardType;
const Shred = ledger.shred.Shred;
const Pubkey = sig.core.Pubkey;
const TestState = ledger_tests.TestState;
const TestDB = ledger_tests.TestDB;

const schema = ledger.schema.schema;
const loadShredsFromFile = ledger_tests.loadShredsFromFile;
const deinitShreds = ledger_tests.deinitShreds;
const testShreds = ledger_tests.testShreds;
const comptimePrint = std.fmt.comptimePrint;

const test_shreds_dir = sig.TEST_DATA_DIR ++ "/shreds";
const State = TestState("global");
const DB = TestDB("global");

fn createRewards(allocator: std.mem.Allocator, count: usize) !Rewards {
    var rng = std.Random.DefaultPrng.init(100);
    const rand = rng.random();
    var rewards: Rewards = Rewards.init(allocator);
    for (0..count) |i| {
        try rewards.append(Reward{
            .pubkey = &Pubkey.random(rand).data,
            .lamports = @intCast(42 + i),
            .post_balance = std.math.maxInt(u64),
            .reward_type = RewardType.Fee,
            .commission = null,
        });
    }
    return rewards;
}

pub const BenchmarLegder = struct {
    pub const min_iterations = 5;
    pub const max_iterations = 5;

    // Analogous to [bench_write_small](https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L59)
    pub fn benchWriteSmall() !u64 {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench write small");
        defer state.deinit();
        var inserter = try state.shredInserter();

        const prefix = "agave.blockstore.bench_write_small.";
        const shreds = try testShreds(std.heap.c_allocator, prefix ++ "shreds.bin");
        defer inline for (.{shreds}) |slice| {
            deinitShreds(allocator, slice);
        };

        const is_repairs = try inserter.allocator.alloc(bool, shreds.len);
        defer inserter.allocator.free(is_repairs);
        for (0..shreds.len) |i| {
            is_repairs[i] = false;
        }

        var timer = try std.time.Timer.start();
        _ = try inserter.insertShreds(shreds, is_repairs, null, false, null);
        return timer.read();
    }

    // Analogous to [bench_read_sequential]https://github.com/anza-xyz/agave/blob/cfd393654f84c36a3c49f15dbe25e16a0269008d/ledger/benches/blockstore.rs#L78
    pub fn benchReadSequential() !u64 {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bentch read sequential");
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const prefix = "agave.blockstore.bench_read.";
        const shreds = try testShreds(std.heap.c_allocator, prefix ++ "shreds.bin");
        defer inline for (.{shreds}) |slice| {
            deinitShreds(allocator, slice);
        };

        const total_shreds = shreds.len;

        _ = try ledger.insert_shred.insertShredsForTest(&inserter, shreds);

        const slot: u32 = 0;
        const num_reads = total_shreds / 15;

        var rng = std.Random.DefaultPrng.init(100);

        var timer = try std.time.Timer.start();
        const start_index = rng.random().intRangeAtMost(u32, 0, @intCast(total_shreds));
        for (start_index..start_index + num_reads) |i| {
            const shred_index = i % total_shreds;
            _ = try reader.getDataShred(slot, shred_index);
        }
        return timer.read();
    }

    // Analogous to [bench_read_random]https://github.com/anza-xyz/agave/blob/92eca1192b055d896558a78759d4e79ab4721ff1/ledger/benches/blockstore.rs#L103
    pub fn benchReadRandom() !u64 {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench read randmom");
        defer state.deinit();
        var inserter = try state.shredInserter();
        var reader = try state.reader();

        const prefix = "agave.blockstore.bench_read.";
        const shreds = try testShreds(std.heap.c_allocator, prefix ++ "shreds.bin");
        defer inline for (.{shreds}) |slice| {
            deinitShreds(allocator, slice);
        };

        const total_shreds = shreds.len;
        _ = try ledger.insert_shred.insertShredsForTest(&inserter, shreds);

        const slot: u32 = 0;

        var rng = std.Random.DefaultPrng.init(100);

        var indices = try std.ArrayList(u32).initCapacity(inserter.allocator, total_shreds);
        defer indices.deinit();
        for (total_shreds) |_| {
            indices.appendAssumeCapacity(rng.random().uintAtMost(u32, @intCast(total_shreds)));
        }

        var timer = try std.time.Timer.start();
        for (indices.items) |shred_index| {
            _ = try reader.getDataShred(slot, shred_index);
        }
        return timer.read();
    }

    // Analogous to [bench_serialize_write_bincode](https://github.com/anza-xyz/agave/blob/9c2098450ca7e5271e3690277992fbc910be27d0/ledger/benches/protobuf.rs#L88)
    pub fn benchSerializeWriteBincode() !u64 {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench serialize write bincode");
        defer state.deinit();
        const slot: u32 = 0;

        var rewards: Rewards = try createRewards(allocator, 100);
        var timer = try std.time.Timer.start();
        try state.db.put(schema.rewards, slot, .{
            .rewards = try rewards.toOwnedSlice(),
            .num_partitions = null,
        });
        return timer.read();
    }

    pub fn benchReadBincode() !u64 {
        const allocator = std.heap.c_allocator;
        var state = try State.init(allocator, "bench read bincode");
        defer state.deinit();
        const slot: u32 = 1;

        var rewards: Rewards = try createRewards(allocator, 100);
        try state.db.put(schema.rewards, slot, .{
            .rewards = try rewards.toOwnedSlice(),
            .num_partitions = null,
        });
        var timer = try std.time.Timer.start();
        _ = try state.db.getBytes(schema.rewards, slot);
        return timer.read();
    }
};
