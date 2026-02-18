//! Benchmarks for AccountsDB v2
//!
//! These benchmarks measure the read/write performance of the v2 accountsdb
//! which uses a hybrid Unrooted (in-memory) + Rooted (sqlite) storage system.

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const Two = @import("Two.zig");
const Rooted = @import("Rooted.zig");
const Unrooted = @import("Unrooted.zig");
const Pubkey = sig.core.Pubkey;
const Ancestors = sig.core.Ancestors;
const AccountSharedData = sig.runtime.AccountSharedData;
const Resolution = @import("../../benchmarks.zig").Resolution;

pub const BenchmarkAccountsDBTwo = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 10;
    pub const name = "AccountsDBTwo";

    pub const BenchInputs = struct {
        /// The number of accounts to store in the database (for each slot)
        n_accounts: usize,
        /// The number of slots to write (each slot is one batch write)
        n_slots: usize,
        /// Whether to root slots after writing (moves data to sqlite)
        root_slots: bool,
        /// The name of the benchmark
        name: []const u8 = "",
    };

    pub const inputs = [_]BenchInputs{
        .{
            .n_accounts = 10_000,
            .n_slots = 1,
            .root_slots = false,
            .name = "10k accounts (1 slot - unrooted only)",
        },
        .{
            .n_accounts = 10_000,
            .n_slots = 10,
            .root_slots = false,
            .name = "10k accounts (10 slots - unrooted only)",
        },
        .{
            .n_accounts = 10_000,
            .n_slots = 1,
            .root_slots = true,
            .name = "10k accounts (1 slot - rooted)",
        },
        .{
            .n_accounts = 10_000,
            .n_slots = 10,
            .root_slots = true,
            .name = "10k accounts (10 slots - rooted)",
        },
        .{
            .n_accounts = 100_000,
            .n_slots = 1,
            .root_slots = false,
            .name = "100k accounts (1 slot - unrooted only)",
        },
        .{
            .n_accounts = 100_000,
            .n_slots = 1,
            .root_slots = true,
            .name = "100k accounts (1 slot - rooted)",
        },
    };

    pub fn readWriteAccounts(
        units: Resolution,
        bench_args: BenchInputs,
    ) !struct { read_time: u64, write_time: u64 } {
        const n_accounts = bench_args.n_accounts;
        const n_slots = bench_args.n_slots;

        const allocator = if (builtin.is_test) std.testing.allocator else std.heap.c_allocator;

        // Initialize the v2 database
        var test_state = try Two.initTest(allocator);
        defer test_state.deinit();
        const db = &test_state.db;

        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const random = prng.random();

        // Generate random pubkeys
        var pubkeys = try allocator.alloc(Pubkey, n_accounts);
        defer allocator.free(pubkeys);
        for (0..n_accounts) |i| {
            pubkeys[i] = Pubkey.initRandom(random);
        }

        // Generate random accounts
        var accounts = try allocator.alloc(AccountSharedData, n_accounts);
        defer {
            for (accounts) |*acc| acc.deinit(allocator);
            allocator.free(accounts);
        }
        for (0..n_accounts) |i| {
            const data_len = i % 200; // varying data sizes up to 200 bytes
            const data = try allocator.alloc(u8, data_len);
            random.bytes(data);
            accounts[i] = .{
                .lamports = random.int(u64),
                .data = data,
                .owner = Pubkey.initRandom(random),
                .executable = random.boolean(),
                .rent_epoch = random.int(u64),
            };
        }

        // Setup ancestors for queries
        var ancestors: Ancestors = .EMPTY;
        defer ancestors.deinit(allocator);

        // Benchmark writes
        var write_timer = sig.time.Timer.start();
        for (0..n_slots) |slot| {
            try ancestors.addSlot(allocator, slot);
            ancestors.cleanup();

            for (0..n_accounts) |i| {
                try db.put(slot, pubkeys[i], accounts[i]);
            }

            // Optionally root the slot (moves data from unrooted to rooted storage)
            if (bench_args.root_slots and slot > 0) {
                db.onSlotRooted(slot - 1, &ancestors);
            }
        }
        // Root the final slot if rooting is enabled
        if (bench_args.root_slots and n_slots > 0) {
            db.onSlotRooted(n_slots - 1, &ancestors);
        }
        const write_duration = write_timer.read();

        // Benchmark reads
        var read_timer = sig.time.Timer.start();
        for (0..n_accounts) |i| {
            const account = try db.get(allocator, pubkeys[i], &ancestors);
            if (account) |acc| {
                acc.deinit(allocator);
            }
        }
        const read_duration = read_timer.read();

        return .{
            .read_time = units.convertDuration(read_duration),
            .write_time = units.convertDuration(write_duration),
        };
    }
};

test "BenchmarkAccountsDBTwo basic sanity" {
    const allocator = std.testing.allocator;
    _ = allocator;

    // Just ensure the benchmark can run with small inputs
    const result = try BenchmarkAccountsDBTwo.readWriteAccounts(.millis, .{
        .n_accounts = 100,
        .n_slots = 1,
        .root_slots = false,
        .name = "test",
    });
    _ = result;
}
