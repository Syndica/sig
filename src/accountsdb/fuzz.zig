//! Fuzz test for AccountsDB v2 (Two.zig).
//!
//! This fuzzer tests the correctness of account storage and retrieval
//! by comparing against a simple reference implementation (TrackedAccountsMap).

const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");
const cli = @import("cli");

const Account = sig.runtime.AccountSharedData;
const Pubkey = sig.core.pubkey.Pubkey;
const Slot = sig.core.time.Slot;

const Two = sig.accounts_db.Two;
const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;

const N_RANDOM_THREADS = 8;

const TrackedAccountsMap = sig.utils.collections.PubkeyMap(TrackedAccount);

pub const TrackedAccount = struct {
    pubkey: Pubkey,
    slot: u64,
    data: [32]u8,

    pub fn initRandom(random: std.Random, slot: Slot) TrackedAccount {
        var data: [32]u8 = undefined;
        random.bytes(&data);
        return .{
            .pubkey = .initRandom(random),
            .slot = slot,
            .data = data,
        };
    }

    pub fn toAccount(self: *const TrackedAccount, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = 19,
            .data = try allocator.dupe(u8, &self.data),
            .owner = Pubkey.ZEROES,
            .executable = false,
            .rent_epoch = 0,
        };
    }
};

pub const RunCmd = struct {
    max_slots: ?Slot,
    non_sequential_slots: bool,

    pub const cmd_info: cli.CommandInfo(RunCmd) = .{
        .help = .{
            .short = "Fuzz accountsdb v2.",
            .long = null,
        },
        .sub = .{
            .max_slots = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = null,
                .config = {},
                .help = "The number of slots number which, when surpassed, will exit the fuzzer.",
            },
            .non_sequential_slots = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "Enable non-sequential slots.",
            },
        },
    };
};

const Logger = sig.trace.Logger("accountsdb.fuzz");

pub fn run(
    allocator: std.mem.Allocator,
    logger: Logger,
    seed: u64,
    _: std.fs.Dir, // fuzz_data_dir - not used for v2
    run_cmd: RunCmd,
) !void {
    var prng_state: std.Random.DefaultPrng = .init(seed);
    const random = prng_state.random();

    // NOTE: we don't necessarily want to grow the db indefinitely -- so when we reach
    // the max, we only update existing accounts
    const N_ACCOUNTS_MAX: u64 = 100_000;
    const N_ACCOUNTS_PER_SLOT = 10;

    const maybe_max_slots = run_cmd.max_slots;
    const non_sequential_slots = run_cmd.non_sequential_slots;

    logger.info().logf("non-sequential slots: {}", .{non_sequential_slots});

    var test_state = try Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    const account_store: AccountStore = .{ .accounts_db_two = db };

    var tracked_accounts_rw: sig.sync.RwMux(TrackedAccountsMap) = .init(.empty);
    defer {
        const tracked_accounts, var tracked_accounts_lg = tracked_accounts_rw.writeWithLock();
        defer tracked_accounts_lg.unlock();
        tracked_accounts.deinit(allocator);
    }

    {
        const tracked_accounts, var lg = tracked_accounts_rw.writeWithLock();
        defer lg.unlock();
        try tracked_accounts.ensureTotalCapacity(allocator, 10_000);
    }

    var reader_exit: std.atomic.Value(bool) = .init(false);
    var threads: std14.BoundedArray(std.Thread, N_RANDOM_THREADS) = .{};
    defer {
        reader_exit.store(true, .seq_cst);
        for (threads.constSlice()) |thread| thread.join();
    }

    // spawn the random reader threads
    for (0..N_RANDOM_THREADS) |thread_i| {
        // NOTE: these threads just access accounts and do not perform
        // any validation (in the .get block of the main fuzzer
        // loop, we perform validation)
        threads.appendAssumeCapacity(try .spawn(.{}, readRandomAccounts, .{
            allocator,
            logger,
            account_store.reader(),
            &tracked_accounts_rw,
            seed + thread_i,
            &reader_exit,
            thread_i,
        }));
    }

    var top_slot: Slot = 0;

    var ancestors: sig.core.Ancestors = .EMPTY;
    defer ancestors.deinit(allocator);

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_slots) |max_slots| if (top_slot >= max_slots) {
            logger.info().logf("reached max slots: {}", .{max_slots});
            break;
        };
        const will_inc_slot = switch (random.int(u2)) {
            0 => true,
            1, 2, 3 => false,
        };
        defer if (will_inc_slot) {
            top_slot += random.intRangeAtMost(Slot, 1, 2);
        };
        try ancestors.addSlot(allocator, top_slot);

        const current_slot = if (!non_sequential_slots) top_slot else slot: {
            const ancestor_slots: []const Slot = ancestors.ancestors.keys();
            std.debug.assert(ancestor_slots[ancestor_slots.len - 1] == top_slot);
            const ancestor_index = random.intRangeLessThan(
                usize,
                ancestor_slots.len -| 10,
                ancestor_slots.len,
            );
            break :slot ancestor_slots[ancestor_index];
        };

        const action = random.enumValue(enum { put, get });
        switch (action) {
            .put => {
                const tracked_accounts, var tracked_accounts_lg =
                    tracked_accounts_rw.writeWithLock();
                defer tracked_accounts_lg.unlock();

                var pubkeys_this_slot: std.AutoHashMapUnmanaged(Pubkey, void) = .empty;
                defer pubkeys_this_slot.deinit(allocator);
                for (0..N_ACCOUNTS_PER_SLOT) |_| {
                    var tracked_account: TrackedAccount = .initRandom(random, current_slot);

                    const update_all_existing =
                        tracked_accounts.count() > N_ACCOUNTS_MAX;
                    const overwrite_existing =
                        tracked_accounts.count() > 0 and
                        random.boolean();
                    const pubkey: Pubkey = blk: {
                        if (overwrite_existing or update_all_existing) {
                            const index = random.uintLessThan(usize, tracked_accounts.count());
                            const key = tracked_accounts.keys()[index];
                            // only if the pubkey is not already in this slot
                            if (!pubkeys_this_slot.contains(key)) {
                                tracked_account.pubkey = key;
                            }
                        }
                        break :blk tracked_account.pubkey;
                    };

                    const account_shared_data = try tracked_account.toAccount(allocator);
                    defer account_shared_data.deinit(allocator);
                    try account_store.put(current_slot, pubkey, account_shared_data);

                    // always overwrite the old slot
                    try tracked_accounts.put(allocator, pubkey, tracked_account);
                    try pubkeys_this_slot.put(allocator, pubkey, {});
                }
            },
            .get => {
                const pubkey, const tracked_account = blk: {
                    const tracked_accounts, var tracked_accounts_lg =
                        tracked_accounts_rw.readWithLock();
                    defer tracked_accounts_lg.unlock();

                    const n_keys = tracked_accounts.count();
                    if (n_keys == 0) {
                        continue;
                    }
                    const index = random.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                    const key = tracked_accounts.keys()[index];

                    break :blk .{ key, tracked_accounts.get(key).? };
                };

                var ancestors_sub = try ancestors.clone(allocator);
                defer ancestors_sub.deinit(allocator);
                for (ancestors_sub.ancestors.keys()) |other_slot| {
                    if (other_slot <= tracked_account.slot) continue;
                    _ = ancestors_sub.ancestors.swapRemove(other_slot);
                }
                ancestors_sub.ancestors.sort(struct {
                    ancestors_sub: []Slot,
                    pub fn lessThan(ctx: @This(), a: usize, b: usize) bool {
                        return ctx.ancestors_sub[a] < ctx.ancestors_sub[b];
                    }
                }{ .ancestors_sub = ancestors_sub.ancestors.keys() });

                const account_reader_for_slot = account_store.reader().forSlot(&ancestors_sub);
                const account =
                    try account_reader_for_slot.get(allocator, pubkey) orelse {
                        logger.err().logf(
                            "accounts_db missing tracked account '{f}': {any}",
                            .{ pubkey, tracked_account },
                        );
                        return error.MissingAccount;
                    };
                defer account.deinit(allocator);

                const account_data = try account.data.readAllAllocate(allocator);
                defer allocator.free(account_data);

                if (!std.mem.eql(u8, account_data, &tracked_account.data)) {
                    logger.err().logf(
                        "found account {f} with different data: " ++
                            "tracked: {any} vs found: {any}\n",
                        .{ pubkey, tracked_account.data, account_data },
                    );
                    return error.TrackedAccountMismatch;
                }
            },
        }
    }

    logger.info().logf("fuzzing complete", .{});
}

fn readRandomAccounts(
    allocator: std.mem.Allocator,
    logger: Logger,
    account_reader: AccountReader,
    tracked_accounts_rw: *sig.sync.RwMux(TrackedAccountsMap),
    seed: u64,
    exit: *std.atomic.Value(bool),
    thread_id: usize,
) void {
    logger.debug().logf("started readRandomAccounts thread: {}", .{thread_id});
    defer logger.debug().logf("finishing readRandomAccounts thread: {}", .{thread_id});

    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();

    while (true) {
        if (exit.load(.seq_cst)) return;

        var pubkeys: [50]Pubkey = undefined;
        {
            const tracked_accounts, var tracked_accounts_lg = tracked_accounts_rw.readWithLock();
            defer tracked_accounts_lg.unlock();

            const tracked_pubkeys = tracked_accounts.keys();
            if (tracked_pubkeys.len == 0) {
                // wait for some accounts to exist
                std.Thread.sleep(std.time.ns_per_s);
                continue;
            }

            for (&pubkeys) |*pubkey| pubkey.* = blk: {
                const index = random.intRangeLessThan(usize, 0, tracked_pubkeys.len);
                break :blk tracked_pubkeys[index];
            };
        }

        for (pubkeys) |pubkey| {
            const account = account_reader.getLatest(allocator, pubkey) catch |e| {
                logger.err().logf("getAccount failed with error: {}", .{e});
                return;
            } orelse continue;
            defer account.deinit(allocator);
        }
    }
}

test run {
    if (true) return error.SkipZigTest; // flaky test

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try run(std.testing.allocator, .FOR_TESTS, std.testing.random_seed, tmp_dir.dir, .{
        .max_slots = 100,
        .non_sequential_slots = true,
    });
}
