const std = @import("std");

const sig = @import("../lib.zig");

const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Blake3 = std.crypto.hash.Blake3;

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Hash = sig.core.hash.Hash;
const Slot = sig.core.time.Slot;
const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;

const sysvars = sig.accounts_db.sysvars;
const AccountsDbFields = sig.accounts_db.snapshots.AccountsDbFields;
const AccountFileInfo = sig.accounts_db.snapshots.AccountFileInfo;
const AccountFile = sig.accounts_db.accounts_file.AccountFile;
const FileId = sig.accounts_db.accounts_file.FileId;
const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const SnapshotFields = sig.accounts_db.snapshots.SnapshotFields;
const BankIncrementalSnapshotPersistence = sig.accounts_db.snapshots.BankIncrementalSnapshotPersistence;
const AllSnapshotFields = sig.accounts_db.snapshots.AllSnapshotFields;
const SnapshotFieldsAndPaths = sig.accounts_db.snapshots.SnapshotFieldsAndPaths;
const SnapshotFiles = sig.accounts_db.snapshots.SnapshotFiles;
const Bank = sig.accounts_db.bank.Bank;
const AccountIndex = sig.accounts_db.index.AccountIndex;
const AccountRef = sig.accounts_db.index.AccountRef;
const DiskMemoryAllocator = sig.accounts_db.index.DiskMemoryAllocator;
const parallelUnpackZstdTarBall = sig.accounts_db.snapshots.parallelUnpackZstdTarBall;

const MAX_FUZZ_TIME = std.time.ns_per_s * 100_000;

pub const TrackedAccount = struct {
    pubkey: Pubkey,
    slot: u64,
    data: []u8,

    pub fn random(rand: std.rand.Random, slot: Slot, allocator: std.mem.Allocator) !TrackedAccount {
        return .{
            .pubkey = Pubkey.random(rand),
            .slot = slot,
            .data = try allocator.alloc(u8, 32),
        };
    }

    pub fn deinit(self: *TrackedAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn toAccount(self: *const TrackedAccount, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = 19,
            .data = try allocator.dupe(u8, self.data),
            .owner = Pubkey.default(),
            .executable = false,
            .rent_epoch = 0,
        };
    }
};

pub fn run(args: *std.process.ArgIterator) !void {
    _ = args;

    const seed = std.crypto.random.int(u64);
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();
    std.debug.print("seed: {}\n", .{seed});

    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa_allocator.allocator();

    const logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    const use_disk = rand.boolean();
    const snapshot_dir = "test_data/accountsdb_fuzz";
    defer {
        std.fs.cwd().deleteTree(snapshot_dir) catch |err| {
            std.debug.print("failed to delete snapshot dir: {}\n", .{err});
        };
    }
    std.debug.print("use disk: {}\n", .{use_disk});

    var accounts_db = try AccountsDB.init(allocator, logger, .{
        .use_disk_index = use_disk,
        .snapshot_dir = snapshot_dir,
    });
    defer accounts_db.deinit(true);

    const exit = try allocator.create(std.atomic.Value(bool));
    exit.* = std.atomic.Value(bool).init(false);

    var handle = try std.Thread.spawn(.{}, AccountsDB.runManagerLoop, .{
        &accounts_db,
        exit,
    });

    var tracked_accounts = std.AutoArrayHashMap(Pubkey, TrackedAccount).init(allocator);
    defer {
        for (tracked_accounts.keys()) |key| {
            tracked_accounts.getEntry(key).?.value_ptr.deinit(allocator);
        }
        tracked_accounts.deinit();
    }
    try tracked_accounts.ensureTotalCapacity(10_000);

    var largest_rooted_slot: usize = 0;
    var slot: usize = 0;

    const Actions = enum { put, get };

    // get/put a bunch of accounts
    var timer = try std.time.Timer.start();
    while (timer.read() < MAX_FUZZ_TIME) {
        defer slot += 1;

        const action_int = rand.intRangeAtMost(u8, 0, 1);
        const action: Actions = @enumFromInt(action_int);

        switch (action) {
            .put => {
                const N_ACCOUNTS_PER_SLOT = 5;

                const accounts = try allocator.alloc(Account, N_ACCOUNTS_PER_SLOT);
                const pubkeys = try allocator.alloc(Pubkey, N_ACCOUNTS_PER_SLOT);

                for (0..N_ACCOUNTS_PER_SLOT) |i| {
                    var tracked_account = try TrackedAccount.random(rand, slot, allocator);

                    const existing_pubkey = rand.boolean();
                    if (existing_pubkey and tracked_accounts.count() > 0) {
                        const index = rand.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                        const key = tracked_accounts.keys()[index];
                        tracked_account.pubkey = key;
                    }

                    accounts[i] = try tracked_account.toAccount(allocator);
                    pubkeys[i] = tracked_account.pubkey;

                    const r = try tracked_accounts.getOrPut(tracked_account.pubkey);
                    if (r.found_existing) {
                        r.value_ptr.deinit(allocator);
                    }
                    // always overwrite the old slot
                    r.value_ptr.* = tracked_account;
                }

                try accounts_db.putAccountSlice(
                    accounts,
                    pubkeys,
                    slot,
                );
            },
            .get => {
                const n_keys = tracked_accounts.count();
                if (n_keys == 0) {
                    continue;
                }
                const index = rand.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                const key = tracked_accounts.keys()[index];

                const tracked_account = tracked_accounts.get(key).?;
                var account = try accounts_db.getAccount(&tracked_account.pubkey);
                defer account.deinit(allocator);

                if (!std.mem.eql(u8, tracked_account.data, account.data)) {
                    @panic("found accounts with different data");
                }
            },
        }

        const create_new_root = rand.boolean();
        if (create_new_root) {
            largest_rooted_slot = @min(slot, largest_rooted_slot + 2);
            accounts_db.largest_root_slot.store(largest_rooted_slot, .seq_cst);
        }
    }

    exit.store(true, .seq_cst);
    handle.join();
}
