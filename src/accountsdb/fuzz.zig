const std = @import("std");
const sig = @import("../lib.zig");

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;
const GeyserWriter = sig.geyser.GeyserWriter;

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

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa_allocator.allocator();

    const logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    const use_disk = rand.boolean();
    const snapshot_dir = "test_data/accountsdb_fuzz";
    defer {
        // NOTE: sometimes this can take a long time so we print when we start and finish
        std.debug.print("deleting snapshot dir...\n", .{});
        std.fs.cwd().deleteTree(snapshot_dir) catch |err| {
            std.debug.print("failed to delete snapshot dir: {}\n", .{err});
        };
        std.debug.print("deleted snapshot dir\n", .{});
    }
    std.debug.print("use disk: {}\n", .{use_disk});

    var accounts_db = try AccountsDB.init(allocator, logger, .{
        .use_disk_index = use_disk,
        .snapshot_dir = snapshot_dir,
        // TODO: other things we can fuzz (number of bins, ...)
    });
    defer accounts_db.deinit(true);

    const exit = try allocator.create(std.atomic.Value(bool));
    exit.* = std.atomic.Value(bool).init(false);

    const manager_handle = try std.Thread.spawn(.{}, AccountsDB.runManagerLoop, .{
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

    var geyser = try GeyserWriter.init(allocator, "test_data/accountsdb_fuzz.pipe", null, .{});
    defer geyser.deinit();

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_actions) |max_actions| {
            if (slot >= max_actions) {
                std.debug.print("reached max actions: {}\n", .{max_actions});
                break;
            }
        }
        defer slot += 1;

        const action_int = rand.intRangeAtMost(u8, 0, 1);
        const action: Actions = @enumFromInt(action_int);

        switch (action) {
            .put => {
                const N_ACCOUNTS_PER_SLOT = 10;

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

                // send through geyser
                _ = try geyser.writePayload(.{ .AccountPayloadV1 = .{
                    .accounts = accounts,
                    .pubkeys = pubkeys,
                    .slot = slot,
                } });

                // write to accounts_db
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

    std.debug.print("fuzzing complete\n", .{});
    exit.store(true, .seq_cst);
    manager_handle.join();
}
