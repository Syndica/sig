const std = @import("std");
const sig = @import("../lib.zig");

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;
const Account = sig.core.Account;
const Slot = sig.core.time.Slot;
const Pubkey = sig.core.pubkey.Pubkey;

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

    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const logger = Logger.init(gpa, .debug);
    defer logger.deinit();
    logger.spawn();

    const use_disk = rand.boolean();

    const test_data_dir_path = "test_data";
    const snapshot_dir_name = "accountsdb_fuzz";
    const snapshot_dir_path = test_data_dir_path ++ "/" ++ snapshot_dir_name;

    var test_data_dir = try std.fs.cwd().makeOpenPath("test_data", .{});
    defer test_data_dir.close();

    var snapshot_dir = try test_data_dir.makeOpenPath(snapshot_dir_name, .{});
    defer snapshot_dir.close();
    // defer {
    //     // NOTE: sometimes this can take a long time so we print when we start and finish
    //     std.debug.print("deleting snapshot dir...\n", .{});
    //     test_data_dir.deleteTree(snapshot_dir_name) catch |err| {
    //         std.debug.print("failed to delete snapshot dir ('{s}'): {}\n", .{ snapshot_dir_name, err });
    //     };
    //     std.debug.print("deleted snapshot dir\n", .{});
    // }
    std.debug.print("use disk: {}\n", .{use_disk});

    var accounts_db = try AccountsDB.init(gpa, logger, .{
        .use_disk_index = use_disk,
        .snapshot_dir = snapshot_dir_path,
        // TODO: other things we can fuzz (number of bins, ...)
    });
    defer accounts_db.deinit(true);

    const exit = try gpa.create(std.atomic.Value(bool));
    // defer gpa.destroy(exit);
    exit.* = std.atomic.Value(bool).init(false);

    const manager_handle = try std.Thread.spawn(.{}, AccountsDB.runManagerLoop, .{
        &accounts_db,
        exit,
    });

    var tracked_accounts = std.AutoArrayHashMap(Pubkey, TrackedAccount).init(gpa);
    defer tracked_accounts.deinit();
    defer for (tracked_accounts.values()) |*value| {
        value.deinit(gpa);
    };
    try tracked_accounts.ensureTotalCapacity(10_000);

    var largest_rooted_slot: usize = 0;
    var slot: usize = 0;

    // get/put a bunch of accounts
    while (true) {
        if (maybe_max_actions) |max_actions| {
            if (slot >= max_actions) {
                std.debug.print("reached max actions: {}\n", .{max_actions});
                break;
            }
        }
        defer slot += 1;

        const Action = enum { put, get };
        const action: Action = rand.enumValue(Action);

        switch (action) {
            .put => {
                const N_ACCOUNTS_PER_SLOT = 10;

                var accounts: [N_ACCOUNTS_PER_SLOT]Account = undefined;
                var pubkeys: [N_ACCOUNTS_PER_SLOT]Pubkey = undefined;

                for (&accounts, &pubkeys) |*account, *pubkey| {
                    var tracked_account = try TrackedAccount.random(rand, slot, gpa);

                    const existing_pubkey = rand.boolean();
                    if (existing_pubkey and tracked_accounts.count() > 0) {
                        const index = rand.intRangeAtMost(usize, 0, tracked_accounts.count() - 1);
                        const key = tracked_accounts.keys()[index];
                        tracked_account.pubkey = key;
                    }

                    account.* = try tracked_account.toAccount(gpa);
                    pubkey.* = tracked_account.pubkey;

                    const r = try tracked_accounts.getOrPut(tracked_account.pubkey);
                    if (r.found_existing) {
                        r.value_ptr.deinit(gpa);
                    }
                    // always overwrite the old slot
                    r.value_ptr.* = tracked_account;
                }

                try accounts_db.putAccountSlice(
                    &accounts,
                    &pubkeys,
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
                defer account.deinit(gpa);

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
