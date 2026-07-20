const std = @import("std");
const builtin = @import("builtin");
const lib = @import("../lib.zig");

const tracy = @import("tracy");

const AccountRef = lib.accounts_db.AccountPool.AccountRef;
const Pubkey = lib.solana.Pubkey;

/// Holds the accounts mutated for each tracked Block.
pub const Unrooted = extern struct {
    seed: u64,
    maps: [max_blocks]Map, // we could initialise with `= @splat(.{})`, but lld disagrees

    // [firedancer] https://github.com/firedancer-io/firedancer/blob/c2050b9c7fb8787b1eaaf9e50cac421a7281f70f/src/flamenco/runtime/fd_cost_tracker.h#L78
    // TODO: calculate this constant ourselves / keep it up to date
    //
    // Shrunk in test builds to keep the fixture memory footprint reasonable
    // (~4MiB total vs ~1.5GiB at production capacity).
    // TODO: Should we add comptime param to Unrooted for this? Does make code messy.
    const max_mutations_per_block: u32 = if (builtin.is_test) 1024 else 367_535;

    const max_blocks = lib.replay.BlockPool.capacity;

    const Map = extern struct {
        len: u32 = 0, // only used to assert `max_mutations_per_block` holds true
        data: [N]AccountRef = @splat(.invalid), // ~1.4MiB at production N

        // NOTE: might be a good idea to oversize this for performance reasons
        const N = max_mutations_per_block;

        fn EntryPtr(comptime SelfPtr: type) type {
            return switch (SelfPtr) {
                *Map => *AccountRef,
                *const Map => *const AccountRef,
                else => unreachable,
            };
        }

        fn entry(
            self: anytype,
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) EntryPtr(@TypeOf(self)) {
            var i: usize = @intCast(pubkey.hash(seed) % N);

            while (true) : (i = (i + 1) % N) {
                if (self.data[i] == .invalid)
                    return &self.data[i];
                if (pubkey.equals(&account_pool.getAccount(self.data[i]).pubkey))
                    return &self.data[i];
            }
        }

        pub fn get(
            self: *const Map,
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) AccountRef {
            return self.entry(seed, account_pool, pubkey).*;
        }

        // The map takes a ref to the new account.
        // Returns the replaced entry, which the caller is expected to unref/free.
        // Entries are replaced when an account of the inserted pubkey already exists in the map.
        // lint: allow_unused
        pub fn put(
            self: *Map,
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            new_account_ref: AccountRef,
        ) AccountRef {
            const zone = tracy.Zone.init(@src(), .{ .name = "Map.put" });
            defer zone.deinit();

            std.debug.assert(new_account_ref != .invalid);
            const new_account = account_pool.getAccount(new_account_ref);
            const pubkey: *const Pubkey = &new_account.pubkey;

            const found_entry: *AccountRef = self.entry(seed, account_pool, pubkey);

            // don't "replace" an accountref with itself!
            std.debug.assert(found_entry.* != new_account_ref);

            const old_account_ref = found_entry.*;
            if (old_account_ref != .invalid) {
                zone.text("replace");

                std.debug.assert(pubkey.equals(&account_pool.getAccount(old_account_ref).pubkey));
            } else {
                zone.text("insert");

                self.len += 1;
                if (self.len > max_mutations_per_block) @panic("max_mutations_per_block exceeded");
            }

            found_entry.* = new_account_ref;
            new_account.ref();

            return old_account_ref;
        }
    };

    pub fn init(self: *Unrooted) void {
        // TODO: create randomly + secretly at startup, to avoid performance degradation from
        //       attackers using pre-made keys to cause bad clustering
        self.seed = 123;
        for (&self.maps) |*map| map.* = .{};
    }

    /// Get an account purely from the unrooted store.
    /// For internal/testing usage only.
    /// NOTE: caller is responsible for freeing the account
    pub fn fetch(
        self: *Unrooted,
        key: *const lib.solana.Pubkey,

        // current block + pool for ancestor lookups
        block: lib.replay.BlockRef,
        block_pool: *lib.replay.BlockPool,

        // account storage
        account_pool: *lib.accounts_db.AccountPool,
    ) AccountRef {
        const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.fetch" });
        defer zone.deinit();

        var current: ?*lib.replay.Node = block.ptr(block_pool);
        while (current) |ancestor_block| {
            const current_map: *const Map =
                &self.maps[block_pool.ptrToIndex(ancestor_block).index()];

            const account_ref = current_map.get(self.seed, account_pool, key);
            if (account_ref != .invalid) {
                const account = account_pool.getAccount(account_ref);
                account.ref();

                zone.text("found");

                return account_ref;
            }
            current = if (ancestor_block.parent.opt()) |p| p.ptr(block_pool) else null;
        }

        return .invalid;
    }
};
