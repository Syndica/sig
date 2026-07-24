const std = @import("std");

const lib = @import("../lib.zig");
const tracy = @import("tracy");

const replay = lib.replay;

const Pubkey = lib.solana.Pubkey;
const AccountRef = lib.accounts_db.AccountPool.AccountRef;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/c2050b9c7fb8787b1eaaf9e50cac421a7281f70f/src/flamenco/runtime/fd_cost_tracker.h#L78
// TODO: calculate this constant ourselves / keep it up to date
pub const Unrooted = UnrootedType(.{
    .max_blocks = lib.replay.BlockPool.capacity,
    .max_mutations_per_block = 367_535,
});

pub const Config = struct {
    max_blocks: usize,
    max_mutations_per_block: usize,
};

/// Holds the accounts mutated for each tracked Block.
pub fn UnrootedType(comptime config: Config) type {
    return extern struct {
        const Self = @This();

        pub const max_blocks = config.max_blocks;
        pub const max_mutations_per_block = config.max_mutations_per_block;

        seed: u64,
        maps: [max_blocks]Map, // we could initialise with `= @splat(.{})`, but lld disagrees

        const Map = extern struct {
            len: u32 = 0, // only used to assert `max_mutations_per_block` holds true
            data: [max_mutations_per_block]AccountRef = @splat(.invalid),

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
                var i: usize = @intCast(pubkey.hash(seed) % max_mutations_per_block);

                while (true) : (i = (i + 1) % max_mutations_per_block) {
                    if (self.data[i] == .invalid)
                        return &self.data[i];
                    if (pubkey.equals(&account_pool.getAccount(self.data[i]).pubkey))
                        return &self.data[i];
                }
            }

            fn get(
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
            fn put(
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

        pub fn init(self: *Self) void {
            // TODO: create randomly + secretly at startup, to avoid performance degradation from
            //       attackers using pre-made keys to cause bad clustering
            self.seed = 123;
            for (&self.maps) |*map| map.* = .{};
        }

        /// Get an account purely from the unrooted store.
        /// For internal/testing usage only.
        /// NOTE: caller is responsible for freeing the account
        pub fn fetch(
            self: *Self,
            key: *const lib.solana.Pubkey,

            // current block + pool for ancestor lookups
            block: lib.replay.BlockRef,
            block_pool: *lib.replay.BlockPool,

            // account storage
            account_pool: *lib.accounts_db.AccountPool,
        ) AccountRef {
            const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.fetch" });
            defer zone.deinit();

            var current: ?*replay.Node = block.ptr(block_pool);
            while (current) |ancestor_block| {
                const block_index = block_pool.ptrToIndex(ancestor_block).index();
                std.debug.assert(block_index < max_blocks);

                const current_map: *const Map = &self.maps[block_index];

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
}
