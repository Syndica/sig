const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Slot = lib.solana.Slot;
const Pubkey = lib.solana.Pubkey;

pub const Table = extern struct {
    seed: u64,
    reducer: lib.util.FastDiv,
    count: u64,
    items_ptr: [*]align(1) Item,
    items_len: u32,

    // Number of probes to do in parallel when accessing items. Optimized to amortize DRAM latency.
    const PARALLEL_SCAN = 8;

    const Item = extern struct {
        hash: [16]u8,
        slot: u32, // can represent another 50yrs of 400ms slots from current mainnet
        idx: u32, // the reduced self.items index of the hash
        entry: DiskEntry,
    };

    pub fn init(seed: u64, memory: []u8) Table {
        const items = std.mem.bytesAsSlice(Item, memory);
        return .{
            .seed = seed,
            .reducer = .init(items.len),
            .count = 0,
            .items_ptr = items.ptr,
            .items_len = @intCast(items.len),
        };
    }

    pub const DiskEntry = packed struct(u64) {
        len: u24,
        offset: u40,

        pub const NULL: DiskEntry = .{ .len = 0, .offset = 0 };
        pub fn isNull(self: DiskEntry) bool {
            return @as(u64, @bitCast(self)) == 0;
        }
    };

    fn hashPubkey(self: *const Table, pubkey: *const Pubkey) u128 {
        // based on xxh3 / rapidhash / wyhash mixing
        const s: [4]u64 = .{
            0xbe4ba423396cfeb8,
            0x1cad21f72c81017c,
            0xdb979083e96dd4de,
            0x1f67b3b7a4a44072,
        };
        const seed = self.seed;
        const in: [4]u64 = @bitCast(pubkey.data);
        const a: [2]u64 = @bitCast(@as(u128, in[0] ^ (s[0] +% seed)) * (in[1] ^ (s[1] -% seed)));
        const b: [2]u64 = @bitCast(@as(u128, in[2] ^ (s[2] +% seed)) * (in[3] ^ (s[3] -% seed)));
        return @bitCast([2]u64{ a[0] ^ a[1], b[0] ^ b[1] });
    }

    fn reduceHash(self: *const Table, hash: u128) u32 {
        // merge both u64's in hash
        var acc = @as(u64, 0x9E3779B185EBCA87) *% 16;
        acc +%= @as([2]u64, @bitCast(hash))[0];
        acc +%= @as([2]u64, @bitCast(hash))[1];

        // avalanche across all bits
        acc ^= acc >> 37;
        acc *%= 0x165667919E3779F9;
        acc ^= acc >> 32;

        // reduce into item index
        const acc_mod_len = acc - (self.reducer.div(acc) * self.items_len);
        std.debug.assert(acc_mod_len < self.items_len);
        return @intCast(acc_mod_len);
    }

    pub const PutBatch = extern struct {
        len: u32,
        items: [PARALLEL_SCAN]Item,

        pub const empty: PutBatch = .{ .len = 0, .items = undefined };
    };

    pub fn put(
        noalias self: *Table,
        noalias batch: *PutBatch,
        noalias pubkey: *const Pubkey,
        slot: Slot,
        entry: DiskEntry,
    ) void {
        const hash = self.hashPubkey(pubkey);
        std.debug.assert(hash != 0);
        std.debug.assert(!entry.isNull());
        std.debug.assert(batch.len < PARALLEL_SCAN);

        batch.items[batch.len] = .{
            .hash = @bitCast(hash),
            .slot = @intCast(slot),
            .idx = self.reduceHash(hash),
            .entry = entry,
        };

        batch.len += 1;
        if (batch.len == PARALLEL_SCAN) self.flushPuts(batch);
    }

    pub fn flushPuts(noalias self: *Table, noalias batch: *PutBatch) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Table.flushPuts" });
        defer zone.deinit();

        const batch_len = batch.len;
        std.debug.assert(batch_len <= PARALLEL_SCAN);
        if (batch_len == 0) return;
        batch.len = 0;

        // phase-0: incomplete batch items are zeroed out
        for (0..PARALLEL_SCAN) |i| {
            const mask: @Vector(32, bool) = @splat(i < batch_len);
            const put_vec: @Vector(32, i8) = @bitCast(batch.items[i]);
            batch.items[i] = @bitCast(@select(i8, mask, put_vec, put_vec - put_vec));
        }

        // phase-1: gather map pointers
        var ptrs: [PARALLEL_SCAN][*]align(1) Item = undefined;
        for (0..PARALLEL_SCAN) |i| {
            ptrs[i] = self.items_ptr + batch.items[i].idx;
        }

        // phase-2: parallel-loads of items
        var items: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            items[i] = @bitCast(ptrs[i][0]); // start load of entry
            @prefetch(@as([*]u8, @ptrCast(ptrs[i])) + 64, .{}); // start fetching next probe cache line
        }

        // phase-3: parallel-probe of items
        std.debug.assert(self.count < self.items_len);
        while (true) {
            var has_collisions = false;
            for (0..PARALLEL_SCAN) |i| {
                const put_hash: @Vector(16, u8) = batch.items[i].hash;
                const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];

                // check for collisions
                const zero: @Vector(16, u8) = @splat(0);
                const empty_mask = @select(u8, item_hash == zero, ~zero, zero);
                const eq_mask = @select(u8, item_hash == put_hash, ~zero, zero);
                const collided = @reduce(.Or, (empty_mask | eq_mask) == zero);
                if (collided) has_collisions = true;

                // probe next item if collided
                ptrs[i] += @intFromBool(collided);
                if (ptrs[i] == self.items_ptr + self.items_len) ptrs[i] = self.items_ptr;
                items[i] = @bitCast(ptrs[i][0]);
            }
            if (!has_collisions) break;
        }

        // phase-4: overwrite items that are empty or have lower slots
        var stub: Item = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];
            self.count += @intFromBool(@reduce(.Or, item_hash) == 0);

            const overwrite = @as(Item, @bitCast(items[i])).slot <= batch.items[i].slot;
            const ptr = if (overwrite) &ptrs[i][0] else &stub;
            ptr.* = batch.items[i];
        }
    }

    pub const GetBatch = extern struct {
        len: u32,
        queue: extern union {
            in: extern struct {
                idx: [PARALLEL_SCAN]u32,
                hash: [PARALLEL_SCAN][16]u8,
            },
            out: [PARALLEL_SCAN]DiskEntry,
        },

        pub const empty: GetBatch = .{ .len = 0, .queue = undefined };
    };

    /// Returns number of items flushed if any
    pub fn get(
        noalias self: *const Table,
        noalias batch: *GetBatch,
        noalias pubkey: *const Pubkey,
    ) u32 {
        const hash = self.hashPubkey(pubkey);
        std.debug.assert(hash != 0);
        std.debug.assert(batch.len < PARALLEL_SCAN);

        batch.queue.in.hash[batch.len] = @bitCast(hash);
        batch.queue.in.idx[batch.len] = self.reduceHash(hash);

        batch.len += 1;
        if (batch.len == PARALLEL_SCAN) return self.flushGets(batch);
        return 0;
    }

    /// Reads all the queries prepared in batch.queue.in and writes out their res in batch.queue.out
    /// returning the batch.len. Caller must reset it for future .get()s
    pub fn flushGets(noalias self: *const Table, noalias batch: *GetBatch) u32 {
        const zone = tracy.Zone.init(@src(), .{ .name = "Table.flushGets" });
        defer zone.deinit();

        const batch_len = batch.len;
        std.debug.assert(batch_len <= PARALLEL_SCAN);
        if (batch_len == 0) return 0;

        // phase-0/1: gather map pointers & hashes (incomplete items are zeroed out)
        var hashes: [PARALLEL_SCAN]@Vector(16, u8) = undefined;
        var ptrs: [PARALLEL_SCAN][*]align(1) Item = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const valid = i < batch_len;
            const idx = batch.queue.in.idx[i] * @intFromBool(valid);
            ptrs[i] = self.items_ptr + idx;

            const mask: @Vector(16, bool) = @splat(valid);
            const get_vec: @Vector(16, u8) = @bitCast(batch.queue.in.hash[i]);
            hashes[i] = @select(u8, mask, get_vec, get_vec - get_vec);
        }

        // phase-2: parallel-loads of items
        var items: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            items[i] = @bitCast(ptrs[i][0]); // start load of entry
            @prefetch(@as([*]u8, @ptrCast(ptrs[i])) + 64, .{}); // start fetching next probe cache line
        }

        // phase-3: parallel-probe of items
        std.debug.assert(self.count < self.items_len);
        while (true) {
            var has_collisions = false;
            for (0..PARALLEL_SCAN) |i| {
                const get_hash: @Vector(16, u8) = hashes[i];
                const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];

                // check for collisions
                const zero: @Vector(16, u8) = @splat(0);
                const empty_mask = @select(u8, item_hash == zero, ~zero, zero);
                const eq_mask = @select(u8, item_hash == get_hash, ~zero, zero);
                const collided = @reduce(.Or, (empty_mask | eq_mask) == zero);
                if (collided) has_collisions = true;

                // probe next item if collided
                ptrs[i] += @intFromBool(collided);
                if (ptrs[i] == self.items_ptr + self.items_len) ptrs[i] = self.items_ptr;
                items[i] = @bitCast(ptrs[i][0]);
            }
            if (!has_collisions) break;
        }

        for (0..PARALLEL_SCAN) |i| {
            const get_hash: @Vector(16, u8) = hashes[i];
            const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];
            var item_entry: u64 = @bitCast(@as(Item, @bitCast(items[i])).entry);

            const exists = @reduce(.And, get_hash == item_hash);
            item_entry *= @intFromBool(exists);
            batch.queue.out[i] = @bitCast(item_entry);
        }

        return batch_len;
    }
};
