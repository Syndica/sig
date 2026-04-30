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
    put_queue_len: u32,
    put_queue: [PARALLEL_SCAN]Item,

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
            .put_queue_len = 0,
            .put_queue = undefined,
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

    fn hashPubkey(self: *const Table, pubkey: *const Pubkey) @Vector(16, u8) {
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

    fn reduceHash(self: *const Table, hash: @Vector(16, u8)) u32 {
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

    // TODO: not optimized for DRAM latency
    pub fn get(self: *const Table, pubkey: *const Pubkey) DiskEntry {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Table.get" });
        defer zone.deinit();

        std.debug.assert(self.put_queue_len == 0); // all put()s should be flushed by now.

        const hash = self.hashPubkey(pubkey);
        std.debug.assert(@reduce(.Or, hash) != 0);

        var ptr = self.items_ptr + self.reduceHash(hash);
        for (0..self.items_len) |_| {
            const item_hash: @Vector(16, u8) = ptr[0].hash;
            const item_entry = ptr[0].entry;

            ptr += 1;
            if (ptr == self.items_ptr + self.items_len) ptr = self.items_ptr;

            if (@reduce(.Or, item_hash) == 0) return .NULL;
            if (@reduce(.Or, item_hash == hash)) return item_entry;
        }

        unreachable; // map is full?
    }

    pub fn put(self: *Table, pubkey: *const Pubkey, slot: Slot, entry: DiskEntry) void {
        std.debug.assert(!entry.isNull());

        const hash = self.hashPubkey(pubkey);
        std.debug.assert(@reduce(.Or, hash) != 0);

        self.put_queue[self.put_queue_len] = .{
            .hash = hash,
            .slot = @intCast(slot),
            .idx = self.reduceHash(hash),
            .entry = entry,
        };

        self.put_queue_len += 1;
        if (self.put_queue_len == PARALLEL_SCAN) self.flushPuts();
    }

    pub fn flushPuts(self: *Table) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Db.Table.flushPuts" });
        defer zone.deinit();

        const put_len = self.put_queue_len;
        self.put_queue_len = 0;

        std.debug.assert(put_len <= PARALLEL_SCAN);
        if (put_len == 0) return;

        // phase-0: incomplete batch items are zeroed out
        for (0..PARALLEL_SCAN) |i| {
            const mask: @Vector(32, bool) = @splat(i < put_len);
            const put_vec: @Vector(32, i8) = @bitCast(self.put_queue[i]);
            self.put_queue[i] = @bitCast(@select(i8, mask, put_vec, put_vec - put_vec));
        }

        // phase-1: gather map pointers
        var ptrs: [PARALLEL_SCAN][*]align(1) Item = undefined;
        for (0..PARALLEL_SCAN) |i| {
            ptrs[i] = self.items_ptr + self.put_queue[i].idx;
        }

        // phase-2: parallel-loads of items
        var items: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            items[i] = @bitCast(ptrs[i][0]); // start load of entry
            @prefetch(@as([*]u8, @ptrCast(ptrs[i])) + 64, .{}); // start fetching next probe cache line
        }

        // phase-3: parallel-probe of items
        var had_collisions = true;
        while (had_collisions) {
            had_collisions = false;

            for (0..PARALLEL_SCAN) |i| {
                const put_hash: @Vector(16, u8) = self.put_queue[i].hash;
                const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];

                // check for collisions
                const zero: @Vector(16, u8) = @splat(0);
                const empty_mask = @select(u8, item_hash == zero, ~zero, zero);
                const eq_mask = @select(u8, item_hash == put_hash, ~zero, zero);
                const collided = @reduce(.Or, (empty_mask | eq_mask) == zero);

                if (collided) had_collisions = true;

                // probe next item if collided
                ptrs[i] += @intFromBool(collided);
                if (ptrs[i] == self.items_ptr + self.items_len) ptrs[i] = self.items_ptr;
                items[i] = @bitCast(ptrs[i][0]);
            }
        }

        // phase-4: map-insert those which land on empty
        var stub: Item = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const item_hash = @as([2]@Vector(16, u8), @bitCast(items[i]))[0];
            self.count += @intFromBool(@reduce(.Or, item_hash) == 0);

            const overwrite = @as(Item, @bitCast(items[i])).slot <= self.put_queue[i].slot;
            const ptr = if (overwrite) &ptrs[i][0] else &stub;
            ptr.* = self.put_queue[i];
        }
    }
};
