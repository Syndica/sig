const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

const FastDiv = lib.util.FastDiv;

pub const Table = struct {
    seed: u64, // runtime-provided hashing seed (if wanting to help lower collision attacks)
    count: u32, // can represent 4-billion accounts (would need re-design after that)
    reducer: FastDiv, // for fast hash % entries.len
    entries: []Entry,

    pub const Key = Pubkey;
    pub const Value = packed struct(u64) {
        len: u24, // can address up to 16MB range
        offset: u40, // can address up to 1TB offset

        const empty: Value = .{ .len = 0, .offset = 0 };

        pub fn isEmpty(self: Value) bool {
            return @as(u64, @bitCast(self)) == @as(u64, @bitCast(empty));
        }
    };

    const Entry = extern struct { // 32-bytes, align(1) to ptrCast when stored in table.memory
        hash: [16]u8, // compressed repr of Key (0 = empty, u128 should be enough for no collisions)
        slot: u32 align(1), // can represent another 50yrs of 400ms slots from current mainnet
        idx: u32 align(1), // intermediary state for hash % num_entries
        value: Value align(1),
    };

    pub fn init(seed: u64, memory: []u8) Table {
        // NOTE: self.memory should already be zeroed from mmap
        const entries = std.mem.bytesAsSlice(Entry, memory);
        std.debug.assert(entries.len > 0);

        return .{
            .seed = seed,
            .count = 0,
            .reducer = .init(entries.len),
            .entries = entries,
        };
    }

    // Number of hash map probes to do together with ILP to amortize DRAM cache-miss latency.
    const PARALLEL_SCAN = 8;

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

    // hash % num_entries (based on xxh3 avalanche)
    fn reduceHash(self: *const Table, hash: u128) u32 {
        // merge both u64's in hash
        var acc = @as(u64, 0x9E3779B185EBCA87) *% @sizeOf(@TypeOf(hash));
        acc +%= @as([2]u64, @bitCast(hash))[0];
        acc +%= @as([2]u64, @bitCast(hash))[1];

        // avalanche across all bits
        acc ^= acc >> 37;
        acc *%= 0x165667919E3779F9;
        acc ^= acc >> 32;

        // reduce into item index
        const acc_mod_len = acc - (self.reducer.div(acc) * self.entries.len);
        std.debug.assert(acc_mod_len < self.entries.len);
        return @intCast(acc_mod_len);
    }

    pub const PutBatch = extern struct {
        len: u32,
        entries: [PARALLEL_SCAN]Entry,

        pub const empty: PutBatch = .{ .len = 0, .entries = undefined };
    };

    pub fn put(
        noalias self: *Table,
        noalias batch: *PutBatch,
        noalias pubkey: *const Pubkey,
        slot: Slot,
        value: Value,
    ) void {
        std.debug.assert(slot <= std.math.maxInt(u32));
        std.debug.assert(!value.isEmpty());

        const hash = self.hashPubkey(pubkey);
        std.debug.assert(hash != 0);

        std.debug.assert(batch.len < PARALLEL_SCAN);
        batch.entries[batch.len] = .{
            .hash = @bitCast(hash),
            .slot = @intCast(slot),
            .idx = self.reduceHash(hash),
            .value = value,
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
        batch.len = 0; // mark batch as flushed

        // phase-0: incomplete batch entries are zeroed out
        for (0..PARALLEL_SCAN) |i| {
            const mask: @Vector(32, bool) = @splat(i < batch_len);
            const put_vec: @Vector(32, i8) = @bitCast(batch.entries[i]); // i8 cmp has better codegen
            batch.entries[i] = @bitCast(@select(i8, mask, put_vec, put_vec - put_vec)); // x-x=0
        }

        // phase-1: gather map pointers
        var ptrs: [PARALLEL_SCAN][*]Entry = undefined;
        for (0..PARALLEL_SCAN) |i| {
            ptrs[i] = self.entries.ptr + batch.entries[i].idx;
        }

        // phase-2: parallel-loads of entries
        var curr: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            curr[i] = @bitCast(ptrs[i][0]); // start load of entry
            @prefetch(@as([*]u8, @ptrCast(ptrs[i])) + 64, .{}); // start fetching next probe cache line
        }

        // phase-3: parallel-probe of entries
        std.debug.assert(self.count < self.entries.len);
        while (true) {
            var has_collisions = false;
            for (0..PARALLEL_SCAN) |i| {
                const put_hash: @Vector(16, u8) = batch.entries[i].hash;
                const curr_hash = @as([2]@Vector(16, u8), @bitCast(curr[i]))[0];

                const zero: @Vector(16, u8) = @splat(0);
                const empty_mask = @select(u8, curr_hash == zero, ~zero, zero);
                const eq_mask = @select(u8, curr_hash == put_hash, ~zero, zero);

                // check for collisions (!eq and !empty = populated with unrelated entry)
                const collided = @reduce(.Or, (empty_mask | eq_mask) == zero);
                if (collided) has_collisions = true;

                // probe next item if collided
                ptrs[i] += @intFromBool(collided);
                if (ptrs[i] == self.entries.ptr + self.entries.len) ptrs[i] = self.entries.ptr;
                curr[i] = @bitCast(ptrs[i][0]);
            }
            if (!has_collisions) break;
        }

        // phase-4: insert into entries that are empty or have lower slots
        var stub: Entry = undefined;
        for (0..PARALLEL_SCAN) |i| {
            // empty curr has .slot=0 : always overwritten
            const newer_slot = @as(Entry, @bitCast(curr[i])).slot <= batch.entries[i].slot;

            const new_write = newer_slot and batch.entries[i].slot > 0;
            self.count +=  @intFromBool(new_write); // bump for empty inserts

            const ptr = if (newer_slot) &ptrs[i][0] else &stub;
            ptr.* = batch.entries[i];
        }
    }

    pub fn get(self: *const Table, pubkey: *const Pubkey) Value {
        const hash = self.hashPubkey(pubkey);
        std.debug.assert(hash != 0);

        var idx = self.reduceHash(hash);
        for (0..self.entries.len) |_| {
            const e = &self.entries[idx];
            idx +%= 1;
            if (idx >= self.entries.len) idx = 0; // cmov

            const e_hash: u128 = @bitCast(e.hash);
            if (e_hash == 0) {
                @branchHint(.unlikely); // looking up non-existing accounts is rare
                return .empty;
            }

            if (e_hash == hash) {
                std.debug.assert(!e.value.isEmpty());
                return e.value;
            }
        }

        unreachable; // table is full?
    }
};
