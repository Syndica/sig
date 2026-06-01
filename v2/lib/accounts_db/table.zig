const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

const FastDiv = lib.util.FastDiv;

pub const Table = struct {
    seed: u64, // runtime-provided hashing seed (if wanting to help lower collision attacks)
    count: u64, // number of entries present in the table
    reducer: FastDiv, // for fast hash % entries.len
    num_entries: u64,
    mapped: []align(std.heap.page_size_min) u8,
    zero_entry: Entry, // special case for a valid zero pubkey

    const Entry = extern struct {
        key: Key align(1),
        value: Value align(1),
        slot: u32 align(1), // can represent another 50yrs of 400ms slots from current mainnet

        comptime {
            std.debug.assert(@alignOf(Entry) == 1);
        }
    };

    pub const Key = Pubkey;
    pub const Value = packed struct(u64) {
        len: u24, // can address up to 16MB range
        offset: u40, // can address up to 1TB offset

        const empty: Value = .{ .len = 0, .offset = 0 };

        pub fn isEmpty(self: Value) bool {
            return @as(u64, @bitCast(self)) == @as(u64, @bitCast(empty));
        }
    };

    pub fn init(seed: u64, memory_len: usize) !Table {
        const num_entries = @divFloor(memory_len, @sizeOf(Entry));
        std.debug.assert(num_entries > 0);

        const huge_page_size = 1 * 1024 * 1024 * 1024; // assume the max
        const huge_page_aligned = std.mem.alignForward(
            usize,
            num_entries * @sizeOf(Entry),
            huge_page_size,
        );

        // NOTE: memory should already be zeroed from mmap
        const mapped = try std.posix.mmap(
            null,
            huge_page_aligned,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .HUGETLB = true, .POPULATE = true },
            -1,
            0,
        );
        errdefer std.posix.munmap(mapped);

        return .{
            .seed = seed,
            .count = 0,
            .reducer = .init(num_entries),
            .num_entries = num_entries,
            .mapped = mapped,
            .zero_entry = .{ .key = .ZEROES, .value = .empty, .slot = 0 },
        };
    }

    pub fn deinit(self: *const Table) void {
        std.posix.munmap(self.mapped);
    }

    // Number of hash map probes to do together with ILP to amortize DRAM cache-miss latency.
    const PARALLEL_SCAN = 8;

    pub const PutBatch = extern struct {
        len: u32,
        items: [PARALLEL_SCAN]Entry,

        pub const empty: PutBatch = .{ .len = 0, .items = undefined };
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

        // We use a zero pubkey in the map to denote empty Entry.
        // If actualy inserting to the zero pubkey, update the one in the table instead.
        if (pubkey.isZeroed()) {
            @branchHint(.unlikely); // zero pubkey is System Program. Should rarely be written.
            if (slot >= self.zero_entry.slot) self.zero_entry.value = value;
            return;
        }

        std.debug.assert(batch.len <= PARALLEL_SCAN);
        if (batch.len == PARALLEL_SCAN) {
            @branchHint(.unlikely);
            self.flushPuts(batch);
        }

        batch.items[batch.len] = .{
            .key = pubkey.*,
            .value = value,
            .slot = @intCast(slot),
        };
        batch.len += 1;
    }

    pub fn flushPuts(noalias self: *Table, noalias batch: *PutBatch) void {
        const batch_len = batch.len;
        std.debug.assert(batch_len <= PARALLEL_SCAN);
        if (batch_len == 0) return;
        batch.len = 0; // mark as flushed

        // table should never fill up fully (means it shouldve been given more memory)
        const entries: []Entry = @ptrCast(self.mapped[0..self.num_entries * @sizeOf(Entry)]);
        std.debug.assert(self.count + batch_len < entries.len);

        // phase-0: zero out unused batch items
        const zero: @Vector(32, u8) = @splat(0);
        var item_keys: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const valid: @Vector(32, bool) = @splat(i < batch_len);
            const key: @Vector(32, u8) = @bitCast(batch.items[i].key);
            item_keys[i] = @bitCast(@select(u8, valid, key, zero)); // valid ? key : 0
        }

        // phase-1: hash pubkeys into table entry pointers
        var ptrs: [PARALLEL_SCAN][*]Entry = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const pubkey: Pubkey = @bitCast(item_keys[i]);
            ptrs[i] = entries.ptr + self.hashKeyToIndex(&pubkey);
        }
        
        // phase-2: parallel-loads of entries
        var keys: [PARALLEL_SCAN]@Vector(32, u8) = undefined;
        for (0..PARALLEL_SCAN) |i| {
            keys[i] = @bitCast(ptrs[i][0].key);
        }

        // phase-3: parallel-probe of entries
        while (true) {
            var had_collision = false;
            for (0..PARALLEL_SCAN) |i| {
                const item_key = item_keys[i];
                const empty_mask = @select(u8, keys[i] == zero, ~zero, zero);
                const eq_mask = @select(u8, keys[i] == item_key, ~zero, zero);

                // check for collisions (!eq and !empty = populated with unrelated entry)
                const collided = @reduce(.Or, (empty_mask | eq_mask) == zero);
                if (collided) had_collision = true;

                // probe next item if collided
                ptrs[i] += @intFromBool(collided);
                if (ptrs[i] == entries.ptr + entries.len) ptrs[i] = entries.ptr;
                keys[i] = @bitCast(ptrs[i][0].key);
            }
            if (!had_collision) break;
        }

        // phase-4: do the updates
        var stub: Entry = undefined;
        for (0..PARALLEL_SCAN) |i| {
            const item_slot = batch.items[i].slot;
            const newer_slot = @intFromBool(item_slot >= ptrs[i][0].slot);
            
            const item_key: Pubkey = @bitCast(item_keys[i]);
            const valid = @intFromBool(!item_key.isZeroed());

            const overwrite = valid & newer_slot;
            const was_empty = @intFromBool(ptrs[i][0].key.isZeroed());
            self.count += overwrite & was_empty;

            const dst = if (overwrite > 0) &ptrs[i][0] else &stub;
            dst.* = .{
                .key = item_key,
                .slot = item_slot,
                .value = batch.items[i].value,
            };
        }
    }

    pub fn get(self: *const Table, pubkey: *const Pubkey) Value {
        // We use a zero pubkey in the map to denote empty Entry.
        // If actualy fetching from the zero pubkey, access the one in the table instead.
        if (pubkey.isZeroed()) {
            @branchHint(.unlikely); // zero pubkey is System Program, which is hopefully cached.
            return self.zero_entry.value;
        }

        const entries: []Entry = @ptrCast(self.mapped[0..self.num_entries * @sizeOf(Entry)]);
        var ptr = entries.ptr + self.hashKeyToIndex(pubkey);
        while (true) {
            // load the entry values out
            const key = ptr[0].key;
            const value = ptr[0].value;

            // branchless increment
            ptr += 1;
            if (ptr == entries.ptr + entries.len) ptr = entries.ptr;

            // branch out for empty (looking up unfound accounts is rare)
            if (key.isZeroed()) {
                @branchHint(.unlikely);
                return .empty;
            }

            // branch back to loop on collision (entry, but not matching one)
            if (key.equals(pubkey)) {
                std.debug.assert(!value.isEmpty());
                return value;
            }
        }
    }

    fn hashKeyToIndex(self: *const Table, pubkey: *const Pubkey) u64 {
        // based on xxh3 / rapidhash / wyhash mixing
        const sd = self.seed;
        const sk: [4]u64 = .{
            0xbe4ba423396cfeb8,
            0x1cad21f72c81017c,
            0xdb979083e96dd4de,
            0x1f67b3b7a4a44072,
        };
        
        // XXH3_mix16B
        const in: [4]u64 = @bitCast(pubkey.*);
        const a: [2]u64 = @bitCast(@as(u128, in[0] ^ (sk[0] +% sd)) * (in[1] ^ (sk[1] -% sd)));
        const b: [2]u64 = @bitCast(@as(u128, in[2] ^ (sk[2] +% sd)) * (in[3] ^ (sk[3] -% sd)));
        
        // XXH3_len_17to128_64b
        var acc = @as(u64, 0x9E3779B185EBCA87) *% 32;
        acc +%= a[0] ^ a[1];
        acc +%= b[0] ^ b[1];

        // XXH3_avalanche
        acc ^= acc >> 37;
        acc *%= 0x165667919E3779F9;
        acc ^= acc >> 32;

        // reduce into table index
        const acc_mod_len = acc - (self.reducer.div(acc) * self.num_entries);
        std.debug.assert(acc_mod_len < self.num_entries);
        return acc_mod_len;
    }
};

