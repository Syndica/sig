const std = @import("std");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

const FastDiv = lib.util.FastDiv;

pub const Table = struct {
    seed: u64, // runtime-provided hashing seed (to help decrease chance of collision attacks)
    size: u64, // number of entries present in the table (including the zero_entry)
    zero_entry: Entry, // special cased Value for the zero Key (given 0 is empty for Entry)
    reducer: FastDiv, // for fast hash % capacity
    entries: []Entry,

    // Need to store the slot as put()s from the snapshot can appear out of slot-order.
    // Slot could be u32 here (as its enough to represent another 50yrs of 400ms mainnet slots),
    // but keeping it u64 allows separate slot/value access to be done in single simd operations.
    const Entry = extern struct {
        key: Key,
        slot: Slot align(1),
        value: Value align(1),

        // Must be all zeroes: see init()
        const empty: Entry = .{ .key = .ZEROES, .slot = 0, .value = .empty };

        comptime {
            std.debug.assert(@alignOf(Entry) == 1);
        }
    };

    pub const Key = Pubkey;
    pub const Value = packed struct(u64) {
        len: u24, // can address up to 16MB range
        offset: u40, // can address up to 1TB offset

        // Must be all zeroes: see get().
        const empty: Value = .{ .len = 0, .offset = 0 };

        pub fn isEmpty(self: Value) bool {
            return @as(u64, @bitCast(self)) == @as(u64, @bitCast(empty));
        }
    };

    /// Initializes the table using the provided memory.
    /// Relies on the memory already being zero-initialized (default property of mmap).
    pub fn init(seed: u64, memory: []u8) Table {
        const capacity = @divFloor(memory.len, @sizeOf(Entry));
        std.debug.assert(capacity > 1);

        return .{
            .seed = seed,
            .size = 0,
            .zero_entry = .empty,
            .reducer = .init(capacity),
            .entries = std.mem.bytesAsSlice(Entry, memory[0 .. capacity * @sizeOf(Entry)]),
        };
    }

    pub fn count(self: *const Table) u64 {
        return self.size;
    }

    // Number of hash map probes to do together with memory-level-parallelism (MLP)
    // to amortize DRAM cache-miss latency when accessing random table locations.
    const PARALLEL_SCAN = 16;

    pub const PutBatch = extern struct {
        len: u32,
        entries: [PARALLEL_SCAN]Entry,

        pub const empty: PutBatch = .{
            .len = 0,
            .entries = @splat(.empty),
        };
    };

    pub fn put(
        noalias self: *Table,
        noalias batch: *PutBatch,
        noalias pubkey: *const Pubkey,
        slot: Slot,
        value: Value,
    ) void {
        std.debug.assert(!value.isEmpty());
        std.debug.assert(batch.len <= PARALLEL_SCAN);

        // We use a zero pubkey in the map to denote empty Entry.
        // If actualy putting to the zero pubkey, access the one in the table instead.
        if (pubkey.isZeroed()) {
            @branchHint(.unlikely); // zero pubkey is System Program, which is rarely modified.
            if (slot >= self.zero_entry.slot) {
                // Bump size on first populate
                self.size += @intFromBool(self.zero_entry.value.isEmpty());
                self.zero_entry = .{ .key = .ZEROES, .slot = slot, .value = value };
            }
            return;
        }

        if (batch.len == PARALLEL_SCAN) {
            @branchHint(.unlikely);
            self.flushPuts(batch);
        }

        batch.entries[batch.len] = .{ .key = pubkey.*, .slot = slot, .value = value };
        batch.len += 1;
    }

    pub fn flushPuts(noalias self: *Table, noalias batch: *PutBatch) void {
        const batch_len = batch.len;
        if (batch_len == 0) return;
        std.debug.assert(batch_len <= PARALLEL_SCAN);

        // mark as flushed at the end.
        defer batch.* = .empty;

        // table should never be near full (means it shouldve been given more memory)
        std.debug.assert(self.size + batch_len < self.entries.len);

        // phase-1: compute table locations from the keys and prefetch them upfront for probing
        var ptrs: [PARALLEL_SCAN][*]Entry = undefined;
        for (0..PARALLEL_SCAN) |i| {
            ptrs[i] = self.entries.ptr + self.hashToIndex(&batch.entries[i].key);
            @prefetch(ptrs[i], .{});
        }

        // phase-2: do the probes one by one to handle intra-batch duplicates/hash-index-collisions
        for (0..PARALLEL_SCAN) |i| {
            // disable unrolling by forcing index into a register
            asm volatile (""
                :
                : [_] "r" (i),
            );

            // stop at unfilled batch items
            const batch_entry = batch.entries[i];
            if (batch_entry.key.isZeroed()) break;

            while (true) {
                // Observe ptr & increment it upfront to keep a single loop-back branch below.
                const entry = &ptrs[i][0];
                ptrs[i] += 1;
                if (ptrs[i] == self.entries.ptr + self.entries.len) ptrs[i] = self.entries.ptr;

                const empty = entry.key.isZeroed();
                const eq = entry.key.equals(&batch_entry.key);
                if (eq or empty) {
                    @branchHint(.likely);
                    if (batch_entry.slot >= entry.slot) {
                        self.size += @intFromBool(entry.key.isZeroed()); // was empty
                        entry.* = batch_entry;
                    }
                    break;
                }
            }
        }
    }

    pub fn get(self: *const Table, pubkey: *const Pubkey) Value {
        // Searching on a full table can deadlock the loop below + shouldnt happen given flushPuts.
        std.debug.assert(self.size < self.entries.len);

        // We use a zero pubkey in the map to denote empty Entry.
        // If actualy fetching from the zero pubkey, access the one in the table instead.
        if (pubkey.isZeroed()) {
            @branchHint(.unlikely); // zero pubkey is System Program, which is hopefully cached.
            return self.zero_entry.value;
        }

        var idx = self.hashToIndex(pubkey);
        while (true) {
            // Observe idx & increment it upfront to keep a single loop-back branch below.
            const entry = &self.entries.ptr[idx];
            idx +%= 1;
            if (idx == self.entries.len) idx = 0;

            const empty = entry.key.isZeroed();
            const eq = entry.key.equals(pubkey);
            if (eq or empty) {
                @branchHint(.likely);
                return entry.value; // on empty its Value.empty
            }
        }
    }

    /// Reduce a hash into a table index.
    fn hashToIndex(self: *const Table, pubkey: *const Pubkey) u64 {
        const hash = pubkey.hash(self.seed);
        const len = self.entries.len;

        const hash_mod_len = hash - (self.reducer.div(hash) * len);
        std.debug.assert(hash_mod_len < len);
        return hash_mod_len;
    }
};
