const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;

/// An in-memory table mapping Pubkey to Disk offset & length.
pub const Table = struct {
    cells: []Cell,
    count: u64 = 0,
    rcp_mul: u64,
    rcp_shr: u6,
    put_len: u32 = 0,
    put_queue: [BATCH_SIZE]Cell = undefined,

    /// Comapct representation of a disk range
    pub const Entry = packed struct(u64) {
        len: u24, // allows for addressing a 16MB block
        offset: u40, // allows for addressing 1TB of disk space

        const empty: Entry = .{ .len = 0, .offset = 0 };

        fn isEmpty(self: Entry) bool {
            return @as(u64, @bitCast(self)) == 0;
        }
    };

    // number of parallel hashmap operations to do at once to amortize RAM/cache-miss latency
    const BATCH_SIZE = 8;

    // Compact representation of a (Pubkey, Entry) pair.
    const Cell = extern struct {
        // hashes the pubkey down to 128-bits, which should be enough entropy to avoid collisions
        hash: [16]u8,
        // Used internally during put_queue. Unused once inserted into the map/cells array.
        idx: u32 align(1),
        // a u32 slot allows for *another* 50 years of mainnet (assuming 400ms slot times).
        slot: u32 align(1),
        entry: Entry align(1),
    };

    // Assumes memory is all zeroed
    pub fn init(memory: []u8) Table {
        const cells = std.mem.bytesAsSlice(Cell, memory);
        std.debug.assert(cells.len > 1);
        std.debug.assert(cells.len < (1 << 63));

        // Compute the integer reciprocal of the cells.len:
        // https://gist.github.com/B-Y-P/5872dbaaf768c204480109007f64a915
        // This allows the hashmap reduction of `hash % cells.len` to be computed without division
        // with quotient as `Q = u64(u128(hash * mul) >> 64) >> shr`
        // and remainder as `hash - (Q * cells.len)`
        const bits = std.math.log2_int_ceil(u64, cells.len);
        const shr: u6 = @intCast(@as(u64, bits) + 63 - 64);
        const mul: u64 = @intCast(((@as(u128, 1) << shr << 64) | (cells.len - 1)) / cells.len);

        return .{ .cells = cells, .rcp_mul = mul, .rcp_shr = shr };
    }

    inline fn hashPubkey(pubkey: *const Pubkey) u128 {
        // hash pubkey to u128 (xxh3 mixFold)
        const sk = [_]u64{
            0xC2B2AE3D27D4EB4F,
            0x165667B19E3779F9,
            0x85EBCA77C2B2AE63,
            0x27D4EB2F165667C5,
        };
        const pk: [4]u64 = @bitCast(pubkey.*);
        const lo: [2]u64 = @bitCast(@as(u128, pk[0] ^ sk[0]) * (pk[1] ^ sk[1]));
        const hi: [2]u64 = @bitCast(@as(u128, pk[2] ^ sk[2]) * (pk[3] ^ sk[3]));
        return @bitCast([_]u64{
            (lo[0] ^ lo[1]) | 1, // keep one bit set to ensure final hash isn't zero
            hi[0] ^ hi[1],
        });
    }

    inline fn reduceHash(self: *const Table, hash: [2]u64) u32 {
        // merge u128 into u64 & spread entropy across bits (xxh3 avalanche)
        var x = (@as(u64, 0x9E3779B185EBCA87) *% 16) +% hash[0] +% hash[1];
        x = (x ^ (x >> 37)) *% 0x165667919E3779F9;
        x = (x ^ (x >> 32));

        // fast division with integer reciprocals, to do `x % self.cells.len`
        const x_div_len: u64 = @truncate((@as(u128, x) * self.rcp_mul) >> 64 >> self.rcp_shr);
        return @intCast(x - (x_div_len * self.cells.len));
    }

    // TODO: batch gets?
    pub fn get(self: *const Table, pubkey: *const Pubkey) Entry {
        const hash: @Vector(16, u8) = @bitCast(hashPubkey(pubkey));

        var idx = self.reduceHash(@bitCast(hash));
        while (true) {
            const e = &self.cells[idx];
            idx +%= 1;
            if (idx == self.cells.len) idx = 0;

            const e_hash: @Vector(16, u8) = e.hash;
            if (e_hash == hash) return e.entry;
            if (e_hash == (e_hash - e_hash)) return .empty;
        }
    }

    pub fn put(self: *Table, pubkey: *const Pubkey, slot: Slot, entry: Entry) void {
        std.debug.assert(!entry.isEmpty());

        const hash = hashPubkey(pubkey);
        self.put_queue[self.put_len] = .{
            .hash = @bitCast(hash),
            .idx = self.reduceHash(@bitCast(hash)),
            .slot = @intCast(slot),
            .entry = entry,
        };

        // bump len until BATCH_SIZE. Once hit, its reset to zero & putBatch() is called.
        self.put_len = (self.put_len + 1) % BATCH_SIZE;
        if (self.put_len == 0) self.putBatch();
    }

    pub fn flushPuts(self: *Table) void {
        const put_len = if (self.put_len > 0) self.put_len else return;
        self.put_len = 0;

        // zero-out unused put_queue cells
        for (0..BATCH_SIZE) |i| {
            const keep: @Vector(32, bool) = @splat(i < put_len);
            const put_vec: @Vector(32, u8) = @bitCast(self.put_queue[i]);
            self.put_queue[i] = @bitCast(@select(u8, keep, put_vec, put_vec - put_vec));
        }

        self.putBatch();
    }

    fn putBatch(self: *Table) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "Table.putBatch" });
        defer zone.deinit();

        // load put_queue items upfront
        var put_vec: [BATCH_SIZE]@Vector(8, u32) = undefined;
        for (0..BATCH_SIZE) |i| put_vec[i] = @bitCast(self.put_queue[i]);

        // extract their indexes as tbl pointers
        const idx_offset = @divExact(@offsetOf(Cell, "idx"), @sizeOf(u32));
        var ptr: [BATCH_SIZE][*]Cell = undefined;
        for (0..BATCH_SIZE) |i| ptr[i] = self.cells.ptr + put_vec[i][idx_offset];

        // load table cells together to amortize random access cache-miss latency
        var tbl_vec: [BATCH_SIZE]@Vector(8, u32) = undefined;
        while (true) {
            for (0..BATCH_SIZE) |i| tbl_vec[i] = @bitCast(ptr[i][0]);

            // check if table entry to overwrite is found (staying in vector types for optz)
            var empty_or_eq: [BATCH_SIZE]@Vector(8, u1) = undefined;
            for (0..BATCH_SIZE) |i| {
                const empty: @Vector(8, u1) = @bitCast(tbl_vec[i] == (tbl_vec[i] - tbl_vec[i]));
                const eq: @Vector(8, u1) = @bitCast(tbl_vec[i] == put_vec[i]);
                const ignored: @Vector(8, u1) = .{ 0, 0, 0, 0, 1, 1, 1, 1 }; // ignore all but hash
                empty_or_eq[i] = empty | eq | ignored;
            }

            // check if all ptr positions are overwritable. If not, advance their ptr & retry
            var collisions: u32 = 0;
            for (0..BATCH_SIZE) |i| {
                const collided = ~@reduce(.And, empty_or_eq[i]);
                collisions |= collided;
                ptr[i] += collided;
                if (ptr[i] == self.cells.ptr + self.cells.len) ptr[i] = self.cells.ptr;
            }
            if (collisions == 0) break;
        }

        // Only overwrite cells where the put_queue[i].slot >= tbl_entry[i].slot
        for (0..BATCH_SIZE) |i| {
            const slot_offset = @divExact(@offsetOf(Cell, "slot"), @sizeOf(u32));
            const slot_mask: [8]i32 = @splat(slot_offset);
            const newer_slot = @shuffle(bool, put_vec[i] >= tbl_vec[i], undefined, slot_mask);
            ptr[i][0] = @bitCast(@select(u32, newer_slot, put_vec[i], tbl_vec[i]));
            self.count += @intFromBool(@reduce(.Or, newer_slot));
        }
    }
};
