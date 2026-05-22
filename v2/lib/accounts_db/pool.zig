const std = @import("std");
const lib = @import("../lib.zig");

const Pubkey = lib.solana.Pubkey;
const Epoch = lib.solana.Epoch;

pub const AccountPool = extern struct {
    // pool could have concurrent alloc/free calls
    lock: Lock,

    allocated: Index,
    buckets: [data_size_classes.len]Bucket,

    memory_len: usize,
    memory: [0]u8 align(index_scale), // VLA [0..memory_len]

    // 8-byte aligned offset into memory
    pub const Index = u32;
    pub const invalid_index = std.math.maxInt(Index);
    const index_scale = 8;

    const Bucket = extern struct {
        free_list: Index,
        stolen: extern struct {
            block: Index,
            offset: u32,
            len: u32,
        },
    };

    pub fn init(self: *AccountPool, memory_len: usize) void {
        self.lock = .{};
        self.allocated = 0;
        @memset(&self.buckets, .{
            .free_list = invalid_index,
            .stolen = .{
                .block = invalid_index,
                .offset = 0,
                .len = 0,
            },
        });
        self.memory_len = memory_len;
    }

    // Similar to qspinlock in the linux kernel
    const Lock = extern struct {
        locked: std.atomic.Value(u32) = .init(0),

        // If we want to switch to queued spinlocks.
        const Holder = void;

        fn acquire(self: *Lock, _: *Holder) void {
            if (self.locked.fetchOr(1, .acquire) & 1 > 0) { // lock bts instruction
                @branchHint(.unlikely);
                while (true) {
                    while (self.locked.load(.monotonic) != 0) std.atomic.spinLoopHint();
                    if (self.locked.fetchOr(1, .acquire) & 1 == 0) break;
                }
            }
        }

        fn release(self: *Lock, _: *Holder) void {
            self.locked.store(0, .release);
        }
    };

    // TODO: base on mainnet binning of accounts usually loaded in during txns
    const MAX_DATA_LEN = 10 * 1024 * 1024;
    const data_size_classes = [_]u24{
        0, // alot of accounts have zero data
        8,
        32,
        64,
        256,
        1024,
        4096,
        16 * 1024,
        64 * 1024,
        1 * 1024 * 1024,
        4 * 1024 * 1024,
        10 * 1024 * 1024,
    };

    fn getSizeClass(data_len: u32) u32 {
        std.debug.assert(data_len <= MAX_DATA_LEN);
        for (data_size_classes, 0..) |sc, sc_idx| {
            if (data_len <= sc) return @intCast(sc_idx);
        } else unreachable;
    }

    // A VLA account stored in pool.memory (all fields align(1) to allow such).
    pub const Account = extern struct {
        ref_count: std.atomic.Value(u32),
        pubkey: Pubkey,
        owner: Pubkey,
        lamports: u64,
        rent_epoch: Epoch,
        data: packed struct(u32) {
            executable: bool,
            len: u31,
        } align(1),

        comptime {
            std.debug.assert(@alignOf(Account) <= index_scale);
        }

        // Bumps a ref on the account to keep it alive
        pub fn ref(self: *Account) *Account {
            const rc = self.ref_count.fetchAdd(1, .monotonic);
            std.debug.assert(rc != std.math.maxInt(u32));
        }

        // Returns true when the account is safe to free.
        pub fn unref(self: *Account) bool {
            const rc = self.ref_count.fetchSub(1, .acq_rel);
            std.debug.assert(rc > 0);
            return rc == 1;
        }

        pub fn getData(self: *Account) []u8 {
            std.debug.assert(self.data.len <= MAX_DATA_LEN);
            return (@as([*]u8, @ptrCast(self)) + @sizeOf(Account))[0..self.data.len];
        }
    };

    pub fn alloc(self: *AccountPool, data_len: u32) !Index {
        std.debug.assert(data_len <= MAX_DATA_LEN);

        const sc_idx = getSizeClass(data_len);
        const sc_data_size = data_size_classes[sc_idx];
        const bucket = &self.buckets[sc_idx];

        var lock_holder: Lock.Holder = undefined;
        self.lock.acquire(&lock_holder);
        defer self.lock.release(&lock_holder);

        // try free-list first
        var idx = bucket.free_list;
        if (idx != invalid_index) {
            bucket.free_list = @bitCast(
                self.memory[0..].ptr[@as(u64, idx) * index_scale ..][0..@sizeOf(Index)].*,
            );
            return idx;
        }

        const idx_bump = // how many Indexes worth of memory are we wanting to alloc
            std.math.divCeil(Index, @sizeOf(Account) + sc_data_size, index_scale) catch unreachable;

        // try bump from our own bucket's stolen block, if any
        if (bucket.stolen.block != invalid_index) {
            idx = bucket.stolen.block + bucket.stolen.offset;
            if (idx + idx_bump < bucket.stolen.len) {
                bucket.stolen.offset += idx_bump;
                return idx;
            }
        }

        // try bump from memory
        idx = self.allocated;
        if ((@as(u64, idx + idx_bump) * index_scale) < self.memory_len) {
            self.allocated += idx_bump;
            return idx;
        }

        // entire memory is full, try steal from another size-class as last ditch effort
        for (data_size_classes, 0..) |target_sc_data_size, target_sc_idx| {
            if (target_sc_idx == sc_idx) continue; // ignore ourselves
            if (target_sc_data_size < sc_data_size) continue; // ignore size classes smaller than us
            const target = &self.buckets[target_sc_idx];

            // try steal from its own stolen bump allocating region
            if (target.stolen.block != invalid_index) {
                idx = target.stolen.block + target.stolen.offset;
                if (idx + idx_bump < target.stolen.len) {
                    target.stolen.offset += idx_bump;
                    return idx;
                }
            }

            // try steal from its free list into our own stolen block
            idx = target.free_list;
            if (idx != invalid_index) {
                bucket.stolen = .{
                    .block = idx,
                    .offset = idx_bump,
                    .len = std.math.divCeil(
                        Index,
                        @sizeOf(Account) + target_sc_data_size,
                        index_scale,
                    ) catch unreachable,
                };
                return idx;
            }
        }

        return error.OutOfMemory;
    }

    pub fn getAccount(self: *AccountPool, idx: Index) *Account {
        std.debug.assert(idx != invalid_index);
        std.debug.assert(idx < self.allocated);
        return @ptrCast(@alignCast(
            self.memory[0..].ptr[@as(u64, idx) * index_scale ..][0..@sizeOf(Account)],
        ));
    }

    pub fn free(self: *AccountPool, idx: Index) void {
        const acc = self.getAccount(idx);
        std.debug.assert(acc.ref_count.load(.monotonic) == 0);

        const sc_idx = getSizeClass(acc.data.len);
        const bucket = &self.buckets[sc_idx];

        var lock_holder: Lock.Holder = undefined;
        self.lock.acquire(&lock_holder);
        defer self.lock.release(&lock_holder);

        // add to free list
        self.memory[0..].ptr[@as(u64, idx) * index_scale ..][0..@sizeOf(Index)].* =
            @bitCast(bucket.free_list);
        bucket.free_list = idx;
    }
};
