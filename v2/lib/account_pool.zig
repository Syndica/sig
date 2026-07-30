const std = @import("std");
const lib = @import("lib.zig");

const Pubkey = lib.solana.Pubkey;
const Epoch = lib.solana.Epoch;

pub const AccountPool = extern struct {
    // pool could have concurrent alloc/free calls
    lock: Lock,

    allocated: AccountRef,
    buckets: [data_size_classes.len]Bucket,

    memory_len: usize,
    memory: [0]u8 align(index_scale), // VLA [0..memory_len]

    const IndexInt = u32;
    pub const AccountRef = enum(IndexInt) {
        invalid = std.math.maxInt(IndexInt),
        _,

        pub const Int = IndexInt;

        pub fn index(self: AccountRef) ?IndexInt {
            if (self == .invalid) return null;
            return @intFromEnum(self);
        }

        pub fn fromInt(int: IndexInt) AccountRef {
            return @enumFromInt(int);
        }
    };

    const index_scale = 8;

    const Bucket = extern struct {
        free_list: AccountRef,
        stolen: extern struct {
            start: AccountRef,
            end: u32,
        },

        fn pushFreeList(self: *Bucket, idx: AccountRef, memory: []u8) void {
            memory[@as(u64, idx.index().?) * index_scale ..][0..@sizeOf(AccountRef)].* =
                @bitCast(@intFromEnum(self.free_list));

            self.free_list = idx;
        }

        fn popFreeList(self: *Bucket, memory: []const u8) ?AccountRef {
            const idx = self.free_list;
            if (idx == .invalid) return null;

            self.free_list = .fromInt(@bitCast(
                memory[@as(u64, idx.index().?) * index_scale ..][0..@sizeOf(AccountRef)].*,
            ));
            return idx;
        }

        fn bumpStolenBlock(self: *Bucket, idx_bump: AccountRef) ?AccountRef {
            const idx = self.stolen.start;
            if (idx == .invalid) return null;

            if (idx.index().? + idx_bump.index().? > self.stolen.end) return null;
            self.stolen.start = .fromInt(idx.index().? + idx_bump.index().?);
            return idx;
        }
    };

    pub fn init(self: *AccountPool, memory_len: usize) void {
        self.lock = .{};
        self.allocated = .fromInt(0);
        @memset(&self.buckets, .{
            .free_list = .invalid,
            .stolen = .{
                .start = .invalid,
                .end = @intFromEnum(AccountRef.invalid),
            },
        });
        self.memory_len = memory_len;
    }

    // A lock to protect alloc() path mostly, since the operations it needs to do could be made
    // lock-free, but it would be complex to do so. Not using std.Thread.Mutex as that can block the
    // OS thread which 1) is slow for us since wanting to pin cores 2) uses syscalls not in seccomp.
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

    // A VLA account stored in pool.memory.
    // The `memory` field is aligned to `index_scale`, and all allocations are done on `index_scale`
    // units, so Accounts in `.memory` should all be properly aligned to avoid `align(1)` on fields.
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
        pub fn ref(self: *Account) void {
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

    pub fn alloc(self: *AccountPool, data_len: u32) !AccountRef {
        std.debug.assert(data_len <= MAX_DATA_LEN);

        const memory = self.memory[0..].ptr[0..self.memory_len];
        const sc_idx = getSizeClass(data_len);
        const sc_data_size = data_size_classes[sc_idx];
        const bucket = &self.buckets[sc_idx];

        var lock_holder: Lock.Holder = undefined;
        self.lock.acquire(&lock_holder);
        defer self.lock.release(&lock_holder);

        // try free-list first
        if (bucket.popFreeList(memory)) |idx| {
            return idx;
        }

        const idx_bump = // how many Indexes worth of memory are we wanting to alloc
            std.math.divCeil(AccountRef.Int, @sizeOf(Account) + sc_data_size, index_scale) catch
                unreachable;

        // try bump from our own bucket's stolen block, if any
        if (bucket.bumpStolenBlock(.fromInt(idx_bump))) |idx| {
            return idx;
        }

        // try bump from total memory
        if ((@as(u64, self.allocated.index().? + idx_bump) * index_scale) <= self.memory_len) {
            const idx = self.allocated;

            self.allocated = .fromInt(self.allocated.index().? + idx_bump);
            return idx;
        }

        // entire memory is full, try steal from another size-class as last ditch effort
        for (data_size_classes, 0..) |target_sc_data_size, target_sc_idx| {
            if (target_sc_idx == sc_idx) continue; // ignore ourselves
            if (target_sc_data_size < sc_data_size) continue; // ignore size classes smaller than us
            const target = &self.buckets[target_sc_idx];

            // try steal from its own stolen bump allocating region
            if (target.bumpStolenBlock(.fromInt(idx_bump))) |idx| {
                return idx;
            }

            // try steal from its free list into our own stolen block
            if (target.popFreeList(memory)) |stolen_block_idx| {
                bucket.stolen = .{
                    .start = stolen_block_idx,
                    .end = stolen_block_idx.index().? + (std.math.divCeil(
                        AccountRef.Int,
                        @sizeOf(Account) + target_sc_data_size,
                        index_scale,
                    ) catch unreachable),
                };
                return bucket.bumpStolenBlock(.fromInt(idx_bump)) orelse unreachable;
            }
        }

        // TODO: Under extreme memory pressure. Should really signal operator here.
        // But additionally, try to coalesce contiguous 1) stolen blocks or 2) free_list chunks
        // from size classes, in order to service this allocation request.
        return error.OutOfMemory;
    }

    pub fn getAccount(self: *AccountPool, idx: AccountRef) *Account {
        std.debug.assert(idx != .invalid);
        std.debug.assert(idx.index().? < self.allocated.index().?);
        return @ptrCast(@alignCast(
            self.memory[0..].ptr[@as(u64, idx.index().?) * index_scale ..][0..@sizeOf(Account)],
        ));
    }

    pub fn free(self: *AccountPool, idx: AccountRef) void {
        const acc = self.getAccount(idx);
        std.debug.assert(acc.ref_count.load(.monotonic) == 0);

        const memory = self.memory[0..].ptr[0..self.memory_len];
        const sc_idx = getSizeClass(acc.data.len);
        const bucket = &self.buckets[sc_idx];

        var lock_holder: Lock.Holder = undefined;
        self.lock.acquire(&lock_holder);
        defer self.lock.release(&lock_holder);

        bucket.pushFreeList(idx, memory);
    }
};
