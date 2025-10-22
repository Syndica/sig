//! A database which stores unrooted account modifications.
//! TODO: better doc comment
const std = @import("std");
const sig = @import("sig");

const Atomic = std.atomic.Value;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const AccountSharedData = sig.runtime.AccountSharedData;

const Unrooted = @This();
const TABLE_BITS = 20; // 2^20 buckets TODO: maybe optimize this? can there really ever be a case when we need more?
const TABLE_SIZE = 1 << TABLE_BITS;
const TABLE_MASK = TABLE_SIZE - 1;

// per slot, only ever one writer per key, but multiple readers per key
// for an account/address, possible multiple writers for different slots
//
// very unlikely to have multiple writers on same account for different slots,
// only happens on concurrent forked execution

table: []Bucket,

const Bucket = Atomic(?*Entry);

const Entry = struct {
    key: Pubkey,
    versions: std.ArrayListUnmanaged(Version),
    next: ?*Entry,

    fn create(allocator: std.mem.Allocator, key: Pubkey, version: Version) !*Entry {
        const e = try allocator.create(Entry);
        errdefer allocator.destroy(e);

        var versions: std.ArrayListUnmanaged(Version) = try .initCapacity(allocator, 1);
        errdefer versions.deinit(allocator);
        versions.appendAssumeCapacity(version);

        e.* = .{
            .key = key,
            .versions = versions,
            .next = null,
        };

        return e;
    }

    // TODO: consider that this *can* be called multi-thread, although super rare
    fn insert(self: *Entry, allocator: std.mem.Allocator, version: Version) !void {
        const new_index = std.sort.partitionPoint(
            Version,
            self.versions.items,
            version,
            struct {
                fn cmp(new: Version, old: Version) bool {
                    return new.slot < old.slot;
                }
            }.cmp,
        );
        try self.versions.insert(allocator, new_index, version);
    }
};

const Version = struct {
    slot: Slot,
    data: AccountSharedData,
};

pub fn init(allocator: std.mem.Allocator) !Unrooted {
    const table = try allocator.alloc(Bucket, TABLE_SIZE);
    @memset(table, .init(null));
    return .{ .table = table };
}

pub fn deinit(self: *Unrooted, allocator: std.mem.Allocator) void {
    allocator.free(self.table);
}

fn hash(key: Pubkey) u32 {
    return std.hash.Fnv1a_32.hash(&key.data);
}

pub fn put(
    self: *Unrooted,
    allocator: std.mem.Allocator,
    slot: Slot,
    address: Pubkey,
    data: AccountSharedData,
) !void {
    // TODO: try just getting the last 32-bits instead of hashing
    const h = hash(address);
    const idx = h & TABLE_MASK;
    const old_head = self.table[idx].load(.acquire);

    while (true) {
        var new_head: ?*Entry = null;
        var maybe_current = old_head;
        var found: bool = false;

        while (maybe_current) |current| : (maybe_current = current.next) {
            if (current.key.equals(&address)) {
                found = true;
                try current.insert(allocator, .{ .slot = slot, .data = data });
                break;
            }
        }

        if (!found) {
            // new entry
            const entry: *Entry = try .create(allocator, address, .{
                .slot = slot,
                .data = data,
            });
            entry.next = new_head;
            new_head = entry;
        } else {
            // new_head already contains clones
        }

        // publish
        if (self.table[idx].cmpxchgWeak(old_head, new_head, .release, .acquire)) |_| {
            @panic("TODO");
        } else return;
    }
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var db: Unrooted = try .init(allocator);
    defer db.deinit(allocator);

    const account_a: Pubkey = .parse("GBuP6xK2zcUHbQuUWM4gbBjom46AomsG8JzSp1bzJyn8");
    const account_b: Pubkey = .parse("Fd7btgySsrjuo25CJCj7oE7VPMyezDhnx7pZkj2v69Nk");

    try db.put(
        allocator,
        1, // slot
        account_a, // address
        .{ // data
            .data = &.{},
            .executable = true,
            .lamports = 1_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    try db.put(
        allocator,
        2, // slot
        account_a, // address
        .{ // data
            .data = &.{},
            .executable = true,
            .lamports = 2_000_000,
            .owner = account_b,
            .rent_epoch = 30,
        },
    );

    std.debug.print("hello world\n", .{});
}
