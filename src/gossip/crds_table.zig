const std = @import("std");
const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;

const bincode = @import("../bincode/bincode.zig");

const hash = @import("../core/hash.zig");
const Hash = hash.Hash;
const CompareResult = hash.CompareResult;

const SocketAddr = @import("net.zig").SocketAddr;

const CrdsShards = @import("./crds_shards.zig").CrdsShards;

const crds = @import("./crds.zig");
const CrdsValue = crds.CrdsValue;
const CrdsData = crds.CrdsData;
const CrdsVersionedValue = crds.CrdsVersionedValue;
const CrdsValueLabel = crds.CrdsValueLabel;
const LegacyContactInfo = crds.LegacyContactInfo;

const Transaction = @import("../core/transaction.zig").Transaction;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const RwLock = std.Thread.RwLock;

pub const CrdsError = error{
    OldValue,
};

const CRDS_SHARDS_BITS: u32 = 12;

/// Cluster Replicated Data Store: stores gossip data
/// the self.store uses an AutoArrayHashMap which is a HashMap that also allows for
/// indexing values (value = arrayhashmap[0]). This allows us to insert data
/// into the store and track the indexs of different types for
/// retrieval. We use the 'cursor' value to track what index is the head of the
/// store.
/// Other functions include getters with a cursor
/// (`get_votes_with_cursor`) which allows you to retrieve values which are
/// past a certain cursor index. A listener would use their own cursor to
/// retrieve new values inserted in the store.
/// insertion of values is all based on the CRDSLabel type -- when duplicates
/// are found, the entry with the largest wallclock time (newest) is stored.
pub const CrdsTable = struct {
    store: AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue),

    // special types tracked with their index
    contact_infos: AutoArrayHashMap(usize, void), // hashset for O(1) insertion/removal
    votes: AutoArrayHashMap(usize, usize),
    epoch_slots: AutoArrayHashMap(usize, usize),
    duplicate_shreds: AutoArrayHashMap(usize, usize),
    shred_versions: AutoHashMap(Pubkey, u16),

    // used to build pull responses efficiently
    shards: CrdsShards,

    // head of the store
    cursor: usize = 0,

    // thread safe
    lock: RwLock = .{},

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .store = AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue).init(allocator),
            .contact_infos = AutoArrayHashMap(usize, void).init(allocator),
            .shred_versions = AutoHashMap(Pubkey, u16).init(allocator),
            .votes = AutoArrayHashMap(usize, usize).init(allocator),
            .epoch_slots = AutoArrayHashMap(usize, usize).init(allocator),
            .duplicate_shreds = AutoArrayHashMap(usize, usize).init(allocator),
            .shards = try CrdsShards.init(allocator, CRDS_SHARDS_BITS),
        };
    }

    pub fn deinit(self: *Self) void {
        self.store.deinit();
        self.contact_infos.deinit();
        self.shred_versions.deinit();
        self.votes.deinit();
        self.epoch_slots.deinit();
        self.duplicate_shreds.deinit();
        self.shards.deinit();
    }

    pub fn write(self: *Self) void {
        self.lock.lock();
    }

    pub fn release_write(self: *Self) void {
        self.lock.unlock();
    }

    pub fn read(self: *Self) void {
        self.lock.lockShared();
    }

    pub fn release_read(self: *Self) void {
        self.lock.unlockShared();
    }

    pub fn len(self: *Self) usize {
        return self.store.count();
    }

    pub fn insert(self: *Self, value: CrdsValue, now: u64) !void {
        // TODO: check to make sure this sizing is correct or use heap
        var buf = [_]u8{0} ** 2048; // does this break if its called in parallel? / dangle?
        var bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
        const value_hash = Hash.generateSha256Hash(bytes);
        const versioned_value = CrdsVersionedValue{
            .value = value,
            .value_hash = value_hash,
            .local_timestamp = now,
            .num_push_dups = 0,
            .ordinal = self.cursor,
        };

        const label = value.label();
        var result = try self.store.getOrPut(label);
        const entry_index = result.index;

        // entry doesnt exist
        if (!result.found_existing) {
            switch (value.data) {
                .LegacyContactInfo => |*info| {
                    try self.contact_infos.put(entry_index, {});
                    try self.shred_versions.put(info.id, info.shred_version);
                },
                .Vote => {
                    try self.votes.put(self.cursor, entry_index);
                },
                .EpochSlots => {
                    try self.epoch_slots.put(self.cursor, entry_index);
                },
                .DuplicateShred => {
                    try self.duplicate_shreds.put(self.cursor, entry_index);
                },
                else => {},
            }

            try self.shards.insert(entry_index, &versioned_value.value_hash);

            result.value_ptr.* = versioned_value;

            self.cursor += 1;

            // should overwrite existing entry
        } else if (crds_overwrites(&versioned_value, result.value_ptr)) {
            const old_entry = result.value_ptr.*;

            switch (value.data) {
                .LegacyContactInfo => |*info| {
                    try self.shred_versions.put(info.id, info.shred_version);
                },
                .Vote => {
                    var did_remove = self.votes.swapRemove(old_entry.ordinal);
                    std.debug.assert(did_remove);
                    try self.votes.put(self.cursor, entry_index);
                },
                .EpochSlots => {
                    var did_remove = self.epoch_slots.swapRemove(old_entry.ordinal);
                    std.debug.assert(did_remove);
                    try self.epoch_slots.put(self.cursor, entry_index);
                },
                .DuplicateShred => {
                    var did_remove = self.duplicate_shreds.swapRemove(old_entry.ordinal);
                    std.debug.assert(did_remove);
                    try self.duplicate_shreds.put(self.cursor, entry_index);
                },
                else => {},
            }

            // remove and insert to make sure the shard ordering is oldest-to-newest
            // NOTE: do we need the ordering to be oldest-to-newest?
            try self.shards.remove(entry_index, &old_entry.value_hash);
            try self.shards.insert(entry_index, &versioned_value.value_hash);

            result.value_ptr.* = versioned_value;

            self.cursor += 1;

            // do nothing
        } else {
            return CrdsError.OldValue;
        }
    }

    pub fn get(self: *Self, label: CrdsValueLabel) ?CrdsVersionedValue {
        return self.store.get(label);
    }

    pub fn get_votes_with_cursor(self: *Self, buf: []*CrdsVersionedValue, caller_cursor: *usize) ![]*CrdsVersionedValue {
        const keys = self.votes.keys();
        var index: usize = 0;
        for (keys) |key| {
            if (key < caller_cursor.*) {
                continue;
            }
            const entry_index = self.votes.get(key).?;
            var entry = self.store.iterator().values[entry_index];
            buf[index] = &entry;
            index += 1;

            if (index == buf.len) {
                break;
            }
        }
        // move up the caller_cursor
        caller_cursor.* += index;
        return buf[0..index];
    }

    pub fn get_epoch_slots_with_cursor(self: *Self, buf: []*CrdsVersionedValue, caller_cursor: *usize) ![]*CrdsVersionedValue {
        const keys = self.epoch_slots.keys();
        var index: usize = 0;
        for (keys) |key| {
            if (key < caller_cursor.*) {
                continue;
            }
            const entry_index = self.epoch_slots.get(key).?;
            var entry = self.store.iterator().values[entry_index];
            buf[index] = &entry;
            index += 1;

            if (index == buf.len) {
                break;
            }
        }
        // move up the caller_cursor
        caller_cursor.* += index;
        return buf[0..index];
    }

    pub fn get_duplicate_shreds_with_cursor(self: *Self, buf: []*CrdsVersionedValue, caller_cursor: *usize) ![]*CrdsVersionedValue {
        const keys = self.duplicate_shreds.keys();
        var index: usize = 0;
        for (keys) |key| {
            if (key < caller_cursor.*) {
                continue;
            }
            const entry_index = self.duplicate_shreds.get(key).?;
            var entry = self.store.iterator().values[entry_index];
            buf[index] = &entry;
            index += 1;

            if (index == buf.len) {
                break;
            }
        }
        // move up the caller_cursor
        caller_cursor.* += index;
        return buf[0..index];
    }

    pub fn get_contact_infos(self: *const Self, buf: []*CrdsVersionedValue) ![]*CrdsVersionedValue {
        const store_values = self.store.iterator().values;
        const contact_indexs = self.contact_infos.iterator().keys;

        const size = @min(self.contact_infos.count(), buf.len);

        for (0..size) |i| {
            const index = contact_indexs[i];
            const entry = &store_values[index]; // does this dangle?
            buf[i] = entry;
        }
        return buf[0..size];
    }

    pub fn get_bitmask_matches(
        self: *const Self,
        alloc: std.mem.Allocator,
        mask: u64,
        mask_bits: u64,
    ) !std.ArrayList(usize) {
        const indexs = try self.shards.find(alloc, mask, @intCast(mask_bits));
        return indexs;
    }
};

pub fn crds_overwrites(new_value: *const CrdsVersionedValue, old_value: *const CrdsVersionedValue) bool {
    // labels must match
    std.debug.assert(@intFromEnum(new_value.value.label()) == @intFromEnum(old_value.value.label()));

    const new_ts = new_value.value.wallclock();
    const old_ts = old_value.value.wallclock();

    if (new_ts > old_ts) {
        return true;
    } else if (new_ts < old_ts) {
        return false;
    } else {
        return old_value.value_hash.cmp(&new_value.value_hash) == CompareResult.Less;
    }
}

test "gossip.crds_table: insert and get" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var value = try CrdsValue.random(rng, keypair);

    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    try crds_table.insert(value, 0);

    const label = value.label();
    const x = crds_table.get(label).?;
    _ = x;
}

test "gossip.crds_table: insert and get votes" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);

    var vote = crds.Vote{ .from = id, .transaction = Transaction.default(), .wallclock = 10 };
    var crds_value = try CrdsValue.initSigned(CrdsData{
        .Vote = .{ 0, vote },
    }, kp);

    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();
    try crds_table.insert(crds_value, 0);

    var cursor: usize = 0;
    var buf: [100]*CrdsVersionedValue = undefined;
    var votes = try crds_table.get_votes_with_cursor(&buf, &cursor);

    try std.testing.expect(votes.len == 1);
    try std.testing.expect(cursor == 1);

    // try inserting another vote
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();
    id = Pubkey.random(rng, .{});
    vote = crds.Vote{ .from = id, .transaction = Transaction.default(), .wallclock = 10 };
    crds_value = try CrdsValue.initSigned(CrdsData{
        .Vote = .{ 0, vote },
    }, kp);
    try crds_table.insert(crds_value, 1);

    votes = try crds_table.get_votes_with_cursor(&buf, &cursor);
    try std.testing.expect(votes.len == 1);
    try std.testing.expect(cursor == 2);

    const v = try crds_table.get_bitmask_matches(std.testing.allocator, 10, 1);
    defer v.deinit();
}

test "gossip.crds_table: insert and get contact_info" {
    const kp = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&kp.public_key, true);

    var legacy_contact_info = crds.LegacyContactInfo.default();
    legacy_contact_info.id = id;
    var crds_value = try CrdsValue.initSigned(CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, kp);

    var crds_table = try CrdsTable.init(std.testing.allocator);
    defer crds_table.deinit();

    // test insertion
    try crds_table.insert(crds_value, 0);

    // test retrieval
    var buf: [100]*CrdsVersionedValue = undefined;
    var nodes = try crds_table.get_contact_infos(&buf);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].value.data.LegacyContactInfo.id.equals(&id));

    // test re-insertion
    const result = crds_table.insert(crds_value, 0);
    try std.testing.expectError(CrdsError.OldValue, result);

    // test re-insertion with greater wallclock
    crds_value.data.LegacyContactInfo.wallclock += 2;
    const v = crds_value.data.LegacyContactInfo.wallclock;
    try crds_table.insert(crds_value, 0);

    // check retrieval
    nodes = try crds_table.get_contact_infos(&buf);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].value.data.LegacyContactInfo.wallclock == v);
}
