const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const GossipTableShards = sig.gossip.shards.GossipTableShards;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const GossipKey = sig.gossip.data.GossipKey;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const ThreadPool = sig.sync.ThreadPool;
const Task = sig.sync.ThreadPool.Task;
const Batch = sig.sync.ThreadPool.Batch;
const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.Pubkey;
const SocketAddr = sig.net.SocketAddr;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;

pub const UNIQUE_PUBKEY_CAPACITY: usize = 8_192;
pub const MAX_TABLE_SIZE: usize = 100_000; // TODO: better value for this

pub const HashAndTime = struct { hash: Hash, timestamp: u64 };

// indexable HashSet
pub fn AutoArrayHashSet(comptime T: type) type {
    return AutoArrayHashMap(T, void);
}

pub const InsertResults = struct {
    inserted: ?std.ArrayList(usize),
    timeouts: ?std.ArrayList(usize),
    failed: ?std.ArrayList(usize),

    pub fn deinit(self: InsertResults) void {
        if (self.inserted) |inserted| {
            inserted.deinit();
        }
        if (self.timeouts) |timeouts| {
            timeouts.deinit();
        }
        if (self.failed) |failed| {
            failed.deinit();
        }
    }
};

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
/// insertion of values is all based on the GossipData type -- when duplicates
/// are found, the entry with the largest wallclock time (newest) is stored.
///
/// Analogous to [Crds](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds.rs#L68)
pub const GossipTable = struct {
    store: AutoArrayHashMap(GossipKey, GossipVersionedData),

    // special types tracked with their index
    contact_infos: AutoArrayHashSet(usize),
    votes: AutoArrayHashMap(usize, usize),
    epoch_slots: AutoArrayHashMap(usize, usize),
    duplicate_shreds: AutoArrayHashMap(usize, usize),
    shred_versions: AutoHashMap(Pubkey, u16),

    /// Stores a converted ContactInfo for every LegacyContactInfo in the store.
    /// This reduces compute and memory allocations vs converting when needed.
    converted_contact_infos: AutoArrayHashMap(Pubkey, ContactInfo),

    // tracking for cursor to index
    entries: AutoArrayHashMap(u64, usize),

    // Indices of all gossip values associated with a node/pubkey.
    pubkey_to_values: AutoArrayHashMap(Pubkey, AutoArrayHashSet(usize)),

    // used to build pull responses efficiently
    shards: GossipTableShards,

    // used when sending pull requests
    purged: HashTimeQueue,

    // head of the store
    cursor: usize = 0,

    // NOTE: this allocator is used to free any memory allocated by the bincode library
    allocator: std.mem.Allocator,
    thread_pool: *ThreadPool,

    const Self = @This();

    pub const InsertionError = error{
        OldValue,
        DuplicateValue,
    };

    pub fn init(allocator: std.mem.Allocator, thread_pool: *ThreadPool) !Self {
        return Self{
            .store = AutoArrayHashMap(GossipKey, GossipVersionedData).init(allocator),
            .contact_infos = AutoArrayHashSet(usize).init(allocator),
            .shred_versions = AutoHashMap(Pubkey, u16).init(allocator),
            .votes = AutoArrayHashMap(usize, usize).init(allocator),
            .epoch_slots = AutoArrayHashMap(usize, usize).init(allocator),
            .duplicate_shreds = AutoArrayHashMap(usize, usize).init(allocator),
            .converted_contact_infos = AutoArrayHashMap(Pubkey, ContactInfo).init(allocator),
            .entries = AutoArrayHashMap(u64, usize).init(allocator),
            .pubkey_to_values = AutoArrayHashMap(Pubkey, AutoArrayHashSet(usize)).init(allocator),
            .shards = try GossipTableShards.init(allocator),
            .purged = HashTimeQueue.init(allocator),
            .allocator = allocator,
            .thread_pool = thread_pool,
        };
    }

    pub fn deinit(self: *Self) void {
        self.contact_infos.deinit();
        self.shred_versions.deinit();
        self.votes.deinit();
        self.epoch_slots.deinit();
        self.duplicate_shreds.deinit();
        self.entries.deinit();
        self.shards.deinit();
        self.purged.deinit();

        var iter = self.pubkey_to_values.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.pubkey_to_values.deinit();

        var citer = self.converted_contact_infos.iterator();
        while (citer.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.converted_contact_infos.deinit();

        var store_iter = self.store.iterator();
        while (store_iter.next()) |entry| {
            entry.value_ptr.value.data.deinit(self.allocator);
        }
        self.store.deinit();
    }

    pub fn insert(self: *Self, value: SignedGossipData, now: u64) !bool {
        if (self.store.count() >= MAX_TABLE_SIZE) {
            return error.GossipTableFull;
        }

        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
        const value_hash = Hash.generateSha256Hash(bytes);
        const versioned_value = GossipVersionedData{
            .value = value,
            .value_hash = value_hash,
            .timestamp_on_insertion = now,
            .cursor_on_insertion = self.cursor,
        };

        const label = value.label();
        const result = try self.store.getOrPut(label);
        const entry_index = result.index;
        const origin = value.id();

        // entry doesnt exist
        if (!result.found_existing) {
            switch (value.data) {
                .ContactInfo => |*info| {
                    try self.contact_infos.put(entry_index, {});
                    try self.shred_versions.put(info.pubkey, info.shred_version);
                },
                .LegacyContactInfo => |*info| {
                    try self.contact_infos.put(entry_index, {});
                    try self.shred_versions.put(info.id, info.shred_version);
                    const contact_info = try info.toContactInfo(self.allocator);
                    try self.converted_contact_infos.put(info.id, contact_info);
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

            try self.entries.put(self.cursor, entry_index);

            const maybe_node_entry = self.pubkey_to_values.getEntry(origin);
            if (maybe_node_entry) |node_entry| {
                try node_entry.value_ptr.put(entry_index, {});
            } else {
                var indexs = AutoArrayHashSet(usize).init(self.allocator);
                try indexs.put(entry_index, {});
                try self.pubkey_to_values.put(origin, indexs);
            }

            result.value_ptr.* = versioned_value;

            self.cursor += 1;

            return true;
            // should overwrite existing entry
        } else if (versioned_value.overwrites(result.value_ptr)) {
            const old_entry = result.value_ptr.*;

            switch (value.data) {
                .ContactInfo => |*info| {
                    try self.shred_versions.put(info.pubkey, info.shred_version);
                },
                .LegacyContactInfo => |*info| {
                    try self.shred_versions.put(info.id, info.shred_version);
                    const contact_info = try info.toContactInfo(self.allocator);
                    var old_info = try self.converted_contact_infos.fetchPut(info.id, contact_info);
                    old_info.?.value.deinit();
                },
                .Vote => {
                    const did_remove = self.votes.swapRemove(old_entry.cursor_on_insertion);
                    std.debug.assert(did_remove);
                    try self.votes.put(self.cursor, entry_index);
                },
                .EpochSlots => {
                    const did_remove = self.epoch_slots.swapRemove(old_entry.cursor_on_insertion);
                    std.debug.assert(did_remove);
                    try self.epoch_slots.put(self.cursor, entry_index);
                },
                .DuplicateShred => {
                    const did_remove = self.duplicate_shreds.swapRemove(old_entry.cursor_on_insertion);
                    std.debug.assert(did_remove);
                    try self.duplicate_shreds.put(self.cursor, entry_index);
                },
                else => {},
            }

            // remove and insert to make sure the shard ordering is oldest-to-newest
            // NOTE: do we need the ordering to be oldest-to-newest?
            self.shards.remove(entry_index, &old_entry.value_hash);
            try self.shards.insert(entry_index, &versioned_value.value_hash);

            const did_remove = self.entries.swapRemove(old_entry.cursor_on_insertion);
            std.debug.assert(did_remove);
            try self.entries.put(self.cursor, entry_index);

            // As long as the pubkey does not change, self.records
            // does not need to be updated.
            std.debug.assert(old_entry.value.id().equals(&origin));

            try self.purged.insert(old_entry.value_hash, now);

            result.value_ptr.* = versioned_value;

            self.cursor += 1;
            return true;

            // do nothing
        } else {
            const old_entry = result.value_ptr.*;

            if (old_entry.value_hash.order(&versioned_value.value_hash) != .eq) {
                // if hash isnt the same and override() is false then msg is old
                try self.purged.insert(old_entry.value_hash, now);
                return InsertionError.OldValue;
            } else {
                // hash is the same then its a duplicate
                return InsertionError.DuplicateValue;
            }

            return false;
        }
    }

    pub fn insertValues(
        self: *Self,
        now: u64,
        values: []SignedGossipData,
        timeout: u64,
        comptime record_inserts: bool,
        comptime record_timeouts: bool,
    ) error{OutOfMemory}!InsertResults {
        // TODO: change to record duplicate and old values seperately + handle when
        // gossip table is full
        var failed_indexs = std.ArrayList(usize).init(self.allocator);
        var inserted_indexs = std.ArrayList(usize).init(self.allocator);
        var timeout_indexs = std.ArrayList(usize).init(self.allocator);

        for (values, 0..) |value, index| {
            const value_time = value.wallclock();
            const is_too_new = value_time > now +| timeout;
            const is_too_old = value_time < now -| timeout;
            if (is_too_new or is_too_old) {
                if (record_timeouts) {
                    try timeout_indexs.append(index);
                }
                continue;
            }

            const was_inserted = self.insert(value, now) catch false;
            if (was_inserted) {
                try inserted_indexs.append(index);
            } else {
                try failed_indexs.append(index);
            }
        }

        return InsertResults{
            .inserted = if (record_inserts) inserted_indexs else null,
            .timeouts = if (record_timeouts) timeout_indexs else null,
            .failed = failed_indexs,
        };
    }

    /// Like insertValues, but it minimizes the number of memory allocations.
    ///
    /// This is optimized to minimize the number of times that allocations occur.
    /// It is *not* optimized to minimize overall memory usage.
    ///
    /// It accepts an arraylist of failures instead of returning an InsertResults, so it
    /// can reuse the arraylist from a previous execution rather than allocating a new one.
    ///
    /// For simplicity and performance, only tracks failures without `inserted` and `timeouts`,
    pub fn insertValuesMinAllocs(
        self: *Self,
        now: u64,
        values: []SignedGossipData,
        timeout: u64,
        failed_indexes: *std.ArrayList(usize),
    ) error{OutOfMemory}!void {
        failed_indexes.clearRetainingCapacity();
        try failed_indexes.ensureTotalCapacity(values.len);

        for (values, 0..) |value, index| {
            const value_time = value.wallclock();
            const is_too_new = value_time > now +| timeout;
            const is_too_old = value_time < now -| timeout;
            if (is_too_new or is_too_old) {
                continue;
            }

            const did_insert = self.insert(value, now) catch false;
            if (!did_insert) {
                failed_indexes.appendAssumeCapacity(index);
            }
        }
    }

    pub fn len(self: *const Self) usize {
        return self.store.count();
    }

    pub fn updateRecordTimestamp(self: *Self, pubkey: Pubkey, now: u64) void {
        var updated_contact_info = false;
        const labels = .{
            GossipKey{ .ContactInfo = pubkey },
            GossipKey{ .LegacyContactInfo = pubkey },
        };
        // It suffices to only overwrite the origin's timestamp since that is
        // used when purging old values.
        inline for (labels) |contact_info_label| {
            if (self.store.getEntry(contact_info_label)) |entry| {
                entry.value_ptr.timestamp_on_insertion = now;
                updated_contact_info = true;
            }
        }
        if (updated_contact_info) return;
        // If the origin does not exist in the
        // table, fallback to exhaustive update on all associated records.
        if (self.pubkey_to_values.getEntry(pubkey)) |entry| {
            const pubkey_indexs = entry.value_ptr;
            for (pubkey_indexs.keys()) |index| {
                const value = &self.store.values()[index];
                value.timestamp_on_insertion = now;
            }
        }
    }

    // ** getter functions **
    pub fn get(self: *const Self, label: GossipKey) ?GossipVersionedData {
        return self.store.get(label);
    }

    /// Since a node may be represented with ContactInfo or LegacyContactInfo,
    /// this function checks for both, and efficiently returns the data as
    /// ThreadSafeContactInfo, regardless of how it was received.
    pub fn getThreadSafeContactInfo(self: *const Self, pubkey: Pubkey) ?ThreadSafeContactInfo {
        const label = GossipKey{ .ContactInfo = pubkey };
        if (self.store.get(label)) |v| {
            return ThreadSafeContactInfo.fromContactInfo(v.value.data.ContactInfo);
        } else {
            return ThreadSafeContactInfo.fromContactInfo(self.converted_contact_infos.get(pubkey) orelse return null);
        }
    }

    /// Iterates over the values in the given hashmap and looks up the
    /// corresponding values in the store. If the value is found, it is
    /// copied into the buffer. The cursor is updated to the last index
    /// that was copied.
    ///
    /// NOTE: if the allocator is null, the values are
    /// not cloned and the buffer will contain references to the store.
    /// In this case, its not safe to access these values across lock boundaries.
    ///
    /// Typical usage is to call this function with one of the tracked fields.
    /// For example, using `GossipTable.contact_infos` or `GossipTable.votes` as
    /// the `hashmap` field will return the corresponding ContactInfos or Votes from the store.
    ///
    /// eg,
    /// genericGetWithCursor(
    ///     allocator,
    ///     self.votes,
    ///     self.store,
    ///     &buf,
    ///     &caller_cursor,
    /// );
    fn genericGetEntriesWithCursor(
        allocator: ?std.mem.Allocator,
        hashmap: anytype,
        store: AutoArrayHashMap(GossipKey, GossipVersionedData),
        buf: []GossipVersionedData,
        caller_cursor: *usize,
    ) error{OutOfMemory}![]GossipVersionedData {
        const cursor_indexs = hashmap.keys();
        const store_values = store.values();

        var index: usize = 0;
        for (cursor_indexs) |cursor_index| {
            if (cursor_index < caller_cursor.*) {
                continue;
            }

            const entry_index = hashmap.get(cursor_index).?;
            const entry = store_values[entry_index];
            buf[index] = if (allocator == null) entry else try entry.clone(allocator.?);
            index += 1;

            if (index == buf.len) {
                break;
            }
        }
        // move up the caller_cursor
        caller_cursor.* += index;
        return buf[0..index];
    }

    pub fn getClonedEntriesWithCursor(
        self: *const Self,
        allocator: std.mem.Allocator,
        buf: []GossipVersionedData,
        caller_cursor: *usize,
    ) error{OutOfMemory}![]GossipVersionedData {
        return genericGetEntriesWithCursor(
            allocator,
            self.entries,
            self.store,
            buf,
            caller_cursor,
        );
    }

    /// Same as getContactInfos, but returns a slice of ThreadSafeContactInfos.
    /// It should be used in favour of getContactInfos whenever the result crosses
    /// a table lock boundary.
    pub fn getThreadSafeContactInfos(
        self: *const Self,
        buf: []ThreadSafeContactInfo,
        minimum_insertion_timestamp: u64,
    ) []ThreadSafeContactInfo {
        var infos = self.contactInfoIterator(minimum_insertion_timestamp);
        var i: usize = 0;
        while (infos.next()) |info| {
            if (i >= buf.len) break;
            buf[i] = ThreadSafeContactInfo.fromContactInfo(info.*);
            i += 1;
        }
        return buf[0..i];
    }

    /// Returns a slice of contact infos that are no older than minimum_insertion_timestamp.
    /// You must provide a buffer to fill with the contact infos. If you want all contact
    /// infos, the buffer should be at least `self.contact_infos.count()` in size.
    pub fn getContactInfos(
        self: *const Self,
        buf: []ContactInfo,
        minimum_insertion_timestamp: u64,
    ) []ContactInfo {
        var infos = self.contactInfoIterator(minimum_insertion_timestamp);
        var i: usize = 0;
        while (infos.next()) |info| {
            if (i >= buf.len) break;
            buf[i] = info.*;
            i += 1;
        }
        return buf[0..i];
    }

    /// Similar to getContactInfos, but returns an iterator instead
    /// of a slice. This allows you to avoid an allocation and avoid
    /// copying every value.
    pub fn contactInfoIterator(
        self: *const Self,
        minimum_insertion_timestamp: u64,
    ) ContactInfoIterator {
        return .{
            .values = self.store.values(),
            .converted_contact_infos = &self.converted_contact_infos,
            .indices = self.contact_infos.iterator().keys,
            .count = self.contact_infos.count(),
            .minimum_insertion_timestamp = minimum_insertion_timestamp,
        };
    }

    pub const ContactInfoIterator = struct {
        values: []const GossipVersionedData,
        converted_contact_infos: *const AutoArrayHashMap(Pubkey, ContactInfo),
        indices: [*]usize,
        count: usize,
        minimum_insertion_timestamp: u64,
        index_cursor: usize = 0,

        pub fn next(self: *@This()) ?*const ContactInfo {
            while (self.index_cursor < self.count) {
                const index = self.indices[self.index_cursor];
                self.index_cursor += 1;
                const value = &self.values[index];
                if (value.timestamp_on_insertion >= self.minimum_insertion_timestamp) {
                    return switch (value.value.data) {
                        .LegacyContactInfo => |*lci| self.converted_contact_infos.getPtr(lci.id) orelse unreachable,
                        .ContactInfo => |*ci| ci,
                        else => unreachable,
                    };
                }
            }
            return null;
        }
    };

    // ** shard getter fcns **
    pub fn getBitmaskMatches(
        self: *const Self,
        alloc: std.mem.Allocator,
        mask: u64,
        mask_bits: u64,
    ) error{OutOfMemory}!std.ArrayList(usize) {
        const indexs = try self.shards.find(alloc, mask, @intCast(mask_bits));
        return indexs;
    }

    // ** helper functions **
    pub fn checkMatchingShredVersion(self: *const Self, pubkey: Pubkey, expected_shred_version: u16) bool {
        if (self.shred_versions.get(pubkey)) |pubkey_shred_version| {
            if (pubkey_shred_version == expected_shred_version) {
                return true;
            }
        }
        return false;
    }

    /// ** triming values in the GossipTable **
    ///
    /// This frees the memory for any pointers in the GossipData.
    /// Be sure that this GossipData is not being used anywhere else when calling this.
    ///
    /// This method is not safe because neither GossipTable nor SignedGossipData
    /// provide any guarantees that the SignedGossipData being removed is not
    /// also being accessed somewhere else in the code after this is called.
    /// Since this frees the SignedGossipData, any accesses of the SignedGossipData
    /// after this function is called will result in a segfault.
    ///
    /// TODO: implement a safer approach to avoid dangling pointers, such as:
    ///  - removal buffer that is populated here and freed later
    ///  - reference counting for all gossip values
    pub fn remove(self: *Self, label: GossipKey, now: u64) error{ LabelNotFound, OutOfMemory }!void {
        const maybe_entry = self.store.getEntry(label);
        if (maybe_entry == null) return error.LabelNotFound;

        const entry = maybe_entry.?;
        const versioned_value = entry.value_ptr;
        const entry_index = self.entries.get(versioned_value.cursor_on_insertion).?;
        const hash = versioned_value.value_hash;
        const origin = versioned_value.value.id();

        const entry_indexs = self.pubkey_to_values.getEntry(origin).?.value_ptr;
        {
            const did_remove = entry_indexs.swapRemove(entry_index);
            std.debug.assert(did_remove);
        }

        // no more values associated with the pubkey
        if (entry_indexs.count() == 0) {
            {
                entry_indexs.deinit();
                const did_remove = self.pubkey_to_values.swapRemove(origin);
                std.debug.assert(did_remove);
            }

            if (self.shred_versions.contains(origin)) {
                const did_remove = self.shred_versions.remove(origin);
                std.debug.assert(did_remove);
            }
        }

        try self.purged.insert(hash, now);
        self.shards.remove(entry_index, &hash);

        switch (versioned_value.value.data) {
            .ContactInfo => {
                const did_remove = self.contact_infos.swapRemove(entry_index);
                std.debug.assert(did_remove);
            },
            .LegacyContactInfo => |lci| {
                const did_remove = self.contact_infos.swapRemove(entry_index);
                std.debug.assert(did_remove);
                var contact_info = self.converted_contact_infos.fetchSwapRemove(lci.id).?.value;
                contact_info.deinit();
            },
            .Vote => {
                const did_remove = self.votes.swapRemove(versioned_value.cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            .EpochSlots => {
                const did_remove = self.epoch_slots.swapRemove(versioned_value.cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            .DuplicateShred => {
                const did_remove = self.duplicate_shreds.swapRemove(versioned_value.cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            else => {},
        }

        {
            const did_remove = self.entries.swapRemove(versioned_value.cursor_on_insertion);
            std.debug.assert(did_remove);
        }

        // free memory while versioned_value still points to the correct data
        versioned_value.value.data.deinit(self.allocator);

        // remove from store
        // this operation replaces the data pointed to by versioned_value to
        // either the last element of the store, or undefined if the store is empty
        {
            const did_remove = self.store.swapRemove(label);
            std.debug.assert(did_remove);
        }

        // account for the swap with the last element
        const table_len = self.len();
        // if (index == table_len) then it was already the last
        // element so we dont need to do anything
        if (entry_index < table_len) {
            // versioned data now points to the element which was swapped in and needs updating
            const new_index_cursor = versioned_value.cursor_on_insertion;
            const new_index_origin = versioned_value.value.id();

            // update shards
            self.shards.remove(table_len, &versioned_value.value_hash);
            // wont fail because we just removed a value in line above
            self.shards.insert(entry_index, &versioned_value.value_hash) catch unreachable;

            // these also should not fail since there are no allocations - just changing the value
            switch (versioned_value.value.data) {
                .ContactInfo => {
                    const did_remove = self.contact_infos.swapRemove(table_len);
                    std.debug.assert(did_remove);
                    self.contact_infos.put(entry_index, {}) catch unreachable;
                },
                .LegacyContactInfo => {
                    const did_remove = self.contact_infos.swapRemove(table_len);
                    std.debug.assert(did_remove);
                    self.contact_infos.put(entry_index, {}) catch unreachable;
                },
                .Vote => {
                    self.votes.put(new_index_cursor, entry_index) catch unreachable;
                },
                .EpochSlots => {
                    self.epoch_slots.put(new_index_cursor, entry_index) catch unreachable;
                },
                .DuplicateShred => {
                    self.duplicate_shreds.put(new_index_cursor, entry_index) catch unreachable;
                },
                else => {},
            }
            self.entries.put(new_index_cursor, entry_index) catch unreachable;

            const new_entry_indexs = self.pubkey_to_values.getEntry(new_index_origin).?.value_ptr;
            const did_remove = new_entry_indexs.swapRemove(table_len);
            std.debug.assert(did_remove);
            new_entry_indexs.put(entry_index, {}) catch unreachable;
        }
    }

    /// Trim when over 90% of max capacity
    pub fn shouldTrim(self: *const Self, max_pubkey_capacity: usize) bool {
        const n_pubkeys = self.pubkey_to_values.count();
        return (10 * n_pubkeys > 9 * max_pubkey_capacity);
    }

    /// removes pubkeys and their associated values until the pubkey count is less than max_pubkey_capacity.
    /// returns the number of pubkeys removed.
    ///
    /// NOTE: the `now` parameter is used to populate the purged field with the timestamp of the removal.
    pub fn attemptTrim(self: *Self, now: u64, max_pubkey_capacity: usize) error{OutOfMemory}!u64 {
        if (!self.shouldTrim(max_pubkey_capacity)) return 0;

        const n_pubkeys = self.pubkey_to_values.count();
        const drop_size = n_pubkeys -| max_pubkey_capacity;
        // TODO: drop based on stake weight
        const drop_pubkeys = self.pubkey_to_values.keys()[0..drop_size];
        const labels = self.store.keys();

        // allocate here so SwapRemove doesnt mess with us
        var labels_to_remove = std.ArrayList(GossipKey).init(self.allocator);
        defer labels_to_remove.deinit();

        for (drop_pubkeys) |pubkey| {
            // remove all entries associated with the pubkey
            const entry_indexs = self.pubkey_to_values.getEntry(pubkey).?.value_ptr;
            const count = entry_indexs.count();
            for (entry_indexs.keys()[0..count]) |entry_index| {
                try labels_to_remove.append(labels[entry_index]);
            }
        }

        for (labels_to_remove.items) |label| {
            self.remove(label, now) catch unreachable;
        }

        return drop_pubkeys.len;
    }

    pub fn removeOldLabels(
        self: *Self,
        now: u64,
        timeout: u64,
    ) error{OutOfMemory}!u64 {
        const old_labels = try self.getOldLabels(now, timeout);
        defer old_labels.deinit();

        for (old_labels.items) |old_label| {
            // unreachable: label should always exist in store
            self.remove(old_label, now) catch unreachable;
        }

        return old_labels.items.len;
    }

    const GetOldLabelsTask = struct {
        // context
        key: Pubkey,
        table: *const GossipTable,
        cutoff_timestamp: u64,
        old_labels: std.ArrayList(GossipKey),

        // standard
        task: Task = .{ .callback = callback },
        done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

        pub fn deinit(self: *GetOldLabelsTask) void {
            self.old_labels.deinit();
        }

        pub fn callback(task: *Task) void {
            const self: *@This() = @fieldParentPtr("task", task);
            defer self.done.store(true, .release);

            // get assocaited entries
            const entry = self.table.pubkey_to_values.getEntry(self.key).?;

            // if contact info is up to date then we dont need to check the values
            const pubkey = entry.key_ptr;
            const labels = .{
                GossipKey{ .LegacyContactInfo = pubkey.* },
                GossipKey{ .ContactInfo = pubkey.* },
            };
            inline for (labels) |label| {
                if (self.table.get(label)) |*contact_info| {
                    const value_timestamp = @min(
                        contact_info.value.wallclock(),
                        contact_info.timestamp_on_insertion,
                    );
                    if (value_timestamp > self.cutoff_timestamp) {
                        return;
                    }
                }
            }

            // otherwise we iterate over the values
            var entry_indexs = entry.value_ptr;
            const count = entry_indexs.count();

            for (entry_indexs.iterator().keys[0..count]) |entry_index| {
                const versioned_value = self.table.store.values()[entry_index];
                const value_timestamp = @min(
                    versioned_value.value.wallclock(),
                    versioned_value.timestamp_on_insertion,
                );
                if (value_timestamp <= self.cutoff_timestamp) {
                    self.old_labels.append(versioned_value.value.label()) catch unreachable;
                }
            }
        }
    };

    pub fn getOldLabels(
        self: *Self,
        now: u64,
        timeout: u64,
    ) error{OutOfMemory}!std.ArrayList(GossipKey) {
        const cutoff_timestamp = now -| timeout;
        const n_pubkeys = self.pubkey_to_values.count();

        var tasks = try self.allocator.alloc(GetOldLabelsTask, n_pubkeys);
        defer {
            for (tasks) |*task| task.deinit();
            self.allocator.free(tasks);
        }

        // run this loop in parallel
        for (self.pubkey_to_values.keys()[0..n_pubkeys], 0..) |key, i| {
            tasks[i] = GetOldLabelsTask{
                .key = key,
                .table = self,
                .cutoff_timestamp = cutoff_timestamp,
                .old_labels = std.ArrayList(GossipKey).init(self.allocator),
            };

            // run it
            const batch = Batch.from(&tasks[i].task);
            self.thread_pool.schedule(batch);
        }

        // wait for them to be done to release the lock
        var output_length: u64 = 0;
        for (tasks) |*task| {
            while (!task.done.load(.acquire)) {
                // wait
            }
            output_length += task.old_labels.items.len;
        }

        // move labels to one big array
        var output = try std.ArrayList(GossipKey).initCapacity(self.allocator, output_length);
        for (tasks) |*task| {
            output.appendSliceAssumeCapacity(task.old_labels.items);
        }

        return output;
    }

    pub fn getOwnedContactInfoByGossipAddr(
        self: *const Self,
        gossip_addr: SocketAddr,
    ) !?ContactInfo {
        const contact_indexs = self.contact_infos.keys();
        for (contact_indexs) |index| {
            const entry: GossipVersionedData = self.store.values()[index];
            switch (entry.value.data) {
                .ContactInfo => |ci| if (ci.getSocket(.gossip)) |addr| {
                    if (addr.eql(&gossip_addr)) return try ci.clone();
                },
                .LegacyContactInfo => |lci| if (lci.gossip.eql(&gossip_addr)) {
                    return try lci.toContactInfo(self.allocator);
                },
                else => continue,
            }
        }
        return null;
    }
};

pub const HashTimeQueue = struct {
    // TODO: benchmark other structs?
    queue: std.ArrayList(HashAndTime),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .queue = std.ArrayList(HashAndTime).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.queue.deinit();
    }

    pub fn len(self: *const Self) usize {
        return self.queue.items.len;
    }

    pub fn insert(self: *Self, v: Hash, now: u64) error{OutOfMemory}!void {
        const hat = HashAndTime{
            .hash = v,
            .timestamp = now,
        };
        try self.queue.append(hat);
    }

    pub fn trim(self: *Self, oldest_timestamp: u64) error{OutOfMemory}!void {
        var i: usize = 0;
        const length = self.len();
        while (i < length) {
            const data_timestamp = self.queue.items[i].timestamp;
            if (data_timestamp >= oldest_timestamp) {
                break;
            }
            i += 1;
        }

        // remove values up to i
        if (i > 0) {
            var new_queue = try std.ArrayList(HashAndTime).initCapacity(self.allocator, length - i);
            new_queue.appendSliceAssumeCapacity(self.queue.items[i..length]);

            self.queue.deinit();
            self.queue = new_queue;
        }
    }

    pub fn getValues(self: *const Self) error{OutOfMemory}!std.ArrayList(Hash) {
        var hashes = try std.ArrayList(Hash).initCapacity(self.allocator, self.len());
        for (self.queue.items) |data| {
            hashes.appendAssumeCapacity(data.hash);
        }
        return hashes;
    }
};

test "gossip.table: remove old values" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rng = std.rand.DefaultPrng.init(seed);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    for (0..5) |_| {
        const value = try SignedGossipData.initSigned(
            GossipData.random(rng.random()),
            &keypair,
        );
        // TS = 100
        _ = try table.insert(value, 100);
    }
    try std.testing.expect(table.len() == 5);

    // cutoff = 150
    const values = try table.getOldLabels(200, 50);
    defer values.deinit();
    // remove all values
    for (values.items) |value| {
        try table.remove(value, 200);
    }

    try std.testing.expectEqual(table.len(), 0);
}

test "gossip.table: insert and remove value" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rng = std.rand.DefaultPrng.init(seed);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    const value = try SignedGossipData.initSigned(
        GossipData.randomFromIndex(rng.random(), 0),
        &keypair,
    );
    _ = try table.insert(value, 100);

    const label = value.label();
    try table.remove(label, 100);
}

test "gossip.table: trim pruned values" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rng = std.rand.DefaultPrng.init(seed);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    const N_VALUES = 10;
    const N_TRIM_VALUES = 5;

    var values = std.ArrayList(SignedGossipData).init(std.testing.allocator);
    defer values.deinit();

    for (0..N_VALUES) |_| {
        const value = try SignedGossipData.initSigned(
            GossipData.random(rng.random()),
            &keypair,
        );
        _ = try table.insert(value, 100);
        try values.append(value);
    }
    try std.testing.expectEqual(table.len(), N_VALUES);
    try std.testing.expectEqual(table.purged.len(), 0);
    try std.testing.expectEqual(table.pubkey_to_values.count(), N_VALUES);

    for (0..values.items.len) |i| {
        const origin = values.items[i].id();
        _ = table.pubkey_to_values.get(origin).?;
    }

    _ = try table.attemptTrim(0, N_TRIM_VALUES);

    try std.testing.expectEqual(table.len(), N_VALUES - N_TRIM_VALUES);
    try std.testing.expectEqual(table.pubkey_to_values.count(), N_VALUES - N_TRIM_VALUES);
    try std.testing.expectEqual(table.purged.len(), N_TRIM_VALUES);

    _ = try table.attemptTrim(0, 0);
    try std.testing.expectEqual(table.len(), 0);
}

test "gossip.HashTimeQueue: insert multiple values" {
    var htq = HashTimeQueue.init(std.testing.allocator);
    defer htq.deinit();

    var default_prng = std.rand.DefaultPrng.init(@bitCast(std.time.milliTimestamp()));
    const rand = default_prng.random();

    try htq.insert(Hash.random(rand), 100);
    try htq.insert(Hash.random(rand), 102);
    try htq.insert(Hash.random(rand), 103);

    try htq.trim(102);
    try std.testing.expect(htq.len() == 2);

    try htq.insert(Hash.random(rand), 101);
    try htq.insert(Hash.random(rand), 120);
    try std.testing.expect(htq.len() == 4);

    try htq.trim(150);
    try std.testing.expect(htq.len() == 0);
}

test "gossip.HashTimeQueue: trim pruned values" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();
    const data = GossipData{
        .LegacyContactInfo = LegacyContactInfo.random(rng),
    };
    var value = try SignedGossipData.initSigned(data, &keypair);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    // timestamp = 100
    _ = try table.insert(value, 100);

    // should lead to prev being pruned
    var new_data = GossipData{
        .LegacyContactInfo = LegacyContactInfo.random(rng),
    };
    new_data.LegacyContactInfo.id = data.LegacyContactInfo.id;
    // older wallclock
    new_data.LegacyContactInfo.wallclock += data.LegacyContactInfo.wallclock;
    value = try SignedGossipData.initSigned(new_data, &keypair);
    _ = try table.insert(value, 120);

    try std.testing.expectEqual(table.purged.len(), 1);

    // its timestamp should be 120 so, 130 = clear pruned values
    try table.purged.trim(130);

    try std.testing.expectEqual(table.purged.len(), 0);
}

test "gossip.table: insert and get" {
    const keypair = try KeyPair.create([_]u8{1} ** 32);

    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();
    var value = try SignedGossipData.random(rng, &keypair);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    _ = try table.insert(value, 0);

    const label = value.label();
    const x = table.get(label).?;
    _ = x;
}

test "gossip.table: insert and get contact_info" {
    const kp = try KeyPair.create([_]u8{1} ** 32);
    var id = Pubkey.fromPublicKey(&kp.public_key);

    const legacy_contact_info = LegacyContactInfo.default(id);
    var gossip_value = try SignedGossipData.initSigned(GossipData{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(std.testing.allocator, &tp);
    defer table.deinit();

    // test insertion
    _ = try table.insert(gossip_value, 0);

    // test retrieval
    var buf: [100]ContactInfo = undefined;
    var nodes = table.getContactInfos(&buf, 0);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].pubkey.equals(&id));

    // test re-insertion
    const result = table.insert(gossip_value, 0);
    try std.testing.expectError(GossipTable.InsertionError.DuplicateValue, result);

    // test re-insertion with greater wallclock
    gossip_value.data.LegacyContactInfo.wallclock += 2;
    const v = gossip_value.data.LegacyContactInfo.wallclock;
    _ = try table.insert(gossip_value, 0);

    // check retrieval
    nodes = table.getContactInfos(&buf, 0);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].wallclock == v);
}
