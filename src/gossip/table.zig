const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const AutoArrayHashMap = std.AutoArrayHashMap;
const AutoHashMap = std.AutoHashMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const GossipTableShards = sig.gossip.shards.GossipTableShards;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const GossipData = sig.gossip.data.GossipData;
const GossipMap = sig.gossip.map.GossipMap;
const GossipMetadata = sig.gossip.data.GossipMetadata;
const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const GossipKey = sig.gossip.data.GossipKey;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.Pubkey;
const SocketAddr = sig.net.SocketAddr;

const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;
pub const UNIQUE_PUBKEY_CAPACITY: usize = 8_192;
// TODO: cli arg for this
pub const MAX_TABLE_SIZE: usize = 1_000_000; // TODO: better value for this

pub const HashAndTime = struct { hash: Hash, timestamp: u64 };

// indexable HashSet
pub fn AutoArrayHashSet(comptime T: type) type {
    return AutoArrayHashMap(T, void);
}

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
    store: GossipMap,

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
    // NOTE: this allocator is used to free any gossip data inserted into the table
    gossip_data_allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, gossip_data_allocator: std.mem.Allocator) !Self {
        return Self{
            .store = .{},
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
            .gossip_data_allocator = gossip_data_allocator,
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
            entry.getGossipData().deinit(self.gossip_data_allocator);
        }
        self.store.deinit(self.allocator);
    }

    pub const InsertResult = union(enum) {
        success: enum { new, replaced },
        fail: enum { too_old, duplicate, table_full },
    };

    pub fn insert(self: *Self, value: SignedGossipData, now: u64) !InsertResult {
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const bytes = try bincode.writeToSlice(&buf, value, bincode.Params.standard);
        const value_hash = Hash.init(bytes);
        const metadata = GossipMetadata{
            .signature = value.signature,
            .value_hash = value_hash,
            .timestamp_on_insertion = now,
            .cursor_on_insertion = self.cursor,
        };
        const versioned_value = GossipVersionedData{
            .data = value.data,
            .metadata = metadata,
        };

        const label = value.label();
        const result = try self.store.getOrPut(self.allocator, label);
        const entry_index = result.entry.index;
        const origin = value.id();

        // entry doesnt exist
        if (!result.found_existing) {
            // if table is full, return early
            if (self.store.count() >= MAX_TABLE_SIZE) {
                _ = self.store.swapRemove(label);
                return .{ .fail = .table_full };
            }

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

            try self.shards.insert(entry_index, &metadata.value_hash);

            try self.entries.put(self.cursor, entry_index);

            const maybe_node_entry = self.pubkey_to_values.getEntry(origin);
            if (maybe_node_entry) |node_entry| {
                try node_entry.value_ptr.put(entry_index, {});
            } else {
                var indexs = AutoArrayHashSet(usize).init(self.allocator);
                errdefer indexs.deinit();
                try indexs.put(entry_index, {});
                try self.pubkey_to_values.put(origin, indexs);
            }

            result.entry.setVersionedData(versioned_value);
            self.cursor += 1;

            // inserted new entry
            return .{ .success = .new };

            // should overwrite existing entry
        } else if (versioned_value.overwrites(&result.entry.getVersionedData())) {
            const old_entry = result.entry.metadata_ptr.*;

            switch (value.data) {
                .ContactInfo => |*info| {
                    try self.shred_versions.put(info.pubkey, info.shred_version);
                },
                .LegacyContactInfo => |*info| {
                    try self.shred_versions.put(info.id, info.shred_version);
                    const contact_info = try info.toContactInfo(self.allocator);
                    var old_info = try self.converted_contact_infos.fetchPut(
                        info.id,
                        contact_info,
                    );
                    old_info.?.value.deinit();
                },
                .Vote => {
                    const did_remove = self.votes.swapRemove(old_entry.cursor_on_insertion);
                    std.debug.assert(did_remove);
                    try self.votes.put(self.cursor, entry_index);
                },
                .EpochSlots => {
                    const did_remove = self.epoch_slots.swapRemove(
                        old_entry.cursor_on_insertion,
                    );
                    std.debug.assert(did_remove);
                    try self.epoch_slots.put(self.cursor, entry_index);
                },
                .DuplicateShred => {
                    const did_remove = self.duplicate_shreds.swapRemove(
                        old_entry.cursor_on_insertion,
                    );
                    std.debug.assert(did_remove);
                    try self.duplicate_shreds.put(self.cursor, entry_index);
                },
                else => {},
            }

            // remove and insert to make sure the shard ordering is oldest-to-newest
            // NOTE: do we need the ordering to be oldest-to-newest?
            self.shards.remove(entry_index, &old_entry.value_hash);
            try self.shards.insert(entry_index, &metadata.value_hash);

            const did_remove = self.entries.swapRemove(old_entry.cursor_on_insertion);
            std.debug.assert(did_remove);
            try self.entries.put(self.cursor, entry_index);

            // As long as the pubkey does not change, self.records
            // does not need to be updated.
            std.debug.assert(result.entry.getGossipData().id().equals(&origin));

            try self.purged.insert(old_entry.value_hash, now);

            const overwritten_data = result.entry.getGossipData();
            overwritten_data.deinit(self.gossip_data_allocator);
            result.entry.setVersionedData(versioned_value);
            self.cursor += 1;

            // overwrite existing entry
            return .{ .success = .replaced };

            // do nothing
        } else {
            const current_entry = result.entry.metadata_ptr.*;

            if (current_entry.value_hash.order(&metadata.value_hash) != .eq) {
                // if hash isnt the same and override() is false then msg is old
                try self.purged.insert(metadata.value_hash, now);
                return .{ .fail = .too_old };
            } else {
                // hash is the same then its a duplicate value which isnt stored
                return .{ .fail = .duplicate };
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
                entry.metadata_ptr.timestamp_on_insertion = now;
                updated_contact_info = true;
            }
        }
        if (updated_contact_info) return;
        // If the origin does not exist in the
        // table, fallback to exhaustive update on all associated records.
        if (self.pubkey_to_values.getEntry(pubkey)) |entry| {
            const pubkey_indexs = entry.value_ptr;
            for (pubkey_indexs.keys()) |index| {
                self.store.metadata.items[index].timestamp_on_insertion = now;
            }
        }
    }

    /// Gets both a GossipData and its associated GossipMetadata.
    /// Try not to use this unless absolutely necessary.
    /// Use getData or getMetadata instead if possible,
    pub fn get(self: *const Self, label: GossipKey) ?GossipVersionedData {
        return self.store.get(label);
    }

    pub fn getData(self: *const Self, label: GossipKey) ?GossipData {
        return self.store.getData(label);
    }

    pub fn getMetadata(self: *const Self, label: GossipKey) ?GossipMetadata {
        return self.store.getMetadata(label);
    }

    /// Since a node may be represented with ContactInfo or LegacyContactInfo,
    /// this function checks for both, and efficiently returns the data as
    /// ThreadSafeContactInfo, regardless of how it was received.
    pub fn getThreadSafeContactInfo(self: *const Self, pubkey: Pubkey) ?ThreadSafeContactInfo {
        const label = GossipKey{ .ContactInfo = pubkey };
        if (self.store.get(label)) |v| {
            return ThreadSafeContactInfo.fromContactInfo(v.data.ContactInfo);
        } else {
            const contact_info = self.converted_contact_infos.get(pubkey) orelse return null;
            return ThreadSafeContactInfo.fromContactInfo(contact_info);
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
        allocator: std.mem.Allocator,
        cursor_hashmap: anytype,
        store: GossipMap,
        buf: []GossipVersionedData,
        caller_cursor: *usize,
    ) error{OutOfMemory}![]GossipVersionedData {
        const cursor_keys = cursor_hashmap.keys();

        // NOTE: we need a clone so we dont modify (and break) the map.
        // see .keys() doc comment for more info.
        const cursors = try allocator.dupe(u64, cursor_keys);
        defer allocator.free(cursors);

        // sort the cursors so they are increasing
        std.mem.sort(u64, cursors, {}, struct {
            fn lessThan(_: void, lhs: u64, rhs: u64) bool {
                return lhs < rhs;
            }
        }.lessThan);

        var count: usize = 0;
        var last_cursor_included: u64 = caller_cursor.*;

        for (cursors) |cursor| {
            if (cursor < caller_cursor.*) {
                continue;
            }

            const entry_index = cursor_hashmap.get(cursor).?;
            const entry = store.getByIndex(entry_index);
            // sanity check
            std.debug.assert(entry.metadata.cursor_on_insertion == cursor);

            buf[count] = try entry.clone(allocator);
            count += 1;
            // NOTE: cursor values are not guaranteed to be incremental so
            // we dont use an incremental (/+1) approach
            last_cursor_included = cursor;

            if (count == buf.len) {
                break;
            }
        }

        // update the caller_cursor
        caller_cursor.* = last_cursor_included;
        // +1 do we dont include the last value next loop
        if (count != 0) caller_cursor.* += 1;

        return buf[0..count];
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
        while (infos.nextThreadSafe()) |info| {
            if (i >= buf.len) break;
            buf[i] = info;
            i += 1;
        }
        return buf[0..i];
    }

    /// Get peers from the gossip table which have the same shred version.
    pub fn getThreadSafeContactInfosMatchingShredVersion(
        self: Self,
        allocator: std.mem.Allocator,
        pubkey: *const Pubkey,
        shred_version: u16,
        minumum_insertion_timestamp: u64,
    ) !std.ArrayList(ThreadSafeContactInfo) {
        var contact_info_iter = self.contactInfoIterator(minumum_insertion_timestamp);
        var peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(
            allocator,
            self.contact_infos.count(),
        );

        while (contact_info_iter.nextThreadSafe()) |contact_info| {
            if (!contact_info.pubkey.equals(pubkey) and
                contact_info.shred_version == shred_version)
            {
                peers.appendAssumeCapacity(contact_info);
            }
        }

        return peers;
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
            .map = &self.store,
            .converted_contact_infos = &self.converted_contact_infos,
            .indices = self.contact_infos.iterator().keys,
            .count = self.contact_infos.count(),
            .minimum_insertion_timestamp = minimum_insertion_timestamp,
        };
    }

    pub const ContactInfoIterator = struct {
        map: *const GossipMap,
        converted_contact_infos: *const AutoArrayHashMap(Pubkey, ContactInfo),
        indices: [*]usize,
        count: usize,
        minimum_insertion_timestamp: u64,
        index_cursor: usize = 0,

        pub fn next(self: *@This()) ?*const ContactInfo {
            while (self.index_cursor < self.count) {
                const index = self.indices[self.index_cursor];
                self.index_cursor += 1;
                const metadata = self.map.metadata.items[index];
                if (metadata.timestamp_on_insertion >= self.minimum_insertion_timestamp) {
                    switch (self.map.tagOfIndex(index)) {
                        .ContactInfo => return self.map.getTypedPtr(.ContactInfo, index),
                        .LegacyContactInfo => {
                            const legacy_info = self.map.getTypedPtr(.LegacyContactInfo, index);
                            return self.converted_contact_infos.getPtr(legacy_info.id).?;
                        },
                        else => unreachable,
                    }
                }
            }
            return null;
        }

        pub fn nextThreadSafe(self: *@This()) ?ThreadSafeContactInfo {
            const contact_info = self.next() orelse return null;
            return ThreadSafeContactInfo.fromContactInfo(contact_info.*);
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
    pub fn checkMatchingShredVersion(
        self: *const Self,
        pubkey: Pubkey,
        expected_shred_version: u16,
    ) bool {
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
    pub fn remove(
        self: *Self,
        label: GossipKey,
        now: u64,
    ) error{ LabelNotFound, OutOfMemory }!void {
        const maybe_entry = self.store.getEntry(label);
        if (maybe_entry == null) return error.LabelNotFound;

        const entry = maybe_entry.?;
        var gossip_data = entry.getGossipData();
        const entry_index = self.entries.get(entry.metadata_ptr.cursor_on_insertion).?;
        const hash = entry.metadata_ptr.value_hash;
        const origin = gossip_data.id();

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

        const cursor_on_insertion = entry.metadata_ptr.cursor_on_insertion;

        switch (entry.tag()) {
            .ContactInfo => {
                const did_remove = self.contact_infos.swapRemove(entry_index);
                std.debug.assert(did_remove);
            },
            .LegacyContactInfo => {
                const did_remove = self.contact_infos.swapRemove(entry_index);
                std.debug.assert(did_remove);
                const lci = self.store.getTypedPtr(.LegacyContactInfo, entry_index);
                var contact_info = self.converted_contact_infos.fetchSwapRemove(lci.id).?.value;
                contact_info.deinit();
            },
            .Vote => {
                const did_remove = self.votes.swapRemove(cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            .EpochSlots => {
                const did_remove = self.epoch_slots.swapRemove(cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            .DuplicateShred => {
                const did_remove = self.duplicate_shreds.swapRemove(cursor_on_insertion);
                std.debug.assert(did_remove);
            },
            else => {},
        }

        {
            const did_remove = self.entries.swapRemove(cursor_on_insertion);
            std.debug.assert(did_remove);
        }

        // free memory while gossip_data still points to the correct data
        gossip_data.deinit(self.gossip_data_allocator);

        // remove from store
        // this operation replaces the data pointed to by gossip_data to
        // either the last element of the store, or undefined if the store is empty
        {
            const did_remove = self.store.swapRemove(label);
            std.debug.assert(did_remove);
        }

        self.accountForSwapRemove(entry_index);
    }

    /// Called during remove to account for the swap that occurs when an item is
    /// swapRemoved from the map. The last item from the map is moved into that
    /// location, so the indices pointing to that item need to be updated to
    /// point to its new index.
    ///
    /// This is separated into a different function to isolate the state to
    /// avoid mistakes. The new entry must be acquired from map using the
    /// existing index. The prior entry does not point to the correct item.
    fn accountForSwapRemove(self: *GossipTable, entry_index: usize) void {
        const table_len = self.len();
        // if (index == table_len) then it was already the last
        // element so we dont need to do anything
        std.debug.assert(entry_index <= table_len);
        if (entry_index == table_len) return;

        // replace data with newly swapped value
        const entry = self.store.getEntryByIndex(entry_index);
        const new_index_cursor = entry.metadata_ptr.cursor_on_insertion;
        const new_index_origin = entry.getGossipData().id();

        // update shards
        self.shards.remove(table_len, &entry.metadata_ptr.value_hash);
        // wont fail because we just removed a value in line above
        self.shards.insert(entry_index, &entry.metadata_ptr.value_hash) catch unreachable;

        // these also should not fail since there are no allocations - just changing the value
        switch (entry.tag()) {
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
            self.remove(label, now) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => unreachable,
            };
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

    pub fn getOldLabels(
        self: *Self,
        now: u64,
        timeout: u64,
    ) error{OutOfMemory}!std.ArrayList(GossipKey) {
        const cutoff_timestamp = now -| timeout;

        var old_labels = std.ArrayList(GossipKey).init(self.allocator);
        errdefer old_labels.deinit();

        next_key: for (self.pubkey_to_values.keys()) |key| {
            // get associated entries
            const entry = self.pubkey_to_values.getEntry(key).?;

            // if contact info is up to date then we dont need to check the values
            const pubkey = entry.key_ptr;
            const labels = .{
                GossipKey{ .LegacyContactInfo = pubkey.* },
                GossipKey{ .ContactInfo = pubkey.* },
            };
            inline for (labels) |label| {
                if (self.get(label)) |*contact_info| {
                    const value_timestamp = @min(
                        contact_info.data.wallclock(),
                        contact_info.metadata.timestamp_on_insertion,
                    );
                    if (value_timestamp > cutoff_timestamp) {
                        continue :next_key;
                    }
                }
            }

            // otherwise we iterate over the values
            var entry_indexs = entry.value_ptr;
            const count = entry_indexs.count();

            for (entry_indexs.iterator().keys[0..count]) |entry_index| {
                const versioned_value = self.store.getByIndex(entry_index);
                const value_timestamp = @min(
                    versioned_value.data.wallclock(),
                    versioned_value.metadata.timestamp_on_insertion,
                );
                if (value_timestamp <= cutoff_timestamp) {
                    try old_labels.append(versioned_value.data.label());
                }
            }
        }

        return old_labels;
    }

    pub fn getOwnedContactInfoByGossipAddr(
        self: *const Self,
        gossip_addr: SocketAddr,
    ) !?ContactInfo {
        const contact_indexs = self.contact_infos.keys();
        for (contact_indexs) |index| {
            switch (self.store.tagOfIndex(index)) {
                .ContactInfo => {
                    const ci = self.store.getTypedPtr(.ContactInfo, index);
                    if (ci.getSocket(.gossip)) |addr| {
                        if (addr.eql(&gossip_addr)) return try ci.clone();
                    }
                },
                .LegacyContactInfo => {
                    const lci = self.store.getTypedPtr(.LegacyContactInfo, index);
                    if (lci.gossip.eql(&gossip_addr)) {
                        return try lci.toContactInfo(self.allocator);
                    }
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
            var new_queue = try std.ArrayList(HashAndTime).initCapacity(
                self.allocator,
                length - i,
            );
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

test "remove old values" {
    const keypair = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    for (0..5) |_| {
        const value = SignedGossipData.initSigned(
            &keypair,
            GossipData.initRandom(prng.random()),
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

test "insert and remove value" {
    const keypair = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    const value = SignedGossipData.initSigned(
        &keypair,
        GossipData.randomFromIndex(prng.random(), 0),
    );
    _ = try table.insert(value, 100);

    const label = value.label();
    try table.remove(label, 100);
}

test "trim pruned values" {
    const keypair = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    const N_VALUES = 10;
    const N_TRIM_VALUES = 5;

    var values = std.ArrayList(SignedGossipData).init(std.testing.allocator);
    defer values.deinit();

    for (0..N_VALUES) |_| {
        const value = SignedGossipData.initSigned(
            &keypair,
            GossipData.initRandom(prng.random()),
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    try htq.insert(Hash.initRandom(random), 100);
    try htq.insert(Hash.initRandom(random), 102);
    try htq.insert(Hash.initRandom(random), 103);

    try htq.trim(102);
    try std.testing.expect(htq.len() == 2);

    try htq.insert(Hash.initRandom(random), 101);
    try htq.insert(Hash.initRandom(random), 120);
    try std.testing.expect(htq.len() == 4);

    try htq.trim(150);
    try std.testing.expect(htq.len() == 0);
}

test "gossip.HashTimeQueue: trim pruned values" {
    const keypair = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const data = GossipData{
        .LegacyContactInfo = LegacyContactInfo.initRandom(random),
    };
    var value = SignedGossipData.initSigned(&keypair, data);

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    // timestamp = 100
    _ = try table.insert(value, 100);

    // should lead to prev being pruned
    var new_data = GossipData{
        .LegacyContactInfo = LegacyContactInfo.initRandom(random),
    };
    new_data.LegacyContactInfo.id = data.LegacyContactInfo.id;
    // older wallclock
    new_data.LegacyContactInfo.wallclock += data.LegacyContactInfo.wallclock;
    value = SignedGossipData.initSigned(&keypair, new_data);
    _ = try table.insert(value, 120);

    try std.testing.expectEqual(table.purged.len(), 1);

    // its timestamp should be 120 so, 130 = clear pruned values
    try table.purged.trim(130);

    try std.testing.expectEqual(table.purged.len(), 0);
}

test "insert and get" {
    const keypair = try KeyPair.generateDeterministic(@splat(1));

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var value = SignedGossipData.initRandom(random, &keypair);

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    _ = try table.insert(value, 0);

    const label = value.label();
    const x = table.get(label).?;
    _ = x;
}

test "insert and get contact_info" {
    const kp = try KeyPair.generateDeterministic(@splat(1));
    var id = Pubkey.fromPublicKey(&kp.public_key);

    var prng = std.Random.Xoshiro256.init(10);
    const random = prng.random();

    const ci = try ContactInfo.initRandom(
        std.testing.allocator,
        random,
        id,
        0,
        0,
        10,
    );
    var gossip_value = SignedGossipData.initSigned(&kp, .{
        .ContactInfo = ci,
    });

    var table = try GossipTable.init(std.testing.allocator, std.testing.allocator);
    defer table.deinit();

    // test insertion
    const result = try table.insert(gossip_value, 0);
    try std.testing.expectEqual(.success, std.meta.activeTag(result));
    try std.testing.expectEqual(.new, result.success);

    // test retrieval
    var buf: [100]ContactInfo = undefined;
    var nodes = table.getContactInfos(&buf, 0);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].pubkey.equals(&id));

    // test re-insertion
    const result2 = try table.insert(gossip_value, 0);
    try std.testing.expectEqual(.fail, std.meta.activeTag(result2));
    try std.testing.expectEqual(.duplicate, result2.fail);

    // test re-insertion with greater wallclock
    gossip_value.data.ContactInfo.wallclock += 2;
    const v = gossip_value.data.ContactInfo.wallclock;
    const result3 = blk: {
        const cloned = try gossip_value.clone(std.testing.allocator);
        errdefer cloned.deinit(std.testing.allocator);
        break :blk try table.insert(cloned, 0);
    };
    try std.testing.expectEqual(.success, std.meta.activeTag(result3));
    try std.testing.expectEqual(.replaced, result3.success);

    // check retrieval
    nodes = table.getContactInfos(&buf, 0);
    try std.testing.expect(nodes.len == 1);
    try std.testing.expect(nodes[0].wallclock == v);
}
