const std = @import("std");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const SplitUnionList = sig.utils.collections.SplitUnionList;

const GossipData = gossip.data.GossipData;
const GossipDataTag = gossip.data.GossipDataTag;
const GossipKey = gossip.data.GossipKey;
const GossipVersionedData = gossip.data.GossipVersionedData;

const assert = std.debug.assert;

pub const GossipMap = struct {
    key_to_index: KeyToIndex = .{},
    gossip_data: SplitUnionList(GossipData) = SplitUnionList(GossipData).init(),
    metadata: std.ArrayListUnmanaged(Metadata) = .{},

    const KeyToIndex = std.AutoArrayHashMapUnmanaged(GossipKey, SplitUnionList(GossipData).Index);

    pub const Metadata = struct {
        signature: Signature,
        value_hash: Hash,
        timestamp_on_insertion: u64,
        cursor_on_insertion: u64,
    };

    pub fn deinit(self: *GossipMap, allocator: Allocator) void {
        self.key_to_index.deinit(allocator);
        self.gossip_data.deinit(allocator);
        self.metadata.deinit(allocator);
    }

    pub fn count(self: *const GossipMap) usize {
        return self.key_to_index.count();
    }

    pub fn get(self: *const GossipMap, key: GossipKey) ?GossipVersionedData {
        const index = self.key_to_index.getIndex(key) orelse return null;
        return self.getByIndex(index);
    }

    pub fn getByIndex(self: *const GossipMap, index: usize) GossipVersionedData {
        const metadata = self.metadata.items[index];
        const tagged_index = self.key_to_index.values()[index];
        return .{
            .value = .{
                .signature = metadata.signature,
                .data = self.gossip_data.get(tagged_index),
            },
            .value_hash = metadata.value_hash,
            .timestamp_on_insertion = metadata.timestamp_on_insertion,
            .cursor_on_insertion = metadata.cursor_on_insertion,
        };
    }

    pub fn getEntry(self: *const GossipMap, key: GossipKey) ?Entry {
        const index = self.key_to_index.getIndex(key) orelse return null;
        return self.getEntryByIndex(index);
    }

    pub fn getEntryByIndex(self: *const GossipMap, index: usize) Entry {
        const entries = self.key_to_index.entries.slice();
        return .{
            .key_ptr = &entries.items(.key)[index],
            .metadata_ptr = &self.metadata.items[index],
            .gossip_data_entry = self.gossip_data.getEntry(entries.items(.value)[index]),
            .index = index,
        };
    }

    pub const Entry = struct {
        key_ptr: *GossipKey,
        metadata_ptr: *Metadata,
        gossip_data_entry: SplitUnionList(GossipData).Entry,
        index: usize,

        pub fn tag(self: Entry) GossipDataTag {
            return self.gossip_data_entry.index.tag;
        }

        pub fn getVersionedData(self: Entry) GossipVersionedData {
            return .{
                .value = .{
                    .signature = self.metadata_ptr.signature,
                    .data = self.getGossipData(),
                },
                .value_hash = self.metadata_ptr.value_hash,
                .timestamp_on_insertion = self.metadata_ptr.timestamp_on_insertion,
                .cursor_on_insertion = self.metadata_ptr.cursor_on_insertion,
            };
        }

        pub fn setVersionedData(self: Entry, versioned: GossipVersionedData) void {
            self.metadata_ptr.* = .{
                .signature = versioned.value.signature,
                .value_hash = versioned.value_hash,
                .timestamp_on_insertion = versioned.timestamp_on_insertion,
                .cursor_on_insertion = versioned.cursor_on_insertion,
            };
            self.setGossipData(versioned.value.data);
        }

        pub fn getGossipData(self: Entry) GossipData {
            return self.gossip_data_entry.read();
        }

        pub fn setGossipData(self: Entry, gossip_data: GossipData) void {
            return self.gossip_data_entry.write(gossip_data);
        }

        pub fn getTypedPtr(
            self: *const Entry,
            comptime gossip_tag: GossipDataTag,
        ) *const gossip_tag.Value() {
            return &@field(self.gossip_data_entry.items(.data)[self.index], @tagName(gossip_tag));
        }
    };

    pub fn keys(self: *const GossipMap) []GossipKey {
        return self.key_to_index.keys();
    }

    /// If you already know the index and the type of an item, you can directly
    /// access that value with this function. The return value will be unwrapped
    /// out of the union. It will be the direct bare data such as a ContactInfo.
    ///
    /// This is cheaper than using `getByIndex` since it doesn't need to copy
    /// anything except a pointer.
    ///
    /// This function has undefined behavior if the index does not correspond to
    /// an item of the specified type.
    pub fn getTypedPtr(
        self: *const GossipMap,
        comptime tag: GossipDataTag,
        index: usize,
    ) *const tag.Value() {
        return self.gossip_data.getTypedConst(tag, self.key_to_index.values()[index]);
    }

    pub fn tagOfIndex(self: *const GossipMap, index: usize) GossipDataTag {
        return self.key_to_index.values()[index].tag;
    }

    pub fn swapRemove(self: *GossipMap, key: GossipKey) bool {
        const index = self.key_to_index.getIndex(key) orelse return false;
        const tagged_index = self.key_to_index.values()[index];

        self.key_to_index.swapRemoveAt(index);
        _ = self.gossip_data.swapRemove(tagged_index);
        _ = self.metadata.swapRemove(index);

        // reindex the moved item, if there was one
        const tag_len = self.gossip_data.tagLen(tagged_index.tag);
        assert(tagged_index.index <= tag_len);
        if (tagged_index.index < tag_len) {
            const newly_swapped = self.gossip_data.get(tagged_index);
            const index_entry = self.key_to_index.getEntry(newly_swapped.label()).?;
            index_entry.value_ptr.* = tagged_index;
        }

        return true;
    }

    pub fn getOrPut(self: *GossipMap, allocator: Allocator, key: GossipKey) !GetOrPut {
        const key_gop = try self.key_to_index.getOrPut(allocator, key);

        const metadata_ptr, const list_entry = if (key_gop.found_existing) .{
            &self.metadata.items[key_gop.index], self.gossip_data.getEntry(key_gop.value_ptr.*), //
        } else blk: {
            const metadata_ptr = try self.metadata.addOne(allocator);
            errdefer _ = self.metadata.pop();
            assert(key_gop.index == self.metadata.items.len - 1);

            const list_entry = try self.gossip_data.addOne(allocator, key);
            key_gop.value_ptr.* = list_entry.index;

            break :blk .{ metadata_ptr, list_entry };
        };

        return .{
            .entry = .{
                .key_ptr = key_gop.key_ptr,
                .metadata_ptr = metadata_ptr,
                .gossip_data_entry = list_entry,
                .index = key_gop.index,
            },
            .found_existing = key_gop.found_existing,
        };
    }

    pub const GetOrPut = struct {
        entry: Entry,
        found_existing: bool,
    };

    pub fn iterator(self: *const GossipMap) Iterator {
        const slice = self.key_to_index.entries.slice();
        return .{
            .keys = slice.items(.key),
            .indices = slice.items(.value),
            .gossip_data = &self.gossip_data,
            .metadata = self.metadata.items,
        };
    }

    pub const Iterator = struct {
        keys: []GossipKey,
        indices: []SplitUnionList(GossipData).Index,
        gossip_data: *const SplitUnionList(GossipData),
        metadata: []Metadata,
        cursor: usize = 0,

        pub fn next(self: *Iterator) ?Entry {
            defer self.cursor += 1;
            return if (self.cursor < self.keys.len) .{
                .key_ptr = &self.keys[self.cursor],
                .metadata_ptr = &self.metadata[self.cursor],
                .gossip_data_entry = self.gossip_data.getEntry(self.indices[self.cursor]),
                .index = self.cursor,
            } else null;
        }
    };
};

test "put and get" {
    const keypair = try std.crypto.sign.Ed25519.KeyPair.create([_]u8{1} ** 32);
    var prng = std.rand.DefaultPrng.init(91);

    var map = GossipMap{};
    defer map.deinit(std.testing.allocator);

    const value = gossip.SignedGossipData.initSigned(
        &keypair,
        GossipData.initRandom(prng.random()),
    );
    const key = value.data.label();
    const data = GossipVersionedData{
        .value = value,
        .value_hash = undefined,
        .timestamp_on_insertion = 12345,
        .cursor_on_insertion = 101,
    };

    const gop = try map.getOrPut(std.testing.allocator, key);
    gop.entry.setVersionedData(data);

    try std.testing.expect(map.count() == 1);

    const get = map.get(key);
    try std.testing.expectEqual(data, get);
}

test "put, remove, and get" {
    const keypair = try std.crypto.sign.Ed25519.KeyPair.create([_]u8{1} ** 32);
    var prng = std.rand.DefaultPrng.init(91);

    var map = GossipMap{};
    defer map.deinit(std.testing.allocator);

    var keys: [4]GossipKey = undefined;
    var data: [4]GossipVersionedData = undefined;

    for (0..4) |i| {
        const value = gossip.SignedGossipData.initSigned(
            &keypair,
            GossipData.initRandom(prng.random()),
        );
        const key = value.data.label();
        const versioned = GossipVersionedData{
            .value = value,
            .value_hash = undefined,
            .timestamp_on_insertion = 12345,
            .cursor_on_insertion = 101,
        };

        keys[i] = key;
        data[i] = versioned;

        const gop = try map.getOrPut(std.testing.allocator, key);
        gop.entry.setVersionedData(versioned);
    }

    try std.testing.expect(map.count() == 4);
    try std.testing.expect(map.swapRemove(keys[0]));
    try std.testing.expect(map.count() == 3);
    try std.testing.expect(map.swapRemove(keys[1]));
    try std.testing.expect(map.count() == 2);

    for (2..4) |i| {
        const get = map.get(keys[i]);
        try std.testing.expectEqual(data[i], get);
    }
}

test "repeat add+remove" {
    const keypair = try std.crypto.sign.Ed25519.KeyPair.create([_]u8{1} ** 32);
    var prng = std.rand.DefaultPrng.init(91);
    const random = prng.random();

    var map = GossipMap{};
    defer map.deinit(std.testing.allocator);

    var keys = std.ArrayList(GossipKey).init(std.testing.allocator);
    defer keys.deinit();

    for (0..20) |_| {
        // add
        for (0..10) |_| {
            const value = gossip.SignedGossipData.initSigned(
                &keypair,
                .{ .ContactInfo = try gossip.ContactInfo.initRandom(
                    std.testing.allocator,
                    prng.random(),
                    sig.core.Pubkey.initRandom(random),
                    random.int(u64),
                    random.int(u64),
                    random.int(u16),
                ) },
            );

            const key = value.data.label();
            const versioned = GossipVersionedData{
                .value = value,
                .value_hash = undefined,
                .timestamp_on_insertion = 12345,
                .cursor_on_insertion = 101,
            };

            try keys.append(key);

            const gop = try map.getOrPut(std.testing.allocator, key);
            gop.entry.setVersionedData(versioned);
        }

        // remove
        for (0..3) |_| {
            const index = random.intRangeLessThan(usize, 0, keys.items.len);
            const key = keys.swapRemove(index);

            const item = map.get(key) orelse unreachable;
            item.deinit(std.testing.allocator);
            try std.testing.expect(map.swapRemove(key));
        }
    }

    for (keys.items) |key| {
        const item = map.get(key) orelse unreachable;
        item.deinit(std.testing.allocator);
        try std.testing.expect(map.swapRemove(key));
    }
}
