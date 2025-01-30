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
    key_to_index: std.AutoArrayHashMapUnmanaged(GossipKey, usize) = .{},
    gossip_data: SplitUnionList(GossipData) = SplitUnionList(GossipData).init(),
    metadata: std.ArrayListUnmanaged(Metadata) = .{},

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
        const index = self.getIndex(key) orelse return null;
        return self.getByIndex(index);
    }

    fn getIndex(self: *const GossipMap, key: GossipKey) ?usize {
        const index = self.key_to_index.getIndex(key) orelse return null;
        assert(index == self.key_to_index.get(key).?);
        return index;
    }

    pub fn getByIndex(self: *const GossipMap, index: usize) GossipVersionedData {
        const metadata = self.metadata.items[index];
        return .{
            .value = .{
                .signature = metadata.signature,
                .data = self.gossip_data.get(index),
            },
            .value_hash = metadata.value_hash,
            .timestamp_on_insertion = metadata.timestamp_on_insertion,
            .cursor_on_insertion = metadata.cursor_on_insertion,
        };
    }

    pub fn getEntry(self: GossipMap, key: GossipKey) ?Entry {
        const entry = self.key_to_index.getEntry(key) orelse return null;
        const index = entry.value_ptr.*;
        return .{
            .key_ptr = entry.key_ptr,
            .gossip_data_entry = self.gossip_data.getEntry(index),
            .metadata_ptr = &self.metadata.items[index],
            .index = index,
        };
    }

    pub fn getEntryByIndex(self: *const GossipMap, index: usize) Entry {
        return .{
            .key_ptr = &self.key_to_index.keys()[index],
            .gossip_data_entry = self.gossip_data.getEntry(index),
            .metadata_ptr = &self.metadata.items[index],
            .index = index,
        };
    }

    pub const Entry = struct {
        key_ptr: *GossipKey,
        metadata_ptr: *Metadata,
        gossip_data_entry: SplitUnionList(GossipData).Entry,
        index: usize,

        pub fn tag(self: Entry) GossipDataTag {
            return self.gossip_data_entry.tag;
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
        return self.gossip_data.getTypedConst(tag, index);
    }

    pub fn tagOfIndex(self: *const GossipMap, index: usize) GossipDataTag {
        return self.gossip_data.getTag(index);
    }

    pub fn swapRemove(self: *GossipMap, key: GossipKey) bool {
        const index = self.getIndex(key) orelse return false;
        self.key_to_index.swapRemoveAt(index);
        self.gossip_data.swapRemove(index);
        _ = self.metadata.swapRemove(index);
        if (self.key_to_index.count() > 0 and self.key_to_index.count() > index) {
            self.key_to_index.entries.items(.value)[index] = index;
        }
        return true;
    }

    pub fn getOrPut(self: *GossipMap, allocator: Allocator, key: GossipKey) !GetOrPut {
        const key_gop = try self.key_to_index.getOrPut(allocator, key);

        const metadata_ptr, const list_entry = if (key_gop.found_existing) .{
            &self.metadata.items[key_gop.index], self.gossip_data.getEntry(key_gop.index), //
        } else blk: {
            key_gop.value_ptr.* = key_gop.index;
            const metadata_ptr = try self.metadata.addOne(allocator);
            errdefer _ = self.metadata.pop();
            const list_entry = try self.gossip_data.addOne(allocator, key);
            assert(list_entry.index == key_gop.index);
            assert(list_entry.index == self.metadata.items.len - 1);
            errdefer _ = self.gossip_data.pop();
            break :blk .{ metadata_ptr, list_entry };
        };

        assert(key_gop.value_ptr.* == key_gop.index);
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
        return .{
            .key_to_index = self.key_to_index.iterator(),
            .gossip_data = self.gossip_data.iterator(),
            .metadata = self.metadata.items,
        };
    }

    pub const Iterator = struct {
        key_to_index: std.AutoArrayHashMapUnmanaged(GossipKey, usize).Iterator,
        gossip_data: SplitUnionList(GossipData).Iterator,
        metadata: []Metadata,

        pub fn next(self: *Iterator) ?Entry {
            return if (self.key_to_index.next()) |key_index| .{
                .key_ptr = key_index.key_ptr,
                .metadata_ptr = &self.metadata[key_index.value_ptr.*],
                .gossip_data_entry = self.gossip_data.next() orelse unreachable,
                .index = key_index.value_ptr.*,
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
    // var data = std.ArrayList(GossipVersionedData).init(std.testing.allocator);

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
