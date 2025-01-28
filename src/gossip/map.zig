const std = @import("std");
const sig = @import("../sig.zig");
const gossip = @import("lib.zig");

const Allocator = std.mem.Allocator;

const EnumFieldStructMultiType = sig.utils.enums.EnumFieldStructMultiType;
const EnumFieldUnion = sig.utils.enums.EnumFieldUnion;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;

const GossipData = gossip.data.GossipData;
const GossipDataTag = gossip.data.GossipDataTag;
const GossipKey = gossip.data.GossipKey;
const GossipVersionedData = gossip.data.GossipVersionedData;

pub const GossipMap = struct {
    maps: EnumFieldStructMultiType(GossipDataTag, Map),

    const fields = blk: {
        const len = @typeInfo(GossipDataTag).Enum.fields.len;
        var names: [len][]const u8 = undefined;
        var tags: [len]GossipDataTag = undefined;
        for (@typeInfo(GossipDataTag).Enum.fields, 0..) |f, i| {
            names[i] = f.name;
            tags[i] = @field(GossipDataTag, f.name);
        }
        break :blk .{ .names = names, .tags = tags };
    };

    fn Map(tag: GossipDataTag) type {
        return std.AutoArrayHashMapUnmanaged(tag.Key(), Value(tag));
    }

    pub fn Value(tag: GossipDataTag) type {
        return struct {
            data: tag.Value(),
            signature: Signature,
            value_hash: Hash,
            timestamp_on_insertion: u64,
            cursor_on_insertion: u64,

            pub fn gossipData(self: @This()) GossipData {
                var data: GossipData = undefined;
                @field(data, @tagName(tag)) = self.data;
                return data;
            }

            pub fn versioned(self: @This()) GossipVersionedData {
                var data: GossipData = undefined;
                @field(data, @tagName(tag)) = self.data;
                return .{
                    .value = .{ .signature = self.signature, .data = self.gossipData() },
                    .value_hash = self.value_hash,
                    .timestamp_on_insertion = self.timestamp_on_insertion,
                    .cursor_on_insertion = self.cursor_on_insertion,
                };
            }
        };
    }

    pub fn init() GossipMap {
        var maps: EnumFieldStructMultiType(GossipDataTag, Map) = undefined;
        inline for (fields.names) |f| @field(maps, f) = .{};
        return .{ .maps = maps };
    }

    pub fn deinit(self: *GossipMap, allocator: Allocator) void {
        inline for (fields.names) |f| @field(self.maps, f).deinit(allocator);
    }

    pub fn count(self: *const GossipMap) usize {
        var c: usize = 0;
        inline for (fields.names) |f| c += @field(self.maps, f).count();
        return c;
    }

    pub fn get(self: *const GossipMap, key: GossipKey) ?GossipVersionedData {
        switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| {
                const inner_key = @field(key, @tagName(comptime_tag));
                const value = self.map(comptime_tag).get(inner_key) orelse return null;
                return value.versioned();
            },
        }
    }

    pub fn keyByIndex(
        self: *const GossipMap,
        comptime tag: GossipDataTag,
        index: usize,
    ) tag.Key() {
        return @field(self, @tagName(tag)).keys()[index];
    }

    pub fn valueByIndex(
        self: *const GossipMap,
        comptime tag: GossipDataTag,
        index: usize,
    ) Value(tag) {
        return @field(self, @tagName(tag)).values()[index];
    }

    pub fn valuePtrByIndex(
        self: *GossipMap,
        comptime tag: GossipDataTag,
        index: usize,
    ) *Value(tag) {
        return @field(self, @tagName(tag)).values()[index];
    }

    pub fn getOrPut(self: *GossipMap, allocator: Allocator, key: GossipKey) !GetOrPutResult {
        switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| {
                const gop = try self.mapMut(comptime_tag)
                    .getOrPut(allocator, @field(key, @tagName(comptime_tag)));
                var entry: Entry = undefined;
                @field(entry.inner, @tagName(comptime_tag)) = .{
                    .key_ptr = gop.key_ptr,
                    .value_ptr = gop.value_ptr,
                };
                return .{
                    .entry = entry,
                    .found_existing = gop.found_existing,
                    .index = gop.index,
                };
            },
        }
    }

    pub const GetOrPutResult = struct {
        entry: Entry,
        found_existing: bool,
        index: usize,

        fn Inner(tag: GossipDataTag) type {
            return Map(tag).GetOrPutResult;
        }
    };

    pub fn getEntry(self: *GossipMap, key: GossipKey) ?Entry {
        switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| {
                const inner_entry = self.map(comptime_tag)
                    .getEntry(@field(key, @tagName(comptime_tag))) orelse return null;
                var entry: Entry = undefined;
                @field(entry.inner, @tagName(comptime_tag)) = inner_entry;
                return entry;
            },
        }
    }

    pub const Entry = struct {
        inner: EnumFieldUnion(GossipDataTag, Inner),

        fn Inner(tag: GossipDataTag) type {
            return Map(tag).Entry;
        }

        pub fn value(self: Entry) GossipVersionedData {
            return switch (self.inner) {
                inline else => |entry| entry.value_ptr.*.versioned(),
            };
        }

        pub fn gossipData(self: Entry) GossipData {
            return switch (self.inner) {
                inline else => |entry| entry.value_ptr.*.gossipData(),
            };
        }

        pub fn setTimestamp(self: Entry, timestamp: u64) void {
            switch (self.inner) {
                inline else => |entry| entry.value_ptr.timestamp_on_insertion = timestamp,
            }
        }

        pub fn write(self: Entry, item: GossipVersionedData) void {
            switch (@as(GossipDataTag, self.inner)) {
                inline else => |comptime_tag| {
                    const entry = @field(self.inner, @tagName(comptime_tag));
                    entry.value_ptr.* = .{
                        .data = @field(item.value.data, @tagName(comptime_tag)),
                        .signature = item.value.signature,
                        .value_hash = item.value_hash,
                        .timestamp_on_insertion = item.timestamp_on_insertion,
                        .cursor_on_insertion = item.cursor_on_insertion,
                    };
                },
            }
        }
    };

    pub fn iterator(self: GossipMap) Iterator {
        var iter: Iterator = undefined;
        inline for (fields.names) |f| {
            @field(iter.inner, f) = @field(self.maps, f).iterator();
        }
        return iter;
    }

    pub const Iterator = struct {
        inner: EnumFieldUnion(GossipDataTag, Inner),
        current_tag: u32,

        const max = @typeInfo(GossipDataTag).Enum.fields.len;

        comptime {
            for (@typeInfo(GossipDataTag).Enum.fields, 0..) |field, i| {
                // enum must be contiguous starting at 0
                std.debug.assert(i == field.value);
            }
        }

        fn Inner(tag: GossipDataTag) type {
            return Map(tag).Iterator;
        }

        pub fn next(self: *Iterator) ?Entry {
            var entry: Entry = undefined;
            while (self.current_tag <= max) {
                switch (@as(GossipDataTag, @enumFromInt(self.current_tag))) {
                    inline else => |comptime_tag| {
                        if (@field(self.inner, @tagName(comptime_tag)).next()) |item| {
                            @field(entry.inner, @tagName(comptime_tag)) = item;
                            return entry;
                        }
                        self.current_tag += 1;
                    },
                }
            }
            return null;
        }
    };

    pub fn swapRemove(self: *GossipMap, key: GossipKey) bool {
        return switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| self.mapMut(comptime_tag)
                .swapRemove(@field(key, @tagName(comptime_tag))),
        };
    }

    fn map(self: *const GossipMap, comptime tag: GossipDataTag) *const Map(tag) {
        return &@field(self.maps, @tagName(tag));
    }

    fn mapMut(self: *GossipMap, comptime tag: GossipDataTag) *Map(tag) {
        return &@field(self.maps, @tagName(tag));
    }
};
