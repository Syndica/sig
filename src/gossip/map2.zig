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
    /// Maps a gossip key to the index that you'll find the item in its
    /// respective array list in lists_struct.
    key_to_index: KeyToIndex,
    /// A struct with one field per gossip tag, where each is an array list
    /// containing the respective payload type for that gossip tag.
    lists_struct: EnumFieldStructMultiType(GossipDataTag, List),

    const KeyToIndex = std.AutoArrayHashMapUnmanaged(GossipKey, usize);

    fn List(tag: GossipDataTag) type {
        return std.ArrayListUnmanaged(Value(tag));
    }

    /// Stores the same data as GossipVersionedValue, except:
    /// - the nested structs are flattened
    /// - it's generic instead of a tagged union, to save memory
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

    pub fn init() GossipMap {
        var lists: EnumFieldStructMultiType(GossipDataTag, List) = undefined;
        inline for (fields.names) |f| @field(lists, f) = .{};
        return .{
            .key_to_index = .{},
            .lists_struct = lists,
        };
    }

    pub fn deinit(self: *GossipMap, allocator: Allocator) void {
        // TODO decide: deinit inner values?
        inline for (fields.names) |f| @field(self.lists_struct, f).deinit(allocator);
    }

    pub fn count(self: *const GossipMap) usize {
        return self.key_to_index.count();
    }

    pub fn get(self: *const GossipMap, key: GossipKey) ?GossipVersionedData {
        const index = self.key_to_index.get(key) orelse return null;
        switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| {
                const value = self.list(comptime_tag).items[index];
                return value.versioned();
            },
        }
    }

    pub fn getEntry(self: *GossipMap, key: GossipKey) ?Entry {
        const index_entry = self.key_to_index.getEntry(key) orelse return null;
        const index = index_entry.value_ptr.*;
        switch (@as(GossipDataTag, key)) {
            inline else => |comptime_tag| {
                var entry: Entry = undefined;
                @field(entry.inner, @tagName(comptime_tag)) = .{
                    .key_ptr = index,
                    .value_ptr = self.list(comptime_tag)[index],
                };
                return entry;
            },
        }
    }

    pub const Entry = struct {
        inner: EnumFieldUnion(GossipDataTag, GenericEntry),

        fn GenericEntry(tag: GossipDataTag) type {
            return struct {
                key_ptr: *GossipKey,
                value_ptr: *Value(tag),
            };
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
            return List(tag).Iterator;
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

    fn list(self: *const GossipMap, comptime tag: GossipDataTag) *const List(tag) {
        return &@field(self.lists_struct, @tagName(tag));
    }

    fn listMut(self: *GossipMap, comptime tag: GossipDataTag) *List(tag) {
        return &@field(self.lists_struct, @tagName(tag));
    }
};
