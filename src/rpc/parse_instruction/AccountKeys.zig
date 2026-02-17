const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

const AccountKeys = @This();

static_keys: []const Pubkey,
dynamic_keys: ?sig.ledger.transaction_status.LoadedAddresses,

pub fn init(
    static_keys: []const Pubkey,
    dynamic_keys: ?sig.ledger.transaction_status.LoadedAddresses,
) AccountKeys {
    return .{
        .static_keys = static_keys,
        .dynamic_keys = dynamic_keys,
    };
}

pub fn keySegmentIter(self: *const AccountKeys) [3][]const Pubkey {
    if (self.dynamic_keys) |dynamic_keys| {
        return .{
            self.static_keys,
            dynamic_keys.writable,
            dynamic_keys.readonly,
        };
    } else {
        return .{ self.static_keys, &.{}, &.{} };
    }
}

pub fn get(self: *const AccountKeys, index: usize) ?Pubkey {
    var index_tracker = index;
    for (self.keySegmentIter()) |key_segment| {
        if (index_tracker < key_segment.len) {
            return key_segment[index_tracker];
        }
        index_tracker = index_tracker -| key_segment.len;
    }
    return null;
}

pub fn len(self: *const AccountKeys) usize {
    var ret: usize = 0;
    for (self.keySegmentIter()) |key_segment| {
        ret = ret +| key_segment.len;
    }
    return ret;
}

pub fn isEmpty(self: *const AccountKeys) bool {
    return self.len() == 0;
}

const testing = @import("std").testing;

test "AccountKeys - static keys only" {
    const key0 = Pubkey{ .data = [_]u8{1} ** 32 };
    const key1 = Pubkey{ .data = [_]u8{2} ** 32 };
    const static_keys = [_]Pubkey{ key0, key1 };

    const ak = AccountKeys.init(&static_keys, null);
    try testing.expectEqual(@as(usize, 2), ak.len());
    try testing.expect(!ak.isEmpty());
    try testing.expectEqual(key0, ak.get(0).?);
    try testing.expectEqual(key1, ak.get(1).?);
    try testing.expectEqual(@as(?Pubkey, null), ak.get(2));
}

test "AccountKeys - with dynamic keys" {
    const key0 = Pubkey{ .data = [_]u8{1} ** 32 };
    const writable_key = Pubkey{ .data = [_]u8{3} ** 32 };
    const readonly_key = Pubkey{ .data = [_]u8{4} ** 32 };
    const static_keys = [_]Pubkey{key0};
    const writable = [_]Pubkey{writable_key};
    const readonly = [_]Pubkey{readonly_key};

    const ak = AccountKeys.init(&static_keys, .{
        .writable = &writable,
        .readonly = &readonly,
    });
    try testing.expectEqual(@as(usize, 3), ak.len());
    try testing.expectEqual(key0, ak.get(0).?); // static
    try testing.expectEqual(writable_key, ak.get(1).?); // writable dynamic
    try testing.expectEqual(readonly_key, ak.get(2).?); // readonly dynamic
    try testing.expectEqual(@as(?Pubkey, null), ak.get(3)); // out of bounds
}

test "AccountKeys - empty" {
    const ak = AccountKeys.init(&.{}, null);
    try testing.expectEqual(@as(usize, 0), ak.len());
    try testing.expect(ak.isEmpty());
    try testing.expectEqual(@as(?Pubkey, null), ak.get(0));
}

test "AccountKeys - keySegmentIter without dynamic" {
    const key0 = Pubkey{ .data = [_]u8{1} ** 32 };
    const static_keys = [_]Pubkey{key0};
    const ak = AccountKeys.init(&static_keys, null);

    const segments = ak.keySegmentIter();
    try testing.expectEqual(@as(usize, 1), segments[0].len);
    try testing.expectEqual(@as(usize, 0), segments[1].len);
    try testing.expectEqual(@as(usize, 0), segments[2].len);
}

test "AccountKeys - keySegmentIter with dynamic" {
    const static_keys = [_]Pubkey{Pubkey.ZEROES};
    const writable = [_]Pubkey{ Pubkey{ .data = [_]u8{1} ** 32 }, Pubkey{ .data = [_]u8{2} ** 32 } };
    const readonly = [_]Pubkey{Pubkey{ .data = [_]u8{3} ** 32 }};

    const ak = AccountKeys.init(&static_keys, .{
        .writable = &writable,
        .readonly = &readonly,
    });
    const segments = ak.keySegmentIter();
    try testing.expectEqual(@as(usize, 1), segments[0].len);
    try testing.expectEqual(@as(usize, 2), segments[1].len);
    try testing.expectEqual(@as(usize, 1), segments[2].len);
}
