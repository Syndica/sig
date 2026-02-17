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
