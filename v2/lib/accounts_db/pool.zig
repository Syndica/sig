const std = @import("std");
const lib = @import("../lib.zig");

const Account = lib.accounts_db.Account;

pub const Pool = struct {
    memory: []u8,
    allocated: Index = 1,
    free_lists: [size_classes.len]Index = @splat(0),

    // 8-byte aligned offset into memory
    const Index = u32;
    const index_scale = 8;

    const free_list_field = "lamports";

    // TODO: base on @sizeOf(Account) + actual mainnet data size binning
    const size_classes = [_]u24{
        @sizeOf(Account) + 8,
        @sizeOf(Account) + 64,
        256,
        1024,
        4096,
        16 * 1024,
        64 * 1024,
        1 * 1024 * 1024,
        4 * 1024 * 1024,
        @sizeOf(Account) + 10 * 1024 * 1024,
    };

    pub fn getAccount(self: *const Pool, index: Index) *align(1) Account {
        std.debug.assert(index > 0);
        std.debug.assert(index < self.allocated);
        return @ptrCast(self.memory[@as(u64, index) * index_scale ..][0..@sizeOf(Account)]);
    }

    pub fn getAccountData(self: *const Pool, index: Index) []u8 {
        const acc = self.getAccount(index);
        const data_len = acc.getDataLength();
        return self.memory[(@as(u64, index) * index_scale) + @sizeOf(Account) ..][0..data_len];
    }

    fn getSizeClassIndex(len: u24) u32 {
        for (size_classes, 0..) |max, i| {
            if (len <= max) return @intCast(i);
        } else unreachable;
    }

    pub fn alloc(self: *Pool, data_len: u24) !Index {
        const alloc_len = @sizeOf(Account) + data_len;
        const sc_idx = getSizeClassIndex(alloc_len);
        const free_list = &self.free_lists[sc_idx];

        var idx = free_list.*;
        if (idx > 0) {
            const free_acc = self.getAccount(idx);
            free_list.* = @intCast(@field(free_acc, free_list_field));
            return idx;
        }

        idx = self.allocated;
        if (idx + size_classes[sc_idx] > self.memory.len * index_scale) return error.OutOfMemory;
        self.allocated = idx + size_classes[sc_idx];
        return idx;
    }

    pub fn free(self: *Pool, index: Index) void {
        std.debug.assert(index > 0);
        std.debug.assert(index < self.allocated);

        const acc = self.getAccount(index);
        const alloc_len = @sizeOf(Account) + acc.getDataLength();

        const sc_idx = getSizeClassIndex(alloc_len);
        const free_list = &self.header.free_lists[sc_idx];

        @field(acc, free_list_field) = free_list.*;
        free_list.* = index;
    }
};
