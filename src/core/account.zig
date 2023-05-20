const Pubkey = @import("./pubkey.zig").Pubkey;
const std = @import("std");

pub const Account = struct {
    lamports: u64,
    data: []u8,
    owner: Pubkey,
    executable: bool,
    rentEpoch: u64,

    const Self = @This();

    pub fn new(lamports: u64, data: []u8, owner: Pubkey, executable: bool, rent_epoch: u64) Self {
        return Self{
            .lamports = lamports,
            .data = data,
            .owner = owner,
            .executable = executable,
            .rentEpoch = rent_epoch,
        };
    }

    pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        self.owner.deinit(allocator);
    }
};
