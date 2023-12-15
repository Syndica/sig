const Pubkey = @import("pubkey.zig").Pubkey;
const Epoch = @import("./time.zig").Epoch;

pub const Account = struct {
    lamports: u64,
    data: []u8,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,
};

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const Hash = @import("./hash.zig").Hash;

pub fn hashAccount(
    lamports: u64,
    data: []u8,
    owner_pubkey_data: []const u8,
    executable: bool,
    rent_epoch: u64,
    address_pubkey_data: []const u8,
) Hash {
    var hasher = Blake3.init(.{});
    var hash_buf: [32]u8 = undefined;

    var int_buf: [8]u8 = undefined;
    std.mem.writeIntLittle(u64, &int_buf, lamports);
    hasher.update(&int_buf);

    std.mem.writeIntLittle(u64, &int_buf, rent_epoch);
    hasher.update(&int_buf);

    hasher.update(data);

    if (executable) {
        hasher.update(&[_]u8{1});
    } else {
        hasher.update(&[_]u8{0});
    }

    hasher.update(owner_pubkey_data);
    hasher.update(address_pubkey_data);

    hasher.final(&hash_buf);
    const hash = Hash{
        .data = hash_buf,
    };

    return hash;
}

test "core.account: test account hash matches rust" {
    var data: [3]u8 = .{ 1, 2, 3 };
    var account = Account{
        .lamports = 10,
        .data = &data,
        .owner = Pubkey.default(),
        .executable = false,
        .rent_epoch = 20,
    };
    const pubkey = Pubkey.default();

    const hash = hashAccount(
        account.lamports,
        account.data,
        &account.owner.data,
        account.executable,
        account.rent_epoch,
        &pubkey.data,
    );

    const expected_hash: [32]u8 = .{ 170, 75, 87, 73, 60, 156, 174, 14, 105, 6, 129, 108, 167, 156, 166, 213, 28, 4, 163, 187, 252, 155, 24, 253, 158, 13, 86, 100, 103, 89, 232, 28 };
    try std.testing.expect(std.mem.eql(u8, &expected_hash, &hash.data));
}
