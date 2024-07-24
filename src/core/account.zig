const Pubkey = @import("pubkey.zig").Pubkey;
const Epoch = @import("./time.zig").Epoch;
const AccountInFile = @import("../accountsdb/accounts_file.zig").AccountInFile;

pub const Account = struct {
    lamports: u64,
    data: []u8,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,

    pub fn deinit(self: Account, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
    }

    pub fn random(allocator: std.mem.Allocator, rng: std.Random, data_len: usize) !Account {
        const data = try allocator.alloc(u8, data_len);
        rng.bytes(data);

        return .{
            .lamports = rng.int(u64),
            .data = data,
            .owner = Pubkey.random(rng),
            .executable = rng.boolean(),
            .rent_epoch = rng.int(Epoch),
        };
    }

    // creates a copy of the account. most important is the copy of the data slice.
    pub fn clone(self: *const Account, allocator: std.mem.Allocator) !Account {
        const data = try allocator.dupe(u8, self.data);
        return .{
            .lamports = self.lamports,
            .data = data,
            .owner = self.owner,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };
    }

    pub fn equals(self: *const Account, other: *const Account) bool {
        return std.mem.eql(u8, self.data, other.data) and
            self.lamports == other.lamports and
            self.owner.equals(&other.owner) and
            self.executable == other.executable and
            self.rent_epoch == other.rent_epoch;
    }

    /// gets the snapshot size of the account (when serialized)
    pub fn getSizeInFile(self: *const Account) usize {
        return std.mem.alignForward(
            usize,
            AccountInFile.STATIC_SIZE + self.data.len,
            @sizeOf(u64),
        );
    }

    /// computes the hash of the account
    pub fn hash(self: *const Account, pubkey: *const Pubkey) Hash {
        return hashAccount(
            self.lamports,
            self.data,
            &self.owner.data,
            self.executable,
            self.rent_epoch,
            &pubkey.data,
        );
    }

    /// writes account to buf in snapshot format
    pub fn writeToBuf(self: *const Account, pubkey: *const Pubkey, buf: []u8) usize {
        var offset: usize = 0;

        const storage_info = AccountInFile.StorageInfo{
            .write_version_obsolete = 0,
            .data_len = self.data.len,
            .pubkey = pubkey.*,
        };
        offset += storage_info.writeToBuf(buf[offset..]);

        const account_info = AccountInFile.AccountInfo{
            .lamports = self.lamports,
            .rent_epoch = self.rent_epoch,
            .owner = self.owner,
            .executable = self.executable,
        };
        offset += account_info.writeToBuf(buf[offset..]);

        const account_hash = self.hash(pubkey);
        @memcpy(buf[offset..(offset + 32)], &account_hash.data);
        offset += 32;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        @memcpy(buf[offset..(offset + self.data.len)], self.data);
        offset += self.data.len;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        return offset;
    }
};

/// helper function for writing to memory
pub fn writeIntLittleMem(
    x: anytype,
    memory: []u8,
) usize {
    const Tx = @TypeOf(x);
    const x_size: usize = @bitSizeOf(Tx) / 8;
    std.mem.writeInt(Tx, memory[0..x_size], x, .little);
    return x_size;
}

const std = @import("std");
const Blake3 = std.crypto.hash.Blake3;
const Hash = @import("hash.zig").Hash;

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
    std.mem.writeInt(u64, &int_buf, lamports, .little);
    hasher.update(&int_buf);

    std.mem.writeInt(u64, &int_buf, rent_epoch, .little);
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
