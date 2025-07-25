const std = @import("std");
const sig = @import("../sig.zig");

const Blake3 = std.crypto.hash.Blake3;

const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const AccountInFile = sig.accounts_db.accounts_file.AccountInFile;
const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;

pub const Account = struct {
    lamports: u64,
    data: AccountDataHandle,
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,

    pub fn deinit(self: Account, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    pub fn initRandom(allocator: std.mem.Allocator, random: std.Random, data_len: usize) !Account {
        const data_buf = try allocator.alloc(u8, data_len);
        errdefer allocator.free(data_buf);

        random.bytes(data_buf);
        const data = AccountDataHandle.initAllocatedOwned(data_buf);

        return .{
            .lamports = random.int(u64),
            .data = data,
            .owner = Pubkey.initRandom(random),
            .executable = random.boolean(),
            .rent_epoch = random.int(Epoch),
        };
    }

    // creates a copy of the account. most important is the copy of the data slice.
    pub fn cloneOwned(self: *const Account, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = self.lamports,
            .data = try self.data.dupeAllocatedOwned(allocator),
            .owner = self.owner,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };
    }

    // creates a cheap borrow of an already-cached account
    pub fn cloneCached(self: *const Account, allocator: std.mem.Allocator) !Account {
        return .{
            .lamports = self.lamports,
            .data = try self.data.duplicateBufferPoolRead(allocator),
            .owner = self.owner,
            .executable = self.executable,
            .rent_epoch = self.rent_epoch,
        };
    }

    pub fn equals(self: *const Account, other: *const Account) bool {
        return self.data.eql(other.data) and
            self.lamports == other.lamports and
            self.owner.equals(&other.owner) and
            self.executable == other.executable and
            self.rent_epoch == other.rent_epoch;
    }

    /// gets the snapshot size of the account (when serialized)
    pub fn getSizeInFile(self: *const Account) usize {
        return std.mem.alignForward(
            usize,
            AccountInFile.STATIC_SIZE + self.data.len(),
            @sizeOf(u64),
        );
    }

    /// computes the blake3 hash of the account
    pub fn hash(self: *const Account, HashType: type, pubkey: *const Pubkey) HashType {
        var the_hash: HashType = .{ .data = undefined };

        var iter = self.data.iterator();
        hashAccount(
            self.lamports,
            &iter,
            &self.owner.data,
            self.executable,
            self.rent_epoch,
            &pubkey.data,
            the_hash.bytes(),
        );

        return the_hash;
    }

    /// writes account to buf in snapshot format
    pub fn writeToBuf(self: *const Account, pubkey: *const Pubkey, buf: []u8) usize {
        var offset: usize = 0;

        const storage_info = AccountInFile.StorageInfo{
            .write_version_obsolete = 0,
            .data_len = self.data.len(),
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

        const account_hash = self.hash(Hash, pubkey);
        @memcpy(buf[offset..(offset + 32)], &account_hash.data);
        offset += 32;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        self.data.readAll(buf[offset..][0..self.data.len()]);

        offset += self.data.len();
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

pub fn hashAccount(
    lamports: u64,
    data: *AccountDataHandle.Iterator,
    owner_pubkey_data: []const u8,
    executable: bool,
    rent_epoch: u64,
    address_pubkey_data: []const u8,
    out_slice: []u8,
) void {
    var hasher = Blake3.init(.{});

    var int_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &int_buf, lamports, .little);
    hasher.update(&int_buf);

    std.mem.writeInt(u64, &int_buf, rent_epoch, .little);
    hasher.update(&int_buf);

    while (data.nextFrame()) |frame_slice| {
        hasher.update(frame_slice);
    }

    if (executable) {
        hasher.update(&[_]u8{1});
    } else {
        hasher.update(&[_]u8{0});
    }

    hasher.update(owner_pubkey_data);
    hasher.update(address_pubkey_data);

    hasher.final(out_slice);
}

test "core.account: test account hash matches rust" {
    var data: [3]u8 = .{ 1, 2, 3 };
    var account: Account = .{
        .lamports = 10,
        .data = AccountDataHandle.initAllocated(&data),
        .owner = Pubkey.ZEROES,
        .executable = false,
        .rent_epoch = 20,
    };
    const pubkey = Pubkey.ZEROES;

    var hash_buf: [32]u8 = undefined;
    var iter = account.data.iterator();
    hashAccount(
        account.lamports,
        &iter,
        &account.owner.data,
        account.executable,
        account.rent_epoch,
        &pubkey.data,
        &hash_buf,
    );

    const expected_hash: [32]u8 = .{
        170, 75,  87,  73,  60,  156, 174, 14, 105,
        6,   129, 108, 167, 156, 166, 213, 28, 4,
        163, 187, 252, 155, 24,  253, 158, 13, 86,
        100, 103, 89,  232, 28,
    };
    try std.testing.expectEqualSlices(u8, &expected_hash, &hash_buf);
}
