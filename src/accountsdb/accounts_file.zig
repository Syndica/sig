//! includes the main struct for reading + validating account files

const std = @import("std");

const Account = @import("../core/account.zig").Account;
const writeIntLittleMem = @import("../core/account.zig").writeIntLittleMem;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/time.zig").Slot;
const Epoch = @import("../core/time.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;

const AccountFileInfo = @import("snapshots.zig").AccountFileInfo;

/// Simple strictly-typed alias for an integer, used to represent a file ID.
///
/// Analogous to [AccountsFileId](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L824)
pub const FileId = enum(Int) {
    _,

    pub const Int = u32;

    pub inline fn fromInt(int: u32) FileId {
        return @enumFromInt(int);
    }

    pub inline fn toInt(file_id: FileId) Int {
        return @intFromEnum(file_id);
    }

    pub inline fn increment(file_id: FileId) FileId {
        return FileId.fromInt(file_id.toInt() + 1);
    }

    pub inline fn max(a: FileId, b: FileId) FileId {
        return FileId.fromInt(@max(a.toInt(), b.toInt()));
    }

    pub fn format(
        _: FileId,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("Should not print " ++ @typeName(FileId) ++ " directly");
    }
};

/// an account thats stored in an AccountFile
///
/// Analogous to [StoredAccountMeta::AppendVec](https://github.com/anza-xyz/agave/blob/f8067ea7883e04bdfc1a82b0779f7363b71bf548/accounts-db/src/account_storage/meta.rs#L21)
pub const AccountInFile = struct {
    // pointers to mmap contents
    store_info: *StorageInfo,
    account_info: *AccountInfo,
    hash_ptr: *Hash,
    data: []u8,

    // other info (used when parsing accounts out)
    offset: usize = 0,
    len: usize = 0,

    /// info about the account stored
    ///
    /// Analogous to [StoredMeta](https://github.com/anza-xyz/agave/blob/f8067ea7883e04bdfc1a82b0779f7363b71bf548/accounts-db/src/account_storage/meta.rs#L134)
    pub const StorageInfo = extern struct {
        write_version_obsolete: u64,
        data_len: u64,
        pubkey: Pubkey,

        pub fn writeToBuf(self: *const StorageInfo, buf: []u8) usize {
            std.debug.assert(buf.len >= @sizeOf(StorageInfo));

            var offset: usize = 0;
            offset += writeIntLittleMem(self.write_version_obsolete, buf[offset..]);
            offset += writeIntLittleMem(self.data_len, buf[offset..]);
            @memcpy(buf[offset..(offset + 32)], &self.pubkey.data);
            offset += 32;
            offset = std.mem.alignForward(usize, offset, @sizeOf(u64));
            return offset;
        }
    };

    /// on-chain account info about the account
    ///
    /// Analogous to [AccountMeta](https://github.com/anza-xyz/agave/blob/f8067ea7883e04bdfc1a82b0779f7363b71bf548/accounts-db/src/account_storage/meta.rs#L149)
    pub const AccountInfo = extern struct {
        lamports: u64,
        rent_epoch: Epoch,
        owner: Pubkey,
        executable: bool,

        pub fn writeToBuf(self: *const AccountInfo, buf: []u8) usize {
            std.debug.assert(buf.len >= @sizeOf(AccountInfo));

            var offset: usize = 0;
            offset += writeIntLittleMem(self.lamports, buf[offset..]);
            offset += writeIntLittleMem(self.rent_epoch, buf[offset..]);
            @memcpy(buf[offset..(offset + 32)], &self.owner.data);
            offset += 32;

            offset += writeIntLittleMem(
                @as(u8, @intFromBool(self.executable)),
                buf[offset..],
            );
            offset = std.mem.alignForward(usize, offset, @sizeOf(u64));
            return offset;
        }
    };

    pub const STATIC_SIZE: usize = blk: {
        var size: usize = 0;

        size += @sizeOf(AccountInFile.StorageInfo);
        size = std.mem.alignForward(usize, size, @sizeOf(u64));

        size += @sizeOf(AccountInFile.AccountInfo);
        size = std.mem.alignForward(usize, size, @sizeOf(u64));

        size += @sizeOf(Hash);
        size = std.mem.alignForward(usize, size, @sizeOf(u64));

        break :blk size;
    };

    pub const ValidateError = error{
        InvalidExecutableFlag,
        InvalidLamports,
    };

    const Self = @This();

    pub fn getSizeInFile(self: *const Self) u64 {
        return std.mem.alignForward(
            usize,
            AccountInFile.STATIC_SIZE + self.data.len,
            @sizeOf(u64),
        );
    }

    pub fn validate(self: *const Self) ValidateError!void {
        // make sure upper bits are zero
        const exec_byte = @as(*u8, @ptrCast(self.executable()));
        const valid_exec = exec_byte.* & ~@as(u8, 1) == 0;
        if (!valid_exec) {
            return error.InvalidExecutableFlag;
        }

        const valid_lamports = self.account_info.lamports != 0 or (
        // ie, is default account
            self.data.len == 0 and
            self.owner().isDefault() and
            self.executable().* == false and
            self.rent_epoch().* == 0);
        if (!valid_lamports) {
            return error.InvalidLamports;
        }
    }

    pub fn toOwnedAccount(self: *const Self, allocator: std.mem.Allocator) !Account {
        const owned_data = try allocator.dupe(u8, self.data);
        return .{
            .data = owned_data,
            .executable = self.executable().*,
            .lamports = self.lamports().*,
            .owner = self.owner().*,
            .rent_epoch = self.rent_epoch().*,
        };
    }

    pub fn toAccount(self: *const Self) !Account {
        return .{
            .data = self.data,
            .executable = self.executable().*,
            .lamports = self.lamports().*,
            .owner = self.owner().*,
            .rent_epoch = self.rent_epoch().*,
        };
    }

    pub inline fn pubkey(self: *const Self) *Pubkey {
        return &self.store_info.pubkey;
    }

    pub inline fn lamports(self: *const Self) *u64 {
        return &self.account_info.lamports;
    }

    pub inline fn owner(self: *const Self) *Pubkey {
        return &self.account_info.owner;
    }

    pub inline fn executable(self: *const Self) *bool {
        return &self.account_info.executable;
    }

    pub inline fn rent_epoch(self: *const Self) *Epoch {
        return &self.account_info.rent_epoch;
    }

    pub inline fn hash(self: *const Self) *Hash {
        return self.hash_ptr;
    }

    pub fn writeToBuf(self: *const Self, buf: []u8) usize {
        std.debug.assert(buf.len >= STATIC_SIZE + self.data.len);

        var offset: usize = 0;
        offset += self.store_info.writeToBuf(buf[offset..]);
        offset += self.account_info.writeToBuf(buf[offset..]);

        @memcpy(buf[offset..(offset + 32)], &self.hash().data);
        offset += 32;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        @memcpy(buf[offset..(offset + self.data.len)], self.data);
        offset += self.data.len;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        return offset;
    }
};

/// Analogous to [AccountStorageEntry](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1069)
pub const AccountFile = struct {
    // file contents
    memory: []align(std.mem.page_size) u8,
    id: FileId,
    slot: Slot,
    // number of bytes used
    length: usize,
    // total bytes available
    file_size: usize,
    file: std.fs.File,

    // number of accounts stored in the file
    number_of_accounts: usize = 0,

    const Self = @This();

    pub fn init(file: std.fs.File, accounts_file_info: AccountFileInfo, slot: Slot) !Self {
        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        try accounts_file_info.validate(file_size);

        const memory = try std.posix.mmap(
            null,
            file_size,
            std.posix.PROT.READ | std.posix.PROT.WRITE,
            std.posix.MAP{ .TYPE = .SHARED },
            file.handle,
            0,
        );

        return Self{
            .memory = memory,
            .length = accounts_file_info.length,
            .id = accounts_file_info.id,
            .file_size = file_size,
            .file = file,
            .slot = slot,
        };
    }

    pub fn deinit(self: *Self) void {
        std.posix.munmap(self.memory);
        self.file.close();
    }

    pub fn validate(self: *const Self) !usize {
        var offset: usize = 0;
        var number_of_accounts: usize = 0;
        var account_bytes: usize = 0;

        while (true) {
            const account = self.readAccount(offset) catch break;
            try account.validate();
            offset = offset + account.len;
            number_of_accounts += 1;
            account_bytes += account.len;
        }

        if (offset != std.mem.alignForward(usize, self.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }

        return number_of_accounts;
    }

    /// get account without reading data (a lot faster if the data field isnt used anyway)
    /// (used when computing account hashes for snapshot validation)
    pub fn getAccountHashAndLamports(self: *const Self, start_offset: usize) error{EOF}!struct { hash: *Hash, lamports: *u64 } {
        var offset = start_offset;

        offset += @sizeOf(AccountInFile.StorageInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const lamports = try self.getType(&offset, u64);

        offset += @sizeOf(AccountInFile.AccountInfo) - @sizeOf(u64);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const hash = try self.getType(&offset, Hash);

        return .{
            .hash = hash,
            .lamports = lamports,
        };
    }

    /// get the account pubkey without parsing data (a lot faster if the data field isnt used anyway)
    pub fn getAccountPubkey(self: *const Self, start_offset: usize) error{EOF}!struct {
        pubkey: *Pubkey,
        account_len: usize,
    } {
        var offset = start_offset;

        var storage_info = try self.getType(&offset, AccountInFile.StorageInfo);

        offset += @sizeOf(AccountInFile.AccountInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        offset += @sizeOf(Hash);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        offset += storage_info.data_len;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        return .{
            .pubkey = &storage_info.pubkey,
            .account_len = offset - start_offset,
        };
    }

    pub fn readAccount(self: *const Self, start_offset: usize) error{EOF}!AccountInFile {
        var offset = start_offset;

        const store_info = try self.getType(&offset, AccountInFile.StorageInfo);
        const account_info = try self.getType(&offset, AccountInFile.AccountInfo);
        const hash = try self.getType(&offset, Hash);
        const data = try self.getSlice(&offset, store_info.data_len);

        const len = offset - start_offset;

        return AccountInFile{
            .store_info = store_info,
            .account_info = account_info,
            .hash_ptr = hash,
            .data = data,
            .len = len,
            .offset = start_offset,
        };
    }

    pub fn getSlice(self: *const Self, start_index_ptr: *usize, length: usize) error{EOF}![]u8 {
        const start_index = start_index_ptr.*;
        const result = @addWithOverflow(start_index, length);
        const end_index = result[0];
        const overflow_flag = result[1];

        if (overflow_flag == 1 or end_index > self.length) {
            return error.EOF;
        }
        start_index_ptr.* = std.mem.alignForward(usize, end_index, @sizeOf(u64));
        return @ptrCast(self.memory[start_index..end_index]);
    }

    pub fn getType(self: *const Self, start_index_ptr: *usize, comptime T: type) error{EOF}!*T {
        const length = @sizeOf(T);
        return @alignCast(@ptrCast(try self.getSlice(start_index_ptr, length)));
    }

    pub const Iterator = struct {
        accounts_file: *const AccountFile,
        offset: usize = 0,

        pub fn next(self: *Iterator) ?AccountInFile {
            while (true) {
                const account = self.accounts_file.readAccount(self.offset) catch break;
                self.offset = self.offset + account.len;
                return account;
            }
            return null;
        }

        pub fn reset(self: *Iterator) void {
            self.offset = 0;
        }
    };

    pub fn iterator(self: *const Self) Iterator {
        return .{ .accounts_file = self };
    }
};

test "core.accounts_file: verify accounts file" {
    const path = "test_data/test_account_file";
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    const file_info = AccountFileInfo{
        .id = FileId.fromInt(0),
        .length = 162224,
    };
    var accounts_file = try AccountFile.init(file, file_info, 10);
    defer accounts_file.deinit();

    _ = try accounts_file.validate();

    const account = try accounts_file.readAccount(0);
    const hash_and_lamports = try accounts_file.getAccountHashAndLamports(0);

    try std.testing.expectEqual(account.lamports().*, hash_and_lamports.lamports.*);
    try std.testing.expectEqual(account.hash().*, hash_and_lamports.hash.*);
}
