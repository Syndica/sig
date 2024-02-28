const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("./account.zig").Account;
const hashAccount = @import("./account.zig").hashAccount;
const Hash = @import("./hash.zig").Hash;
const Slot = @import("./time.zig").Slot;
const Epoch = @import("./time.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;

const AccountFileInfo = @import("./snapshots.zig").AccountFileInfo;
const AccountIndex = @import("accounts_db.zig").AccountIndex;
const AccountRef = @import("./accounts_db.zig").AccountRef;

pub const FileId = u32;

// an account thats stored in an AccountFile
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
    pub const StorageInfo = struct {
        write_version_obsolete: u64,
        data_len: u64,
        pubkey: Pubkey,
    };

    /// on-chain account info about the account
    pub const AccountInfo = struct {
        lamports: u64,
        rent_epoch: Epoch,
        owner: Pubkey,
        executable: bool,
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

    pub fn validate(self: *const @This()) !void {
        // make sure upper bits are zero
        const exec_byte = @as(*u8, @ptrCast(self.executable()));
        const valid_exec = exec_byte.* & ~@as(u8, 1) == 0;
        if (!valid_exec) {
            return error.InvalidExecutableFlag;
        }

        var valid_lamports = self.account_info.lamports != 0 or (
        // ie, is default account
            self.data.len == 0 and
            self.owner().isDefault() and
            self.executable().* == false and
            self.rent_epoch().* == 0);
        if (!valid_lamports) {
            return error.InvalidLamports;
        }
    }

    pub inline fn pubkey(self: *const @This()) *Pubkey {
        return &self.store_info.pubkey;
    }

    pub inline fn lamports(self: *const @This()) *u64 {
        return &self.account_info.lamports;
    }

    pub inline fn owner(self: *const @This()) *Pubkey {
        return &self.account_info.owner;
    }

    pub inline fn executable(self: *const @This()) *bool {
        return &self.account_info.executable;
    }

    pub inline fn rent_epoch(self: *const @This()) *Epoch {
        return &self.account_info.rent_epoch;
    }

    pub inline fn hash(self: *const @This()) *Hash {
        return self.hash_ptr;
    }
};

pub const AccountFile = struct {
    // file contents
    memory: []align(std.mem.page_size) u8,
    id: usize,
    slot: Slot,
    // number of bytes used
    length: usize,
    // total bytes available
    file_size: usize,
    file: std.fs.File,

    // number of accounts stored in the file
    n_accounts: usize = 0,

    const Self = @This();

    pub fn init(file: std.fs.File, accounts_file_info: AccountFileInfo, slot: Slot) !Self {
        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        try accounts_file_info.validate(file_size);

        var memory = try std.os.mmap(
            null,
            file_size,
            std.os.PROT.READ | std.os.PROT.WRITE,
            std.os.MAP.SHARED,
            file.handle,
            0,
        );

        // PERF TODO: get this to work
        // try std.os.madvise(memory, file_size, std.os.MADV.SEQUENTIAL);

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
        std.os.munmap(self.memory);
        self.file.close();
    }

    pub fn validate(self: *Self) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

        while (true) {
            const account = self.readAccount(offset) catch break;
            try account.validate();
            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != std.mem.alignForward(usize, self.length, @sizeOf(u64))) {
            return error.InvalidAccountFileLength;
        }

        self.n_accounts = n_accounts;
    }

    /// get account without parsing data (a lot faster if the data field isnt used anyway)
    /// (used when computing account hashes for snapshot validation)
    pub fn getAccountHashAndLamports(self: *const Self, start_offset: usize) error{EOF}!struct { hash: *Hash, lamports: *u64 } {
        var offset = start_offset;

        offset += @sizeOf(AccountInFile.StorageInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        var lamports = try self.getType(&offset, u64);

        offset += @sizeOf(AccountInFile.AccountInfo) - @sizeOf(u64);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        var hash = try self.getType(&offset, Hash);

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

        var store_info = try self.getType(&offset, AccountInFile.StorageInfo);
        var account_info = try self.getType(&offset, AccountInFile.AccountInfo);
        var hash = try self.getType(&offset, Hash);
        var data = try self.getSlice(&offset, store_info.data_len);

        var len = offset - start_offset;

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
};

test "core.accounts_file: verify accounts file" {
    const path = "test_data/test_account_file";
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    const file_info = AccountFileInfo{
        .id = 0,
        .length = 162224,
    };
    var accounts_file = try AccountFile.init(file, file_info, 10);
    defer accounts_file.deinit();

    try accounts_file.validate();

    const account = try accounts_file.readAccount(0);
    const hash_and_lamports = try accounts_file.getAccountHashAndLamports(0);

    try std.testing.expectEqual(account.lamports().*, hash_and_lamports.lamports.*);
    try std.testing.expectEqual(account.hash().*, hash_and_lamports.hash.*);
}
