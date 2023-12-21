const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("./account.zig").Account;
const hashAccount = @import("./account.zig").hashAccount;
const Hash = @import("./hash.zig").Hash;
const Slot = @import("./time.zig").Slot;
const Epoch = @import("./time.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;

const AccountFileInfo = @import("./snapshot_fields.zig").AccountFileInfo;

pub const FileId = u32;

// metadata which is stored inside an AccountFile
pub const AccountFileStoreInfo = struct {
    write_version_obsolete: u64,
    data_len: u64,
    pubkey: Pubkey,
};

pub const AccountFileInnerAccountInfo = struct {
    lamports: u64,
    rent_epoch: Epoch,
    owner: Pubkey,
    executable: bool,
};

// account meta data which is stored inside an AccountFile
pub const AccountFileAccountInfo = struct {
    store_info: *AccountFileStoreInfo,
    account_info: *AccountFileInnerAccountInfo,

    data: []u8,
    offset: usize,
    len: usize,
    hash: *Hash,

    pub fn sanitize(self: *const @This()) !void {
        // make sure upper bits are zero
        const exec_byte = @as(*u8, @ptrCast(&self.account_info.executable));
        const valid_exec = exec_byte.* & ~@as(u8, 1) == 0;
        if (!valid_exec) {
            return error.InvalidExecutableFlag;
        }

        var valid_lamports = self.account_info.lamports != 0 or (
        // ie, is default account
            self.data.len == 0 and
            self.account_info.owner.isDefault() and
            self.account_info.executable == false and
            self.account_info.rent_epoch == 0);
        if (!valid_lamports) {
            return error.InvalidLamports;
        }
    }

    // pubkey
    pub inline fn pubkey(self: *const @This()) Pubkey {
        return self.store_info.pubkey;
    }

    pub inline fn lamports(self: *const @This()) u64 {
        return self.account_info.lamports;
    }

    pub inline fn owner(self: *const @This()) Pubkey {
        return self.account_info.owner;
    }

    pub inline fn executable(self: *const @This()) bool {
        return self.account_info.executable;
    }

    pub inline fn rent_epoch(self: *const @This()) Epoch {
        return self.account_info.rent_epoch;
    }
};

pub const PubkeyAccountRef = struct {
    pubkey: Pubkey,
    offset: usize,
    slot: Slot,
    file_id: usize,
};

const u64_size: usize = @sizeOf(u64);
pub inline fn alignToU64(addr: usize) usize {
    return (addr + (u64_size - 1)) & ~(u64_size - 1);
}

pub const AccountFile = struct {
    // file contents
    mmap_ptr: []align(std.mem.page_size) u8,
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

        try accounts_file_info.sanitize(file_size);

        var mmap_ptr = try std.os.mmap(
            null,
            file_size,
            std.os.PROT.READ | std.os.PROT.WRITE,
            std.os.MAP.SHARED,
            file.handle,
            0,
        );

        return Self{
            .mmap_ptr = mmap_ptr,
            .length = accounts_file_info.length,
            .id = accounts_file_info.id,
            .file_size = file_size,
            .file = file,
            .slot = slot,
        };
    }

    pub fn deinit(self: *Self) void {
        std.os.munmap(self.mmap_ptr);
        self.file.close();
    }

    pub fn sanitize(self: *Self) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

        while (true) {
            const account = self.getAccount(offset) catch break;
            try account.sanitize();
            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != alignToU64(self.length)) {
            return error.InvalidAccountFileLength;
        }

        self.n_accounts = n_accounts;
    }

    pub fn sanitizeAndGetAccountsRefs(self: *Self, refs: *ArrayList(PubkeyAccountRef)) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

        while (true) {
            var account = self.getAccount(offset) catch break;
            try account.sanitize();

            const pubkey = account.store_info.pubkey;

            const hash_is_missing = std.mem.eql(u8, &account.hash.data, &Hash.default().data);
            if (hash_is_missing) {
                const hash = hashAccount(
                    account.account_info.lamports,
                    account.data,
                    &account.account_info.owner.data,
                    account.account_info.executable,
                    account.account_info.rent_epoch,
                    &pubkey.data,
                );
                account.hash.* = hash;
            }

            try refs.append(PubkeyAccountRef{
                .pubkey = pubkey,
                .offset = offset,
                .slot = self.slot,
                .file_id = self.id,
            });

            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != alignToU64(self.length)) {
            return error.InvalidAccountFileLength;
        }

        self.n_accounts = n_accounts;
    }

    pub fn getAccount(self: *const Self, start_offset: usize) error{EOF}!AccountFileAccountInfo {
        var offset = start_offset;

        var store_info = try self.getType(&offset, AccountFileStoreInfo);
        var account_info = try self.getType(&offset, AccountFileInnerAccountInfo);
        var hash = try self.getType(&offset, Hash);
        var data = try self.getSlice(&offset, store_info.data_len);

        var len = offset - start_offset;

        return AccountFileAccountInfo{
            .store_info = store_info,
            .account_info = account_info,
            .hash = hash,
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
        start_index_ptr.* = alignToU64(end_index);
        return @ptrCast(self.mmap_ptr[start_index..end_index]);
    }

    pub fn getType(self: *const Self, start_index_ptr: *usize, comptime T: type) error{EOF}!*T {
        const length = @sizeOf(T);
        return @alignCast(@ptrCast(try self.getSlice(start_index_ptr, length)));
    }
};
