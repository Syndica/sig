//! includes the main struct for reading + validating account files
const std = @import("std");
const sig = @import("../sig.zig");

const Account = sig.core.account.Account;
const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;
const AccountFileInfo = sig.accounts_db.snapshot.data.AccountFileInfo;
const BufferPool = sig.accounts_db.buffer_pool.BufferPool;
const Epoch = sig.core.time.Epoch;
const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.pubkey.Pubkey;
const Slot = sig.core.time.Slot;
const bincode = sig.bincode;

const writeIntLittleMem = sig.core.account.writeIntLittleMem;

/// Simple strictly-typed alias for an integer, used to represent a file ID.
///
/// Analogous to [AccountsFileId](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L824)
pub const FileId = enum(Int) {
    _,

    pub const Int = u32;

    pub const BincodeConfig: bincode.FieldConfig(FileId) = .{
        .serializer = serialize,
        .deserializer = deserialize,
    };

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
        id: FileId,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try std.fmt.formatType(
            @intFromEnum(id),
            fmt_str,
            options,
            writer,
            std.options.fmt_max_depth,
        );
    }

    fn serialize(
        writer: anytype,
        data: anytype,
        params: sig.bincode.Params,
    ) anyerror!void {
        try sig.bincode.write(writer, @as(usize, data.toInt()), params);
    }

    fn deserialize(
        _: *bincode.LimitAllocator,
        reader: anytype,
        params: sig.bincode.Params,
    ) anyerror!FileId {
        const int = try sig.bincode.readInt(u64, reader, params);
        if (int > std.math.maxInt(FileId.Int)) return error.IdOverflow;
        return FileId.fromInt(@intCast(int));
    }
};

/// an account thats stored in an AccountFile
///
/// Analogous to [StoredAccountMeta::AppendVec](https://github.com/anza-xyz/agave/blob/f8067ea7883e04bdfc1a82b0779f7363b71bf548/accounts-db/src/account_storage/meta.rs#L21)
pub const AccountInFile = struct {
    store_info: StorageInfo,
    account_info: AccountInfo,
    hash: Hash,

    data: AccountDataHandle,

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

        pub fn serialize(self: *const StorageInfo, buf: []u8) usize {
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

        pub fn serialize(self: *const AccountInfo, buf: []u8) usize {
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

    pub fn deinit(self: AccountInFile, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    pub fn getSizeInFile(self: *const AccountInFile) u64 {
        return std.mem.alignForward(
            usize,
            AccountInFile.STATIC_SIZE + self.data.len(),
            @sizeOf(u64),
        );
    }

    pub fn validate(self: *const AccountInFile) ValidateError!void {
        // TODO: this is not valid, make sure we don't need this
        // make sure upper bits are zero
        const exec_byte = @as(*const u8, @ptrCast(&self.account_info.executable)).*;
        const valid_exec = exec_byte & ~@as(u8, 1) == 0;
        if (!valid_exec) {
            return error.InvalidExecutableFlag;
        }

        const info = self.account_info;
        const is_default_account = self.data.len() == 0 and
            info.owner.isZeroed() and
            info.executable == false and
            info.rent_epoch == 0;

        const valid_lamports = info.lamports != 0 or is_default_account;
        if (!valid_lamports) return error.InvalidLamports;
    }

    /// requires .data to be owned by the BufferPool
    pub fn dupeCachedAccount(
        self: *const AccountInFile,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Account {
        const info = self.account_info;
        return .{
            .data = try self.data.duplicateBufferPoolRead(allocator),
            .executable = info.executable,
            .lamports = info.lamports,
            .owner = info.owner,
            .rent_epoch = info.rent_epoch,
        };
    }

    pub fn serialize(self: *const AccountInFile, buf: []u8) usize {
        std.debug.assert(buf.len >= STATIC_SIZE + self.data.len());

        var offset: usize = 0;
        offset += self.store_info.serialize(buf[offset..]);
        offset += self.account_info.serialize(buf[offset..]);

        @memcpy(buf[offset..(offset + 32)], &self.hash.data);
        offset += 32;
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        self.data.readAll(buf[offset..][0..self.data.len()]);
        offset += self.data.len();
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        return offset;
    }
};

/// Analogous to [AccountStorageEntry](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1069)
pub const AccountFile = struct {
    // file contents
    file: std.fs.File,

    id: FileId,
    slot: Slot,

    /// The number of usefully readable bytes in the file
    length: usize,

    /// The size of the file can be >.length. Bytes beyond .length are essentially junk.
    file_size: usize,

    // number of accounts stored in the file
    number_of_accounts: usize = 0,

    pub fn init(file: std.fs.File, accounts_file_info: AccountFileInfo, slot: Slot) !AccountFile {
        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        try accounts_file_info.validate(file_size);

        return .{
            .file = file,
            .length = accounts_file_info.length,
            .file_size = file_size,
            .id = accounts_file_info.id,
            .slot = slot,
        };
    }

    pub fn deinit(self: AccountFile) void {
        self.file.close();
    }

    pub fn validate(
        self: *const AccountFile,
        buffer_pool: *BufferPool,
    ) !usize {
        var offset: usize = 0;
        var number_of_accounts: usize = 0;
        var account_bytes: usize = 0;

        var buffer_pool_frame_buf: [BufferPool.MAX_READ_BYTES_ALLOCATED]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer_pool_frame_buf);
        const allocator = fba.allocator();

        while (true) {
            const account = self.readAccount(
                allocator,
                buffer_pool,
                offset,
            ) catch |err| switch (err) {
                error.EOF => break,
                else => return err,
            };
            defer {
                account.deinit(allocator);
                fba.reset();
            }

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

    /// get account without reading the data field (a lot faster)
    /// (used when computing account hashes for snapshot validation)
    pub fn getAccountHashAndLamports(
        self: *const AccountFile,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        start_offset: usize,
    ) !struct { hash: Hash, lamports: u64 } {
        var offset = start_offset;

        offset += @sizeOf(AccountInFile.StorageInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const buf_size = @sizeOf(AccountInFile.AccountInfo) + @sizeOf(Hash);

        const read = try self.getSlice(
            metadata_allocator,
            buffer_pool,
            &offset,
            buf_size,
        );
        defer read.deinit(metadata_allocator);

        var buf: [buf_size]u8 = undefined;
        read.readAll(&buf);

        var account_info: AccountInFile.AccountInfo = undefined;
        @memcpy(
            std.mem.asBytes(&account_info),
            buf[0..][0..@sizeOf(AccountInFile.AccountInfo)],
        );
        const lamports = account_info.lamports;

        var hash: Hash = undefined;
        @memcpy(
            std.mem.asBytes(&hash),
            buf[@sizeOf(AccountInFile.AccountInfo)..][0..@sizeOf(Hash)],
        );

        return .{
            .hash = hash,
            .lamports = lamports,
        };
    }

    /// get the account pubkey without parsing data (a lot faster if the data field isnt used anyway)
    pub fn getAccountPubkey(self: *const AccountFile, start_offset: usize) error{EOF}!struct {
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

    pub const max_header_buf_len = max_size: {
        var max_size = 0;
        for (0..@sizeOf(u64)) |i| {
            var start = i;

            start += @sizeOf(AccountInFile.StorageInfo);
            start = std.mem.alignForward(usize, start, @sizeOf(u64));
            start += @sizeOf(AccountInFile.AccountInfo);
            start = std.mem.alignForward(usize, start, @sizeOf(u64));

            start += @sizeOf(Hash);
            start = std.mem.alignForward(usize, start, @sizeOf(u64));

            max_size = @max(max_size, start);
        }
        break :max_size max_size;
    };

    pub fn readAccount(
        self: *const AccountFile,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        start_offset: usize,
    ) !AccountInFile {
        var offset = start_offset;

        offset += @sizeOf(AccountInFile.StorageInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const account_info_start = offset;
        offset += @sizeOf(AccountInFile.AccountInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const hash_start = offset;
        offset += @sizeOf(Hash);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const header_byte_len = offset - start_offset;
        std.debug.assert(header_byte_len <= max_header_buf_len);

        var offset_restarted = start_offset;
        var buf: [max_header_buf_len]u8 = undefined;
        {
            const read = try self.getSlice(
                metadata_allocator,
                buffer_pool,
                &offset_restarted,
                header_byte_len,
            );
            defer read.deinit(metadata_allocator);
            std.debug.assert(offset == offset_restarted);
            read.readAll(buf[0..header_byte_len]);
        }

        var store_info: AccountInFile.StorageInfo = undefined;
        @memcpy(
            std.mem.asBytes(&store_info),
            buf[0..][0..@sizeOf(AccountInFile.StorageInfo)],
        );

        var account_info: AccountInFile.AccountInfo = undefined;
        @memcpy(
            std.mem.asBytes(&account_info),
            buf[account_info_start - start_offset ..][0..@sizeOf(AccountInFile.AccountInfo)],
        );

        var hash: Hash = undefined;
        @memcpy(
            std.mem.asBytes(&hash),
            buf[hash_start - start_offset ..][0..@sizeOf(Hash)],
        );

        const data = try self.getSlice(
            metadata_allocator,
            buffer_pool,
            &offset_restarted,
            store_info.data_len,
        );
        errdefer data.deinit(metadata_allocator);

        const len = offset_restarted - start_offset;

        return AccountInFile{
            .store_info = store_info,
            .account_info = account_info,
            .hash = hash,
            .data = data,
            .len = len,
            .offset = start_offset,
        };
    }

    pub fn readAccountNoData(
        self: *const AccountFile,
        buffer_pool: *BufferPool,
        start_offset: usize,
    ) !AccountInFile {
        // enough to store any account header
        var buffer_pool_frame_buf: [@sizeOf(u32) * 3]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buffer_pool_frame_buf);
        const metadata_allocator = fba.allocator();

        var offset = start_offset;

        offset += @sizeOf(AccountInFile.StorageInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const account_info_start = offset;
        offset += @sizeOf(AccountInFile.AccountInfo);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const hash_start = offset;
        offset += @sizeOf(Hash);
        offset = std.mem.alignForward(usize, offset, @sizeOf(u64));

        const header_byte_len = offset - start_offset;
        std.debug.assert(header_byte_len <= max_header_buf_len);

        var offset_restarted = start_offset;
        const read = try self.getSlice(
            metadata_allocator,
            buffer_pool,
            &offset_restarted,
            header_byte_len,
        );
        std.debug.assert(offset == offset_restarted);
        defer read.deinit(metadata_allocator);

        var buf: [max_header_buf_len]u8 = undefined;
        read.readAll(buf[0..header_byte_len]);

        var store_info: AccountInFile.StorageInfo = undefined;
        @memcpy(
            std.mem.asBytes(&store_info),
            buf[0..][0..@sizeOf(AccountInFile.StorageInfo)],
        );

        var account_info: AccountInFile.AccountInfo = undefined;
        @memcpy(
            std.mem.asBytes(&account_info),
            buf[account_info_start - start_offset ..][0..@sizeOf(AccountInFile.AccountInfo)],
        );

        var hash: Hash = undefined;
        @memcpy(
            std.mem.asBytes(&hash),
            buf[hash_start - start_offset ..][0..@sizeOf(Hash)],
        );

        const start_index = offset;
        const result = @addWithOverflow(start_index, store_info.data_len);
        const end_index = result[0];
        const overflow_flag = result[1];
        if (overflow_flag == 1 or end_index > self.length) {
            return error.EOF;
        }

        const data = AccountDataHandle.initEmpty(
            std.math.cast(u32, store_info.data_len) orelse return error.EOF,
        );

        offset = std.mem.alignForward(usize, end_index, @sizeOf(u64));

        const len = offset - start_offset;

        return AccountInFile{
            .store_info = store_info,
            .account_info = account_info,
            .hash = hash,
            .data = data,
            .len = len,
            .offset = start_offset,
        };
    }

    pub fn getSlice(
        self: *const AccountFile,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        start_index_ptr: *usize,
        length: usize,
    ) !AccountDataHandle {
        const start_index = start_index_ptr.*;
        const result = @addWithOverflow(start_index, length);
        const end_index = result[0];
        const overflow_flag = result[1];

        if (overflow_flag == 1 or end_index > self.length) {
            return error.EOF;
        }

        start_index_ptr.* = std.mem.alignForward(usize, end_index, @sizeOf(u64));
        return try buffer_pool.read(
            metadata_allocator,
            self.file,
            self.id,
            @intCast(start_index),
            @intCast(end_index),
        );
    }

    pub fn getType(
        self: *const AccountFile,
        metadata_allocator: std.mem.Allocator,
        buffer_pool: *BufferPool,
        start_index_ptr: *usize,
        comptime T: type,
    ) !T {
        const length = @sizeOf(T);

        const read = try self.getSlice(metadata_allocator, buffer_pool, start_index_ptr, length);
        defer read.deinit(metadata_allocator);

        var buf: T = undefined;
        read.readAll(std.mem.asBytes(&buf));
        return buf;
    }

    pub const Iterator = struct {
        accounts_file: *const AccountFile,
        buffer_pool: *BufferPool,
        offset: usize = 0,

        pub fn next(self: *Iterator, fba: std.mem.Allocator) !?AccountInFile {
            while (true) {
                const account = self.accounts_file.readAccount(
                    fba,
                    self.buffer_pool,
                    self.offset,
                ) catch |err| switch (err) {
                    error.EOF => break,
                    else => return err,
                };
                self.offset = self.offset + account.len;
                return account;
            }
            return null;
        }

        pub fn nextNoData(self: *Iterator) !?AccountInFile {
            while (true) {
                const account = self.accounts_file.readAccountNoData(
                    self.buffer_pool,
                    self.offset,
                ) catch |err| switch (err) {
                    error.EOF => break,
                    else => return err,
                };
                self.offset += account.len;
                return account;
            }
            return null;
        }

        pub fn reset(self: *Iterator) void {
            self.offset = 0;
        }
    };

    pub fn iterator(self: *const AccountFile, buffer_pool: *BufferPool) Iterator {
        return .{
            .accounts_file = self,
            .buffer_pool = buffer_pool,
        };
    }
};

test "core.accounts_file: verify accounts file" {
    const path = sig.TEST_DATA_DIR ++ "test_account_file";
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    const file_info = AccountFileInfo{
        .id = FileId.fromInt(0),
        .length = 162224,
    };

    var bp = try BufferPool.init(std.testing.allocator, 1000);
    defer bp.deinit(std.testing.allocator);

    var accounts_file = try AccountFile.init(file, file_info, 10);
    defer accounts_file.deinit();

    _ = try accounts_file.validate(&bp);

    const account = try accounts_file.readAccount(std.testing.allocator, &bp, 0);
    defer account.deinit(std.testing.allocator);

    const hash_and_lamports = try accounts_file.getAccountHashAndLamports(
        std.testing.allocator,
        &bp,
        0,
    );

    try std.testing.expectEqual(account.account_info.lamports, hash_and_lamports.lamports);
    try std.testing.expectEqual(account.hash, hash_and_lamports.hash);
}
