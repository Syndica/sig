//! includes the main struct for reading + validating account files
const std = @import("std");
const sig = @import("../sig.zig");

const AccountDataHandle = sig.accounts_db.buffer_pool.AccountDataHandle;
const Epoch = sig.core.time.Epoch;
const Hash = sig.core.hash.Hash;
const Pubkey = sig.core.pubkey.Pubkey;
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
