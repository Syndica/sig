const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("./account.zig").Account;
const Hash = @import("./hash.zig").Hash;
const Slot = @import("./clock.zig").Slot;
const Epoch = @import("./clock.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const SnapshotFields = @import("./snapshot_fields.zig").SnapshotFields;
const AccountsDbFields = @import("./snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("./snapshot_fields.zig").AppendVecInfo;

const base58 = @import("base58-zig");

pub const TmpPubkey = struct {
    data: [32]u8,
    // note: need to remove cached string to have correct ptr casting

    pub fn base58_encode(self: *const TmpPubkey) error{EncodingError}![44]u8 {
        var dest: [44]u8 = undefined;
        @memset(&dest, 0);

        const encoder = base58.Encoder.init(.{});
        var written = encoder.encode(&self.data, &dest) catch return error.EncodingError;
        if (written > 44) {
            std.debug.panic("written is > 44, written: {}, dest: {any}, bytes: {any}", .{ written, dest, self.data });
        }
        return dest;
    }

    pub fn format(self: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) std.os.WriteError!void {
        const str = self.base58_encode() catch unreachable;
        return writer.print("{s}", .{str});
    }

    pub fn isDefault(self: *const TmpPubkey) bool {
        return std.mem.eql(u8, &self.data, &[_]u8{0} ** 32);
    }
};

// metadata which is stored inside an AppendVec
pub const AppendVecStoreInfo = struct {
    write_version_obsolete: u64,
    data_len: u64,
    pubkey: TmpPubkey,
};

pub const AppendVecInnerAccountInfo = struct {
    lamports: u64,
    rent_epoch: Epoch,
    owner: TmpPubkey,
    executable: bool,
};

// account meta data which is stored inside an AppendVec
pub const AppendVecAccountInfo = struct {
    store_info: *AppendVecStoreInfo,
    account_info: *AppendVecInnerAccountInfo,

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
};

const u64_size: usize = @sizeOf(u64);
inline fn alignToU64(addr: usize) usize {
    return (addr + (u64_size - 1)) & ~(u64_size - 1);
}

pub const AppendVec = struct {
    // file contents
    mmap_ptr: []align(std.mem.page_size) u8,
    id: usize,
    // number of bytes used
    length: usize,
    // total bytes available
    file_size: usize,
    // number of accounts stored in the file
    n_accounts: usize = 0,

    const Self = @This();

    pub fn init(file: std.fs.File, append_vec_info: AppendVecInfo) !Self {
        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        try append_vec_info.sanitize(file_size);

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
            .length = append_vec_info.length,
            .id = append_vec_info.id,
            .file_size = file_size,
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
        const length = bincode.getComptimeSize(T);
        return @alignCast(@ptrCast(try self.getSlice(start_index_ptr, length)));
    }

    pub fn getAccount(self: *const Self, start_offset: usize) error{EOF}!AppendVecAccountInfo {
        var offset = start_offset;

        var store_info = try self.getType(&offset, AppendVecStoreInfo);
        var account_info = try self.getType(&offset, AppendVecInnerAccountInfo);
        var hash = try self.getType(&offset, Hash);
        var data = try self.getSlice(&offset, store_info.data_len);

        var len = offset - start_offset;

        return AppendVecAccountInfo{
            .store_info = store_info,
            .account_info = account_info,
            .hash = hash,
            .data = data,
            .len = len,
            .offset = start_offset,
        };
    }

    pub fn sanitize(self: *Self) !void {
        var offset: usize = 0;
        var n_accounts: usize = 0;

        // parse all the accounts out of the append vec
        while (true) {
            const account = self.getAccount(offset) catch break;
            try account.sanitize();
            offset = offset + account.len;
            n_accounts += 1;
        }

        if (offset != alignToU64(self.length)) {
            return error.InvalidAppendVecLength;
        }

        self.n_accounts = n_accounts;
    }

    pub fn deinit(self: *Self) void {
        std.os.munmap(self.mmap_ptr);
    }
};

test "core.snapshot_utils: tmp" {
    const alloc = std.testing.allocator;
    const accounts_db_meta_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";

    const file = try std.fs.openFileAbsolute(accounts_db_meta_path, .{});
    const file_size = (try file.stat()).size;
    var buf = try std.ArrayList(u8).initCapacity(alloc, file_size);
    defer buf.deinit();

    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    // // const abs_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts/225272877.1826257";
    // const abs_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts/225207528.1691286";
    // const slot = 225207528;
    // const append_vec_id = 1691286;

    // const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
    // // we should only have one entry (in newer snapshots)
    // std.debug.assert(slot_metas.items.len == 1);
    // const slot_meta = slot_metas.items[0];
    // std.debug.assert(slot_meta.id == append_vec_id);

    // std.debug.print("slot_meta {any}\n", .{slot_meta});

    // const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
    // var append_vec = try AppendVec.init(append_vec_file, slot_meta);
    // defer append_vec.deinit();

    // try append_vec.sanitize();

    // verify fields are correct
    const accounts_dir = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
    // iterate over the files in the dir
    var slot_to_n_appendvec = HashMap(Slot, usize).init(alloc);
    defer slot_to_n_appendvec.deinit();

    var count: usize = 0;
    var dir = try std.fs.openIterableDirAbsolute(accounts_dir, .{});
    var accounts_dir_iter = dir.iterate();
    var n_valid_appendvec: usize = 0;
    while (try accounts_dir_iter.next()) |entry| {
        var filename: []const u8 = entry.name;

        // parse "{slot}.{id}" from the filename
        var fiter = std.mem.tokenizeSequence(u8, filename, ".");
        const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
        const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

        // this should never fail with a newer snapshot (we only support newer snapshots)
        slot_to_n_appendvec.putNoClobber(slot, append_vec_id) catch {
            std.debug.print("clobber occured at slot {d} with id {d}\n", .{ slot, append_vec_id });
            @panic("");
        };
        count += 1;

        const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
        // we should only have one entry (in newer snapshots)
        std.debug.assert(slot_metas.items.len == 1);
        const slot_meta = slot_metas.items[0];
        std.debug.assert(slot_meta.id == append_vec_id);

        // file => appendVec
        var abs_path_buf: [1024]u8 = undefined;
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir, filename });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        defer append_vec_file.close();

        var append_vec = AppendVec.init(append_vec_file, slot_meta) catch continue;
        defer append_vec.deinit();

        append_vec.sanitize() catch {
            // std.debug.print("sanitize failed @ slot {d} with id {d}: {s}\n", .{ slot, append_vec_id, @errorName(err) });
            continue;
        };
        // std.debug.print("sanitize SUCCESS @ slot {d} with id {d}\n", .{ slot, append_vec_id });
        n_valid_appendvec += 1;
    }
    std.debug.print("n_valid_appendvec: {d}, total_append_vec: {d}\n", .{ n_valid_appendvec, count });
}
