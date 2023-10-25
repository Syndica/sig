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

    pub fn toString(self: *const TmpPubkey) error{EncodingError}![44]u8 {
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
        const str = self.toString() catch unreachable;
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
    file: std.fs.File,

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
            .file = file,
        };
    }

    pub fn deinit(self: *Self) void {
        std.os.munmap(self.mmap_ptr);
        self.file.close();
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

test "core.append_vec: parse accounts out of append vec" {
    // to run this test
    // 1) run the test `core.snapshot_fields: parse snapshot fields`
    //     - to build accounts_db.bincode file
    // 2) change paths for `accounts_db_fields_path` and `accounts_dir_path`
    // 3) run the test
    const alloc = std.testing.allocator;

    const accounts_db_fields_path = "/Users/tmp2/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };

    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    //
    var storage = HashMap(Slot, AppendVec).init(alloc);
    defer {
        var iter = storage.iterator();
        while (iter.next()) |*entry| {
            entry.value_ptr.deinit();
        }
        storage.deinit();
    }

    var n_appendvec: usize = 0;
    var n_valid_appendvec: usize = 0;

    //
    const accounts_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
    var accounts_dir = std.fs.openIterableDirAbsolute(accounts_dir_path, .{}) catch |err| {
        std.debug.print("failed to open accounts dir: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    var accounts_dir_iter = accounts_dir.iterate();

    while (try accounts_dir_iter.next()) |entry| {
        var filename: []const u8 = entry.name;

        // parse "{slot}.{id}" from the filename
        var fiter = std.mem.tokenizeSequence(u8, filename, ".");
        const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
        const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

        // read metadata
        const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
        std.debug.assert(slot_metas.items.len == 1);
        const slot_meta = slot_metas.items[0];
        std.debug.assert(slot_meta.id == append_vec_id);

        // read appendVec from file
        var abs_path_buf: [1024]u8 = undefined;
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, filename });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        n_appendvec += 1;

        var append_vec = AppendVec.init(append_vec_file, slot_meta) catch continue;

        // verify its valid
        append_vec.sanitize() catch {
            append_vec.deinit();
            continue;
        };
        n_valid_appendvec += 1;

        // note: newer snapshots shouldnt clobber
        try storage.putNoClobber(slot, append_vec);

        // dont open too many files (just testing)
        if (n_appendvec == 10) break;
    }

    // note: didnt untar the full snapshot (bc time)
    // n_valid_appendvec: 328_811, total_append_vec: 328_812
    std.debug.print("n_valid_appendvec: {d}, total_append_vec: {d}\n", .{ n_valid_appendvec, n_appendvec });
}
