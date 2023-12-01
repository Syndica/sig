const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("./account.zig").Account;
const Hash = @import("./hash.zig").Hash;
const Slot = @import("./clock.zig").Slot;
const Epoch = @import("./clock.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const AccountsDbFields = @import("./snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("./snapshot_fields.zig").AppendVecInfo;

const base58 = @import("base58-zig");

// metadata which is stored inside an AppendVec
pub const AppendVecStoreInfo = struct {
    write_version_obsolete: u64,
    data_len: u64,
    pubkey: Pubkey,
};

pub const AppendVecInnerAccountInfo = struct {
    lamports: u64,
    rent_epoch: Epoch,
    owner: Pubkey,
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

pub const PubkeyAndAccountInAppendVecRef = struct {
    pubkey: TmpPubkey,
    account_ref: AccountInAppendVecRef,
    // hash: Hash,
};

const u64_size: usize = @sizeOf(u64);
pub inline fn alignToU64(addr: usize) usize {
    return (addr + (u64_size - 1)) & ~(u64_size - 1);
}

pub const AppendVec = struct {
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

    pub fn init(file: std.fs.File, append_vec_info: AppendVecInfo, slot: Slot) !Self {
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

    pub fn getAccountsRefs(self: *const Self, allocator: std.mem.Allocator) !ArrayList(PubkeyAndAccountInAppendVecRef) {
        var accounts = try ArrayList(PubkeyAndAccountInAppendVecRef).initCapacity(allocator, self.n_accounts);

        var offset: usize = 0;
        while (true) {
            const account = self.getAccount(offset) catch break;
            const pubkey = account.store_info.pubkey;

            const pubkey_account_ref = PubkeyAndAccountInAppendVecRef{
                .pubkey = pubkey,
                .account_ref = .{
                    .slot = self.slot,
                    .offset = offset,
                    .append_vec_id = self.id,
                },
                // .hash = Hash.default(),
            };

            accounts.appendAssumeCapacity(pubkey_account_ref);
            offset = offset + account.len;
        }

        return accounts;
    }
};

pub const AccountInAppendVecRef = struct {
    slot: usize,
    append_vec_id: usize,
    offset: usize,
};

pub const AccountsIndex = struct {
    // only support RAM for now
    ram_map: HashMap(TmpPubkey, ArrayList(AccountInAppendVecRef)),
    // TODO: disk_map

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .ram_map = HashMap(TmpPubkey, ArrayList(AccountInAppendVecRef)).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.ram_map.iterator();
        while (iter.next()) |*entry| {
            entry.value_ptr.deinit();
        }
        self.ram_map.deinit();
    }

    pub fn insertNewAccountRef(
        self: *Self,
        pubkey: TmpPubkey,
        account_ref: AccountInAppendVecRef,
    ) !void {
        var maybe_entry = self.ram_map.getEntry(pubkey);

        // if the pubkey already exists
        if (maybe_entry) |*entry| {
            var existing_refs: *ArrayList(AccountInAppendVecRef) = entry.value_ptr;

            // search: if slot already exists, replace the value
            var found_matching_slot = false;
            for (existing_refs.items) |*existing_ref| {
                if (existing_ref.slot == account_ref.slot) {
                    if (!found_matching_slot) {
                        existing_ref.* = account_ref;
                        found_matching_slot = true;
                        break;
                    }
                    // TODO: rust impl continues to scan and removes other slot duplicates
                    // do we need to do this?
                }
            }

            // otherwise we append the new slot
            if (!found_matching_slot) {
                try existing_refs.append(account_ref);
            }
        } else {
            var account_refs = try ArrayList(AccountInAppendVecRef).initCapacity(self.ram_map.allocator, 1);
            account_refs.appendAssumeCapacity(account_ref);
            try self.ram_map.putNoClobber(pubkey, account_refs);
        }
    }
};

test "core.append_vec: parse accounts out of append vec" {
    // to run this test
    // 1) run the test `core.snapshot_fields: parse snapshot fields`
    //     - to build accounts_db.bincode file
    // 2) change paths for `accounts_db_fields_path` and `accounts_dir_path`
    // 3) run the test
    const alloc = std.testing.allocator;

    const accounts_db_fields_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };

    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    const accounts_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
    _ = accounts_dir_path;

    // // time it
    // var timer = try std.time.Timer.start();

    // var accounts_db = AccountsDB.init(alloc);
    // defer accounts_db.deinit();
    // try accounts_db.load(alloc, accounts_db_fields, accounts_dir_path, null);

    // const elapsed = timer.read();
    // std.debug.print("elapsed: {d}\n", .{elapsed / std.time.ns_per_s});

    // note: didnt untar the full snapshot (bc time)
    // n_valid_appendvec: 328_811, total_append_vec: 328_812
    // std.debug.print("n_valid_appendvec: {d}, total_append_vec: {d}\n", .{ n_valid_appendvec, n_appendvec });
}
