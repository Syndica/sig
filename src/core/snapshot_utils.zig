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

pub const AppendVec = struct {
    mmap_ptr: []align(std.mem.page_size) u8,
    accounts_len: usize,
    id: usize,

    const Self = @This();

    pub fn init(file: std.fs.File, append_vec_info: AppendVecInfo) !Self {
        const file_stat = try file.stat();
        const file_size: u64 = @intCast(file_stat.size);

        try append_vec_info.sanitize(file_size);

        var ptr = try std.os.mmap(
            null,
            file_size,
            std.os.PROT.READ | std.os.PROT.WRITE,
            std.os.MAP.SHARED,
            file.handle,
            0,
        );

        return Self{
            .mmap_ptr = ptr,
            .accounts_len = append_vec_info.accounts_len,
            .id = append_vec_info.id,
        };
    }

    pub fn sanitize(self: *const Self) !void {
        // TODO:
        _ = self;
    }

    pub fn deinit(self: *Self) void {
        std.os.munmap(self.mmap_ptr);
    }
};

test "core.snapshot_utils: tmp" {
    const alloc = std.testing.allocator;
    const accounts_db_meta_path = "/Users/tmp/Documents/workspace/solana/data/full_snapshots/remote/accounts_db.bincode";

    const file = try std.fs.openFileAbsolute(accounts_db_meta_path, .{});
    const file_size = (try file.stat()).size;
    var buf = try std.ArrayList(u8).initCapacity(alloc, file_size);
    defer buf.deinit();

    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    // verify fields are correct
    const accounts_dir = "/Users/tmp/Documents/workspace/solana/data/full_snapshots/remote/accounts";

    // iterate over the files in the dir
    var slot_to_n_appendvec = HashMap(Slot, usize).init(alloc);
    defer slot_to_n_appendvec.deinit();

    var count: usize = 0;
    var dir = try std.fs.openIterableDirAbsolute(accounts_dir, .{});
    var accounts_dir_iter = dir.iterate();
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
        const accounts_len = slot_meta.accounts_len;

        std.debug.print("slot: {d}, append_vec_id: {d} current_len: {d}\n", .{ slot, append_vec_id, accounts_len });

        // file => appendVec
        var abs_path_buf: [1024]u8 = undefined;
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir, filename });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        var append_vec = try AppendVec.init(append_vec_file, slot_meta);
        defer append_vec.deinit();

        break;
    }
}
