const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("../core/snapshot_fields.zig").AppendVecInfo;
const AppendVec = @import("../core/append_vec.zig").AppendVec;
const TmpPubkey = @import("../core/append_vec.zig").TmpPubkey;
const Account = @import("../core/account.zig").Account;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const Slot = @import("../core/clock.zig").Slot;
const ArrayList = std.ArrayList;

pub const AccountAndPubkey = struct {
    pubkey: TmpPubkey,
    account: Account,
};

pub fn main() !void {
    const accounts_db_fields_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts_db.bincode";
    const accounts_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts";
    // const dump_dir_path = "/Users/tmp/Documents/zig-solana/snapshots/account_dumps";
    const dump_file_csv_path = "/Users/tmp/Documents/zig-solana/snapshots/accounts.csv";

    const maybe_max_append_vecs: ?usize = null;

    const alloc = std.heap.c_allocator;

    // // where to dump the full account data
    // std.fs.makeDirAbsolute(dump_dir_path) catch {};
    const csv_file = try std.fs.createFileAbsolute(dump_file_csv_path, .{});
    defer csv_file.close();

    const accounts_db_fields_file = try std.fs.openFileAbsolute(accounts_db_fields_path, .{});
    var accounts_db_fields = try bincode.read(alloc, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(alloc, accounts_db_fields);

    var accounts_dir = try std.fs.openIterableDirAbsolute(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    var arena_allocator = std.heap.ArenaAllocator.init(alloc);
    var storage = std.AutoHashMap(Slot, AppendVec).init(arena_allocator.allocator());
    defer arena_allocator.deinit();

    var account_count: usize = 0;
    var append_vec_count: usize = 0;
    var total_append_vec_count: usize = 0;

    // compute the total size to preallocate
    while (try accounts_dir_iter.next()) |_| {
        total_append_vec_count += 1;
    }
    var maybe_last_time: ?u64 = null;

    accounts_dir_iter = accounts_dir.iterate();
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

        var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch continue;

        // verify its valid
        append_vec.sanitize() catch {
            append_vec.deinit();
            continue;
        };

        // note: newer snapshots shouldnt clobber
        try storage.putNoClobber(slot, append_vec);

        const pubkey_and_refs = try append_vec.getAccountsRefs(alloc);
        defer pubkey_and_refs.deinit();

        for (pubkey_and_refs.items) |*pubkey_and_ref| {
            const pubkey = pubkey_and_ref.pubkey;
            const account_ref = pubkey_and_ref.account_ref;

            const account = try append_vec.getAccount(account_ref.offset);
            const owner_pk = try Pubkey.fromBytes(&account.account_info.owner.data, .{});

            const to_dump = AccountAndPubkey{ .pubkey = pubkey, .account = Account{
                .owner = owner_pk,
                .data = account.data,
                .lamports = account.account_info.lamports,
                .executable = account.account_info.executable,
                .rent_epoch = account.account_info.rent_epoch,
            } };

            const csv_row = try std.fmt.allocPrint(alloc, "{s};{s};{any};{d};{any};{d}", .{
                try to_dump.pubkey.toString(),
                try account.account_info.owner.toString(),
                to_dump.account.data,
                to_dump.account.lamports,
                to_dump.account.executable,
                to_dump.account.rent_epoch,
            });

            try csv_file.writer().print("{s}\n", .{csv_row});
            account_count += 1;
        }
        append_vec_count += 1;

        if (append_vec_count % 10 == 0) {
            // estimate how long left
            const now: u64 = @intCast(std.time.milliTimestamp() * std.time.ns_per_ms);
            const time_left_mins = blk: {
                if (maybe_last_time) |last_time| {
                    const elapsed = now - last_time;
                    const ns_per_vec = elapsed / 10;
                    const vecs_left = total_append_vec_count - append_vec_count;
                    const time_left = ns_per_vec * vecs_left;
                    break :blk time_left / std.time.ns_per_min;
                } else {
                    break :blk 0;
                }
            };

            std.debug.print("dumped {d} accounts across {d}/{d} appendvecs (mins left: {d})\r", .{
                account_count,
                append_vec_count,
                total_append_vec_count,
                time_left_mins,
            });
            maybe_last_time = now;
        }

        if (maybe_max_append_vecs) |max_append_vecs| {
            if (append_vec_count == max_append_vecs) {
                break;
            }
        }
    }

    std.debug.print("done!\n", .{});
}
