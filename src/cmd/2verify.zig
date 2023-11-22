const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const Account = @import("../core/account.zig").Account;
const Hash = @import("../core/hash.zig").Hash;
const Slot = @import("../core/clock.zig").Slot;
const Epoch = @import("../core/clock.zig").Epoch;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");

const SnapshotFields = @import("../core/snapshot_fields.zig").SnapshotFields;
const AccountsDbFields = @import("../core/snapshot_fields.zig").AccountsDbFields;
const AppendVecInfo = @import("../core/snapshot_fields.zig").AppendVecInfo;

const base58 = @import("base58-zig");

const AppendVec = @import("../core/append_vec.zig").AppendVec;
const AccountsIndex = @import("../core/append_vec.zig").AccountsIndex;
const TmpPubkey = @import("../core/append_vec.zig").TmpPubkey;
const alignToU64 = @import("../core/append_vec.zig").alignToU64;
const PubkeyAndAccountInAppendVecRef = @import("../core/append_vec.zig").PubkeyAndAccountInAppendVecRef;

const Channel = @import("../sync/channel.zig").Channel;
const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
const Task = ThreadPool.Task;
const Batch = ThreadPool.Batch;

const hashAccount = @import("../core/account.zig").hashAccount;

const merkleTreeHash = @import("../common/merkle_tree.zig").merkleTreeHash;

pub const MERKLE_FANOUT: usize = 16;

const Release = std.atomic.Ordering.Release;
const Acquire = std.atomic.Ordering.Acquire;

pub fn parseAccounts(
    allocator: std.mem.Allocator,
    accounts_db_fields: *const AccountsDbFields,
    accounts_dir_path: []const u8,
    // task specific
    file_names: [][]const u8,
) !void {
    _ = allocator; 

    // TODO: might need to be longer depending on abs path length
    var abs_path_buf: [1024]u8 = undefined;
    var count: usize = 0;

    for (file_names) |file_name| {
        // parse "{slot}.{id}" from the file_name
        var fiter = std.mem.tokenizeSequence(u8, file_name, ".");
        const slot = try std.fmt.parseInt(Slot, fiter.next().?, 10);
        const append_vec_id = try std.fmt.parseInt(usize, fiter.next().?, 10);

        // read metadata
        const slot_metas: ArrayList(AppendVecInfo) = accounts_db_fields.map.get(slot).?;
        std.debug.assert(slot_metas.items.len == 1);
        const slot_meta = slot_metas.items[0];
        std.debug.assert(slot_meta.id == append_vec_id);

        // read appendVec from file
        const abs_path = try std.fmt.bufPrint(&abs_path_buf, "{s}/{s}", .{ accounts_dir_path, file_name });
        const append_vec_file = try std.fs.openFileAbsolute(abs_path, .{ .mode = .read_write });
        var append_vec = AppendVec.init(append_vec_file, slot_meta, slot) catch |err| {
            var buf: [1024]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buf);
            var writer = stream.writer();
            try std.fmt.format(writer, "failed to open appendVec {s}: {s}", .{ file_name, @errorName(err) });
            @panic(stream.getWritten());
        };
        defer append_vec.deinit();

        count += 1;
    }
}

pub const PubkeyBinCalculator = struct { 
    shift_bits: u32,

    pub fn init(n_bins: usize) PubkeyBinCalculator {
        // u8 * 3 (ie, we consider on the first 3 bytes of a pubkey)
        const MAX_BITS: u32 = 24;
        // within bounds
        std.debug.assert(n_bins > 0);
        std.debug.assert(n_bins <= (1 << MAX_BITS));
        // power of two 
        std.debug.assert((n_bins & (n_bins - 1)) == 0);

        // eg,
        // 8 bins 
        // => leading zeros = 28
        // => shift_bits = (24 - (32 - 28 - 1)) = 21
        // ie, 
        // if we have the first 24 bits set (u8 << 16)
        // want to consider the first 3 bits of those 24
            // 0000 ... [100]0 0000 0000 0000 0000 0000
        // then we want to shift left by 21
            // 0000 ... 0000 0000 0000 0000 0000 0[100]
        // those 3 bits can represent 2^3 (= 8) bins
        const shift_bits = MAX_BITS - (32 - @clz(@as(u32, n_bins)) - 1);

        return PubkeyBinCalculator {
            .shift_bits = shift_bits,
        };
    }

    pub fn pubkeyToBin(self: *const PubkeyBinCalculator, pubkey: *const TmpPubkey) usize { 
        const data = &pubkey.data;
        return (
            @as(usize, data[0]) << 16 |
            @as(usize, data[1]) << 8 |
            @as(usize, data[2])
        ) >> self.shift_bits;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    const snapshot_path = "/home/brennan/solana-snapshot-finder";

    const accounts_dir_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_path, "accounts" },
    );
    const accounts_db_fields_path = try std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ snapshot_path, "accounts_db.bincode" },
    );

    var accounts_dir = try std.fs.openIterableDirAbsolute(accounts_dir_path, .{});
    var accounts_dir_iter = accounts_dir.iterate();

    // compute the total size (to compute time left)
    var total_append_vec_count: usize = 0;
    while (try accounts_dir_iter.next()) |_| {
        // compute the size
        total_append_vec_count += 1;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset

    // time it
    var timer = try std.time.Timer.start();

    // allocate all the filenames
    var total_name_size: usize = 0;
    while (try accounts_dir_iter.next()) |entry| {
        total_name_size += entry.name.len;
    }
    var filename_mem = try allocator.alloc(u8, total_name_size);
    defer allocator.free(filename_mem);
    accounts_dir_iter = accounts_dir.iterate(); // reset
    var index: usize = 0;

    // track the slices
    var filename_slices = try ArrayList([]u8).initCapacity(allocator, total_append_vec_count);
    defer filename_slices.deinit();

    while (try accounts_dir_iter.next()) |file_entry| {
        const file_name_len = file_entry.name.len;
        @memcpy(filename_mem[index..(index + file_name_len)], file_entry.name);
        filename_slices.appendAssumeCapacity(filename_mem[index..(index + file_name_len)]);
        index += file_name_len;
    }
    accounts_dir_iter = accounts_dir.iterate(); // reset
    const filename_elapsed = timer.read();
    std.debug.print("parsed filenames in {d}ms\n", .{filename_elapsed / std.time.ns_per_ms});
    std.debug.assert(filename_slices.items.len == total_append_vec_count);

    const accounts_db_fields_file = std.fs.openFileAbsolute(accounts_db_fields_path, .{}) catch |err| {
        std.debug.print("failed to open accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    var accounts_db_fields = try bincode.read(allocator, AccountsDbFields, accounts_db_fields_file.reader(), .{});
    defer bincode.free(allocator, accounts_db_fields);

    const accounts_hash_exp = accounts_db_fields.bank_hash_info.accounts_hash;
    std.debug.print("expected hash: {s}\n", .{accounts_hash_exp});

    // open all appendVec files into arraylist 
    // spawn threads each with a bucket range of pubkeys
    // THREAD_LOGIC (append_vecs, bin_range, *output): 
        // for each appendVec: 
            // for each pubkey:
                // calculate the bin
                // if (bin in bin_range and lamports > 0): 
                        // if pubkey hasnt been appended yet: 
                            // output.append .{ pubkey, slot, hash }
                        // else // there exists a slotA and slotB
                            // index = @max(slotA, slotB)
                            // output.append .{ pubkey, slots[index], hashes[index] }
        // sort(list by pubkey)
        // return
    
    // join all threads 
        // result = &[&[.{ pubkey, slot, hash}]]
    
    // compute merkle tree over the slices 
    // print the final hash 
}
