const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;

const BankFields = sig.core.BankFields;
const Slot = sig.core.Slot;

const AccountFileInfo = sig.accounts_db.snapshot.data.AccountFileInfo;
const AccountsDbFields = sig.accounts_db.snapshot.data.AccountsDbFields;
const ExtraFields = sig.accounts_db.snapshot.data.ExtraFields;
const FileId = sig.accounts_db.accounts_file.FileId;
const SnapshotManifest = sig.accounts_db.snapshot.Manifest;

const MAX_FUZZ_TIME_NS = std.time.ns_per_s * 100_000;

pub fn run() !void {
    const seed = std.crypto.random.int(u64);

    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    {
        // open and append seed
        const SEED_FILE_PATH = sig.TEST_DATA_DIR ++ "fuzz_snapshot_seeds.txt";
        const seed_file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{ .truncate = false });
        defer seed_file.close();

        try seed_file.writer().print("{}\n", .{seed});
    }
    std.debug.print("seed: {}\n", .{seed});

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();

    var bytes_buffer = std.array_list.Managed(u8).init(allocator);
    defer bytes_buffer.deinit();

    var i: u64 = 0;

    var timer = try std.time.Timer.start();
    while (timer.read() < MAX_FUZZ_TIME_NS) : (i += 1) {
        bytes_buffer.clearRetainingCapacity();

        const manifest_original: SnapshotManifest = try randomSnapshotManifest(allocator, random);
        defer manifest_original.deinit(allocator);

        try bytes_buffer.ensureUnusedCapacity(bincode.sizeOf(manifest_original, .{}) * 2);

        const original_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), manifest_original, .{});
        const original_bytes_end = bytes_buffer.items.len;

        const snapshot_deserialized = try bincode.readFromSlice(
            allocator,
            SnapshotManifest,
            bytes_buffer.items[original_bytes_start..original_bytes_end],
            .{},
        );
        defer snapshot_deserialized.deinit(allocator);

        const serialized_bytes_start = bytes_buffer.items.len;
        try bincode.write(bytes_buffer.writer(), snapshot_deserialized, .{});
        const serialized_bytes_end = bytes_buffer.items.len;

        const original_bytes = bytes_buffer.items[original_bytes_start..original_bytes_end];
        const serialized_bytes = bytes_buffer.items[serialized_bytes_start..serialized_bytes_end];
        try std.testing.expectEqualSlices(u8, original_bytes, serialized_bytes);
        std.debug.print("Verified {d} snapshots\n", .{i});
    }
}

const max_list_entries = 1 << 8;

fn randomSnapshotManifest(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    random: std.Random,
) !SnapshotManifest {
    const bank_fields = try BankFields.initRandom(allocator, random, max_list_entries);
    errdefer bank_fields.deinit(allocator);

    const accounts_db_fields = try randomAccountsDbFields(allocator, random, .{});
    errdefer accounts_db_fields.deinit(allocator);

    const bank_extra = try ExtraFields.initRandom(allocator, random, max_list_entries);
    errdefer bank_extra.deinit(allocator);

    return .{
        .bank_fields = bank_fields,
        .accounts_db_fields = accounts_db_fields,
        .bank_extra = bank_extra,
    };
}

const AccountsDbFieldsRandomConfig = struct {
    slot: struct { min: Slot, max: Slot } = .{
        .min = 0,
        .max = std.math.maxInt(Slot),
    },

    file_id: struct { min: FileId, max: FileId } = .{
        .min = FileId.fromInt(0),
        .max = FileId.fromInt(std.math.maxInt(FileId.Int)),
    },

    file_map_len: struct { min: usize, max: usize } = .{
        .min = 1,
        .max = 4096 * 8,
    },

    file_len: struct { min: usize, max: usize } = .{
        .min = 0,
        .max = 4096 * 4,
    },

    stored_meta_write_version_max: u64 = 0,
};

fn randomAccountsDbFields(
    allocator: std.mem.Allocator,
    /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
    /// for commentary on the runtime of this function.
    random: std.Random,
    params: AccountsDbFieldsRandomConfig,
) std.mem.Allocator.Error!AccountsDbFields {
    std.debug.assert(params.file_map_len.min >= 1);

    const FileIdAdapter = struct {
        file_map: *const AccountsDbFields.FileMap,

        pub fn hash(_: @This(), key: FileId) u32 {
            return key.toInt();
        }

        pub fn eql(ctx: @This(), a: FileId, _: void, b_index: usize) bool {
            const b = ctx.file_map.values()[b_index].id;
            return a == b;
        }
    };

    var total_data_len: u64 = 0;
    var max_slot: Slot = 0;

    const file_map_len = random.intRangeAtMost(
        usize,
        params.file_map_len.min,
        params.file_map_len.max,
    );

    var file_map: AccountsDbFields.FileMap = .{};
    errdefer file_map.deinit(allocator);
    try file_map.ensureTotalCapacity(allocator, file_map_len);

    var file_id_set = std.AutoArrayHashMap(void, void).init(allocator);
    defer file_id_set.deinit();
    try file_id_set.ensureTotalCapacity(file_map_len);

    for (0..file_map_len) |_| while (true) {
        const new_slot = random.intRangeAtMost(Slot, params.slot.min, params.slot.max);
        const slot_gop = file_map.getOrPutAssumeCapacity(new_slot);
        if (slot_gop.found_existing) continue;

        const new_id: FileId = while (true) {
            const new_id = FileId.fromInt(random.intRangeAtMost(
                FileId.Int,
                params.file_id.min.toInt(),
                params.file_id.max.toInt(),
            ));
            const id_gop = file_id_set.getOrPutAssumeCapacityAdapted(new_id, FileIdAdapter{
                .file_map = &file_map,
            });
            if (id_gop.found_existing) continue;
            break new_id;
        };

        const account_file_info: AccountFileInfo = .{
            .id = new_id,
            .length = random.intRangeAtMost(
                usize,
                params.file_len.min,
                @min(std.math.maxInt(u64) - total_data_len, params.file_len.max),
            ),
        };
        slot_gop.value_ptr.* = account_file_info;
        max_slot = @max(max_slot, new_slot);
        total_data_len += account_file_info.length;
        break;
    };

    return .{
        .file_map = file_map,
        .stored_meta_write_version = random.uintAtMost(u64, params.stored_meta_write_version_max),
        .slot = max_slot,
        .bank_hash_info = .{
            .stats = .{
                .num_updated_accounts = random.intRangeAtMost(
                    u64,
                    params.file_map_len.min,
                    params.file_map_len.max,
                ),
                .num_removed_accounts = random.intRangeAtMost(
                    u64,
                    params.file_map_len.min,
                    params.file_map_len.max,
                ),
                .num_lamports_stored = random.int(u64),
                .total_data_len = total_data_len,
                .num_executable_accounts = random.intRangeAtMost(
                    u64,
                    params.file_map_len.min,
                    params.file_map_len.max,
                ),
            },
        },
        // NOTE: see field comment about these always being empty
        .rooted_slots = &.{},
        .rooted_slot_hashes = &.{},
    };
}
