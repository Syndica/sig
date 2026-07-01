const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;

fn readBool(r: anytype) !bool {
    return switch (try r.takeByte()) {
        0 => false,
        1 => true,
        else => return error.InvalidBool,
    };
}

/// Incremental iterative parser for the encoded StatusCache datastructure.
pub const StatusCacheHeader = struct {
    slot_deltas: SlotDeltas,

    pub fn init(
        /// `std.Io.Reader` or equivalent interface.
        r: anytype,
    ) !StatusCacheHeader {
        return .{
            .slot_deltas = .{ .len = try r.takeInt(u64, .little) },
        };
    }

    pub const SlotDeltas = struct {
        len: u64,

        pub fn iterator(self: SlotDeltas) SlotDeltaIterator {
            return .{ .slot_deltas_remaining = self.len };
        }
    };

    pub const SlotDeltaIterator = struct {
        slot_deltas_remaining: u64,

        pub const empty: SlotDeltaIterator = .{ .slot_deltas_remaining = 0 };

        pub fn next(
            self: *SlotDeltaIterator,
            /// `std.Io.Reader` or equivalent interface.
            r: anytype,
        ) !?SlotDeltaHeader {
            if (self.slot_deltas_remaining == 0) return null;
            self.slot_deltas_remaining -= 1;

            return .{
                .slot = try r.takeInt(Slot, .little),
                .is_root = try readBool(r),
                .status_map = .{ .len = try r.takeInt(u64, .little) },
            };
        }
    };

    pub const SlotDeltaHeader = struct {
        slot: Slot,
        is_root: bool,
        status_map: StatusMapHeader,

        pub const StatusMapHeader = struct {
            len: u64,

            pub fn iterator(self: StatusMapHeader) StatusMapEntryIterator {
                return .{ .status_map_entries_remaining = self.len };
            }
        };
    };

    pub const StatusMapEntryIterator = struct {
        status_map_entries_remaining: u64,

        pub const empty: StatusMapEntryIterator = .{ .status_map_entries_remaining = 0 };

        pub fn next(
            self: *StatusMapEntryIterator,
            /// `std.Io.Reader` or equivalent interface.
            r: anytype,
        ) !?StatusMapEntryHeader {
            if (self.status_map_entries_remaining == 0) return null;
            self.status_map_entries_remaining -= 1;

            var hash: lib.solana.Hash = .{ .data = undefined };
            try r.readSliceAll(&hash.data);
            return .{
                .hash = hash,
                .key_index = try r.takeInt(u64, .little),
                .status_list = .{ .len = try r.takeInt(u64, .little) },
            };
        }
    };

    pub const StatusMapEntryHeader = struct {
        hash: lib.solana.Hash,
        key_index: u64,
        status_list: StatusList,

        pub const StatusList = struct {
            len: u64,

            pub fn iterator(self: StatusList) StatusIterator {
                return .{ .status_entries_remaining = self.len };
            }
        };
    };

    pub const StatusIterator = struct {
        status_entries_remaining: u64,

        pub const empty: StatusIterator = .{ .status_entries_remaining = 0 };

        pub fn next(
            self: *StatusIterator,
            /// `std.Io.Reader` or equivalent interface.
            r: anytype,
        ) !?Status {
            if (self.status_entries_remaining == 0) return null;
            self.status_entries_remaining -= 1;

            var key_slice: [20]u8 = undefined;
            try r.readSliceAll(&key_slice);

            const ResultTag = @typeInfo(Status.Result).@"union".tag_type.?;
            const result_tag = try r.takeEnum(ResultTag, .little);

            return .{
                .key_slice = key_slice,
                .result = switch (result_tag) {
                    .ok => .ok,
                    .err => .{ .err = try .read(r) },
                },
            };
        }
    };

    pub const Status = struct {
        key_slice: [20]u8,
        result: Result,

        pub const Result = union(enum(u32)) {
            ok,
            err: lib.solana.transaction.Error,
        };
    };

    /// Skip the entire status cache.
    pub fn skip(
        /// `std.Io.Reader` or equivalent interface.
        r: anytype,
    ) !void {
        const status_cache: StatusCacheHeader = try .init(r);
        var sd_iter = status_cache.slot_deltas.iterator();

        for (0..status_cache.slot_deltas.len) |_| {
            const slot_delta = try sd_iter.next(r) orelse unreachable;

            var sme_iter = slot_delta.status_map.iterator();
            for (0..slot_delta.status_map.len) |_| {
                const status_map_entry = try sme_iter.next(r) orelse unreachable;

                var st_iter = status_map_entry.status_list.iterator();
                for (0..status_map_entry.status_list.len) |_| {
                    const status = try st_iter.next(r) orelse unreachable;
                    _ = status;
                }
            }
        }
    }
};

test StatusCacheHeader {
    const gpa = std.testing.allocator;

    const SlotDelta = struct {
        slot: Slot,
        is_root: bool,
        status_map: []const StatusMapEntry,

        const StatusMapEntry = struct { lib.solana.Hash, Status };

        const Status = struct {
            key_index: u64,
            entries: []const Entry,

            const Entry = struct { [20]u8, StatusCacheHeader.Status.Result };
        };
    };

    const status0: SlotDelta.Status = .{
        .key_index = 11,
        .entries = &.{
            .{ "e`]\xb9\x8a\xb28\x9a\xa8\x00C\xd3\x1e\x9ac\xfd\x0f\xa0@\xa5".*, .ok },
            .{ "\xf5\x1cc ,l\x8d\x8d\xec\x9cG\x1e\xc4\xe1u\xa6\n\xf9\xe1|".*, .ok },
            .{ "\xda\xaa\xf42\xbb\x13\xc6\xe1I\xb3\xad5\xc9\xec\xd4\xfe\x00\x8c\x00\x00".*, .ok },
            .{ "\xe3t\x06\xc7J\"\xa0\xa0\x1cb\xc2\xb9RH\xdb\xba3L\xb1\xf0".*, .ok },
            .{ "}\xde\x90$\xc7\x8dU\xf1\x89T^_:\xe6\xa1\x1c{5\xc9\r".*, .ok },
            .{ "\xbc\xd2f\xd6s \xe9\x9a~\x1f\x18\xcf\xc6\x0cP\xbah5\xb9\xf9".*, .ok },
        },
    };
    const status1: SlotDelta.Status = .{
        .key_index = 4,
        .entries = &.{
            .{ "a\xa3o\x8f\xbdTr\xd1\xed\x07o\xb9\xc7\xcf\xba\xdd\x0b4QN".*, .ok },
            .{ "r\xb0\x90\xe3\xf2\xb1\x8f\xd1v7\xca{,/NQ\xf0y\xc9\xfc".*, .ok },
            .{ "~D\xd2&\xfeob.\xe4\xd9\xfc#\x98\x9d\xf6t\x0e\xe0\xe0\xd9".*, .ok },
            .{ "Ry1\xd2d\x88\x05_e\xbc\xdd_G\xe9\xb9xvmN\\".*, .ok },
            .{ "\xb7\x8e=3{s\xce^\x11\x88ia\xfc+\xcf\xd2E\xba\xeb\xed".*, .ok },
            .{ "\x11\x0c]%^s\xf7\xee\xd0\x9f\xbc\x96\x88\x05\xf0x\xa9\xf8D\x89".*, .ok },
        },
    };
    const status_cache_decoded: []const SlotDelta = &.{
        .{
            .slot = 0,
            .is_root = true,
            .status_map = &.{.{ .parse("8e8HsAXGpV5fNBf1c3AancsRjt1F7GKFZGziNMhiQoBR"), status0 }},
        },
        .{
            .slot = 1,
            .is_root = true,
            .status_map = &.{.{ .parse("5Jq6NhSQCWgh9GhMZJ3aJJhdZdALBoX2NWjqDUrh8VK5"), status1 }},
        },
    };
    const status_cache_encoded: []const u8 = &.{
        2,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   1,   1,
        0,   0,   0,   0,   0,   0,   0,   113, 132, 138, 200, 177, 106, 168, 112, 72,  173, 246,
        66,  23,  17,  65,  65,  110, 153, 85,  57,  104, 143, 113, 255, 188, 234, 8,   179, 227,
        217, 89,  124, 11,  0,   0,   0,   0,   0,   0,   0,   6,   0,   0,   0,   0,   0,   0,
        0,   101, 96,  93,  185, 138, 178, 56,  154, 168, 0,   67,  211, 30,  154, 99,  253, 15,
        160, 64,  165, 0,   0,   0,   0,   245, 28,  99,  32,  44,  108, 141, 141, 236, 156, 71,
        30,  196, 225, 117, 166, 10,  249, 225, 124, 0,   0,   0,   0,   218, 170, 244, 50,  187,
        19,  198, 225, 73,  179, 173, 53,  201, 236, 212, 254, 0,   140, 0,   0,   0,   0,   0,
        0,   227, 116, 6,   199, 74,  34,  160, 160, 28,  98,  194, 185, 82,  72,  219, 186, 51,
        76,  177, 240, 0,   0,   0,   0,   125, 222, 144, 36,  199, 141, 85,  241, 137, 84,  94,
        95,  58,  230, 161, 28,  123, 53,  201, 13,  0,   0,   0,   0,   188, 210, 102, 214, 115,
        32,  233, 154, 126, 31,  24,  207, 198, 12,  80,  186, 104, 53,  185, 249, 0,   0,   0,
        0,   1,   0,   0,   0,   0,   0,   0,   0,   1,   1,   0,   0,   0,   0,   0,   0,   0,
        64,  0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   4,   0,   0,   0,
        0,   0,   0,   0,   6,   0,   0,   0,   0,   0,   0,   0,   97,  163, 111, 143, 189, 84,
        114, 209, 237, 7,   111, 185, 199, 207, 186, 221, 11,  52,  81,  78,  0,   0,   0,   0,
        114, 176, 144, 227, 242, 177, 143, 209, 118, 55,  202, 123, 44,  47,  78,  81,  240, 121,
        201, 252, 0,   0,   0,   0,   126, 68,  210, 38,  254, 111, 98,  46,  228, 217, 252, 35,
        152, 157, 246, 116, 14,  224, 224, 217, 0,   0,   0,   0,   82,  121, 49,  210, 100, 136,
        5,   95,  101, 188, 221, 95,  71,  233, 185, 120, 118, 109, 78,  92,  0,   0,   0,   0,
        183, 142, 61,  51,  123, 115, 206, 94,  17,  136, 105, 97,  252, 43,  207, 210, 69,  186,
        235, 237, 0,   0,   0,   0,   17,  12,  93,  37,  94,  115, 247, 238, 208, 159, 188, 150,
        136, 5,   240, 120, 169, 248, 68,  137, 0,   0,   0,   0,
    };

    var fbr: std.Io.Reader = .fixed(status_cache_encoded);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const status_cache: StatusCacheHeader = try .init(&fbr);

    var actual_slot_deltas: std.ArrayList(SlotDelta) = .empty;
    defer actual_slot_deltas.deinit(gpa);
    try actual_slot_deltas.ensureUnusedCapacity(gpa, status_cache.slot_deltas.len);

    var sc_iter = status_cache.slot_deltas.iterator();
    while (try sc_iter.next(&fbr)) |slot_delta| {
        var status_map_al: std.ArrayList(SlotDelta.StatusMapEntry) = .empty;
        try status_map_al.ensureUnusedCapacity(arena, slot_delta.status_map.len);

        var sme_iter = slot_delta.status_map.iterator();
        while (try sme_iter.next(&fbr)) |status_map_entry| {
            var status_entries: std.ArrayList(SlotDelta.Status.Entry) = .empty;
            try status_entries.ensureUnusedCapacity(arena, status_map_entry.status_list.len);

            var st_iter = status_map_entry.status_list.iterator();
            while (try st_iter.next(&fbr)) |status| {
                status_entries.appendAssumeCapacity(.{ status.key_slice, status.result });
            }

            status_map_al.appendAssumeCapacity(.{
                status_map_entry.hash,
                .{
                    .key_index = status_map_entry.key_index,
                    .entries = status_entries.items,
                },
            });
        }

        actual_slot_deltas.appendAssumeCapacity(.{
            .slot = slot_delta.slot,
            .is_root = slot_delta.is_root,
            .status_map = status_map_al.items,
        });
    }

    try std.testing.expectEqualDeep(
        status_cache_decoded,
        actual_slot_deltas.items,
    );

    var actual_encoded: std.Io.Writer.Allocating = .init(gpa);
    defer actual_encoded.deinit();
    const actual_encoded_w = &actual_encoded.writer;

    try actual_encoded.writer.writeInt(u64, actual_slot_deltas.items.len, .little);
    for (actual_slot_deltas.items) |slot_delta| {
        try actual_encoded_w.writeInt(Slot, slot_delta.slot, .little);
        try actual_encoded_w.writeByte(@intFromBool(slot_delta.is_root));

        try actual_encoded_w.writeInt(u64, slot_delta.status_map.len, .little);
        for (slot_delta.status_map) |status_kv| {
            const hash, const status = status_kv;
            try actual_encoded_w.writeAll(&hash.data);
            try actual_encoded_w.writeInt(u64, status.key_index, .little);

            try actual_encoded_w.writeInt(u64, status.entries.len, .little);
            for (status.entries) |status_entry| {
                const key_slice, const result = status_entry;
                try actual_encoded_w.writeAll(&key_slice);
                try lib.solana.bincode.write(actual_encoded_w, result);
            }
        }
    }

    try std.testing.expectEqualSlices(u8, status_cache_encoded, actual_encoded.written());
}

pub const Manifest = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    extra_fields: ExtraFields,

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !Manifest {
        const zone = tracy.Zone.init(@src(), .{ .name = "Manifest.read" });
        defer zone.deinit();

        return .{
            .bank_fields = try .read(fba, r),
            .accounts_db_fields = try .read(fba, r),
            .extra_fields = try .read(fba, r),
        };
    }
};

pub const BankFields = struct {
    slot: Slot,

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !BankFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "BankFields.read" });
        defer zone.deinit();

        _ = fba;

        // blockhash_queue.last_hash_index: u64
        try r.discardAll(8);
        // blockhash_queue.last_hash: ?Hash
        if (try readBool(r)) try r.discardAll(32);
        // blockhash_queue.hash_infos: HashMap(Hash, { lamports_per_signature: u64, hash_index: u64, timestamp: u64 })
        const hash_infos_len = try r.takeInt(u64, .little);
        try r.discardAll(hash_infos_len * (32 + // key: Hash
            8 + // lamports_per_signature: u64
            8 + // hash_index: u64
            8 // timestamp: u64
        ));
        // blockhash_queue.max_age: u64
        try r.discardAll(8);

        // _unused_ancestors: HashMap(Slot, u64)
        const ancestors_len = try r.takeInt(u64, .little);
        try r.discardAll(ancestors_len * (8 + // key: Slot
            8 // value: u64
        ));

        // hash(Hash) + parent_hash(Hash) + parent_slot(Slot)
        try r.discardAll(32 + 32 + 8);

        // hard_forks: Vec({ slot: Slot, count: u64 })
        const hard_forks_len = try r.takeInt(u64, .little);
        try r.discardAll(hard_forks_len * (8 + // slot: Slot
            8 // count: u64
        ));

        try r.discardAll(
            8 + // transaction_count: u64
                8 + // tick_height: u64
                8 + // signature_count: u64
                8 + // capitalization: u64
                8, // max_tick_height: u64
        );

        // hashes_per_tick: ?u64
        if (try readBool(r)) try r.discardAll(8);

        try r.discardAll(8 + // ticks_per_slot: u64
            16 + // ns_per_slot: u128
            8 + // genesis_creation_time: i64
            8 + // slots_per_year: f64
            8 // accounts_data_len: u64
        );
        const slot = try r.takeInt(Slot, .little);
        try r.discardAll(
            8 + // _unused_epoch: Epoch
                8 + // block_height: u64
                32 + // leader_id: Pubkey
                8 + // _unused_collector_fees: u64
                8 + // _unused_fee_calculator: u64
                // fee_rate_governor:
                8 + //   target_lamports_per_signature: u64
                8 + //   target_signatures_per_slot: u64
                8 + //   min_lamports_per_signature: u64
                8 + //   max_lamports_per_signature: u64
                1 + //   burn_percent: u8
                8 + // _unused_collected_rent: u64
                // _unused_rent_collector:
                8 + //   epoch: Epoch
                //   epoch_schedule: EpochSchedule:
                8 + //     slots_per_epoch: u64
                8 + //     leader_schedule_slot_offset: u64
                1 + //     warmup: bool
                8 + //     first_normal_epoch: u64
                8 + //     first_normal_slot: u64
                8 + //   slots_per_year: f64
                //   rent:
                8 + //     lamports_per_byte: u64
                8 + //     exemption_threshold: [8]u8
                1 + //     burn_percent: u8
                // epoch_schedule: EpochSchedule:
                8 + //   slots_per_epoch: u64
                8 + //   leader_schedule_slot_offset: u64
                1 + //   warmup: bool
                8 + //   first_normal_epoch: u64
                8 + //   first_normal_slot: u64
                // inflation:
                8 + //   initial: f64
                8 + //   terminal: f64
                8 + //   taper: f64
                8 + //   foundation: f64
                8 + //   foundation_term: f64
                8, //   __unused: f64
        );

        // stakes: Stakes(Delegation)
        //   vote_accounts: VoteAccounts
        try discardVoteAccounts(r);

        //   stake_delegations: HashMap(Pubkey, Delegation)
        const stake_del_len = try r.takeInt(u64, .little);
        try r.discardAll(stake_del_len * (32 + // key: Pubkey
            // Delegation:
            32 + //   voter_pubkey: Pubkey
            8 + //   stake: u64
            8 + //   activation_epoch: Epoch
            8 + //   deactivation_epoch: Epoch
            8 //   warmup_cooldown_rate: f64
        ));

        try r.discardAll(
            8 + // stakes.unused: u64
                8, // stakes.epoch: Epoch
        );

        //   stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
        const stake_history_len = try r.takeInt(u64, .little);
        try r.discardAll(stake_history_len * (8 + // epoch: Epoch
            8 + // effective: u64
            8 + // activating: u64
            8 // deactivating: u64
        ));

        // _unused_accounts.unused1: HashSet(Pubkey)
        const unused1_len = try r.takeInt(u64, .little);
        try r.discardAll(unused1_len * 32);
        // _unused_accounts.unused2: HashSet(Pubkey)
        const unused2_len = try r.takeInt(u64, .little);
        try r.discardAll(unused2_len * 32);
        // _unused_accounts.unused3: HashMap(Pubkey, u64)
        const unused3_len = try r.takeInt(u64, .little);
        try r.discardAll(unused3_len * (32 + 8));

        // _unused_epoch_stakes: HashSet(Epoch)
        const epoch_stakes_len = try r.takeInt(u64, .little);
        try r.discardAll(epoch_stakes_len * 8);

        // is_delta: bool
        try r.discardAll(1);

        return .{
            .slot = slot,
        };
    }
};

pub const AccountsDbFields = struct {
    slot: u64,
    account_file_map: AccountFileMap,

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !AccountsDbFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountsDbFields.read" });
        defer zone.deinit();

        // account_file_map: HashMap(Slot, Vec(StorageEntry))
        // serialized as u64 len + n * { slot: u64, small_vec_size: u64, id: u64, length: u64 }
        const account_file_map = try AccountFileMap.read(fba, r);

        try r.discardAll(8); // _unused_write_version: u64
        const slot = try r.takeInt(u64, .little);

        try r.discardAll(
            // bank_hash_info:
            32 + //   _unused_accounts_delta_hash: Hash
                32 + //   _unused_accounts_hash: Hash
                //   stats: BankHashStats:
                8 + //     num_updated_accounts: u64
                8 + //     num_removed_accounts: u64
                8 + //     num_lamports_stored: u64
                8 + //     total_data_len: u64
                8, //     num_executable_accounts: u64
        );

        // rooted_slots: NullOnEof(Vec(Slot))
        {
            const len = r.takeInt(u64, .little) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };
            try r.discardAll(len * 8); // Slot: u64
        }

        // rooted_slot_hashes: NullOnEof(Vec(SlotAndHash))
        {
            const len = r.takeInt(u64, .little) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };
            try r.discardAll(len * (8 + // slot: Slot
                32 // hash: Hash
            ));
        }

        return .{
            .account_file_map = account_file_map,
            .slot = slot,
        };
    }

    /// Deserialize into custom HashMap that uses minimal memory with fast lookups.
    /// Fast lookups is beneficial as its used to figure out account file lengths in SnapshotReader.
    pub const AccountFileMap = struct {
        entries: []Entry,
        count: usize,

        const HASH_MULT = 0x9E3779B97F4A7C15;
        const Entry = packed struct(u128) {
            id: u64,
            length: u34, // 16GB max
            slot: u30, // another 8yrs of 400ms slots after current mainnet
            const empty: Entry = .{ .id = 0, .length = 0, .slot = 0 };
        };

        pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !AccountFileMap {
            const zone = tracy.Zone.init(@src(), .{ .name = "AccountFileMap.read" });
            defer zone.deinit();

            // Consumes the equivalent:
            //
            // const file_map_len = try readInt(u64, r);
            // try r.discardAll(file_map_len * (8 + // slot: Slot(u64)
            //     8 + // small_vec_size: u64
            //     8 + // id: u64
            //     8 // length: u64
            // ));

            const n = std.math.cast(u32, try r.takeInt(u64, .little)) orelse return error.Overflow;
            const cap = try std.math.ceilPowerOfTwo(u32, (n * 100) / 75); // .75 load factor
            const entries = try fba.allocator().alloc(Entry, cap);
            @memset(entries, .empty);

            var bc_entry: extern struct {
                slot: u64,
                small_vec_len: u64,
                id: u64,
                length: u64,
            } = undefined;
            for (0..n) |_| {
                try r.readSliceAll(std.mem.asBytes(&bc_entry));
                if (bc_entry.small_vec_len != 1) return error.InvalidBincodeEntry;

                var idx = (bc_entry.slot *% HASH_MULT) >> @intCast(@as(u7, 64) - @ctz(entries.len));
                const e = while (true) {
                    const e = &entries[idx];
                    idx = (idx +% 1) & (entries.len - 1);
                    if (@as(u128, @bitCast(e.*)) == @as(u128, @bitCast(Entry.empty))) break e;
                };
                e.* = .{
                    .id = bc_entry.id,
                    .length = std.math.cast(u34, bc_entry.length) orelse return error.Overflow,
                    .slot = std.math.cast(u30, bc_entry.slot) orelse return error.Overflow,
                };
            }

            return .{ .entries = entries, .count = n };
        }

        pub fn getPtr(self: *const AccountFileMap, slot: u64) ?*Entry {
            const entries = self.entries;
            var idx = (slot *% HASH_MULT) >> @intCast(@as(u7, 64) - @ctz(entries.len));
            while (true) {
                const e = &entries[idx];
                idx = (idx +% 1) & (entries.len - 1);
                if (e.slot == slot) return e;
                if (@as(u128, @bitCast(e.*)) == @as(u128, @bitCast(Entry.empty))) return null;
            }
        }
    };
};

pub const ExtraFields = struct {
    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !ExtraFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "ExtraFields.read" });
        defer zone.deinit();

        _ = fba;

        // lamports_per_signature: NullOnEof(u64)
        r.discardAll(8) catch |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        };

        // _unused_incremental_snapshot_persistence: NullOnEof(?{ full: SlotAndHash, full_capitalization: u64, incremental_hash: Hash, incremental_capitalization: u64 })
        {
            const is_some = readBool(r) catch |err| switch (err) {
                error.EndOfStream => false,
                else => |e| return e,
            };
            if (is_some) try r.discardAll(
                8 + // full.slot: Slot
                    32 + // full.hash: Hash
                    8 + // full_capitalization: u64
                    32 + // incremental_hash: Hash
                    8, // incremental_capitalization: u64
            );
        }

        // _unused_epoch_accounts_hash: NullOnEof(?Hash)
        {
            const is_some = readBool(r) catch |err| switch (err) {
                error.EndOfStream => false,
                else => |e| return e,
            };
            if (is_some) try r.discardAll(32);
        }

        // versioned_epoch_stakes: NullOnEof(Vec({ epoch: u64, value: union(enum(u32)) { current: ... } }))
        {
            const outer_len = r.takeInt(u64, .little) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };
            for (0..outer_len) |_| {
                try r.discardAll(
                    8 + // epoch: u64
                        4, // union tag: u32 (enum(u32), always 'current')
                );

                // current.epoch_stakes: Stakes(StakeDelegationWithStake)
                //   vote_accounts: VoteAccounts
                try discardVoteAccounts(r);

                //   stake_delegations: HashMap(Pubkey, { delegation: Delegation, credits_observed: u64 })
                const stake_del_len = try r.takeInt(u64, .little);
                try r.discardAll(stake_del_len * (32 + // key: Pubkey
                    32 + // delegation.voter_pubkey: Pubkey
                    8 + // delegation.stake: u64
                    8 + // delegation.activation_epoch: Epoch
                    8 + // delegation.deactivation_epoch: Epoch
                    8 + // delegation.warmup_cooldown_rate: f64
                    8 // credits_observed: u64
                ));

                try r.discardAll(
                    8 + // stakes.unused: u64
                        8, // stakes.epoch: Epoch
                );

                //   stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
                const sh_len = try r.takeInt(u64, .little);
                try r.discardAll(sh_len * (8 + 8 + 8 + 8));

                // current.total_stake: u64
                try r.discardAll(8);

                // current.node_id_to_vote_accounts: HashMap(Pubkey, { vote_accounts: Vec(Pubkey), total_stake: u64 })
                const nv_len = try r.takeInt(u64, .little);
                for (0..nv_len) |_| {
                    // key: Pubkey
                    try r.discardAll(32);
                    // value.vote_accounts: Vec(Pubkey)
                    const va_len = try r.takeInt(u64, .little);
                    try r.discardAll(
                        va_len * 32 + // vote_accounts: []Pubkey
                            8, // total_stake: u64
                    );
                }

                // current.epoch_authorized_voters: HashMap(Pubkey, Pubkey)
                const eav_len = try r.takeInt(u64, .little);
                try r.discardAll(eav_len * (32 + // key: Pubkey
                    32 // value: Pubkey
                ));
            }
        }

        // accounts_lt_hash: NullOnEof(?LtHash)
        {
            const is_some = readBool(r) catch |err| switch (err) {
                error.EndOfStream => false,
                else => |e| return e,
            };
            if (is_some) try r.discardAll(2048); // LtHash = [1024]u16
        }

        // block_id: NullOnEof(Hash)
        r.discardAll(32) catch |err| switch (err) {
            error.EndOfStream => {},
            else => |e| return e,
        };

        return .{};
    }
};

/// Discards VoteAccounts: HashMap(Pubkey, { stake: u64, account: AccountSharedData })
/// AccountSharedData contains a variable-length Vec(u8) data field, so we must loop.
fn discardVoteAccounts(r: anytype) !void {
    const len = try r.takeInt(u64, .little);
    for (0..len) |_| {
        try r.discardAll(
            32 + // key: Pubkey
                8 + // value.stake: u64
                8, // value.account.lamports: u64
        );
        // value.account.data: Vec(u8)
        const data_len = try r.takeInt(u64, .little);
        try r.discardAll(
            data_len + // account data bytes
                32 + // value.account.owner: Pubkey
                1 + // value.account.executable: bool
                8, // value.account.rent_epoch: Epoch(u64)
        );
    }
}

pub fn SnapshotIter(comptime BufReader: type) type {
    return struct {
        // public fields instantiated using the fba from init()
        manifest: ?Manifest,

        tar_iter: TarZstIter(BufReader),
        account_file_len: usize,
        account_file_slot: Slot,
        account_data_len: usize,
        account_data_padding: usize,
        state: enum { version, metadata, accounts },
        const Self = @This();

        pub fn init(buf_reader: BufReader) Self {
            return .{
                .manifest = null,
                .tar_iter = .{ .buf_reader = buf_reader },
                .account_file_len = 0,
                .account_file_slot = 0,
                .account_data_len = 0,
                .account_data_padding = 0,
                .state = .version,
            };
        }

        pub fn checkVersion(self: *Self) !void {
            switch (self.state) {
                .version => {},
                else => unreachable,
            }
            self.state = .metadata;

            // read /version
            const tar_file = (try self.tar_iter.next()) orelse return error.MissingVersionFile;
            if (!std.mem.eql(u8, tar_file.name, "version")) return error.MissingVersionFile;
            const expected = "1.2.0";
            var version: [expected.len]u8 = undefined;
            try self.tar_iter.reader.readSliceAll(&version);
            if (!std.mem.eql(u8, &version, expected)) return error.InvalidVersion;
        }

        pub fn readMetadata(
            self: *Self,
            fba: *std.heap.FixedBufferAllocator,
        ) !void {
            switch (self.state) {
                .metadata => {},
                else => unreachable,
            }
            self.state = .accounts;

            // read /snapshots/status_cache & /snapshots/{slot}/{slot} (can be in any order)
            const tar_file = (try self.tar_iter.next()) orelse return error.MissingMetadata;
            if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
                try StatusCacheHeader.skip(&self.tar_iter.reader);
                _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                self.manifest = try Manifest.read(fba, &self.tar_iter.reader);
            } else {
                self.manifest = try Manifest.read(fba, &self.tar_iter.reader);
                _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                try StatusCacheHeader.skip(&self.tar_iter.reader);
            }
        }

        pub const Account = struct {
            slot: Slot,
            pubkey: Pubkey,
            owner: Pubkey,
            lamports: u64,
            rent_epoch: Epoch,
            data: packed struct(u32) { executable: bool, len: u31 },
        };

        pub fn next(self: *Self) !?Account {
            switch (self.state) {
                .accounts => {},
                else => unreachable,
            }

            // Skip unread data & data padding of previous Accountentry
            self.tar_iter.reader.discardAll(
                self.account_data_len + self.account_data_padding,
            ) catch {};

            // read /accounts/{slot}/{id} (containing Accounts in AppendVecs)
            while (self.account_file_len == 0) {
                @branchHint(.unlikely);

                const tar_file = (try self.tar_iter.next()) orelse return null;
                const split = std.mem.indexOfScalar(u8, tar_file.name, '.') orelse
                    return error.InvalidAccountFileName;
                if (split + 1 >= tar_file.name.len)
                    return error.InvalidAccountFileName;

                const slot = std.fmt.parseInt(u64, tar_file.name["accounts/".len..split], 10) catch
                    return error.InvalidAccountFileSlot;
                const id = std.fmt.parseInt(u32, tar_file.name[split + 1 ..], 10) catch
                    return error.InvalidAccountFileId;
                if (slot > self.manifest.?.accounts_db_fields.slot)
                    return error.InvalidAccountFileSlot;

                const info = self.manifest.?.accounts_db_fields.account_file_map.getPtr(slot) orelse
                    return error.InvalidAccountFileSlot;
                if (info.id != id)
                    return error.InvalidAccountFileId;
                if (info.length > tar_file.size)
                    return error.InvalidAccountFileLength;

                self.account_file_slot = slot;
                self.account_file_len = info.length;
            }

            var header: extern struct { // little-endian
                _unused_write_version: u64,
                data_len: u64,
                pubkey: lib.solana.Pubkey,
                lamports: u64,
                rent_epoch: lib.solana.Epoch,
                owner: lib.solana.Pubkey,
                executable: u8,
                _padding: [7]u8,
                hash: lib.solana.Hash,
            } = undefined;
            self.account_file_len -= @sizeOf(@TypeOf(header));
            self.tar_iter.reader.readSliceAll(std.mem.asBytes(&header)) catch
                return error.InvalidAccountHeader;

            // Header's hash is obsolete and always zero:
            // https://github.com/anza-xyz/agave/blob/v4.0/accounts-db/src/append_vec.rs#L1353-L1357
            if (!header.hash.eql(&lib.solana.Hash.ZEROES))
                return error.InvalidAccountHeader;
            if (header.executable > 1)
                return error.InvalidAccountHeader;
            if (header.data_len > 10 * 1024 * 1024)
                return error.InvalidAccountData;

            const data_padded_len = std.mem.alignForward(u64, header.data_len, 8);
            self.account_file_len -|= data_padded_len;
            self.account_data_padding = data_padded_len - header.data_len; // skip padding
            self.account_data_len = header.data_len; // track data read from account

            return .{
                .slot = self.account_file_slot,
                .pubkey = header.pubkey,
                .owner = header.owner,
                .lamports = header.lamports,
                .rent_epoch = header.rent_epoch,
                .data = .{ .executable = header.executable > 0, .len = @intCast(header.data_len) },
            };
        }

        pub fn readSliceAll(self: *Self, buf: []u8) !void {
            if (buf.len > self.account_data_len) return error.EndOfStream;
            self.account_data_len -= buf.len;
            try self.tar_iter.reader.readSliceAll(buf);
        }
    };
}

pub fn TarZstIter(comptime BufReader: type) type {
    lib.util.assertInterface(BufReader, struct {
        /// Get a slice of readable memory. Returns empty slice on EOF.
        pub fn getBuffer(self: BufReader) ?[]const u8 {
            _ = .{self};
            return undefined;
        }

        /// Mark n bytes (from a previous getBuffer() call) as consumed.
        pub fn advance(self: BufReader, n: usize) void {
            _ = .{ self, n };
            return undefined;
        }
    });

    return struct {
        buf_reader: BufReader,
        header: [512]u8 = undefined,
        file_size: usize = 0,
        file_padding: usize = 0,
        reader: ReaderMixin = .{},

        const Self = @This();

        pub const TarFile = struct {
            name: []const u8,
            size: usize,
        };

        pub fn next(self: *Self) !?TarFile {
            while (true) {
                // skip the previously returned TarFile's unread + padding data
                _ = self.read(null, self.file_padding + self.file_size);

                const n = self.read(&self.header, self.header.len);
                if (n == 0) return null;
                if (n < 512) return error.EndOfStream;

                const is_file = self.header[156] == '0' or self.header[156] == 0;
                const file_name = std.mem.sliceTo(self.header[0..100], 0);
                const file_size = blk: {
                    const buf = self.header[124..][0..12];
                    if (buf[0] == 0xff) return error.InvalidTar; // negative size
                    if (buf[0] == 0x80) {
                        if (std.mem.readInt(u32, buf[0..4], .little) != 0x80) {
                            return error.InvalidTar;
                        }
                        break :blk std.mem.readInt(u64, buf[4..12], .big);
                    }
                    const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, buf, "0 "), " \x00");
                    if (trimmed.len == 0) break :blk 0;
                    break :blk std.fmt.parseInt(u64, trimmed, 8) catch return error.InvalidTar;
                };

                self.file_size = file_size;
                self.file_padding = std.mem.alignForward(usize, file_size, 512) - file_size;
                if (file_size == 0 and file_name.len == 0) return null;
                if (is_file) return .{ .name = file_name, .size = file_size };
            }
        }

        /// Zero-sized std.Io.Reader-like mixin API for Manifest/StatusCache's `.read()`.
        /// Should never be copied out of the iterator, its address is used to reference the
        /// iterator.
        pub const ReaderMixin = struct {
            zst: void align(@alignOf(Self)) = {},

            pub fn readSliceAll(mixin: *ReaderMixin, buf: []u8) error{EndOfStream}!void {
                const iter: *Self = @fieldParentPtr("reader", mixin);
                if (iter.file_size < buf.len) return error.EndOfStream;
                iter.file_size -= buf.len;
                if (iter.read(buf.ptr, buf.len) != buf.len) return error.EndOfStream;
            }

            pub fn discardAll(mixin: *ReaderMixin, n: usize) error{EndOfStream}!void {
                const iter: *Self = @fieldParentPtr("reader", mixin);
                if (iter.file_size < n) return error.EndOfStream;
                iter.file_size -= n;
                if (iter.read(null, n) != n) return error.EndOfStream;
            }

            pub fn takeByte(mixin: *ReaderMixin) error{EndOfStream}!u8 {
                var byte: u8 = undefined;
                try mixin.readSliceAll((&byte)[0..1]);
                return byte;
            }

            pub fn takeInt(
                mixin: *ReaderMixin,
                comptime T: type,
                endian: std.builtin.Endian,
            ) error{EndOfStream}!T {
                const n = @divExact(@typeInfo(T).int.bits, 8);
                var buf: [n]u8 = undefined;
                try mixin.readSliceAll(&buf);
                return std.mem.readInt(T, &buf, endian);
            }

            pub fn takeEnum(
                mixin: *ReaderMixin,
                comptime E: type,
                endian: std.builtin.Endian,
            ) error{ EndOfStream, InvalidEnumTag }!E {
                const Int = @typeInfo(E).@"enum".tag_type;
                const int = try mixin.takeInt(Int, endian);
                return try std.meta.intToEnum(E, int);
            }
        };

        fn read(self: *Self, maybe_buf: ?[*]u8, len: usize) usize {
            var n: usize = 0;
            while (n < len) : (std.atomic.spinLoopHint()) {
                const buf: []const u8 = self.buf_reader.getBuffer() orelse continue;
                if (buf.len == 0) break;

                const take = @min(buf.len, len - n);
                if (maybe_buf) |b| @memcpy(b[n..][0..take], buf[0..take]);

                self.buf_reader.advance(take);
                n += take;
            }
            return n;
        }
    };
}

pub const ZstReader = struct {
    decompressor: Decompressor,
    file_reader: lib.fio.FileReader(.{
        .buffer_size = 64 * 1024 * 1024,
        .block_size = 1 * 1024 * 1024,
    }),

    // TODO: InBuffer/OutBuffer aren't public & cba to update the zstd fork being referenced.
    const Decompressor = @TypeOf(@as(@import("zstd").Reader, undefined).decompressor);
    const params = @typeInfo(@TypeOf(Decompressor.decompressStream)).@"fn".params;
    const InBuffer = @typeInfo(params[1].type.?).pointer.child;
    const OutBuffer = @typeInfo(params[2].type.?).pointer.child;

    pub fn init(self: *ZstReader, dir: std.fs.Dir, path: []const u8) !void {
        self.decompressor = try .init(.{});
        errdefer self.decompressor.deinit();

        const file = try lib.fio.openDirect(dir, path, .read_only);
        errdefer file.close();

        try self.file_reader.init(file);
        errdefer self.file_reader.deinit();
    }

    pub fn deinit(self: *const ZstReader) void {
        self.decompressor.deinit();
        self.file_reader.deinit();
        self.file_reader.file.close();
    }

    pub fn read(
        self: *ZstReader,
        logger: tel.Logger("ZstReader.read"),
        buffer: []u8,
    ) !usize {
        var n: usize = 0;
        while (n < buffer.len) {
            // Get compressed buffer from file.
            const compressed = try self.file_reader.getBuffer(.from(logger));
            if (compressed.len == 0) break; // EOF

            // Get decompressed buffer to write to.
            const decompressed = buffer[n..];

            var in = InBuffer{ .src = compressed.ptr, .size = compressed.len, .pos = 0 };
            var out = OutBuffer{ .dst = decompressed.ptr, .size = decompressed.len, .pos = 0 };
            _ = try self.decompressor.decompressStream(&in, &out);

            try self.file_reader.advance(in.pos);
            n += out.pos;
        }
        return n;
    }
};
