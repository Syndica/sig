const std = @import("std");
const tracy = @import("tracy");
const lib = @import("../lib.zig");

fn readInt(Int: type, r: anytype) !u64 {
    var buf: [@sizeOf(Int)]u8 = undefined;
    try r.readSliceAll(&buf);
    return std.mem.readInt(Int, &buf, .little);
}

fn readBool(r: anytype) !bool {
    var buf: [1]u8 = undefined;
    try r.readSliceAll(&buf);
    if (buf[0] > 1) return error.InvalidBool;
    return buf[0] > 0;
}

pub const StatusCache = struct {
    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !StatusCache {
        const zone = tracy.Zone.init(@src(), .{ .name = "StatusCache.read" });
        defer zone.deinit();

        _ = fba;

        // slot_deltas: Vec({ slot: Slot, is_root: bool, status_map: StatusMap })
        const slot_deltas_len = try readInt(u64, r);
        for (0..slot_deltas_len) |_| {
            // slot(Slot) + is_root(bool)
            try r.discardAll(8 + 1);

            // status_map: HashMap(Hash, { fork_count: u64, entries: Vec({ key_slice: [20]u8, result: union }) })
            const status_map_len = try readInt(u64, r);
            for (0..status_map_len) |_| {
                // key: Hash + value.fork_count: u64
                try r.discardAll(32 + 8);

                // value.entries: Vec({ key_slice: KeySlice, result: union(enum(u32)) { ok, err: TransactionError } })
                const entries_len = try readInt(u64, r);
                for (0..entries_len) |_| {
                    // key_slice: [20]u8 + result tag: u32
                    try r.discardAll(20);
                    switch (try readInt(u32, r)) {
                        0 => {}, // ok: void
                        1 => try discardTransactionError(r), // err: TransactionError
                        else => return error.InvalidResultTag,
                    }
                }
            }
        }

        return .{};
    }

    /// Discards a TransactionError union. Most variants are void; some carry a u8 payload;
    /// InstructionError carries { index: u8, err: InstructionError }.
    fn discardTransactionError(r: anytype) !void {
        switch (try readInt(u32, r)) {
            8 => { // InstructionError: { index: u8, err: InstructionError }
                try r.discardAll(1); // index: u8
                try discardInstructionError(r);
            },
            30, // DuplicateInstruction: u8
            31, // InsufficientFundsForRent: u8
            35, // ProgramExecutionTemporarilyRestricted: u8
            => try r.discardAll(1),
            else => {}, // all other variants are void
        }
    }

    /// Discards an InstructionError union. Most variants are void; Custom is u32; BorshIoError is Vec(u8).
    fn discardInstructionError(r: anytype) !void {
        switch (try readInt(u32, r)) {
            25 => try r.discardAll(4), // Custom: u32
            45 => { // BorshIoError: Vec(u8)
                const len = try readInt(u64, r);
                try r.discardAll(len);
            },
            else => {}, // all other variants are void
        }
    }
};

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
    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !BankFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "BankFields.read" });
        defer zone.deinit();

        _ = fba;

        // blockhash_queue.last_hash_index: u64
        try r.discardAll(8);
        // blockhash_queue.last_hash: ?Hash
        if (try readBool(r)) try r.discardAll(32);
        // blockhash_queue.hash_infos: HashMap(Hash, { lamports_per_signature: u64, hash_index: u64, timestamp: u64 })
        const hash_infos_len = try readInt(u64, r);
        try r.discardAll(hash_infos_len * (32 + // key: Hash
            8 + // lamports_per_signature: u64
            8 + // hash_index: u64
            8 // timestamp: u64
        ));
        // blockhash_queue.max_age: u64
        try r.discardAll(8);

        // _unused_ancestors: HashMap(Slot, u64)
        const ancestors_len = try readInt(u64, r);
        try r.discardAll(ancestors_len * (8 + // key: Slot
            8 // value: u64
        ));

        // hash(Hash) + parent_hash(Hash) + parent_slot(Slot)
        try r.discardAll(32 + 32 + 8);

        // hard_forks: Vec({ slot: Slot, count: u64 })
        const hard_forks_len = try readInt(u64, r);
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

        try r.discardAll(
            8 + // ticks_per_slot: u64
                16 + // ns_per_slot: u128
                8 + // genesis_creation_time: i64
                8 + // slots_per_year: f64
                8 + // accounts_data_len: u64
                8 + // slot: Slot
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
        const stake_del_len = try readInt(u64, r);
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
        const stake_history_len = try readInt(u64, r);
        try r.discardAll(stake_history_len * (8 + // epoch: Epoch
            8 + // effective: u64
            8 + // activating: u64
            8 // deactivating: u64
        ));

        // _unused_accounts.unused1: HashSet(Pubkey)
        const unused1_len = try readInt(u64, r);
        try r.discardAll(unused1_len * 32);
        // _unused_accounts.unused2: HashSet(Pubkey)
        const unused2_len = try readInt(u64, r);
        try r.discardAll(unused2_len * 32);
        // _unused_accounts.unused3: HashMap(Pubkey, u64)
        const unused3_len = try readInt(u64, r);
        try r.discardAll(unused3_len * (32 + 8));

        // _unused_epoch_stakes: HashSet(Epoch)
        const epoch_stakes_len = try readInt(u64, r);
        try r.discardAll(epoch_stakes_len * 8);

        // is_delta: bool
        try r.discardAll(1);

        return .{};
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
        const slot = try readInt(u64, r);

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
            const len = readInt(u64, r) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };
            try r.discardAll(len * 8); // Slot: u64
        }

        // rooted_slot_hashes: NullOnEof(Vec(SlotAndHash))
        {
            const len = readInt(u64, r) catch |err| switch (err) {
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
            const zone = tracy.Zone.init(@src(), .{ .name = "accountFileMap.read" });
            defer zone.deinit();

            // const file_map_len = try readInt(u64, r);
            // try r.discardAll(file_map_len * (8 + // slot: Slot(u64)
            //     8 + // small_vec_size: u64
            //     8 + // id: u64
            //     8 // length: u64
            // ));

            const n = std.math.cast(u32, try readInt(u64, r)) orelse return error.Overflow;
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
            const zone = tracy.Zone.init(@src(), .{ .name = "AccountFileMap.get" });
            defer zone.deinit();

            const entries = self.entries;
            var idx = (slot *% HASH_MULT) >> @intCast(@as(u7, 64) - @ctz(entries.len));
            while (true) {
                const e = &entries[idx];
                idx = (idx +% 1) & (entries.len - 1);
                if (@as(u128, @bitCast(e.*)) == @as(u128, @bitCast(Entry.empty))) continue;
                if (e.slot == slot) return e;
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
            const outer_len = readInt(u64, r) catch |err| switch (err) {
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
                const stake_del_len = try readInt(u64, r);
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
                const sh_len = try readInt(u64, r);
                try r.discardAll(sh_len * (8 + 8 + 8 + 8));

                // current.total_stake: u64
                try r.discardAll(8);

                // current.node_id_to_vote_accounts: HashMap(Pubkey, { vote_accounts: Vec(Pubkey), total_stake: u64 })
                const nv_len = try readInt(u64, r);
                for (0..nv_len) |_| {
                    // key: Pubkey
                    try r.discardAll(32);
                    // value.vote_accounts: Vec(Pubkey)
                    const va_len = try readInt(u64, r);
                    try r.discardAll(
                        va_len * 32 + // vote_accounts: []Pubkey
                            8, // total_stake: u64
                    );
                }

                // current.epoch_authorized_voters: HashMap(Pubkey, Pubkey)
                const eav_len = try readInt(u64, r);
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
    const len = try readInt(u64, r);
    for (0..len) |_| {
        try r.discardAll(
            32 + // key: Pubkey
                8 + // value.stake: u64
                8, // value.account.lamports: u64
        );
        // value.account.data: Vec(u8)
        const data_len = try readInt(u64, r);
        try r.discardAll(
            data_len + // account data bytes
                32 + // value.account.owner: Pubkey
                1 + // value.account.executable: bool
                8, // value.account.rent_epoch: Epoch(u64)
        );
    }
}
