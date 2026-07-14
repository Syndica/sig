const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;

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

fn PubkeyMap(comptime Value: type) type {
    return struct {
        entries: []Entry,
        zero_entry: Entry = undefined,
        zero_entry_populated: bool = false,

        const Self = @This();
        const Entry = struct {
            pubkey: Pubkey,
            value: Value,
        };

        pub fn init(fba: *std.heap.FixedBufferAllocator, len: usize) !Self {
            const cap = try std.math.ceilPowerOfTwo(u64, len);
            const entries = try fba.allocator().alloc(Entry, cap);
            @memset(entries, .{ .pubkey = .ZEROES, .value = undefined });
            return .{ .entries = entries };
        }

        pub fn insert(self: *Self, pubkey: *const Pubkey, value: *const Value) void {
            // We use zero pubkey to mean empty slot in the map, so special case it here.
            if (pubkey.isZeroed()) {
                @branchHint(.unlikely);
                self.zero_entry = .{ .pubkey = .ZEROES, .value = value.* };
                self.zero_entry_populated = true;
                return;
            }

            const mask = self.entries.len - 1;
            var i = pubkey.hash(0) & mask;
            while (true) {
                const e = &self.entries[i];
                i = (i + 1) & mask;
                if (e.pubkey.equals(pubkey) or e.pubkey.isZeroed()) {
                    e.* = .{ .pubkey = pubkey.*, .value = value.* };
                    break;
                }
            }
        }

        pub fn find(self: *Self, pubkey: *const Pubkey) ?*Entry {
            if (pubkey.isZeroed()) {
                @branchHint(.unlikely);
                if (self.zero_entry_populated) return &self.zero_entry;
                return null;
            }

            const mask = self.entries.len - 1;
            var i = pubkey.hash(0) & mask;
            while (true) {
                const e = &self.entries[i];
                i = (i + 1) & mask;
                if (e.pubkey.equals(pubkey)) return e;
                if (e.pubkey.isZeroed()) return null;
            }
        }
    };
}

pub const EpochStakes = struct {
    epoch: Epoch,
    vote_accounts: VoteAccountMap,
    stake_delegations: StakeDelegationMap,
    stake_history: StakeHistory,

    // Maps vote_account -> account info
    const VoteAccountMap = PubkeyMap(VoteAccount);

    const VoteAccount = extern struct {
        stake: u64,
        // A vote account lives in its PubkeyMap and is optionally linked to other entries in the
        // map who share the same node owner.
        next: ?*VoteAccount = null,
    };

    // HashMap(Pubkey, { stake: u64, account: AccountSharedData }) where AccountSharedData =
    // { lamports: u64, data: Vec(u8), owner: Pubkey, executable: bool, rent_epoch: Epoch }
    fn readVoteAccounts(
        fba: *std.heap.FixedBufferAllocator,
        r: anytype,
        len: u64,
    ) !VoteAccountMap {
        var vote_accounts = try VoteAccountMap.init(fba, len);
        var vote_entry_header: extern struct {
            key: Pubkey,
            stake: u64,
            lamports: u64,
            data_len: u64,
        } = undefined;
        for (0..len) |_| {
            try r.readSliceAll(std.mem.asBytes(&vote_entry_header));
            // skip rest of its AccountSharedData (TODO: validate)
            try r.discardAll(vote_entry_header.data_len + // data bytes
                32 + // owner: Pubkey
                1 + // executable: bool
                8 // rent_epoch: Epoch
            );
            vote_accounts.insert(&vote_entry_header.key, &.{
                .stake = vote_entry_header.stake,
            });
        }
        return vote_accounts;
    }

    const StakeDelegationMap = PubkeyMap(Delegation); // this thing is MASSIVE
    const Delegation = extern struct {
        voter: Pubkey,
        stake: u64,
        activation_epoch: Epoch,
        deactivation_epoch: Epoch,
        warmup_cooldown_rate: f64,
        credits_observed: u64,
    };

    pub fn readStakeDelegations(
        fba: *std.heap.FixedBufferAllocator,
        r: anytype,
        len: u64,
    ) !StakeDelegationMap {
        // read in chunks to amortize the cost of `r.readSliceAll` calls.
        var delegation_map = try StakeDelegationMap.init(fba, len);
        var delegation_chunk: [64]extern struct {
            pubkey: Pubkey,
            voter_pubkey: Pubkey,
            stake: u64,
            activation_epoch: Epoch,
            deactivation_epoch: Epoch,
            warmup_cooldown_rate: f64,
            credits_observed: u64,
        } = undefined;

        var n = len;
        while (n > 0) {
            const num_chunks = @min(n, delegation_chunk.len);
            n -= num_chunks;

            const chunk = delegation_chunk[0..num_chunks];
            try r.readSliceAll(std.mem.sliceAsBytes(chunk));

            for (chunk) |*delegation| {
                delegation_map.insert(&delegation.pubkey, &.{
                    .voter = delegation.voter_pubkey,
                    .stake = delegation.stake,
                    .activation_epoch = delegation.activation_epoch,
                    .deactivation_epoch = delegation.deactivation_epoch,
                    .warmup_cooldown_rate = delegation.warmup_cooldown_rate,
                    .credits_observed = delegation.credits_observed,
                });
            }
        }

        return delegation_map;
    }

    const StakeHistory = struct {
        latest_epoch: Epoch,
        entries: []Entry,

        const Entry = extern struct {
            effective: u64,
            activating: u64,
            deactivating: u64,
        };
    };

    fn readStakeHistory(
        fba: *std.heap.FixedBufferAllocator,
        r: anytype,
        len: usize,
    ) !StakeHistory {
        // https://docs.rs/solana-stake-history/1.0.0/src/solana_stake_history/lib.rs.html#22
        const MAX_ENTRIES = 512;
        if (len > MAX_ENTRIES) return error.TooManyStakeHistoryEntries;

        var latest_epoch: ?Epoch = null;
        const entries = try fba.allocator().alloc(StakeHistory.Entry, len);
        var i: usize = 0;

        // read in chunks to amortize the cost of `r.readSliceAll` calls.
        var last_epoch: ?Epoch = null;
        var history_chunks: [64]extern struct {
            epoch: Epoch,
            effective: u64,
            activating: u64,
            deactivating: u64,
        } = undefined;

        var n = len;
        while (n > 0) {
            const num_chunks = @min(n, history_chunks.len);
            n -= num_chunks;

            const chunk = history_chunks[0..num_chunks];
            try r.readSliceAll(std.mem.sliceAsBytes(chunk));

            // set the first epoch
            if (latest_epoch == null) {
                latest_epoch = chunk[0].epoch;
            }

            // history entries must have strictly descending entries:
            // https://docs.rs/solana-stake-history/1.0.0/src/solana_stake_history/lib.rs.html#140-144
            for (chunk) |*e| {
                if (last_epoch != null and last_epoch.? <= e.epoch) {
                    @branchHint(.unlikely);
                    return error.InvalidStakeHistoryEpochEntry;
                }
                last_epoch = e.epoch;
                entries[i] = .{
                    .effective = e.effective,
                    .activating = e.activating,
                    .deactivating = e.deactivating,
                };
                i += 1;
            }
        }

        return .{
            .latest_epoch = latest_epoch orelse return error.NoStakeHistoryEntries,
            .entries = entries,
        };
    }

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !EpochStakes {
        // epoch_stakes: Stakes(Delegation)
        //   vote_accounts: VoteAccounts
        const vote_len = try readInt(u64, r);
        const vote_accounts = try readVoteAccounts(fba, r, vote_len);

        //   stake_delegations: HashMap(Pubkey, Delegation)
        const stakes_len = try readInt(u64, r);
        const stake_delegations = try readStakeDelegations(fba, r, stakes_len);

        //   unused: u64
        //   epoch: Epoch
        //   stake_history: Vec(...) see below
        var info: extern struct {
            _unused: u64,
            epoch: Epoch,
            stake_history_len: u64,
        } = undefined;
        try r.readSliceAll(std.mem.asBytes(&info));

        //   stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
        const stake_history = try readStakeHistory(fba, r, info.stake_history_len);

        return .{
            .epoch = info.epoch,
            .vote_accounts = vote_accounts,
            .stake_delegations = stake_delegations,
            .stake_history = stake_history,
        };
    }

    pub fn discard(r: anytype) !void {
        // dicard vote accounts
        var len = try readInt(u64, r);
        var vote_entry_header: extern struct {
            key: Pubkey,
            stake: u64,
            lamports: u64,
            data_len: u64,
        } = undefined;
        for (0..len) |_| { // the data_len is variable, so need to skip each one by one.
            try r.readSliceAll(std.mem.asBytes(&vote_entry_header));
            try r.discardAll(vote_entry_header.data_len + // data bytes
                32 + // owner: Pubkey
                1 + // executable: bool
                8 // rent_epoch: Epoch
            );
        }

        // discard stake delegations
        len = try readInt(u64, r);
        try r.discardAll(len * (32 + // pubkey: Pubkey,
            32 + // voter_pubkey: Pubkey,
            8 + // stake: u64,
            8 + // activation_epoch: Epoch,
            8 + // deactivation_epoch: Epoch,
            8 // warmup_cooldown_rate: f64,
        ));

        //   unused: u64
        //   epoch: Epoch
        //   stake_history: Vec(...) see below
        var info: extern struct {
            _unused: u64,
            epoch: Epoch,
            stake_history_len: u64,
        } = undefined;
        try r.readSliceAll(std.mem.asBytes(&info));

        // discard stake history
        try r.discardAll(info.stake_history_len * (8 + // epoch: Epoch,
            8 + // effective: u64,
            8 + // activating: u64,
            8 // deactivating: u64,
        ));
    }
};

pub const BankFields = struct {
    slot: Slot,
    blockhash_queue: BlockHashQueue,

    pub const BlockHashQueue = struct {
        last_hash: ?Hash,
        max_age: u64,
        hashes: struct {
            array: []Hash,
            count: usize,
        },

        pub const Entry = extern struct {
            hash: Hash,
            hash_index: u64,
        };

        pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !BlockHashQueue {
            const last_hash_index = try readInt(u64, r);
            const maybe_last_hash: ?Hash = if (!(try readBool(r))) null else blk: {
                var hash: Hash = undefined;
                try r.readSliceAll(std.mem.asBytes(&hash));
                break :blk hash;
            };

            const n_hash_infos = try readInt(u64, r);
            const hashes = try fba.allocator().alloc(Hash, n_hash_infos);

            const BlockhashEntry = extern struct {
                hash: Hash,
                lamports_per_signature: u64,
                hash_index: u64,
                timestamp: u64,
            };

            const entries = try fba.allocator().alloc(BlockhashEntry, n_hash_infos);
            defer fba.allocator().free(entries); // its the last allocation, so makes sense
            try r.readSliceAll(std.mem.sliceAsBytes(entries));

            const max_age = try readInt(u64, r);

            // sort entries by hash_index
            std.mem.sortUnstable(BlockhashEntry, entries, {}, struct {
                fn lessThan(_: void, a: BlockhashEntry, b: BlockhashEntry) bool {
                    return a.hash_index < b.hash_index;
                }
            }.lessThan);

            // then add only the live ones by max_age to the hashes
            var count: usize = 0;
            for (entries) |*e| {
                const age = last_hash_index - e.hash_index;
                if (age <= max_age) {
                    hashes[count] = e.hash;
                    count += 1;
                }
            }

            return .{
                .last_hash = maybe_last_hash,
                .max_age = max_age,
                .hashes = .{ .array = hashes, .count = count },
            };
        }
    };

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !BankFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "BankFields.read" });
        defer zone.deinit();

        const blockhash_queue = try BlockHashQueue.read(fba, r);

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

        try r.discardAll(8 + // ticks_per_slot: u64
            16 + // ns_per_slot: u128
            8 + // genesis_creation_time: i64
            8 + // slots_per_year: f64
            8 // accounts_data_len: u64
        );
        const slot = try readInt(Slot, r);
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

        try EpochStakes.discard(r);

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

        return .{
            .slot = slot,
            .blockhash_queue = blockhash_queue,
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
    versioned_epoch_stakes: []VersionedEpochStakes,

    const VersionedEpochStakes = struct {
        epoch: Epoch,
        stakes: EpochStakes,
        total_stake: u64,
        // maps node to list of its vote accounts
        node_id_to_vote_accounts: NodeToVoteAccountList,
        // maps vote account to authorized voter
        epoch_authorized_voters: EpochAuthorizedVoters,

        const NodeToVoteAccountList = struct {
            map: PubkeyMap(struct {
                head: ?*EpochStakes.VoteAccount,
                total_stake: u64,
            }),

            pub fn getVoteAccounts(
                self: *const NodeToVoteAccountList,
                node_pubkey: *const Pubkey,
            ) ?VoteAccountIterator {
                const node_entry = self.map.find(node_pubkey) orelse return null;
                return .{
                    .total_stake = node_entry.value.total_stake,
                    .entry = node_entry.value.head,
                };
            }

            pub const VoteAccountIterator = struct {
                total_stake: u64,
                entry: ?*EpochStakes.VoteAccount,

                pub fn next(self: *VoteAccountIterator) ?*EpochStakes.VoteAccountMap.Entry {
                    const vote_acc = self.entry orelse return null;
                    self.entry = vote_acc.next orelse {
                        @panic("unlinked vote account in node map");
                    };
                    // last entry points to itself.
                    if (self.entry == vote_acc) self.entry = null;

                    // the vote_acc lives in an EpochStakes.vote_accounts map.
                    // That entry includes its pubkey, so return that + its value.
                    return @alignCast(@fieldParentPtr("value", vote_acc));
                }
            };
        };

        // HashMap(Pubkey, { vote_accounts: Vec(Pubkey), total_stake: u64 })
        fn readNodeToVoteAccountList(
            fba: *std.heap.FixedBufferAllocator,
            r: anytype,
            stakes: *EpochStakes,
        ) !NodeToVoteAccountList {
            // HashMap.len: u64
            const len = try readInt(u64, r);
            var list: NodeToVoteAccountList = .{ .map = try .init(fba, len) };

            var vote_pubkey_chunk: [64]Pubkey = undefined;
            var header: extern struct {
                node_pubkey: Pubkey,
                num_vote_accounts: u64,
            } = undefined;

            for (0..len) |_| {
                try r.readSliceAll(std.mem.asBytes(&header));

                // link up vote accounts in epoch_stakes mapped to by this node
                var head_entry: ?*EpochStakes.VoteAccount = null;
                var tail_entry: ?*EpochStakes.VoteAccount = null;

                // read pubkeys in chunks to amortize r.readSliceAll calls.
                var n_pubkeys = header.num_vote_accounts;
                while (n_pubkeys > 0) {
                    const n = @min(n_pubkeys, vote_pubkey_chunk.len);
                    n_pubkeys -= n;

                    const pubkey_chunk = vote_pubkey_chunk[0..n];
                    try r.readSliceAll(std.mem.sliceAsBytes(pubkey_chunk));

                    for (pubkey_chunk) |*vote_pubkey| {
                        const vote_entry = stakes.vote_accounts.find(vote_pubkey) orelse
                            return error.MissingVoteAccount;

                        // a node in a list either points to next, or points to itself (tail)
                        const vote_account = &vote_entry.value;
                        if (vote_account.next != null) return error.VoteAccountOwnedByMultipleNodes;
                        vote_account.next = vote_account;

                        // track link list.
                        if (head_entry == null) head_entry = vote_account;
                        if (tail_entry) |tail| tail.next = vote_account;
                        tail_entry = vote_account;
                    }
                }

                const total_stake = try readInt(u64, r);
                list.map.insert(&header.node_pubkey, &.{
                    .head = head_entry,
                    .total_stake = total_stake,
                });
            }

            return list;
        }

        const EpochAuthorizedVoters = PubkeyMap(Pubkey);

        fn readEpochAuthorizedVoters(
            fba: *std.heap.FixedBufferAllocator,
            r: anytype,
        ) !EpochAuthorizedVoters {
            var len = try readInt(u64, r);
            var map = try EpochAuthorizedVoters.init(fba, len);

            // read pubkeys in chunks to amortize r.readSliceAll calls.
            var entry_chunks: [64]extern struct { voter_key: Pubkey, auth_key: Pubkey } = undefined;
            while (len > 0) {
                const n = @min(len, entry_chunks.len);
                len -= n;

                const chunks = entry_chunks[0..n];
                try r.readSliceAll(std.mem.sliceAsBytes(chunks));

                for (chunks) |*entry| {
                    map.insert(&entry.voter_key, &entry.auth_key);
                }
            }

            return map;
        }

        pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !VersionedEpochStakes {
            // epoch: Epoch
            const epoch = try readInt(Epoch, r);

            // union tag: u32 (enum(u32), always 'current')
            const union_tag = try readInt(u32, r);
            if (union_tag != 0) {
                return error.InvalidVersionedEpochStakesUnion;
            }

            // Stakes(.Delegation)
            var epoch_stakes = try EpochStakes.read(fba, r);

            // total_stake: u64
            const total_stake = try readInt(u64, r);

            // HashMap(Pubkey, Vec(Pubkey))
            const node_to_vote_account_list = try readNodeToVoteAccountList(fba, r, &epoch_stakes);

            // epoch_authorized_voters: HashMap(Pubkey, Pubkey)
            const epoch_authorized_voters = try readEpochAuthorizedVoters(fba, r);

            return .{
                .epoch = epoch,
                .stakes = epoch_stakes,
                .total_stake = total_stake,
                .node_id_to_vote_accounts = node_to_vote_account_list,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }
    };

    pub fn read(fba: *std.heap.FixedBufferAllocator, r: anytype) !ExtraFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "ExtraFields.read" });
        defer zone.deinit();

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
        var versioned_epoch_stakes: []VersionedEpochStakes = &.{};
        {
            const len = readInt(u64, r) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };

            versioned_epoch_stakes = try fba.allocator().alloc(VersionedEpochStakes, len);
            for (versioned_epoch_stakes) |*versioned_epoch_stake| {
                versioned_epoch_stake.* = try .read(fba, r);
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

        return .{
            .versioned_epoch_stakes = versioned_epoch_stakes,
        };
    }
};

pub fn SnapshotIter(comptime BufReader: type) type {
    return struct {
        // public fields instantiated using the fba from init()
        status_cache: StatusCache,
        manifest: Manifest,

        tar_iter: TarZstIter(BufReader),
        account_file_len: usize,
        account_file_slot: Slot,
        account_data_len: usize,
        account_data_padding: usize,

        const Self = @This();

        pub fn init(
            fba: *std.heap.FixedBufferAllocator,
            buf_reader: BufReader,
        ) !Self {
            var self: Self = undefined;
            self.tar_iter = .{ .buf_reader = buf_reader };

            // read /version
            {
                const tar_file = (try self.tar_iter.next()) orelse return error.MissingVersionFile;
                if (!std.mem.eql(u8, tar_file.name, "version")) return error.MissingVersionFile;
                const expected = "1.2.0";
                var version: [expected.len]u8 = undefined;
                try self.tar_iter.readSliceAll(&version);
                if (!std.mem.eql(u8, &version, expected)) return error.InvalidVersion;
            }

            // read /snapshots/status_cache & /snapshots/{slot}/{slot} (can be in any order)
            {
                const tar_file = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                if (std.mem.eql(u8, tar_file.name, "snapshots/status_cache")) {
                    self.status_cache = try StatusCache.read(fba, &self.tar_iter);
                    _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                    self.manifest = try Manifest.read(fba, &self.tar_iter);
                } else {
                    self.manifest = try Manifest.read(fba, &self.tar_iter);
                    _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                    self.status_cache = try StatusCache.read(fba, &self.tar_iter);
                }
            }

            self.account_file_len = 0;
            self.account_file_slot = 0;
            self.account_data_len = 0;
            self.account_data_padding = 0;
            return self;
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
            // Skip unread data & data padding of previous Accountentry
            self.tar_iter.discardAll(self.account_data_len + self.account_data_padding) catch {};

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
                if (slot > self.manifest.accounts_db_fields.slot)
                    return error.InvalidAccountFileSlot;

                const info = self.manifest.accounts_db_fields.account_file_map.getPtr(slot) orelse
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
            self.tar_iter.readSliceAll(std.mem.asBytes(&header)) catch
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
            try self.tar_iter.readSliceAll(buf);
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

        // std.Io.Reader-like API for Manifest/StatusCache.read()

        pub fn readSliceAll(self: *Self, buf: []u8) !void {
            if (self.file_size < buf.len) return error.EndOfStream;
            self.file_size -= buf.len;
            if (self.read(buf.ptr, buf.len) != buf.len) return error.EndOfStream;
        }

        pub fn discardAll(self: *Self, n: usize) !void {
            if (self.file_size < n) return error.EndOfStream;
            self.file_size -= n;
            if (self.read(null, n) != n) return error.EndOfStream;
        }

        fn read(self: *Self, maybe_buf: ?[*]u8, len: usize) usize {
            var n: usize = 0;
            while (n < len) {
                const buf: []const u8 = self.buf_reader.getBuffer();
                if (buf.len == 0) break; // EOF

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
