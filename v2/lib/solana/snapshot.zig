const std = @import("std");
const lib = @import("../lib.zig");
const tracy = @import("tracy");

const tel = lib.telemetry;

const Pubkey = lib.solana.Pubkey;
const Slot = lib.solana.Slot;
const Epoch = lib.solana.Epoch;
const Hash = lib.solana.Hash;
const EpochSchedule = lib.solana.EpochSchedule;
const Inflation = lib.solana.Inflation;

/// A slice into a shared-memory region, expressed as an offset from a base pointer
/// plus a length. Position-independent so it can live inside an extern struct that is
/// mmap'd at different virtual addresses across processes.
pub fn RelativeSlice(comptime T: type) type {
    return extern struct {
        offset: u32 = 0,
        len: u32 = 0,

        const Self = @This();

        pub fn fromSlice(base: [*]const u8, s: []const T) Self {
            const start = @intFromPtr(s.ptr) - @intFromPtr(base);
            std.debug.assert(start <= std.math.maxInt(u32));
            std.debug.assert(s.len <= std.math.maxInt(u32));
            return .{ .offset = @intCast(start), .len = @intCast(s.len) };
        }

        pub fn slice(self: Self, base: [*]u8) []T {
            const raw = base + self.offset;
            std.debug.assert(@intFromPtr(raw) % @alignOf(T) == 0);
            const ptr: [*]T = @ptrCast(@alignCast(raw));
            return ptr[0..self.len];
        }

        pub fn sliceConst(self: Self, base: [*]const u8) []const T {
            const raw = base + self.offset;
            std.debug.assert(@intFromPtr(raw) % @alignOf(T) == 0);
            const ptr: [*]const T = @ptrCast(@alignCast(raw));
            return ptr[0..self.len];
        }
    };
}

/// A single-pointer variant of `RelativeSlice`. `offset == 0` is the null sentinel;
/// callers must guarantee no valid allocation lands at offset 0 (see `Rooted.loadSnapshot`
/// which reserves the first byte of its FBA for exactly this purpose).
pub fn RelativeOffset(comptime T: type) type {
    return extern struct {
        offset: u32 = 0,

        const Self = @This();

        pub fn from(base: [*]const u8, ptr: *const T) Self {
            const o = @intFromPtr(ptr) - @intFromPtr(base);
            std.debug.assert(o != 0);
            std.debug.assert(o <= std.math.maxInt(u32));
            return .{ .offset = @intCast(o) };
        }

        pub fn isNull(self: Self) bool {
            return self.offset == 0;
        }

        pub fn pointer(self: Self, base: [*]u8) *T {
            std.debug.assert(self.offset != 0);
            const raw = base + self.offset;
            std.debug.assert(@intFromPtr(raw) % @alignOf(T) == 0);
            return @ptrCast(@alignCast(raw));
        }

        pub fn pointerConst(self: Self, base: [*]const u8) *const T {
            std.debug.assert(self.offset != 0);
            const raw = base + self.offset;
            std.debug.assert(@intFromPtr(raw) % @alignOf(T) == 0);
            return @ptrCast(@alignCast(raw));
        }
    };
}

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

pub const StatusCache = extern struct {
    /// Placeholder — the deserialized contents are currently discarded. Kept as an
    /// extern struct so it can live inline in `SnapshotMetadata` and be persisted
    /// alongside the `Manifest` in the rooted DB blob.
    _reserved: u8 = 0,

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
    ///
    /// See SerdeInstructionError in agave's runtime/src/serde_snapshot/status_cache.rs
    fn discardInstructionError(r: anytype) !void {
        switch (try readInt(u32, r)) {
            25 => try r.discardAll(4), // Custom: u32
            44 => { // BorshIoError: Vec(u8)
                const len = try readInt(u64, r);
                try r.discardAll(len);
            },
            else => {}, // all other variants are void
        }
    }
};

pub const Manifest = extern struct {
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
    return extern struct {
        entries: RelativeSlice(Entry) = .{},
        len: u32 = 0,

        const Self = @This();
        pub const Entry = extern struct {
            pubkey: Pubkey,
            value: Value,
        };

        pub fn init(fba: *std.heap.FixedBufferAllocator, len: usize) !Self {
            const cap = try std.math.ceilPowerOfTwo(u64, len);
            const entries = try fba.allocator().alloc(Entry, cap);
            @memset(entries, .{ .pubkey = .ZEROES, .value = undefined });
            return .{ .entries = .fromSlice(fba.buffer.ptr, entries) };
        }

        pub fn insert(
            self: *Self,
            base: [*]u8,
            pubkey: *const Pubkey,
            value: *const Value,
        ) void {
            // This uses the zero-pubkey to indicate empty
            std.debug.assert(!pubkey.isZeroed());

            const entries = self.entries.slice(base);
            const mask = entries.len - 1;
            var i = pubkey.hash(0) & mask;
            while (true) {
                const e = &entries[i];
                i = (i + 1) & mask;
                if (e.pubkey.equals(pubkey) or e.pubkey.isZeroed()) {
                    self.len += @intFromBool(e.pubkey.isZeroed());
                    e.* = .{ .pubkey = pubkey.*, .value = value.* };
                    break;
                }
            }
        }

        pub fn find(self: *const Self, base: [*]u8, pubkey: *const Pubkey) ?*Entry {
            // This uses the zero-pubkey to indicate empty
            std.debug.assert(!pubkey.isZeroed());

            const entries = self.entries.slice(base);
            const mask = entries.len - 1;
            var i = pubkey.hash(0) & mask;
            while (true) {
                const e = &entries[i];
                i = (i + 1) & mask;
                if (e.pubkey.equals(pubkey)) return e;
                if (e.pubkey.isZeroed()) return null;
            }
        }

        pub fn iterator(self: *const Self, base: [*]u8) Iterator {
            return .{ .entries = self.entries.slice(base) };
        }

        pub const Iterator = struct {
            entries: []Entry,

            pub fn next(self: *Iterator) ?*Entry {
                while (self.entries.len > 0) {
                    const e = &self.entries[0];
                    self.entries = self.entries[1..];
                    if (!e.pubkey.isZeroed()) return e;
                }
                return null;
            }
        };
    };
}

pub const BankFields = extern struct {
    slot: Slot,
    blockhash_queue: BlockHashQueue,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: extern struct {
        epoch: Epoch,
        delegations: PubkeyMap(Delegation),
    },

    pub const StakeDelegations = PubkeyMap(Delegation);
    pub const Delegation = extern struct {
        voter_pubkey: Pubkey,
        stake: u64,
        activation_epoch: Epoch,
        deactivation_epoch: Epoch,
    };

    pub const BlockHashQueue = extern struct {
        /// Agave's MAX_RECENT_BLOCKHASHES and the current `Rooted.Journal.blockhash_max_age`.
        /// It's plus-one given cutoff is `<= max_age` instead of `< max_age`.
        /// [agave] https://github.com/anza-xyz/solana-sdk/blob/clock%40v3.1.1/clock/src/lib.rs#L95
        pub const MAX_RECENT_BLOCKHASHES: u32 = 300 + 1;

        last_hash: Hash,
        max_age: u64,
        hashes: [MAX_RECENT_BLOCKHASHES]Hash,
        hashes_count: u32,

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

            var out: BlockHashQueue = .{
                .last_hash = maybe_last_hash orelse .ZEROES,
                .max_age = max_age,
                .hashes = @splat(.ZEROES),
                .hashes_count = 0,
            };

            // then add only the live ones by max_age
            for (entries) |*e| {
                const age = last_hash_index - e.hash_index;
                if (age <= max_age) {
                    if (out.hashes_count >= MAX_RECENT_BLOCKHASHES) return error.TooManyBlockhashes;
                    out.hashes[out.hashes_count] = e.hash;
                    out.hashes_count += 1;
                }
            }

            return out;
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
        try r.discardAll(8 + // _unused_epoch: Epoch
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
            //       epoch_schedule: EpochSchedule:
            8 + //     slots_per_epoch: u64
            8 + //     leader_schedule_slot_offset: u64
            1 + //     warmup: bool
            8 + //     first_normal_epoch: u64
            8 + //     first_normal_slot: u64
            8 + //   slots_per_year: f64
            //       rent:
            8 + //     lamports_per_byte: u64
            8 + //     exemption_threshold: [8]u8
            1 //       burn_percent: u8
        );

        var epoch_schedule: EpochSchedule = undefined;
        try r.readSliceAll(std.mem.asBytes(&epoch_schedule));

        var inflation: Inflation = undefined;
        try r.readSliceAll(std.mem.asBytes(&inflation));

        // stakes: Stakes(.Delegation)
        //     vote_accounts: HashMap(Pubkey, {stake, AccountData})
        const vote_acc_len = try readInt(u64, r);
        for (0..vote_acc_len) |_| {
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

        //   stake_delegations: HashMap(Pubkey, Delegation)
        //     Delegation = { voter_pubkey, stake, activation_epoch, deactivation_epoch, warmup }
        var stake_del_len = try readInt(u64, r);
        var stake_delegations = try StakeDelegations.init(fba, stake_del_len);
        {
            // read entries in chunks to amortize cost of r.readSliceAll
            var delegation_chunks: [64]extern struct {
                pubkey: Pubkey,
                delegation: Delegation,
                _deprecated_warmup_cooldown_rate: f64,
            } = undefined;
            while (stake_del_len > 0) {
                const n = @min(stake_del_len, delegation_chunks.len);
                stake_del_len -= n;

                const chunk = delegation_chunks[0..n];
                try r.readSliceAll(std.mem.sliceAsBytes(chunk));

                for (chunk) |*e| {
                    if (e.pubkey.isZeroed())
                        return error.InvalidDelegationPubkey;
                    if (e.delegation.voter_pubkey.isZeroed())
                        return error.InvalidDelegationVoterPubkey;

                    stake_delegations.insert(fba.buffer.ptr, &e.pubkey, &e.delegation);
                }
            }
        }

        _ = try readInt(u64, r); // stakes.unused: u64
        const epoch = try readInt(Epoch, r); // stakes.epoch: Epoch

        //  stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
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

        return .{
            .slot = slot,
            .blockhash_queue = blockhash_queue,
            .epoch_schedule = epoch_schedule,
            .inflation = inflation,
            .stakes = .{
                .epoch = epoch,
                .delegations = stake_delegations,
            },
        };
    }
};

pub const AccountsDbFields = extern struct {
    slot: u64,

    pub fn read(_: *std.heap.FixedBufferAllocator, r: anytype) !AccountsDbFields {
        const zone = tracy.Zone.init(@src(), .{ .name = "AccountsDbFields.read" });
        defer zone.deinit();

        // account_file_map: HashMap(Slot, Vec(StorageEntry))
        // serialized as u64 len + n * { slot: u64, small_vec_size: u64, id: u64, length: u64 }
        //
        // NOTE: agave-built snapshots already have the file_len == tar_file.size for account files
        // so we can avoid having to parse this out to get their true lengths.
        // https://github.com/anza-xyz/agave/blob/v4.2/accounts-db/src/account_storage_reader.rs#L91
        // https://github.com/anza-xyz/agave/blob/v4.2/snapshots/src/archive.rs#L179-L188
        {
            const len = try readInt(u64, r);
            try r.discardAll(len * (8 + // slot: u64
                8 + // small_vec.len: u64 == 1
                16 // small_vec.data[{id: u64, file_len: u64}]
            ));
        }

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
            .slot = slot,
        };
    }
};

pub const ExtraFields = extern struct {
    versioned_epoch_stakes: RelativeSlice(VersionedEpochStakes) = .{},
    /// - TowerBFT: the Merkle root of the last FEC set of the block
    /// - Alpenglow: the "double Merkle root": a Merkle root computed over the
    ///   sequence of per-FEC-set Merkle roots of the block's shreds.
    block_id: Hash,

    pub const VersionedEpochStakes = extern struct {
        epoch: Epoch,
        total_stake: u64,
        // maps pubkey to vote account + its stake + its node membership
        vote_accounts: VoteAccountMap,
        // maps node to list of its vote accounts
        node_id_to_vote_accounts: NodeToVoteAccountList,
        // maps vote account to authorized voter
        epoch_authorized_voters: EpochAuthorizedVoters,

        // Maps vote_account -> stake & node membership list
        pub const VoteAccountMap = PubkeyMap(VoteAccount);
        pub const VoteAccount = extern struct {
            stake: u64,
            // A vote account lives in its PubkeyMap and is optionally linked to other entries
            // in the map who share the same node owner. `next.offset == 0` means unlinked
            // (Rooted.loadSnapshot reserves offset 0 in the FBA so no real entry lands there).
            next: RelativeOffset(VoteAccountMap.Entry) = .{},
            node: Pubkey = .ZEROES,
        };

        /// Reads a Stakes(Delegation), but all we need from it is the VoteAccounts
        fn readEpochStakes(fba: *std.heap.FixedBufferAllocator, r: anytype) !VoteAccountMap {
            // epoch_stakes: Stakes(Delegation)
            //   vote_accounts: HashMap(Pubkey, { stake: u64, account: AccountSharedData })
            //
            // where AccountSharedData =
            // { lamports: u64, data: Vec(u8), owner: Pubkey, executable: bool, rent_epoch: Epoch }
            const vote_len = try readInt(u64, r);
            var vote_accounts = try VoteAccountMap.init(fba, vote_len);
            for (0..vote_len) |_| {
                // read a vote entry.
                var vote_entry: extern struct {
                    key: Pubkey,
                    stake: u64,
                    lamports: u64,
                    data_len: u64,
                } = undefined;
                try r.readSliceAll(std.mem.asBytes(&vote_entry));

                // skip rest of its AccountSharedData (TODO: validate if matches the account?)
                try r.discardAll(vote_entry.data_len + // data bytes
                    32 + // owner: Pubkey
                    1 + // executable: bool
                    8 // rent_epoch: Epoch
                );

                if (vote_entry.key.isZeroed()) return error.InvalidVoteAccount;
                vote_accounts.insert(fba.buffer.ptr, &vote_entry.key, &.{
                    .stake = vote_entry.stake,
                });
            }

            //   stake_delegations: HashMap(Pubkey, { Delegation, credits_observed: u64 })
            //
            // NOTE: this is discarded instead of stored:
            // https://github.com/anza-xyz/agave/blob/v4.2/runtime/src/epoch_stakes.rs#L442-L443
            const stake_del_len = try readInt(u64, r);
            try r.discardAll(stake_del_len * (32 + // key: Pubkey
                32 + // delegation.voter_pubkey: Pubkey
                8 + // delegation.stake: u64
                8 + // delegation.activation_epoch: Epoch
                8 + // delegation.deactivation_epoch: Epoch
                8 + // delegation.warmup_cooldown_rate: f64
                8 // credits_observed: u64
            ));

            //   unused: u64
            //   epoch: Epoch
            try r.discardAll(8 + 8);

            //   stake_history: Vec({Epoch, effective: u64, activating: u64, deactivating: u64})
            //
            // NOTE: this is empty on testnet snapshots and is fine to discard.
            // The one that matters is BankFields.stake_history,
            // and its better to parse it out of the StakeHistory sysvar account from db instead.
            const stake_history_len = try readInt(u64, r);
            try r.discardAll(stake_history_len * (8 + // epoch: Epoch
                8 + // effective: u64
                8 + // activating: u64
                8 // deactivating: u64
            ));

            return vote_accounts;
        }

        pub const NodeToVoteAccountList = PubkeyMap(extern struct {
            head: RelativeOffset(VoteAccountMap.Entry) = .{},
            total_stake: u64,
        });

        // HashMap(Pubkey, { vote_accounts: Vec(Pubkey), total_stake: u64 })
        fn readNodeToVoteAccountList(
            fba: *std.heap.FixedBufferAllocator,
            r: anytype,
            vote_accounts: *VoteAccountMap,
        ) !NodeToVoteAccountList {
            const base = fba.buffer.ptr;
            // HashMap.len: u64
            const len = try readInt(u64, r);
            var list: NodeToVoteAccountList = try .init(fba, len);

            var vote_pubkey_chunk: [64]Pubkey = undefined;
            var header: extern struct {
                node_pubkey: Pubkey,
                num_vote_accounts: u64,
            } = undefined;

            for (0..len) |_| {
                try r.readSliceAll(std.mem.asBytes(&header));
                if (header.node_pubkey.isZeroed()) {
                    return error.InvalidNodePubkey;
                }

                // link up vote accounts in epoch_stakes mapped to by this node
                var head_offset: RelativeOffset(VoteAccountMap.Entry) = .{};
                var tail_entry: ?*VoteAccountMap.Entry = null;

                // read pubkeys in chunks to amortize r.readSliceAll calls.
                var n_pubkeys = header.num_vote_accounts;
                while (n_pubkeys > 0) {
                    const n = @min(n_pubkeys, vote_pubkey_chunk.len);
                    n_pubkeys -= n;

                    const pubkey_chunk = vote_pubkey_chunk[0..n];
                    try r.readSliceAll(std.mem.sliceAsBytes(pubkey_chunk));

                    for (pubkey_chunk) |*vote_pubkey| {
                        const vote_entry = vote_accounts.find(base, vote_pubkey) orelse
                            return error.MissingVoteAccount;

                        const vote_account = &vote_entry.value;
                        if (!vote_account.next.isNull()) {
                            return error.VoteAccountOwnedByMultipleNodes;
                        }

                        const entry_offset: RelativeOffset(VoteAccountMap.Entry) =
                            .from(base, vote_entry);

                        // a node in a list either points to next, or points to itself (tail)
                        vote_account.next = entry_offset;
                        vote_account.node = header.node_pubkey;

                        // track link list.
                        if (head_offset.isNull()) head_offset = entry_offset;
                        if (tail_entry) |tail| tail.value.next = entry_offset;
                        tail_entry = vote_entry;
                    }
                }

                const total_stake = try readInt(u64, r);
                list.insert(base, &header.node_pubkey, &.{
                    .head = head_offset,
                    .total_stake = total_stake,
                });
            }

            return list;
        }

        pub const EpochAuthorizedVoters = PubkeyMap(Pubkey);

        fn readEpochAuthorizedVoters(
            fba: *std.heap.FixedBufferAllocator,
            r: anytype,
        ) !EpochAuthorizedVoters {
            const base = fba.buffer.ptr;
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
                    if (entry.voter_key.isZeroed()) return error.InvalidAuthorizedVoter;
                    map.insert(base, &entry.voter_key, &entry.auth_key);
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

            // Stakes(.Delegation) -- only care about the VoteAccounts inside
            var vote_accounts = try readEpochStakes(fba, r);

            // total_stake: u64
            const total_stake = try readInt(u64, r);

            // HashMap(Pubkey, Vec(Pubkey))
            const node_to_vote_account_list = try readNodeToVoteAccountList(fba, r, &vote_accounts);

            // epoch_authorized_voters: HashMap(Pubkey, Pubkey)
            const epoch_authorized_voters = try readEpochAuthorizedVoters(fba, r);

            return .{
                .epoch = epoch,
                .total_stake = total_stake,
                .vote_accounts = vote_accounts,
                .node_id_to_vote_accounts = node_to_vote_account_list,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }

        pub fn getVoteAccounts(
            self: *const NodeToVoteAccountList,
            base: [*]u8,
            node_pubkey: *const Pubkey,
        ) ?VoteAccountIterator {
            const node_entry = self.find(base, node_pubkey) orelse return null;
            return .{
                .base = base,
                .total_stake = node_entry.value.total_stake,
                .cursor = node_entry.value.head,
            };
        }

        pub const VoteAccountIterator = struct {
            base: [*]u8,
            total_stake: u64,
            /// Offset of the next Entry to yield; `.isNull()` means iteration is done.
            cursor: RelativeOffset(VoteAccountMap.Entry),

            pub fn next(self: *VoteAccountIterator) ?*VoteAccountMap.Entry {
                if (self.cursor.isNull()) return null;

                const entry = self.cursor.pointer(self.base);
                const next_off = entry.value.next;
                if (next_off.isNull()) @panic("unlinked vote account in node map");

                // last entry points to itself.
                self.cursor = if (next_off.offset == self.cursor.offset) .{} else next_off;
                return entry;
            }
        };
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
        var versioned_epoch_stakes: RelativeSlice(VersionedEpochStakes) = .{};
        {
            const len = readInt(u64, r) catch |err| switch (err) {
                error.EndOfStream => 0,
                else => |e| return e,
            };

            const slice = try fba.allocator().alloc(VersionedEpochStakes, len);
            for (slice) |*versioned_epoch_stake| {
                versioned_epoch_stake.* = try .read(fba, r);
            }

            // sort them by the epoch to make it easier for rooted to store deltas
            std.mem.sortUnstable(VersionedEpochStakes, slice, {}, struct {
                fn lessThan(_: void, a: VersionedEpochStakes, b: VersionedEpochStakes) bool {
                    return a.epoch < b.epoch;
                }
            }.lessThan);

            versioned_epoch_stakes = .fromSlice(fba.buffer.ptr, slice);
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
        //
        // in agave, this field is optional on the deserialize side, but it's
        // actually always populated. we do not need to handle the null case,
        // and it's actually not even possible for replay to work if this is
        // null. so we treat this as a required field.
        if (!try readBool(r)) return error.MissingBlockId; // optional discriminant
        var block_id: Hash = undefined;
        r.readSliceAll(&block_id.data) catch |err| switch (err) {
            error.EndOfStream => return error.MissingBlockId,
            else => |e| return e,
        };

        return .{
            .versioned_epoch_stakes = versioned_epoch_stakes,
            .block_id = block_id,
        };
    }
};

pub fn SnapshotIter(comptime BufReader: type) type {
    return struct {
        tar_iter: TarZstIter(BufReader),
        account_file_len: usize,
        account_file_slot: Slot,
        account_data_len: usize,
        account_data_padding: usize,
        /// Cached from the just-parsed Manifest so `next()` can validate account file
        /// slots without holding a pointer into snapshot_metadata (which lives in
        /// another module and is passed as `anytype` at init time).
        accounts_db_slot: Slot,

        const Self = @This();

        /// `snapshot_metadata` is passed as `anytype` to avoid an import cycle with
        /// `v2/lib/accounts_db.zig`. It must be `*SnapshotMetadata` — the Manifest and
        /// StatusCache are written in place there, and the FBA is expected to live
        /// inside `snapshot_metadata.memory`.
        pub fn init(
            fba: *std.heap.FixedBufferAllocator,
            snapshot_metadata: anytype,
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
                    snapshot_metadata.status_cache = try StatusCache.read(fba, &self.tar_iter);
                    _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                    snapshot_metadata.manifest = try Manifest.read(fba, &self.tar_iter);
                } else {
                    snapshot_metadata.manifest = try Manifest.read(fba, &self.tar_iter);
                    _ = (try self.tar_iter.next()) orelse return error.MissingMetadata;
                    snapshot_metadata.status_cache = try StatusCache.read(fba, &self.tar_iter);
                }
            }

            self.accounts_db_slot = snapshot_metadata.manifest.accounts_db_fields.slot;
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
                if (slot > self.accounts_db_slot)
                    return error.InvalidAccountFileSlot;

                self.account_file_slot = slot;
                self.account_file_len = tar_file.size;
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
        pub fn getBuffer(self: BufReader) []const u8 {
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
    file_size: u64,
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

        self.file_size = (try file.stat()).size;

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

test "RelativeSlice/PubkeyMap round-trip after memcpy" {
    const testing = std.testing;

    var src_buf: [16 * 1024]u8 align(16) = undefined;
    var src_fba = std.heap.FixedBufferAllocator.init(&src_buf);

    // Reserve offset 0 the way Rooted.loadSnapshot will, so no valid entry lands there.
    _ = try src_fba.allocator().alloc(u8, 1);

    var map = try PubkeyMap(Pubkey).init(&src_fba, 8);

    var keys: [8]Pubkey = undefined;
    var vals: [8]Pubkey = undefined;
    for (0..8) |i| {
        keys[i] = .ZEROES;
        keys[i].data[0] = @intCast(i + 1);
        vals[i] = .ZEROES;
        vals[i].data[31] = @intCast(i + 1);
        map.insert(src_fba.buffer.ptr, &keys[i], &vals[i]);
    }
    try testing.expectEqual(@as(u32, 8), map.len);

    // Copy the *entire* fba buffer to a differently-addressed destination.
    var dst_buf: [16 * 1024]u8 align(16) = undefined;
    @memcpy(dst_buf[0..src_buf.len], src_buf[0..]);

    // The same `map` value re-interpreted against a new base must still find every key.
    for (0..8) |i| {
        const entry = map.find(&dst_buf, &keys[i]) orelse
            return error.EntryNotFoundAfterRelocation;
        try testing.expect(entry.value.equals(&vals[i]));
    }
}
