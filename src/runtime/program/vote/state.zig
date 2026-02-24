//! [agave] Analogous to https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L1
const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../../sig.zig");
const vote_program = @import("lib.zig");
const builtin = @import("builtin");
const state_v4 = @import("state_v4.zig");

const Allocator = std.mem.Allocator;

const InstructionError = sig.core.instruction.InstructionError;
const VoteError = vote_program.VoteError;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.hash.Hash;
const SortedMap = sig.utils.collections.SortedMapUnmanaged;
const AccountSharedData = sig.runtime.AccountSharedData;

const SlotHashes = sig.runtime.sysvar.SlotHashes;

pub const VoteStateV4 = state_v4.VoteStateV4;
pub const createTestVoteStateV4 = state_v4.createTestVoteStateV4;

pub const MAX_PRIOR_VOTERS: usize = 32;
pub const MAX_LOCKOUT_HISTORY: usize = 31;
pub const INITIAL_LOCKOUT: usize = 2;

// Maximum number of credits history to keep around
pub const MAX_EPOCH_CREDITS_HISTORY: usize = 64;

// Number of slots of grace period for which maximum vote credits are awarded - votes landing within this number of slots of the slot that is being voted on are awarded full credits.
pub const VOTE_CREDITS_GRACE_SLOTS: u8 = 2;

// Maximum number of credits to award for a vote; this number of credits is awarded to votes on slots that land within the grace period. After that grace period, vote credits are reduced.
pub const VOTE_CREDITS_MAXIMUM_PER_SLOT: u8 = 16;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L357
pub const BlockTimestamp = struct {
    slot: Slot,
    timestamp: i64,

    pub const ZEROES = BlockTimestamp{
        .slot = 0,
        .timestamp = 0,
    };
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L85
pub const Lockout = struct {
    slot: Slot,
    /// The count inclusive of this slot plus the number of
    /// slots voted on top of this slot.
    confirmation_count: u32,

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/0edbce2b461d368e3930fa5ceb9ecc2bd7ad157c/vote-interface/src/state/mod.rs#L117
    pub fn isLockedOutAtSlot(self: *const Lockout, slot: Slot) bool {
        return self.lastLockedOutSlot() >= slot;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/0edbce2b461d368e3930fa5ceb9ecc2bd7ad157c/vote-interface/src/state/mod.rs#L113
    /// The last slot at which a vote is still locked out. Validators should not
    /// vote on a slot in another fork which is less than or equal to this slot
    /// to avoid having their stake slashed.
    pub fn lastLockedOutSlot(self: *const Lockout) Slot {
        return (self.slot +| (self.lockout()));
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/0edbce2b461d368e3930fa5ceb9ecc2bd7ad157c/vote-interface/src/state/mod.rs#L103
    ///
    /// The number of slots for which this vote is locked
    pub fn lockout(self: *const Lockout) u64 {
        return std.math.pow(
            u64,
            INITIAL_LOCKOUT,
            @min(
                self.confirmation_count,
                MAX_LOCKOUT_HISTORY,
            ),
        );
    }

    pub fn eql(self: Lockout, other: Lockout) bool {
        return self.slot == other.slot and
            self.confirmation_count == other.confirmation_count;
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L135
pub const LandedVote = struct {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    latency: u8,
    lockout: Lockout,
};

/// [agave] Analogous tuple [(Pubkey, Epoch, Epoch)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L444.
pub const PriorVote = struct {
    /// authorized voter at the time of the vote.
    key: Pubkey,
    /// the start epoch of the vote (inlcusive).
    start: Epoch,
    /// the end epoch of the vote (exclusive).
    end: Epoch,
};

/// [agave] Analogous tuple [(Epoch, u64, u64)] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L448
pub const EpochCredit = struct {
    epoch: Epoch,
    credits: u64,
    prev_credits: u64,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L58
pub const Vote = struct {
    /// A stack of votes starting with the oldest vote
    slots: []const Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,

    pub const ZEROES: Vote = .{
        .slots = &.{},
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    pub fn deinit(vote: Vote, allocator: Allocator) void {
        allocator.free(vote.slots);
    }

    pub fn clone(self: Vote, allocator: Allocator) Allocator.Error!Vote {
        return .{
            .slots = try allocator.dupe(Slot, self.slots),
            .hash = self.hash,
            .timestamp = self.timestamp,
        };
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/52d80637e13bca19ed65920fbda154993c37dbbe/vote-interface/src/state/mod.rs#L178
pub const VoteStateUpdate = struct {
    /// The proposed tower
    lockouts: std.ArrayListUnmanaged(Lockout),
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,

    pub const ZEROES: VoteStateUpdate = .{
        .lockouts = .{},
        .root = null,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    pub fn deinit(self: VoteStateUpdate, allocator: Allocator) void {
        var lockouts = self.lockouts;
        lockouts.deinit(allocator);
    }
};

pub fn serializeCompactVoteStateUpdate(
    writer: anytype,
    data: anytype,
    _: sig.bincode.Params,
) anyerror!void {
    // Calculate lockout offsets
    var slot = data.root orelse 0;
    var lockouts = std14.BoundedArray(struct {
        Slot,
        u8,
    }, MAX_LOCKOUT_HISTORY){};
    for (data.lockouts.items) |lockout| {
        lockouts.appendAssumeCapacity(.{
            std.math.sub(Slot, lockout.slot, slot) catch
                return error.InvalidVoteLockout,
            std.math.cast(u8, lockout.confirmation_count) orelse
                return error.InvalidConfirmationCount,
        });
        slot = lockout.slot;
    }

    // Serialize in compact format
    try writer.writeInt(Slot, data.root orelse std.math.maxInt(u64), .little);
    try std.leb.writeUleb128(writer, @as(u16, @intCast(lockouts.len)));
    for (lockouts.constSlice()) |lockout| {
        try std.leb.writeUleb128(writer, @as(u16, @intCast(lockout[0])));
        try writer.writeInt(u8, @intCast(lockout[1]), .little);
    }
    try writer.writeAll(&data.hash.data);
    if (data.timestamp) |timestamp| {
        try writer.writeInt(u8, 1, .little);
        try writer.writeInt(i64, timestamp, .little);
    } else {
        try writer.writeInt(u8, 0, .little);
    }
}

pub fn deserializeCompactVoteStateUpdate(
    limit_allocator: *sig.bincode.LimitAllocator,
    reader: anytype,
    _: sig.bincode.Params,
) anyerror!VoteStateUpdate {
    const allocator = limit_allocator.allocator();

    var root: ?Slot = try reader.readInt(Slot, .little);
    root = if (root == std.math.maxInt(Slot)) null else root;

    var slot = root orelse 0;
    const lockouts_len = try std.leb.readUleb128(u16, reader);
    const lockouts = try allocator.alloc(Lockout, lockouts_len);
    errdefer allocator.free(lockouts);
    for (lockouts) |*lockout| {
        const offset = try std.leb.readUleb128(u64, reader);
        const confirmation_count = try reader.readInt(u8, .little);
        slot = try std.math.add(Slot, slot, offset);
        lockout.* = .{ .slot = slot, .confirmation_count = confirmation_count };
    }

    var hash = Hash.ZEROES;
    if (try reader.readAll(&hash.data) != Hash.SIZE) return error.NoBytesLeft;

    const timestamp = switch (try reader.readInt(u8, .little)) {
        0 => null,
        1 => try reader.readInt(i64, .little),
        else => return error.InvalidOptionalTimestamp,
    };

    return VoteStateUpdate{
        .lockouts = .{ .items = lockouts, .capacity = lockouts_len },
        .root = root,
        .hash = hash,
        .timestamp = timestamp,
    };
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/52d80637e13bca19ed65920fbda154993c37dbbe/vote-interface/src/state/mod.rs#L232
pub const TowerSync = struct {
    /// The proposed tower
    lockouts: std.ArrayListUnmanaged(Lockout),
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
    /// the unique identifier for the chain up to and
    /// including this block. Does not require replaying
    /// in order to compute.
    block_id: Hash,

    pub const ZEROES: TowerSync = .{
        .lockouts = .{},
        .root = null,
        .hash = Hash.ZEROES,
        .timestamp = null,
        .block_id = Hash.ZEROES,
    };

    pub fn deinit(self: TowerSync, allocator: Allocator) void {
        var lockouts = self.lockouts;
        lockouts.deinit(allocator);
    }

    pub fn fromLockouts(
        allocator: Allocator,
        lockouts: []const Lockout,
    ) Allocator.Error!TowerSync {
        if (!@import("builtin").is_test) @compileError("Not allowed");
        var result: TowerSync = .ZEROES;
        errdefer result.deinit(allocator);
        try result.lockouts.appendSlice(allocator, lockouts);
        return result;
    }
};

pub fn serializeTowerSync(writer: anytype, data: anytype, _: sig.bincode.Params) anyerror!void {
    // Calculate lockout offsets
    var slot = data.root orelse 0;
    var lockouts = std14.BoundedArray(struct {
        Slot,
        u8,
    }, MAX_LOCKOUT_HISTORY){};
    for (data.lockouts.items) |lockout| {
        lockouts.appendAssumeCapacity(.{
            std.math.sub(Slot, lockout.slot, slot) catch
                return error.InvalidVoteLockout,
            std.math.cast(u8, lockout.confirmation_count) orelse
                return error.InvalidConfirmationCount,
        });
        slot = lockout.slot;
    }

    // Serialize in compact format
    try writer.writeInt(Slot, data.root orelse std.math.maxInt(u64), .little);
    try std.leb.writeUleb128(writer, @as(u16, @intCast(lockouts.len)));
    for (lockouts.constSlice()) |lockout| {
        try std.leb.writeUleb128(writer, lockout[0]);
        try writer.writeInt(u8, lockout[1], .little);
    }
    try writer.writeAll(&data.hash.data);
    if (data.timestamp) |timestamp| {
        try writer.writeInt(u8, 1, .little);
        try writer.writeInt(i64, timestamp, .little);
    } else {
        try writer.writeInt(u8, 0, .little);
    }
    try writer.writeAll(&data.block_id.data);
}

pub fn deserializeTowerSync(
    limit_allocator: *sig.bincode.LimitAllocator,
    reader: anytype,
    _: sig.bincode.Params,
) anyerror!TowerSync {
    const allocator = limit_allocator.allocator();
    var root: ?Slot = try reader.readInt(Slot, .little);
    root = if (root == std.math.maxInt(Slot)) null else root;

    var slot = root orelse 0;
    const lockouts_len = try std.leb.readUleb128(u16, reader);
    const lockouts = try allocator.alloc(Lockout, lockouts_len);
    errdefer allocator.free(lockouts);
    for (lockouts) |*lockout| {
        const offset = try std.leb.readUleb128(u64, reader);
        const confirmation_count = try reader.readInt(u8, .little);
        slot = try std.math.add(Slot, slot, offset);
        lockout.* = .{ .slot = slot, .confirmation_count = confirmation_count };
    }

    var hash = Hash.ZEROES;
    if (try reader.readAll(&hash.data) != Hash.SIZE) return error.NoBytesLeft;

    const timestamp = switch (try reader.readInt(u8, .little)) {
        0 => null,
        1 => try reader.readInt(i64, .little),
        else => return error.InvalidOptionalTimestamp,
    };

    var block_id = Hash.ZEROES;
    if (try reader.readAll(&block_id.data) != Hash.SIZE) return error.NoBytesLeft;

    return TowerSync{
        .lockouts = .{ .items = lockouts, .capacity = lockouts_len },
        .root = root,
        .hash = hash,
        .timestamp = timestamp,
        .block_id = block_id,
    };
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/52d80637e13bca19ed65920fbda154993c37dbbe/vote-interface/src/authorized_voters.rs#L11
pub const AuthorizedVoters = struct {
    voters: SortedMap(Epoch, Pubkey),

    pub const EMPTY: AuthorizedVoters = .{ .voters = .empty };
    pub const @"!bincode-config": sig.bincode.FieldConfig(AuthorizedVoters) = .{
        .deserializer = deserialize,
        .serializer = serialize,
    };

    pub fn init(allocator: Allocator, epoch: Epoch, pubkey: Pubkey) !AuthorizedVoters {
        var authorized_voters: SortedMap(Epoch, Pubkey) = .empty;
        try authorized_voters.put(allocator, epoch, pubkey);
        return .{ .voters = authorized_voters };
    }

    pub fn deinit(self: AuthorizedVoters, allocator: Allocator) void {
        self.voters.deinit(allocator);
    }

    pub fn clone(self: *const AuthorizedVoters, allocator: Allocator) !AuthorizedVoters {
        return .{ .voters = try self.voters.clone(allocator) };
    }

    pub fn count(self: *const AuthorizedVoters) usize {
        return self.voters.count();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L22
    pub fn getAuthorizedVoter(self: *AuthorizedVoters, epoch: Epoch) ?Pubkey {
        if (self.getOrCalculateAuthorizedVoterForEpoch(epoch)) |entry| {
            return entry[0];
        } else {
            return null;
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L27
    pub fn getAndCacheAuthorizedVoterForEpoch(
        self: *AuthorizedVoters,
        allocator: Allocator,
        epoch: Epoch,
    ) !?Pubkey {
        if (self.getOrCalculateAuthorizedVoterForEpoch(epoch)) |entry| {
            const pubkey, const existed = entry;
            if (!existed) try self.voters.put(allocator, epoch, pubkey);
            return pubkey;
        } else {
            return null;
        }
    }

    pub fn insert(
        self: *AuthorizedVoters,
        allocator: Allocator,
        epoch: Epoch,
        authorized_voter: Pubkey,
    ) !void {
        try self.voters.put(allocator, epoch, authorized_voter);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L42
    pub fn purgeAuthorizedVoters(
        self: *AuthorizedVoters,
        allocator: Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!bool {
        var expired_keys = std.array_list.Managed(Epoch).init(allocator);
        defer expired_keys.deinit();

        var voter_iter = self.voters.iterator();
        while (voter_iter.next()) |entry| {
            if (entry.key_ptr.* < current_epoch) {
                try expired_keys.append(entry.key_ptr.*);
            }
        }

        for (expired_keys.items) |key| {
            _ = self.voters.swapRemoveNoSort(key);
        }
        self.voters.sort();

        // Have to uphold this invariant b/c this is
        // 1) The check for whether the vote state is initialized
        // 2) How future authorized voters for uninitialized epochs are set
        //    by this function
        std.debug.assert(self.voters.count() != 0);
        return true;
    }

    /// [SIMD-0185] For vote state v4: purge only entries less than (current_epoch - 1)
    /// so that authorized_voters can hold [current_epoch - 1, current_epoch + 2].
    pub fn purgeAuthorizedVotersPreviousEpoch(
        self: *AuthorizedVoters,
        allocator: Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!void {
        const min_epoch = if (current_epoch > 0) current_epoch - 1 else 0;
        var expired_keys: std.ArrayList(Epoch) = .{};
        defer expired_keys.deinit(allocator);

        var voter_iter = self.voters.iterator();
        while (voter_iter.next()) |entry| {
            if (entry.key_ptr.* < min_epoch) {
                try expired_keys.append(allocator, entry.key_ptr.*);
            }
        }

        for (expired_keys.items) |key| {
            _ = self.voters.swapRemoveNoSort(key);
        }
        self.voters.sort();

        // Have to uphold this invariant b/c this is
        // 1) The check for whether the vote state is initialized
        // 2) How future authorized voters for uninitialized epochs are set
        //    by this function
        std.debug.assert(self.voters.count() != 0);
    }

    pub fn isEmpty(self: *const AuthorizedVoters) bool {
        return self.voters.count() == 0;
    }

    pub fn first(self: *AuthorizedVoters) ?struct { Epoch, Pubkey } {
        var voter_iter = self.voters.iterator();
        if (voter_iter.next()) |entry| {
            return .{ entry.key_ptr.*, entry.value_ptr.* };
        } else {
            return null;
        }
    }

    pub fn last(self: *const AuthorizedVoters) ?struct { Epoch, Pubkey } {
        const last_epoch = self.voters.max orelse return null;
        if (self.voters.get(last_epoch)) |last_pubkey| {
            return .{ last_epoch, last_pubkey };
        } else {
            return null;
        }
    }

    pub fn len(self: *const AuthorizedVoters) usize {
        return self.voters.count();
    }

    pub fn contains(self: *const AuthorizedVoters, epoch: Epoch) bool {
        return self.voters.contains(epoch);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/authorized_voters.rs#L90
    ///
    /// Returns the authorized voter at the given epoch if the epoch is >= the
    /// current epoch, and a bool indicating whether the entry for this epoch
    /// exists in the self.authorized_voter map
    fn getOrCalculateAuthorizedVoterForEpoch(
        self: *AuthorizedVoters,
        epoch: Epoch,
    ) ?struct { Pubkey, bool } {
        if (self.voters.get(epoch)) |pubkey| {
            return .{ pubkey, true };
        } else {
            _, const values = self.voters.range(0, epoch);
            if (values.len == 0) {
                return null;
            }
            const last_voter = values[values.len - 1];
            return .{ last_voter, false };
        }
    }

    fn deserialize(
        limit_allocator: *sig.bincode.LimitAllocator,
        reader: anytype,
        _: sig.bincode.Params,
    ) !AuthorizedVoters {
        const allocator = limit_allocator.allocator();

        var authorized_voters: AuthorizedVoters = .EMPTY;
        errdefer authorized_voters.deinit(allocator);

        for (0..try reader.readInt(u64, .little)) |_| {
            const epoch = try reader.readInt(u64, .little);
            var pubkey = Pubkey.ZEROES;
            const bytes_read = try reader.readAll(&pubkey.data);
            if (bytes_read != Pubkey.SIZE) return error.NoBytesLeft;
            try authorized_voters.voters.put(allocator, epoch, pubkey);
        }

        return authorized_voters;
    }

    pub fn serialize(writer: anytype, data: AuthorizedVoters, _: sig.bincode.Params) !void {
        var authorized_voters = data;
        try writer.writeInt(u64, data.len(), .little);
        const epochs, const pubkeys = authorized_voters.voters.items();
        for (epochs, pubkeys) |epoch, key| {
            try writer.writeInt(u64, epoch, .little);
            try writer.writeAll(&key.data);
        }
    }

    pub fn equals(self: *const AuthorizedVoters, other: *const AuthorizedVoters) bool {
        if (self.count() != other.count()) return false;
        var self_voters = self.voters;
        var other_voters = other.voters;
        for (self_voters.keys()) |key| {
            const self_value = self_voters.get(key).?;
            const other_value = other_voters.get(key) orelse return false;
            if (!self_value.equals(&other_value)) return false;
        }
        return true;
    }
};

const CircBufV0 = struct {
    buf: [MAX_PRIOR_VOTERS]Entry,
    idx: usize,

    const Entry = struct { Pubkey, Epoch, Epoch, Slot };

    pub fn init() CircBufV0 {
        return .{
            .buf = [_]Entry{std.mem.zeroes(Entry)} ** MAX_PRIOR_VOTERS,
            .idx = MAX_PRIOR_VOTERS - 1,
        };
    }

    pub fn append(self: *CircBufV0, entry: Entry) void {
        self.idx = (self.idx + 1) % MAX_PRIOR_VOTERS;
        self.buf[self.idx] = entry;
    }
};

pub const CircBufV1 = struct {
    buf: [MAX_PRIOR_VOTERS]Entry,
    idx: usize,
    is_empty: bool,

    const Entry = PriorVote;

    pub fn init() CircBufV1 {
        return .{
            .buf = [_]Entry{std.mem.zeroes(Entry)} ** MAX_PRIOR_VOTERS,
            .idx = MAX_PRIOR_VOTERS - 1,
            .is_empty = true,
        };
    }

    pub fn append(self: *CircBufV1, entry: Entry) void {
        self.idx = (self.idx + 1) % MAX_PRIOR_VOTERS;
        self.buf[self.idx] = entry;
        self.is_empty = false;
    }

    pub fn last(self: *const CircBufV1) ?Entry {
        if (self.is_empty) {
            return null;
        }
        return if (self.idx < self.buf.len) self.buf[self.idx] else null;
    }

    pub fn equals(self: CircBufV1, other: CircBufV1) bool {
        if (self.is_empty != other.is_empty) return false;
        if (self.is_empty) return true;

        var self_idx = self.idx;
        var other_idx = other.idx;
        for (0..MAX_PRIOR_VOTERS) |_| {
            if (!std.meta.eql(self.buf[self_idx], other.buf[other_idx])) return false;
            self_idx = (self_idx + 1) % MAX_PRIOR_VOTERS;
            other_idx = (other_idx + 1) % MAX_PRIOR_VOTERS;
        }

        return true;
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L20
/// [SIMD-0185] v4 added with discriminant 3.
pub const VoteStateVersions = union(enum(u32)) {
    v0_23_5: VoteState0_23_5,
    v1_14_11: VoteState1_14_11,
    v3: VoteStateV3,
    v4: VoteStateV4,

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L80
    pub fn landedVotesFromLockouts(
        allocator: Allocator,
        lockouts: []const Lockout,
    ) ![]LandedVote {
        const landed_votes = try allocator.alloc(LandedVote, lockouts.len);
        errdefer allocator.free(landed_votes);

        for (landed_votes, lockouts) |*landed, lockout| {
            landed.* = .{
                .latency = 0,
                .lockout = lockout,
            };
        }

        return landed_votes;
    }

    pub fn deinit(self: *const VoteStateVersions, allocator: Allocator) void {
        switch (self.*) {
            .v0_23_5 => |*vote_state| vote_state.deinit(allocator),
            .v1_14_11 => |*vote_state| vote_state.deinit(allocator),
            .v3 => |*vote_state| vote_state.deinit(allocator),
            .v4 => |*vote_state| vote_state.deinit(allocator),
        }
    }

    pub fn isCorrectSizeAndInitialized(data: []const u8) bool {
        return VoteStateV3.isCorrectSizeAndInitialized(data) or
            VoteState1_14_11.isCorrectSizeAndInitialized(data) or
            VoteStateV4.isCorrectSizeAndInitialized(data);
    }

    /// Takes ownership of the contained vote state and will either free it or return it.
    ///
    /// [SIMD-0185] Returns VoteStateV4 with default values for new fields when converting from older versions.
    /// vote_pubkey: when provided, used as inflation_rewards_collector default for old versions.
    ///
    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L31
    fn convertToV4(
        self: VoteStateVersions,
        /// must be the allocator used to allocate self
        allocator: Allocator,
        vote_pubkey: ?Pubkey,
    ) !VoteStateV4 {
        const default_collector = vote_pubkey orelse Pubkey.ZEROES;
        switch (self) {
            .v0_23_5 => |state| {
                defer self.deinit(allocator);

                const authorized_voters: AuthorizedVoters = if (state.voter.isZeroed())
                    .EMPTY
                else
                    try AuthorizedVoters.init(
                        allocator,
                        state.voter_epoch,
                        state.voter,
                    );
                errdefer authorized_voters.deinit(allocator);

                const votes = try VoteStateVersions.landedVotesFromLockouts(
                    allocator,
                    state.votes.items,
                );
                errdefer allocator.free(votes);

                const epoch_credits = try state.epoch_credits.clone(allocator);
                errdefer epoch_credits.deinit(allocator);

                return .{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .inflation_rewards_collector = default_collector,
                    .block_revenue_collector = state.node_pubkey,
                    .inflation_rewards_commission_bps = @as(u16, state.commission) * 100,
                    .block_revenue_commission_bps = 10_000,
                    .pending_delegator_rewards = 0,
                    .bls_pubkey_compressed = null,
                    .votes = .fromOwnedSlice(votes),
                    .root_slot = state.root_slot,
                    .authorized_voters = authorized_voters,
                    .epoch_credits = epoch_credits,
                    .last_timestamp = state.last_timestamp,
                };
            },
            .v1_14_11 => |state| {
                defer self.deinit(allocator);

                const authorized_voters = try state.voters.clone(allocator);
                errdefer authorized_voters.deinit(allocator);

                const votes = try VoteStateVersions.landedVotesFromLockouts(
                    allocator,
                    state.votes.items,
                );
                errdefer allocator.free(votes);

                const epoch_credits = try state.epoch_credits.clone(allocator);
                errdefer epoch_credits.deinit(allocator);

                return .{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .inflation_rewards_collector = default_collector,
                    .block_revenue_collector = state.node_pubkey,
                    .inflation_rewards_commission_bps = @as(u16, state.commission) * 100,
                    .block_revenue_commission_bps = 10_000,
                    .pending_delegator_rewards = 0,
                    .bls_pubkey_compressed = null,
                    .votes = .fromOwnedSlice(votes),
                    .root_slot = state.root_slot,
                    .authorized_voters = authorized_voters,
                    .epoch_credits = epoch_credits,
                    .last_timestamp = state.last_timestamp,
                };
            },
            .v3 => |state| {
                defer self.deinit(allocator);

                var authorized_voters = try state.voters.clone(allocator);
                errdefer authorized_voters.deinit(allocator);

                var votes = try state.votes.clone(allocator);
                errdefer votes.deinit(allocator);

                var epoch_credits = try state.epoch_credits.clone(allocator);
                errdefer epoch_credits.deinit(allocator);

                return .{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .inflation_rewards_collector = default_collector,
                    .block_revenue_collector = state.node_pubkey,
                    .inflation_rewards_commission_bps = @as(u16, state.commission) * 100,
                    .block_revenue_commission_bps = 10_000,
                    .pending_delegator_rewards = 0,
                    .bls_pubkey_compressed = null,
                    .votes = votes,
                    .root_slot = state.root_slot,
                    .authorized_voters = authorized_voters,
                    .epoch_credits = epoch_credits,
                    .last_timestamp = state.last_timestamp,
                };
            },
            .v4 => |state| return state,
        }
    }

    /// Convert to the unified VoteState union. Old versions (v0, v1) are upgraded:
    /// if target is v4, they convert to VoteStateV4; if target is v3, they convert to VoteStateV3.
    /// The `target_version` determines which union variant the result will be when converting
    /// from old formats. Already-v3/v4 states map directly to their respective union variant.
    pub fn convertToVoteState(
        self: VoteStateVersions,
        allocator: Allocator,
        vote_pubkey: ?Pubkey,
        target_v4: bool,
    ) !VoteState {
        if (target_v4) {
            return .{ .v4 = try self.convertToV4(allocator, vote_pubkey) };
        }
        // target is v3: convert old versions to v3, v4 stays v4
        switch (self) {
            .v3 => |state| return .{ .v3 = state },
            .v4 => |state| return .{ .v4 = state },
            .v0_23_5 => |state| {
                defer self.deinit(allocator);

                const authorized_voters: AuthorizedVoters = if (state.voter.isZeroed())
                    .EMPTY
                else
                    try AuthorizedVoters.init(
                        allocator,
                        state.voter_epoch,
                        state.voter,
                    );
                errdefer authorized_voters.deinit(allocator);

                const votes_slice = try VoteStateVersions.landedVotesFromLockouts(
                    allocator,
                    state.votes.items,
                );
                errdefer allocator.free(votes_slice);

                const epoch_credits = try state.epoch_credits.clone(allocator);
                errdefer epoch_credits.deinit(allocator);

                return .{ .v3 = .{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .commission = state.commission,
                    .votes = .fromOwnedSlice(votes_slice),
                    .root_slot = state.root_slot,
                    .voters = authorized_voters,
                    .prior_voters = CircBufV1.init(),
                    .epoch_credits = epoch_credits,
                    .last_timestamp = state.last_timestamp,
                } };
            },
            .v1_14_11 => |state| {
                defer self.deinit(allocator);

                const authorized_voters = try state.voters.clone(allocator);
                errdefer authorized_voters.deinit(allocator);

                const votes_slice = try VoteStateVersions.landedVotesFromLockouts(
                    allocator,
                    state.votes.items,
                );
                errdefer allocator.free(votes_slice);

                const epoch_credits = try state.epoch_credits.clone(allocator);
                errdefer epoch_credits.deinit(allocator);

                return .{ .v3 = .{
                    .node_pubkey = state.node_pubkey,
                    .withdrawer = state.withdrawer,
                    .commission = state.commission,
                    .votes = .fromOwnedSlice(votes_slice),
                    .root_slot = state.root_slot,
                    .voters = authorized_voters,
                    .prior_voters = state.prior_voters,
                    .epoch_credits = epoch_credits,
                    .last_timestamp = state.last_timestamp,
                } };
            },
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    /// [SIMD-0185] v4 is never uninitialized.
    pub fn isUninitialized(self: VoteStateVersions) bool {
        switch (self) {
            .v0_23_5 => |state| return state.voter.equals(&Pubkey.ZEROES),
            .v1_14_11 => |state| return state.voters.count() == 0,
            .v3 => |state| return state.voters.count() == 0,
            .v4 => |_| return false,
        }
    }
};

/// Unified vote state that wraps either VoteStateV3 or VoteStateV4, centralizing
/// version-dependent dispatch so callers don't need to track `use_v4` / `target_version`.
pub const VoteState = union(enum(u32)) {
    v3: VoteStateV3 = 2,
    v4: VoteStateV4 = 3,

    // ── Construction / lifecycle ──────────────────────────────────────

    pub fn initV3(
        allocator: Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission_val: u8,
        voter_epoch: Epoch,
    ) Allocator.Error!VoteState {
        return .{ .v3 = try VoteStateV3.init(
            allocator,
            node_pubkey,
            authorized_voter,
            withdrawer,
            commission_val,
            voter_epoch,
        ) };
    }

    pub fn initV4(
        allocator: Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission_pct: u8,
        voter_epoch: Epoch,
        vote_pubkey: Pubkey,
    ) Allocator.Error!VoteState {
        return .{ .v4 = try VoteStateV4.init(
            allocator,
            node_pubkey,
            authorized_voter,
            withdrawer,
            commission_pct,
            voter_epoch,
            vote_pubkey,
        ) };
    }

    pub fn deinit(self: *const VoteState, allocator: Allocator) void {
        switch (self.*) {
            inline else => |*s| s.deinit(allocator),
        }
    }

    pub fn clone(self: VoteState, allocator: Allocator) Allocator.Error!VoteState {
        return switch (self) {
            .v3 => |s| .{ .v3 = try s.clone(allocator) },
            .v4 => |s| .{ .v4 = try s.clone(allocator) },
        };
    }

    pub fn equals(self: *const VoteState, other: *const VoteState) bool {
        return switch (self.*) {
            .v3 => |*s| switch (other.*) {
                .v3 => |*o| s.equals(o),
                .v4 => false,
            },
            .v4 => |*s| switch (other.*) {
                .v4 => |*o| s.equals(o),
                .v3 => false,
            },
        };
    }

    // ── Field accessors ──────────────────────────────────────────────
    // These provide uniform access to fields that exist on both V3 and V4,
    // even if they have different names (e.g. V3 `voters` vs V4 `authorized_voters`).

    pub fn nodePubkey(self: *const VoteState) *const Pubkey {
        return switch (self.*) {
            .v3 => |*s| &s.node_pubkey,
            .v4 => |*s| &s.node_pubkey,
        };
    }

    pub fn nodePubkeyMut(self: *VoteState) *Pubkey {
        return switch (self.*) {
            .v3 => |*s| &s.node_pubkey,
            .v4 => |*s| &s.node_pubkey,
        };
    }

    pub fn withdrawerKey(self: *const VoteState) *const Pubkey {
        return switch (self.*) {
            .v3 => |*s| &s.withdrawer,
            .v4 => |*s| &s.withdrawer,
        };
    }

    pub fn withdrawerMut(self: *VoteState) *Pubkey {
        return switch (self.*) {
            .v3 => |*s| &s.withdrawer,
            .v4 => |*s| &s.withdrawer,
        };
    }

    pub fn commission(self: *const VoteState) u8 {
        return switch (self.*) {
            .v3 => |s| s.commission,
            .v4 => |*s| s.commission(),
        };
    }

    /// Set commission. V3: sets field directly. V4: sets inflation_rewards_commission_bps.
    pub fn setCommission(self: *VoteState, commission_pct: u8) void {
        switch (self.*) {
            .v3 => |*s| s.commission = commission_pct,
            .v4 => |*s| s.inflation_rewards_commission_bps = @as(u16, commission_pct) * 100,
        }
    }

    pub fn votes(self: *const VoteState) *const std.ArrayListUnmanaged(LandedVote) {
        return switch (self.*) {
            .v3 => |*s| &s.votes,
            .v4 => |*s| &s.votes,
        };
    }

    pub fn votesMut(self: *VoteState) *std.ArrayListUnmanaged(LandedVote) {
        return switch (self.*) {
            .v3 => |*s| &s.votes,
            .v4 => |*s| &s.votes,
        };
    }

    pub fn rootSlot(self: *const VoteState) ?Slot {
        return switch (self.*) {
            .v3 => |s| s.root_slot,
            .v4 => |s| s.root_slot,
        };
    }

    pub fn rootSlotMut(self: *VoteState) *?Slot {
        return switch (self.*) {
            .v3 => |*s| &s.root_slot,
            .v4 => |*s| &s.root_slot,
        };
    }

    pub fn authorizedVoters(self: *const VoteState) *const AuthorizedVoters {
        return switch (self.*) {
            .v3 => |*s| &s.voters,
            .v4 => |*s| &s.authorized_voters,
        };
    }

    pub fn authorizedVotersMut(self: *VoteState) *AuthorizedVoters {
        return switch (self.*) {
            .v3 => |*s| &s.voters,
            .v4 => |*s| &s.authorized_voters,
        };
    }

    pub fn epochCreditsList(self: *const VoteState) *const std.ArrayListUnmanaged(EpochCredit) {
        return switch (self.*) {
            .v3 => |*s| &s.epoch_credits,
            .v4 => |*s| &s.epoch_credits,
        };
    }

    pub fn epochCreditsListMut(self: *VoteState) *std.ArrayListUnmanaged(EpochCredit) {
        return switch (self.*) {
            .v3 => |*s| &s.epoch_credits,
            .v4 => |*s| &s.epoch_credits,
        };
    }

    pub fn lastTimestamp(self: *const VoteState) BlockTimestamp {
        return switch (self.*) {
            .v3 => |s| s.last_timestamp,
            .v4 => |s| s.last_timestamp,
        };
    }

    // ── V4-specific field accessors ──────────────────────────────────

    pub fn inflationRewardsCommissionBps(self: *const VoteState) ?u16 {
        return switch (self.*) {
            .v3 => null,
            .v4 => |s| s.inflation_rewards_commission_bps,
        };
    }

    pub fn setInflationRewardsCommissionBps(self: *VoteState, bps: u16) void {
        switch (self.*) {
            .v3 => {},
            .v4 => |*s| s.inflation_rewards_commission_bps = bps,
        }
    }

    pub fn blockRevenueCollector(self: *const VoteState) ?*const Pubkey {
        return switch (self.*) {
            .v3 => null,
            .v4 => |*s| &s.block_revenue_collector,
        };
    }

    pub fn blockRevenueCollectorMut(self: *VoteState) ?*Pubkey {
        return switch (self.*) {
            .v3 => null,
            .v4 => |*s| &s.block_revenue_collector,
        };
    }

    pub fn inflationRewardsCollector(self: *const VoteState) ?*const Pubkey {
        return switch (self.*) {
            .v3 => null,
            .v4 => |*s| &s.inflation_rewards_collector,
        };
    }

    // ── Delegating methods (same interface on both V3 and V4) ────────

    pub fn isUninitialized(self: VoteState) bool {
        return switch (self) {
            .v3 => |s| s.isUninitialized(),
            .v4 => |s| s.isUninitialized(),
        };
    }

    pub fn epochCredits(self: *const VoteState) u64 {
        return switch (self.*) {
            inline else => |*s| s.epochCredits(),
        };
    }

    pub fn lastLockout(self: *const VoteState) ?Lockout {
        return switch (self.*) {
            inline else => |*s| s.lastLockout(),
        };
    }

    pub fn lastVotedSlot(self: *const VoteState) ?Slot {
        return switch (self.*) {
            inline else => |*s| s.lastVotedSlot(),
        };
    }

    pub fn creditsForVoteAtIndex(self: *const VoteState, index: usize) u64 {
        return switch (self.*) {
            inline else => |*s| s.creditsForVoteAtIndex(index),
        };
    }

    pub fn getCredits(self: *const VoteState) u64 {
        return switch (self.*) {
            inline else => |*s| s.getCredits(),
        };
    }

    pub fn incrementCredits(
        self: *VoteState,
        allocator: Allocator,
        epoch: Epoch,
        credits: u64,
    ) error{OutOfMemory}!void {
        switch (self.*) {
            inline else => |*s| try s.incrementCredits(allocator, epoch, credits),
        }
    }

    pub fn containsSlot(self: *const VoteState, candidate_slot: Slot) bool {
        return switch (self.*) {
            inline else => |*s| s.containsSlot(candidate_slot),
        };
    }

    pub fn processTimestamp(self: *VoteState, slot: Slot, timestamp: i64) ?VoteError {
        return switch (self.*) {
            inline else => |*s| s.processTimestamp(slot, timestamp),
        };
    }

    pub fn popExpiredVotes(self: *VoteState, next_vote_slot: Slot) void {
        switch (self.*) {
            inline else => |*s| s.popExpiredVotes(next_vote_slot),
        }
    }

    pub fn doubleLockouts(self: *VoteState) !void {
        switch (self.*) {
            inline else => |*s| try s.doubleLockouts(),
        }
    }

    pub fn processNextVoteSlot(
        self: *VoteState,
        allocator: Allocator,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) !void {
        switch (self.*) {
            inline else => |*s| try s.processNextVoteSlot(
                allocator,
                next_vote_slot,
                epoch,
                current_slot,
            ),
        }
    }

    pub fn setNewAuthorizedVoter(
        self: *VoteState,
        allocator: Allocator,
        new_authorized_voter: Pubkey,
        target_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.setNewAuthorizedVoter(
                allocator,
                new_authorized_voter,
                target_epoch,
            ),
        };
    }

    /// Dispatch getAndUpdateAuthorizedVoter. V3 always uses V3 purge; V4 always uses V4 purge.
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteState,
        allocator: Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!Pubkey {
        return switch (self.*) {
            .v3 => |*s| try s.getAndUpdateAuthorizedVoter(allocator, current_epoch),
            .v4 => |*s| try s.getAndUpdateAuthorizedVoter(allocator, current_epoch, true),
        };
    }

    pub fn checkSlotsAreValid(
        self: *const VoteState,
        vote: *const Vote,
        recent_vote_slots: []const Slot,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.checkSlotsAreValid(vote, recent_vote_slots, slot_hashes),
        };
    }

    pub fn processVote(
        self: *VoteState,
        allocator: Allocator,
        vote: *const Vote,
        slot_hashes: SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.processVote(allocator, vote, slot_hashes, epoch, current_slot),
        };
    }

    pub fn processVoteUnfiltered(
        self: *VoteState,
        allocator: Allocator,
        recent_vote_slots: []const Slot,
        vote: *const Vote,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.processVoteUnfiltered(
                allocator,
                recent_vote_slots,
                vote,
                slot_hashes,
                epoch,
                current_slot,
            ),
        };
    }

    pub fn processVoteStateUpdate(
        self: *VoteState,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        vote_state_update: *VoteStateUpdate,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.processVoteStateUpdate(
                allocator,
                slot_hashes,
                epoch,
                slot,
                vote_state_update,
            ),
        };
    }

    pub fn processTowerSync(
        self: *VoteState,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        tower_sync: *TowerSync,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.processTowerSync(
                allocator,
                slot_hashes,
                epoch,
                slot,
                tower_sync,
            ),
        };
    }

    pub fn checkAndFilterProposedVoteState(
        self: *VoteState,
        proposed_lockouts: *std.ArrayListUnmanaged(Lockout),
        proposed_root: *?Slot,
        proposed_hash: Hash,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.checkAndFilterProposedVoteState(
                proposed_lockouts,
                proposed_root,
                proposed_hash,
                slot_hashes,
            ),
        };
    }

    pub fn processNewVoteState(
        self: *VoteState,
        allocator: Allocator,
        new_state: []LandedVote,
        new_root: ?Slot,
        timestamp: ?i64,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        return switch (self.*) {
            inline else => |*s| try s.processNewVoteState(
                allocator,
                new_state,
                new_root,
                timestamp,
                epoch,
                current_slot,
            ),
        };
    }

    pub fn computeVoteLatency(voted_for_slot: Slot, current_slot: Slot) u8 {
        return VoteStateV3.computeVoteLatency(voted_for_slot, current_slot);
    }

    // ── Version queries ──────────────────────────────────────────────

    pub fn isV4(self: VoteState) bool {
        return self == .v4;
    }

    pub fn isV3(self: VoteState) bool {
        return self == .v3;
    }

    /// Access the underlying VoteStateV3, if this is a V3 state.
    pub fn asV3(self: *VoteState) ?*VoteStateV3 {
        return switch (self.*) {
            .v3 => |*s| s,
            .v4 => null,
        };
    }

    /// Access the underlying VoteStateV4, if this is a V4 state.
    pub fn asV4(self: *VoteState) ?*VoteStateV4 {
        return switch (self.*) {
            .v3 => null,
            .v4 => |*s| s,
        };
    }

    pub fn asV3Const(self: *const VoteState) ?*const VoteStateV3 {
        return switch (self.*) {
            .v3 => |*s| s,
            .v4 => null,
        };
    }

    pub fn asV4Const(self: *const VoteState) ?*const VoteStateV4 {
        return switch (self.*) {
            .v3 => null,
            .v4 => |*s| s,
        };
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_0_23_5.rs#L11
pub const VoteState0_23_5 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for vote transactions
    voter: Pubkey,

    /// when the authorized voter was set/initialized
    voter_epoch: Epoch,

    /// history of prior authorized voters and the epoch ranges for which
    ///  they were set
    prior_voters: CircBufV0,

    /// the signer for withdrawals
    withdrawer: Pubkey,

    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayListUnmanaged(Lockout),

    root_slot: ?Slot,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayListUnmanaged(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    pub fn init(
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission: u8,
        voter_epoch: Epoch,
    ) !VoteState0_23_5 {
        return .{
            .node_pubkey = node_pubkey,
            .voter = authorized_voter,
            .voter_epoch = voter_epoch,
            .prior_voters = CircBufV0.init(),
            .withdrawer = withdrawer,
            .commission = commission,
            .votes = .empty,
            .root_slot = null,
            .epoch_credits = .empty,
            .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: *const VoteState0_23_5, allocator: Allocator) void {
        var votes = self.votes;
        votes.deinit(allocator);
        var epoch_credits = self.epoch_credits;
        epoch_credits.deinit(allocator);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_1_14_11.rs#L16
pub const VoteState1_14_11 = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    // TODO this should be a double ended queue.
    votes: std.ArrayListUnmanaged(Lockout),

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBufV1,

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: std.ArrayListUnmanaged(EpochCredit),

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const MAX_VOTE_STATE_SIZE: usize = 3731;

    // Offset of VoteState1_4_11::prior_voters, for determining initialization status without deserialization
    const DEFAULT_PRIOR_VOTERS_OFFSET: usize = 82;

    pub fn init(
        allocator: Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission: u8,
        voter_epoch: Epoch,
    ) !VoteState1_14_11 {
        const authorized_voters = try AuthorizedVoters.init(
            allocator,
            voter_epoch,
            authorized_voter,
        );
        errdefer authorized_voters.deinit(allocator);

        return .{
            .node_pubkey = node_pubkey,
            .withdrawer = withdrawer,
            .commission = commission,
            .votes = .empty,
            .root_slot = null,
            .voters = authorized_voters,
            .prior_voters = CircBufV1.init(),
            .epoch_credits = .empty,
            .last_timestamp = .{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: *const VoteState1_14_11, allocator: Allocator) void {
        var votes = self.votes;
        votes.deinit(allocator);
        self.voters.deinit(allocator);
        var epoch_credits = self.epoch_credits;
        epoch_credits.deinit(allocator);
    }

    pub fn isCorrectSizeAndInitialized(data: []const u8) bool {
        return data.len == MAX_VOTE_STATE_SIZE and
            !std.mem.allEqual(u8, data[4..][0..DEFAULT_PRIOR_VOTERS_OFFSET], 0);
    }
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/991954602e718d646c0d28717e135314f72cdb78/vote-interface/src/state/mod.rs#L422
pub const VoteStateV3 = struct {
    /// The node that votes in this account.
    node_pubkey: Pubkey,
    /// The signer for withdrawals.
    withdrawer: Pubkey,
    /// Percentage (must be in [0, 100]), that represents what part of
    /// a rewards payout should be given to this VoteAccount.
    commission: u8,
    votes: std.ArrayListUnmanaged(LandedVote),
    /// This is usually the last Lockout which was poped from `votes`,
    /// however, it may be an arbitrary slot when being used inside Tower.
    root_slot: ?Slot,
    /// The signer for Vote transactions.
    voters: AuthorizedVoters,
    /// A history of prior authorized voters and the epochs for which
    /// they were set.
    /// The bottom end of the range is inclusive and the top is exclusive.
    prior_voters: CircBufV1,
    /// A history of how many credits earned by the end of each epoch.
    epoch_credits: std.ArrayListUnmanaged(EpochCredit),
    /// The most recent timestamp submitted with a vote.
    last_timestamp: BlockTimestamp,

    /// Upper limit on the size of the Vote State
    /// when votes.len() is MAX_LOCKOUT_HISTORY.
    pub const MAX_VOTE_STATE_SIZE: usize = 3762;

    // Offset of VoteStateV3::prior_voters, for determining initialization status without deserialization
    const DEFAULT_PRIOR_VOTERS_OFFSET: usize = 114;

    pub const DEFAULT: VoteStateV3 = .{
        .node_pubkey = Pubkey.ZEROES,
        .withdrawer = Pubkey.ZEROES,
        .commission = 0,
        .votes = .empty,
        .root_slot = null,
        .voters = .EMPTY,
        .prior_voters = CircBufV1.init(),
        .epoch_credits = .empty,
        .last_timestamp = .{ .slot = 0, .timestamp = 0 },
    };

    pub fn init(
        allocator: Allocator,
        node_pubkey: Pubkey,
        authorized_voter: Pubkey,
        withdrawer: Pubkey,
        commission: u8,
        voter_epoch: Epoch,
    ) Allocator.Error!VoteStateV3 {
        const authorized_voters = try AuthorizedVoters.init(
            allocator,
            voter_epoch,
            authorized_voter,
        );
        errdefer authorized_voters.deinit(allocator);

        return .{
            .node_pubkey = node_pubkey,
            .voters = authorized_voters,
            .withdrawer = withdrawer,
            .commission = commission,
            .votes = .empty,
            .root_slot = null,
            .prior_voters = .init(),
            .epoch_credits = .empty,
            .last_timestamp = .{ .slot = 0, .timestamp = 0 },
        };
    }

    pub fn deinit(self: *const VoteStateV3, allocator: Allocator) void {
        var votes = self.votes;
        votes.deinit(allocator);
        self.voters.deinit(allocator);
        var epoch_credits = self.epoch_credits;
        epoch_credits.deinit(allocator);
    }

    pub fn clone(self: VoteStateV3, allocator: Allocator) Allocator.Error!VoteStateV3 {
        var votes = try self.votes.clone(allocator);
        errdefer votes.deinit(allocator);

        const voters = try self.voters.clone(allocator);
        errdefer voters.deinit(allocator);

        return .{
            .node_pubkey = self.node_pubkey,
            .withdrawer = self.withdrawer,
            .commission = self.commission,
            .votes = votes,
            .root_slot = self.root_slot,
            .voters = voters,
            .prior_voters = self.prior_voters,
            .epoch_credits = try self.epoch_credits.clone(allocator),
            .last_timestamp = self.last_timestamp,
        };
    }

    /// [SIMD-0185] Build VoteStateV3 from VoteStateV4 for serializing as .v3 when feature is off.
    /// If `prior_voters` is provided, it will be used directly; otherwise an empty CircBuf is used.
    pub fn fromVoteStateV4(
        allocator: Allocator,
        v4: VoteStateV4,
        prior_voters: ?CircBufV1,
    ) Allocator.Error!VoteStateV3 {
        var votes = try v4.votes.clone(allocator);
        errdefer votes.deinit(allocator);

        const voters = try v4.authorized_voters.clone(allocator);
        errdefer voters.deinit(allocator);

        return .{
            .node_pubkey = v4.node_pubkey,
            .withdrawer = v4.withdrawer,
            .commission = v4.commission(),
            .votes = votes,
            .root_slot = v4.root_slot,
            .voters = voters,
            .prior_voters = prior_voters orelse CircBufV1.init(),
            .epoch_credits = try v4.epoch_credits.clone(allocator),
            .last_timestamp = v4.last_timestamp,
        };
    }

    pub fn equals(self: *const VoteStateV3, other: *const VoteStateV3) bool {
        if (self.votes.items.len != other.votes.items.len) return false;
        for (self.votes.items, other.votes.items) |a, b|
            if (!std.meta.eql(a, b)) return false;

        if (!self.voters.equals(&other.voters)) return false;

        if (!self.prior_voters.equals(other.prior_voters)) return false;

        if (self.epoch_credits.items.len != other.epoch_credits.items.len) return false;
        for (self.epoch_credits.items, other.epoch_credits.items) |a, b|
            if (!std.meta.eql(a, b)) return false;

        return self.node_pubkey.equals(&other.node_pubkey) and
            self.withdrawer.equals(&other.withdrawer) and
            self.commission == other.commission and
            self.root_slot == other.root_slot and
            std.meta.eql(self.last_timestamp, other.last_timestamp);
    }

    pub fn epochCredits(self: *const VoteStateV3) u64 {
        return if (self.epoch_credits.getLastOrNull()) |epoch_credit|
            epoch_credit.credits
        else
            0;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/vote_state_versions.rs#L84
    pub fn isUninitialized(self: VoteStateV3) bool {
        return self.voters.count() == 0;
    }

    pub fn isCorrectSizeAndInitialized(data: []const u8) bool {
        return data.len == MAX_VOTE_STATE_SIZE and
            !std.mem.allEqual(u8, data[4..][0..DEFAULT_PRIOR_VOTERS_OFFSET], 0);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L862
    pub fn setNewAuthorizedVoter(
        self: *VoteStateV3,
        allocator: Allocator,
        new_authorized_voter: Pubkey,
        target_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {

        // The offset in slots `n` on which the target_epoch
        // (default value `DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET`) is
        // calculated is the number of slots available from the
        // first slot `S` of an epoch in which to set a new voter for
        // the epoch at `S` + `n`
        if (self.voters.contains(target_epoch)) {
            // Failure, return VoteError.
            return VoteError.too_soon_to_reauthorize;
        }

        const latest_epoch, const latest_pubkey = self.voters.last() orelse
            return InstructionError.InvalidAccountData;

        if (!latest_pubkey.equals(&new_authorized_voter)) {
            const epoch_of_last_authorized_switch = if (self.prior_voters.last()) |prior_voter|
                prior_voter.end
            else
                0;

            if (target_epoch <= latest_epoch) {
                return InstructionError.InvalidAccountData;
            }

            self.prior_voters.append(PriorVote{
                .key = latest_pubkey,
                .start = epoch_of_last_authorized_switch,
                .end = target_epoch,
            });
        }

        try self.voters.insert(allocator, target_epoch, new_authorized_voter);
        // Success, return null.
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/state/mod.rs#L922
    pub fn getAndUpdateAuthorizedVoter(
        self: *VoteStateV3,
        allocator: Allocator,
        current_epoch: Epoch,
    ) (error{OutOfMemory} || InstructionError)!Pubkey {
        const maybe_pubkey = self.voters.getAndCacheAuthorizedVoterForEpoch(
            allocator,
            current_epoch,
        ) catch return error.OutOfMemory;
        const pubkey = maybe_pubkey orelse return InstructionError.InvalidAccountData;

        _ = try self.voters.purgeAuthorizedVoters(allocator, current_epoch);

        return pubkey;
    }

    pub fn lastLockout(self: *const VoteStateV3) ?Lockout {
        if (self.votes.getLastOrNull()) |vote| {
            return vote.lockout;
        }
        return null;
    }

    pub fn lastVotedSlot(self: *const VoteStateV3) ?Slot {
        if (self.lastLockout()) |lock_out| {
            return lock_out.slot;
        }
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L777
    ///
    /// Returns the credits to award for a vote at the given lockout slot index
    pub fn creditsForVoteAtIndex(self: *const VoteStateV3, index: usize) u64 {
        const latency = if (index < self.votes.items.len)
            self.votes.items[index].latency
        else
            0;

        // If latency is 0, this means that the Lockout was created from a software version
        // that didn't store vote latencies; in this case, 1 credit is awarded
        if (latency == 0) {
            return 1;
        }

        if (latency <= VOTE_CREDITS_GRACE_SLOTS) {
            // latency was <= VOTE_CREDITS_GRACE_SLOTS, so maximum credits are awarded
            return VOTE_CREDITS_MAXIMUM_PER_SLOT;
        }

        // diff = latency - VOTE_CREDITS_GRACE_SLOTS, and diff > 0
        const diff = latency - VOTE_CREDITS_GRACE_SLOTS;

        if (diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT) {
            // If diff >= VOTE_CREDITS_MAXIMUM_PER_SLOT, 1 credit is awarded
            return 1;
        }

        // Subtract diff from VOTE_CREDITS_MAXIMUM_PER_SLOT which is the number of credits to award
        return VOTE_CREDITS_MAXIMUM_PER_SLOT - diff;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L845
    ///
    /// Number of "credits" owed to this account from the mining pool. Submit this
    /// VoteStateV3 to the Rewards program to trade credits for lamports.
    pub fn getCredits(self: *const VoteStateV3) u64 {
        return if (self.epoch_credits.items.len == 0)
            0
        else
            self.epoch_credits.getLast().credits;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L743
    ///
    /// increment credits, record credits for last epoch if new epoch
    pub fn incrementCredits(
        self: *VoteStateV3,
        allocator: Allocator,
        epoch: Epoch,
        credits: u64,
    ) error{OutOfMemory}!void {
        // increment credits, record by epoch
        // never seen a credit
        if (self.epoch_credits.items.len == 0) {
            try self.epoch_credits.append(
                allocator,
                .{ .epoch = epoch, .credits = 0, .prev_credits = 0 },
            );
        } else if (epoch != self.epoch_credits.getLast().epoch) {
            const last = self.epoch_credits.getLast();
            const last_credits = last.credits;
            const last_prev_credits = last.prev_credits;

            if (last_credits != last_prev_credits) {
                // if credits were earned previous epoch
                // append entry at end of list for the new epoch
                try self.epoch_credits.append(
                    allocator,
                    .{
                        .epoch = epoch,
                        .credits = last_credits,
                        .prev_credits = last_credits,
                    },
                );
            } else {
                // else just move the current epoch
                const last_epoch_credit =
                    &self.epoch_credits.items[self.epoch_credits.items.len - 1];
                last_epoch_credit.*.epoch = epoch;
            }

            // Remove too old epoch_credits
            if (self.epoch_credits.items.len > MAX_EPOCH_CREDITS_HISTORY) {
                _ = self.epoch_credits.orderedRemove(0);
            }
        }

        // Saturating add for the credits
        {
            const last_epoch_credit = &self.epoch_credits.items[self.epoch_credits.items.len - 1];
            last_epoch_credit.*.credits = last_epoch_credit.credits +| credits;
        }
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/e17340519f792d97cf4af7b9eb81056d475c70f9/programs/vote/src/vote_state/mod.rs#L303
    ///
    // The goal is to check if each slot in vote_slots appears in slot_hashes with the correct hash.
    pub fn checkSlotsAreValid(
        self: *const VoteStateV3,
        vote: *const Vote,
        recent_vote_slots: []const Slot,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        const vote_hash = vote.hash;
        const slot_hash_entries = slot_hashes.entries.constSlice();

        // index into the vote's slots, starting at the oldest slot
        var i: usize = 0;

        // index into the slot_hashes, starting at the oldest known slot hash
        var j: usize = slot_hash_entries.len;

        // Note:
        //
        // 1) `vote_slots` is sorted from oldest/smallest vote to newest/largest
        // vote, due to the way votes are applied to the vote state (newest votes
        // pushed to the back).
        //
        // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
        // the oldest/smallest vote
        //
        // So:
        // for vote_states we are iterating from 0 up to the (size - 1) index
        // for slot_hashes we are iterating from (size - 1) index down to 0
        while (i < recent_vote_slots.len and j > 0) {
            // 1) increment `i` to find the smallest slot `s` in `vote_slots`
            // where `s` >= `last_voted_slot`
            // vote slot `s` to be processed must be newer than last voted slot
            const less_than_last_voted_slot =
                if (self.lastVotedSlot()) |last_voted_slot|
                    recent_vote_slots[i] <= last_voted_slot
                else
                    false;

            if (less_than_last_voted_slot) {
                i = std.math.add(usize, i, 1) catch
                    return InstructionError.ProgramArithmeticOverflow;
                continue;
            }

            // 2) Find the hash for this slot `s`.
            if (recent_vote_slots[i] !=
                slot_hash_entries[
                    std.math.sub(usize, j, 1) catch
                        return InstructionError.ProgramArithmeticOverflow
                ].slot)
            {
                // Decrement `j` to find newer slots
                j = std.math.sub(usize, j, 1) catch
                    return InstructionError.ProgramArithmeticOverflow;
                continue;
            }

            // 3) Once the hash for `s` is found, bump `s` to the next slot
            // in `vote_slots` and continue.
            i = std.math.add(usize, i, 1) catch
                return InstructionError.ProgramArithmeticOverflow;
            j = std.math.sub(usize, j, 1) catch
                return InstructionError.ProgramArithmeticOverflow;
        }

        if (j == slot_hash_entries.len) {
            // This means we never made it to steps 2) or 3) above, otherwise
            // `j` would have been decremented at least once. This means
            // there are not slots in `vote_slots` greater than `last_voted_slot`
            return VoteError.vote_too_old;
        }

        if (i != recent_vote_slots.len) {
            // This means there existed some slot for which we couldn't find
            // a matching slot hash in step 2)
            return VoteError.slots_mismatch;
        }
        if (!vote_hash.eql(slot_hash_entries[j].hash)) {
            // This means the newest slot in the `vote_slots` has a match that
            // doesn't match the expected hash for that slot on this
            // fork
            return VoteError.slot_hash_mismatch;
        }
        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L709
    pub fn processNextVoteSlot(
        self: *VoteStateV3,
        allocator: Allocator,
        next_vote_slot: Slot,
        epoch: Epoch,
        current_slot: Slot,
    ) !void {
        // Ignore votes for slots earlier than we already have votes for
        if (self.lastVotedSlot()) |last_voted_slot| {
            if (next_vote_slot <= last_voted_slot) {
                return;
            }
        }

        self.popExpiredVotes(next_vote_slot);

        const landed_vote: LandedVote = .{
            .latency = VoteStateV3.computeVoteLatency(next_vote_slot, current_slot),
            .lockout = Lockout{ .confirmation_count = 1, .slot = next_vote_slot },
        };

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if (self.votes.items.len == MAX_LOCKOUT_HISTORY) {
            const credits = self.creditsForVoteAtIndex(0);
            const popped_vote = self.votes.orderedRemove(0);
            self.root_slot = popped_vote.lockout.slot;
            try self.incrementCredits(allocator, epoch, credits);
        }

        try self.votes.append(allocator, landed_vote);
        try self.doubleLockouts();
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L939
    ///
    /// Pop all recent votes that are not locked out at the next vote slot.
    /// This allows validators to switch forks once their votes for another fork have
    /// expired. This also allows validators to continue voting on recent blocks in
    /// the same fork without increasing lockouts.
    pub fn popExpiredVotes(
        self: *VoteStateV3,
        next_vote_slot: Slot,
    ) void {
        while (self.lastLockout()) |vote| {
            if (!vote.isLockedOutAtSlot(next_vote_slot)) {
                _ = self.votes.pop();
            } else {
                break;
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L949
    pub fn doubleLockouts(self: *VoteStateV3) !void {
        const stack_depth = self.votes.items.len;

        for (self.votes.items, 0..) |*vote, i| {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            const confirmation_count = vote.lockout.confirmation_count;
            if (stack_depth > std.math.add(usize, i, confirmation_count) catch
                return InstructionError.ProgramArithmeticOverflow)
            {
                vote.lockout.confirmation_count +|= 1;
            }
        }
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L963
    pub fn processTimestamp(
        self: *VoteStateV3,
        slot: Slot,
        timestamp: i64,
    ) ?VoteError {
        const new_timestamp = BlockTimestamp{ .slot = slot, .timestamp = timestamp };

        if (slot < self.last_timestamp.slot or timestamp < self.last_timestamp.timestamp or
            (slot == self.last_timestamp.slot and
                !std.meta.eql(new_timestamp, self.last_timestamp) and
                self.last_timestamp.slot != 0))
        {
            return VoteError.timestamp_too_old;
        }

        self.last_timestamp = new_timestamp;
        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/a0717a15d349dc5e0c30384bee6d039377b92167/programs/vote/src/vote_state/mod.rs#L618
    pub fn processVote(
        self: *VoteStateV3,
        allocator: Allocator,
        vote: *const Vote,
        slot_hashes: SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (vote.slots.len == 0) {
            return VoteError.empty_slots;
        }

        const slot_hash_entries = slot_hashes.entries.constSlice();
        const earliest_slot_in_history = if (slot_hash_entries.len != 0)
            slot_hash_entries[slot_hash_entries.len - 1].slot
        else
            0;

        var recent_vote_slots = std.array_list.Managed(Slot).init(allocator);
        defer recent_vote_slots.deinit();

        for (vote.slots) |slot| {
            if (slot >= earliest_slot_in_history) {
                try recent_vote_slots.append(slot);
            }
        }

        if (recent_vote_slots.items.len == 0) {
            return VoteError.votes_too_old_all_filtered;
        }

        return self.processVoteUnfiltered(
            allocator,
            recent_vote_slots.items,
            vote,
            &slot_hashes,
            epoch,
            current_slot,
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/a0717a15d349dc5e0c30384bee6d039377b92167/programs/vote/src/vote_state/mod.rs#L603
    pub fn processVoteUnfiltered(
        self: *VoteStateV3,
        allocator: Allocator,
        recent_vote_slots: []const Slot,
        vote: *const Vote,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkSlotsAreValid(
            vote,
            recent_vote_slots,
            slot_hashes,
        )) |err| {
            return err;
        }

        for (recent_vote_slots) |recent_vote_slot| {
            try self.processNextVoteSlot(
                allocator,
                recent_vote_slot,
                epoch,
                current_slot,
            );
        }

        return null;
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/fb8a9a06eb7ed1db556d9ef018eefafa5f707467/vote-interface/src/state/mod.rs#L772
    ///
    /// Computes the vote latency for vote on voted_for_slot where the vote itself landed in current_slot
    pub fn computeVoteLatency(voted_for_slot: Slot, current_slot: Slot) u8 {
        return @min(current_slot -| voted_for_slot, std.math.maxInt(u8));
    }

    fn compareFn(key: Slot, mid_item: LandedVote) std.math.Order {
        return std.math.order(key, mid_item.lockout.slot);
    }

    /// [agave] https://github.com/anza-xyz/solana-sdk/blob/52d80637e13bca19ed65920fbda154993c37dbbe/vote-interface/src/state/mod.rs#L690
    ///
    /// Returns if the vote state contains a slot `candidate_slot`
    pub fn containsSlot(self: *const VoteStateV3, candidate_slot: Slot) bool {
        return std.sort.binarySearch(
            LandedVote,
            self.votes.items,
            candidate_slot,
            compareFn,
        ) != null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L1014
    pub fn processTowerSync(
        self: *VoteStateV3,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        tower_sync: *TowerSync,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            slot_hashes,
        )) |err| {
            return err;
        }

        const lockouts = try VoteStateVersions.landedVotesFromLockouts(
            allocator,
            tower_sync.lockouts.items,
        );
        defer allocator.free(lockouts);

        return try self.processNewVoteState(
            allocator,
            lockouts,
            tower_sync.root,
            tower_sync.timestamp,
            epoch,
            slot,
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L964
    pub fn processVoteStateUpdate(
        self: *VoteStateV3,
        allocator: Allocator,
        slot_hashes: *const SlotHashes,
        epoch: Epoch,
        slot: Slot,
        vote_state_update: *VoteStateUpdate,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (try self.checkAndFilterProposedVoteState(
            &vote_state_update.lockouts,
            &vote_state_update.root,
            vote_state_update.hash,
            slot_hashes,
        )) |err| {
            return err;
        }

        const lockouts = try VoteStateVersions.landedVotesFromLockouts(
            allocator,
            vote_state_update.lockouts.items,
        );
        defer allocator.free(lockouts);

        return try self.processNewVoteState(
            allocator,
            lockouts,
            vote_state_update.root,
            vote_state_update.timestamp,
            epoch,
            slot,
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L63
    ///
    /// Checks the proposed vote state with the current and
    /// slot hashes, making adjustments to the root / filtering
    /// votes as needed.
    pub fn checkAndFilterProposedVoteState(
        self: *VoteStateV3,
        proposed_lockouts: *std.ArrayListUnmanaged(Lockout),
        proposed_root: *?Slot,
        proposed_hash: Hash,
        slot_hashes: *const SlotHashes,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        if (proposed_lockouts.items.len == 0) return VoteError.empty_slots;

        // If the proposed state is too old, return `vote_too_old`.
        const last_proposed_slot = proposed_lockouts.getLast().slot;
        if (self.votes.getLastOrNull()) |last_vote| {
            if (last_proposed_slot <= last_vote.lockout.slot) {
                return VoteError.vote_too_old;
            }
        }

        const slot_hash_entries = slot_hashes.entries.constSlice();
        if (slot_hash_entries.len == 0) return VoteError.slots_mismatch;
        const earliest_slot_hash_in_history = slot_hash_entries[slot_hash_entries.len - 1].slot;

        // Check if the proposed vote state is too old to be in the SlotHash history
        if (last_proposed_slot < earliest_slot_hash_in_history) {
            // If this is the last slot in the vote update, it must be in SlotHashes,
            // otherwise we have no way of confirming if the hash matches
            return VoteError.vote_too_old;
        }

        if (proposed_root.*) |root| {
            // If the new proposed root `R` is less than the earliest slot hash in the history
            // such that we cannot verify whether the slot was actually was on this fork, set
            // the root to the latest vote in the vote state that's less than R. If no
            // votes from the vote state are less than R, use its root instead.
            //
            // This handles cases where a proposed root is too old to be verified
            // against the SlotHash history. It ensures that the root remains
            // consistent with the validator's voting history while avoiding
            // issues like finalizing an incorrect fork.
            if (root < earliest_slot_hash_in_history) {
                // First overwrite the proposed root with the vote state's root
                proposed_root.* = self.root_slot;
                // Then try to find the latest vote in vote state that's less than R
                var iter = std.mem.reverseIterator(self.votes.items);
                while (iter.next()) |vote| {
                    if (vote.lockout.slot <= root) {
                        proposed_root.* = vote.lockout.slot;
                        break;
                    }
                }
            }
        }

        // Index into the new proposed vote state's slots, starting with the root if it exists then
        // we use this mutable root to fold checking the root slot into the below loop
        // for performance
        var root_to_check = proposed_root.*;
        var proposed_lockouts_index: u64 = 0;
        // index into the slot_hashes, starting at the oldest known slot hash
        var slot_hashes_index = slot_hash_entries.len;
        // The maximum number of elements is bounded by the maximum instruction size possible.
        var lockouts_to_filter: std14.BoundedArray(
            u64,
            sig.vm.syscalls.cpi.MAX_DATA_LEN / @sizeOf(u64),
        ) = .{};

        // Note:
        //
        // 1) `proposed_lockouts` is sorted from oldest/smallest vote to newest/largest
        // vote, due to the way votes are applied to the vote state (newest votes
        // pushed to the back).
        //
        // 2) Conversely, `slot_hashes` is sorted from newest/largest vote to
        // the oldest/smallest vote
        //
        // We check every proposed lockout because have to ensure that every slot is actually part of
        // the history, not just the most recent ones
        while (proposed_lockouts_index < proposed_lockouts.items.len and slot_hashes_index > 0) {
            const proposed_vote_slot: Slot = if (root_to_check) |root|
                root
            else
                proposed_lockouts.items[proposed_lockouts_index].slot;

            if (root_to_check == null and
                proposed_lockouts_index > 0 and
                proposed_vote_slot <= proposed_lockouts.items[proposed_lockouts_index - 1].slot)
            {
                return VoteError.slots_not_ordered;
            }
            const ancestor_slot = slot_hash_entries[slot_hashes_index - 1].slot;

            // Find if this slot in the proposed vote state exists in the SlotHashes history
            // to confirm if it was a valid ancestor on this fork
            switch (std.math.order(proposed_vote_slot, ancestor_slot)) {
                .lt => {
                    if (slot_hashes_index == slot_hash_entries.len) {
                        // The vote slot does not exist in the SlotHashes history because it's too old,
                        // i.e. older than the oldest slot in the history.
                        if (proposed_vote_slot >= earliest_slot_hash_in_history) {
                            return VoteError.assertion_failed;
                        }
                        if (!self.containsSlot(proposed_vote_slot) and (root_to_check == null)) {
                            // If the vote slot is both:
                            // 1) Too old
                            // 2) Doesn't already exist in vote state
                            //
                            // Then filter it out
                            // NOTE: It is not possible for this to run out of capacity, as
                            // the instruction data could not contain enough lockouts.
                            lockouts_to_filter.appendAssumeCapacity(proposed_lockouts_index);
                        }
                        if (root_to_check) |new_proposed_root| {
                            // 1. Because `root_to_check.is_some()`, then we know that
                            // we haven't checked the root yet in this loop, so
                            // `proposed_vote_slot` == `new_proposed_root` == `proposed_root`.
                            std.debug.assert(new_proposed_root == proposed_vote_slot);
                            // 2. We know from the assert earlier in the function that
                            // `proposed_vote_slot < earliest_slot_hash_in_history`,
                            // so from 1. we know that `new_proposed_root < earliest_slot_hash_in_history`.
                            if (new_proposed_root >= earliest_slot_hash_in_history) {
                                return VoteError.assertion_failed;
                            }
                            root_to_check = null;
                        } else {
                            proposed_lockouts_index += 1;
                        }
                        continue;
                    } else {
                        // If the vote slot is new enough to be in the slot history,
                        // but is not part of the slot history, then it must belong to another fork,
                        // which means this proposed vote state is invalid.
                        if (root_to_check == null) {
                            return VoteError.slots_mismatch;
                        } else {
                            return VoteError.root_on_different_fork;
                        }
                    }
                },
                .gt => {
                    // Decrement `slot_hashes_index` to find newer slots in the SlotHashes history
                    slot_hashes_index -= 1;
                    continue;
                },
                .eq => {
                    // Once the slot in `proposed_lockouts` is found, bump to the next slot
                    // in `proposed_lockouts` and continue. If we were checking the root,
                    // start checking the vote state instead.
                    if (root_to_check != null) {
                        root_to_check = null;
                    } else {
                        proposed_lockouts_index += 1;
                        slot_hashes_index -= 1;
                    }
                },
            }
        }

        if (proposed_lockouts_index != proposed_lockouts.items.len) {
            // The last vote slot in the proposed vote state did not exist in SlotHashes
            return VoteError.slots_mismatch;
        }

        // This assertion must be true at this point because we can assume by now:
        // 1) proposed_lockouts_index == proposed_lockouts.len()
        // 2) last_proposed_slot >= earliest_slot_hash_in_history
        // 3) !proposed_lockouts.is_empty()
        //
        // 1) implies that during the last iteration of the loop above,
        // `proposed_lockouts_index` was equal to `proposed_lockouts.len() - 1`,
        // and was then incremented to `proposed_lockouts.len()`.
        // This means in that last loop iteration,
        // `proposed_vote_slot ==
        //  proposed_lockouts[proposed_lockouts.len() - 1] ==
        //  last_proposed_slot`.
        //
        // Then we know the last comparison `match proposed_vote_slot.cmp(&ancestor_slot)`
        // is equivalent to `match last_proposed_slot.cmp(&ancestor_slot)`. The result
        // of this match to increment `proposed_lockouts_index` must have been either:
        //
        // 1) The Equal case ran, in which case then we know this assertion must be true
        // 2) The Less case ran, and more specifically the case
        // `proposed_vote_slot < earliest_slot_hash_in_history` ran, which is equivalent to
        // `last_proposed_slot < earliest_slot_hash_in_history`, but this is impossible
        // due to assumption 3) above.
        std.debug.assert(last_proposed_slot == slot_hash_entries[slot_hashes_index].slot);

        if (!slot_hash_entries[slot_hashes_index].hash.eql(proposed_hash)) {
            return VoteError.slot_hash_mismatch;
        }

        // Filter out the irrelevant votes
        proposed_lockouts_index = 0;
        var filter_votes_index: usize = 0;
        var i: usize = 0;
        while (i < proposed_lockouts.items.len) {
            const should_retain = retain: {
                if (filter_votes_index == lockouts_to_filter.len) {
                    break :retain true;
                } else if (proposed_lockouts_index == lockouts_to_filter.get(filter_votes_index)) {
                    filter_votes_index += 1;
                    break :retain false;
                } else break :retain true;
            };

            proposed_lockouts_index += 1;
            if (should_retain) {
                i += 1;
            } else {
                _ = proposed_lockouts.orderedRemove(i);
            }
        }
        return null;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L426
    ///
    /// Ensure `check_and_filter_proposed_vote_state(&)` runs on the slots in `new_state`
    /// before `process_new_vote_state()` is called
    /// This function should guarantee the following about `new_state`:
    ///
    /// 1) It's well ordered, i.e. the slots are sorted from smallest to largest,
    /// and the confirmations sorted from largest to smallest.
    /// 2) Confirmations `c` on any vote slot satisfy `0 < c <= MAX_LOCKOUT_HISTORY`
    /// 3) Lockouts are not expired by consecutive votes, i.e. for every consecutive
    /// `v_i`, `v_{i + 1}` satisfy `v_i.last_locked_out_slot() >= v_{i + 1}`.
    /// We also guarantee that compared to the current vote state, `new_state`
    /// introduces no rollback. This means:
    ///
    /// 1) The last slot in `new_state` is always greater than any slot in the
    /// current vote state.
    ///
    /// 2) From 1), this means that for every vote `s` in the current state:
    ///    a) If there exists an `s'` in `new_state` where `s.slot == s'.slot`, then
    ///    we must guarantee `s.confirmations <= s'.confirmations`
    ///
    ///    b) If there does not exist any such `s'` in `new_state`, then there exists
    ///    some `t` that is the smallest vote in `new_state` where `t.slot > s.slot`.
    ///    `t` must have expired/popped off s', so it must be guaranteed that
    ///    `s.last_locked_out_slot() < t`.
    /// Note these two above checks do not guarantee that the vote state being submitted
    /// is a vote state that could have been created by iteratively building a tower
    /// by processing one vote at a time. For instance, the tower:
    ///
    /// { slot 0, confirmations: 31 }
    /// { slot 1, confirmations: 30 }
    ///
    /// is a legal tower that could be submitted on top of a previously empty tower. However,
    /// there is no way to create this tower from the iterative process, because slot 1 would
    /// have to have at least one other slot on top of it, even if the first 30 votes were all
    /// popped off.
    pub fn processNewVoteState(
        self: *VoteStateV3,
        allocator: Allocator,
        new_state: []LandedVote,
        new_root: ?Slot,
        timestamp: ?i64,
        epoch: Epoch,
        current_slot: Slot,
    ) (error{OutOfMemory} || InstructionError)!?VoteError {
        std.debug.assert(new_state.len != 0);

        if (new_state.len > MAX_LOCKOUT_HISTORY) {
            return VoteError.too_many_votes;
        }

        // New root cannot be older than current root (proposed_new_root < current_root -> reject)
        if (new_root) |proposed_new_root| {
            if (self.root_slot) |current_root| {
                if (proposed_new_root < current_root) {
                    return VoteError.root_roll_back;
                }
            }
        } else {
            // Cannot remove an existing root -> reject
            if (self.root_slot != null) {
                return VoteError.root_roll_back;
            }
        }

        var maybe_previous_vote: ?*const LandedVote = null;

        // Check that all the votes in the new proposed state are:
        // 1) Strictly sorted from oldest to newest vote
        // 2) The confirmations are strictly decreasing
        // 3) Not zero confirmation votes
        for (new_state) |*vote| {
            if (vote.lockout.confirmation_count == 0) {
                return VoteError.zero_confirmations;
            } else if (vote.lockout.confirmation_count > MAX_LOCKOUT_HISTORY) {
                return VoteError.confirmation_too_large;
            } else if (new_root) |proposed_new_root| {
                if (vote.lockout.slot <= proposed_new_root and
                    // This check is necessary because
                    // https://github.com/ryoqun/solana/blob/df55bfb46af039cbc597cd60042d49b9d90b5961/core/src/consensus.rs#L120
                    // always sets a root for even empty towers, which is then hard unwrapped here
                    // https://github.com/ryoqun/solana/blob/df55bfb46af039cbc597cd60042d49b9d90b5961/core/src/consensus.rs#L776
                    new_root != 0)
                {
                    return VoteError.slot_smaller_than_root;
                }
            }

            if (maybe_previous_vote) |previous_vote| {
                if (previous_vote.lockout.slot >= vote.lockout.slot) {
                    return VoteError.slots_not_ordered;
                } else if (previous_vote.lockout.confirmation_count <=
                    vote.lockout.confirmation_count)
                {
                    return VoteError.confirmations_not_ordered;
                } else if (vote.lockout.slot > previous_vote.lockout.lastLockedOutSlot()) {
                    return VoteError.new_vote_state_lockout_mismatch;
                }
            }
            maybe_previous_vote = vote;
        }

        // Find the first vote in the current vote state for a slot greater
        // than the new proposed root
        var current_vote_state_index: usize = 0;
        var new_vote_state_index: usize = 0;

        // Accumulate credits earned by newly rooted slots
        var earned_credits: u64 = 0;

        if (new_root) |proposed_new_root| {
            for (self.votes.items) |current_vote| {
                // Sum credits for all votes in current state that are now rooted. (ie <= proposed_new_root).
                if (current_vote.lockout.slot <= proposed_new_root) {
                    earned_credits = std.math.add(
                        u64,
                        earned_credits,
                        self.creditsForVoteAtIndex(current_vote_state_index),
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                    continue;
                }
                break;
            }
        }

        // For any slots newly added to the new vote state, the vote latency of that slot is not provided by the
        // vote instruction contents, but instead is computed from the actual latency of the vote
        // instruction. This prevents other validators from manipulating their own vote latencies within their vote states
        // and forcing the rest of the cluster to accept these possibly fraudulent latency values.  If the
        // timly_vote_credits feature is not enabled then vote latency is set to 0 for new votes.
        //
        // For any slot that is in both the new state and the current state, the vote latency of the new state is taken
        // from the current state.
        //
        // Thus vote latencies are set here for any newly vote-on slots when a vote instruction is received.
        // They are copied into the new vote state after every vote for already voted-on slots.
        // And when voted-on slots are rooted, the vote latencies stored in the vote state of all the rooted slots is used
        // to compute credits earned.
        // All validators compute the same vote latencies because all process the same vote instruction at the
        // same slot, and the only time vote latencies are ever computed is at the time that their slot is first voted on;
        // after that, the latencies are retained unaltered until the slot is rooted.

        // All the votes in our current vote state that are missing from the new vote state
        // must have been expired by later votes. Check that the lockouts match this assumption.
        while (current_vote_state_index < self.votes.items.len and
            new_vote_state_index < new_state.len)
        {
            const current_vote = &self.votes.items[current_vote_state_index];
            const new_vote = &new_state[new_vote_state_index];

            // If the current slot is less than the new proposed slot, then the
            // new slot must have popped off the old slot, so check that the
            // lockouts are correct
            switch (std.math.order(current_vote.lockout.slot, new_vote.lockout.slot)) {
                .lt => {
                    if (current_vote.lockout.lastLockedOutSlot() >= new_vote.lockout.slot) {
                        return VoteError.lockout_conflict;
                    }
                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch return InstructionError.ProgramArithmeticOverflow;
                },
                .eq => {
                    // The new vote state should never have less lockout than
                    // the previous vote state for the same slot
                    if (new_vote.lockout.confirmation_count <
                        current_vote.lockout.confirmation_count)
                    {
                        return VoteError.confirmation_roll_back;
                    }

                    // Copy the vote slot latency in from the current state to the new state
                    new_vote.latency = self.votes.items[current_vote_state_index].latency;

                    current_vote_state_index = std.math.add(
                        usize,
                        current_vote_state_index,
                        1,
                    ) catch
                        return InstructionError.ProgramArithmeticOverflow;
                    new_vote_state_index = std.math.add(usize, new_vote_state_index, 1) catch
                        return InstructionError.ProgramArithmeticOverflow;
                },
                .gt => {
                    new_vote_state_index = std.math.add(usize, new_vote_state_index, 1) catch
                        return InstructionError.ProgramArithmeticOverflow;
                },
            }
        }

        // `new_vote_state` passed all the checks, finalize the change by rewriting
        // our state.

        // Now set the vote latencies on new slots not in the current state.  New slots not in the current vote state will
        // have had their latency initialized to 0 by the above loop.  Those will now be updated to their actual latency.
        for (new_state) |*new_vote| {
            if (new_vote.latency == 0) {
                new_vote.latency = VoteStateV3.computeVoteLatency(
                    new_vote.lockout.slot,
                    current_slot,
                );
            }
        }

        if (self.root_slot != new_root) {
            // Award vote credits based on the number of slots that were voted on and have reached finality
            // For each finalized slot, there was one voted-on slot in the new vote state that was responsible for
            // finalizing it. Each of those votes is awarded 1 credit.
            try self.incrementCredits(allocator, epoch, earned_credits);
        }
        if (timestamp) |tstamp| {
            const last_slot = new_state[new_state.len - 1].lockout.slot;
            if (self.processTimestamp(last_slot, tstamp)) |err| {
                return err;
            }
        }

        self.root_slot = new_root;
        self.votes.clearRetainingCapacity();
        try self.votes.appendSlice(allocator, new_state);

        // Everything is fine.
        return null;
    }
};

/// Re-export of the `VoteAuthorize` enum.
pub const VoteAuthorize = vote_program.vote_instruction.VoteAuthorize;

pub fn createTestVoteStateV3(
    allocator: Allocator,
    node_pubkey: Pubkey,
    maybe_authorized_voter: ?Pubkey,
    withdrawer: Pubkey,
    commission: u8,
) !VoteStateV3 {
    if (!builtin.is_test) {
        @compileError("createTestVoteStateV3 should only be called in test mode");
    }

    return .{
        .node_pubkey = node_pubkey,
        .voters = if (maybe_authorized_voter) |authorized_voter|
            try AuthorizedVoters.init(allocator, 0, authorized_voter)
        else
            .EMPTY,
        .withdrawer = withdrawer,
        .commission = commission,
        .votes = .empty,
        .root_slot = null,
        .prior_voters = CircBufV1.init(),
        .epoch_credits = .empty,
        .last_timestamp = BlockTimestamp{ .slot = 0, .timestamp = 0 },
    };
}

pub fn createTestVoteAccount(
    allocator: Allocator,
    node_pubkey: Pubkey,
    vote_pubkey: Pubkey,
    commission: u8,
    lamports: u64,
    voter_epoch: Epoch,
) Allocator.Error!AccountSharedData {
    if (!builtin.is_test) @compileError("only for test");

    return createTestVoteAccountWithAuthorized(
        allocator,
        node_pubkey,
        vote_pubkey,
        vote_pubkey,
        commission,
        lamports,
        voter_epoch,
    );
}

pub fn createTestVoteAccountWithAuthorized(
    allocator: Allocator,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    lamports: u64,
    voter_epoch: Epoch,
) Allocator.Error!AccountSharedData {
    if (!builtin.is_test) @compileError("only for test");

    var vote_state = try VoteStateV3.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        voter_epoch,
    );
    defer vote_state.deinit(allocator);

    const vote_state_data = try allocator.alloc(u8, VoteStateV3.MAX_VOTE_STATE_SIZE);
    errdefer allocator.free(vote_state_data);
    @memset(vote_state_data, 0);

    _ = sig.bincode.writeToSlice(
        vote_state_data,
        VoteStateVersions{ .v3 = vote_state },
        .{},
    ) catch unreachable;

    return .{
        .lamports = lamports,
        .owner = vote_program.ID,
        .data = vote_state_data,
        .executable = false,
        .rent_epoch = 0,
    };
}

test "AuthorizeVoters.serialize" {
    const allocator = std.testing.allocator;

    const agave_bytes = &[_]u8{
        3, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 2,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,

        1, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 3,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,

        2, 0, 0, 0, 0, 0, 0, 0,

        0, 0, 0, 0, 0, 0, 0, 4,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
    };

    var authorized_voters = try sig.bincode.readFromSlice(
        allocator,
        AuthorizedVoters,
        agave_bytes,
        .{},
    );
    defer authorized_voters.deinit(allocator);

    const sig_bytes = try sig.bincode.writeAlloc(allocator, authorized_voters, .{});
    defer allocator.free(sig_bytes);

    try std.testing.expectEqualSlices(u8, agave_bytes, sig_bytes);
}

test "Lockout.lockout" {
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 1,
        };
        try std.testing.expectEqual(2, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 2,
        };
        try std.testing.expectEqual(4, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 3,
        };
        try std.testing.expectEqual(8, lockout.lockout());
    }
    {
        const lockout = Lockout{
            .slot = 10,
            .confirmation_count = 4,
        };
        try std.testing.expectEqual(16, lockout.lockout());
    }
}

test "state.Lockout.lastLockedOutSlot" {
    // | vote | vote slot | lockout | lock expiration slot |
    // |------|-----------|---------|----------------------|
    // | 4    | 4         | 2       | 6                    |
    // | 3    | 3         | 4       | 7                    |
    // | 2    | 2         | 8       | 10                   |
    // | 1    | 1         | 16      | 17                   |
    {
        const lockout = Lockout{
            .slot = 1,
            .confirmation_count = 4,
        };
        try std.testing.expectEqual(17, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 2,
            .confirmation_count = 3,
        };
        try std.testing.expectEqual(10, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 3,
            .confirmation_count = 2,
        };
        try std.testing.expectEqual(7, lockout.lastLockedOutSlot());
    }
    {
        const lockout = Lockout{
            .slot = 4,
            .confirmation_count = 1,
        };
        try std.testing.expectEqual(6, lockout.lastLockedOutSlot());
    }
}

test "state.Lockout.isLockedOutAtSlot" {
    // | vote | vote slot | lockout | lock expiration slot |
    // |------|-----------|---------|----------------------|
    // | 4    | 4         | 2       | 6                    |
    // | 3    | 3         | 4       | 7                    |
    // | 2    | 2         | 8       | 10                   |
    // | 1    | 1         | 16      | 17                   |
    {
        const lockout = Lockout{
            .slot = 1,
            .confirmation_count = 4,
        };
        try std.testing.expect(lockout.isLockedOutAtSlot(16));
        try std.testing.expect(lockout.isLockedOutAtSlot(17));
        try std.testing.expect(!lockout.isLockedOutAtSlot(18));
        try std.testing.expect(!lockout.isLockedOutAtSlot(19));
    }
    {
        const lockout = Lockout{
            .slot = 2,
            .confirmation_count = 3,
        };
        try std.testing.expect(lockout.isLockedOutAtSlot(9));
        try std.testing.expect(lockout.isLockedOutAtSlot(10));
        try std.testing.expect(!lockout.isLockedOutAtSlot(11));
        try std.testing.expect(!lockout.isLockedOutAtSlot(12));
    }
    {
        const lockout = Lockout{
            .slot = 3,
            .confirmation_count = 2,
        };
        try std.testing.expect(lockout.isLockedOutAtSlot(6));
        try std.testing.expect(lockout.isLockedOutAtSlot(7));
        try std.testing.expect(!lockout.isLockedOutAtSlot(8));
        try std.testing.expect(!lockout.isLockedOutAtSlot(9));
    }
    {
        const lockout = Lockout{
            .slot = 4,
            .confirmation_count = 1,
        };
        try std.testing.expect(lockout.isLockedOutAtSlot(5));
        try std.testing.expect(lockout.isLockedOutAtSlot(6));
        try std.testing.expect(!lockout.isLockedOutAtSlot(7));
        try std.testing.expect(!lockout.isLockedOutAtSlot(8));
    }
}

test "state.VoteStateV3.convertToV4" {
    const allocator = std.testing.allocator;
    const vote_pubkey = Pubkey.ZEROES;
    // VoteState0_23_5 -> V4
    {
        const vote_state_0_23_5: VoteStateVersions = .{ .v0_23_5 = try VoteState0_23_5.init(
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            0,
        ) };
        const vote_state = try VoteStateVersions.convertToV4(
            vote_state_0_23_5,
            allocator,
            vote_pubkey,
        );
        defer vote_state.deinit(allocator);

        try std.testing.expectEqual(0, vote_state.authorized_voters.count());
        try std.testing.expect(vote_state.withdrawer.equals(&Pubkey.ZEROES));
        try std.testing.expectEqual(10, vote_state.commission());
        try std.testing.expectEqual(0, vote_state.votes.items.len);
        try std.testing.expectEqual(null, vote_state.root_slot);
        try std.testing.expectEqual(1000, vote_state.inflation_rewards_commission_bps);
        try std.testing.expectEqual(10_000, vote_state.block_revenue_commission_bps);
        try std.testing.expectEqual(0, vote_state.epoch_credits.items.len);
        try std.testing.expectEqual(0, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(0, vote_state.last_timestamp.timestamp);
    }
    // VoteStatev1_14_11 -> V4
    {
        const vote_state_1_14_1: VoteStateVersions = .{ .v1_14_11 = try VoteState1_14_11.init(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            0,
        ) };
        const vote_state = try VoteStateVersions.convertToV4(
            vote_state_1_14_1,
            allocator,
            vote_pubkey,
        );
        defer vote_state.deinit(allocator);

        try std.testing.expectEqual(1, vote_state.authorized_voters.count());
        var authorized_voter = vote_state.authorized_voters;
        try std.testing.expect(authorized_voter.getAuthorizedVoter(0).?.equals(&Pubkey.ZEROES));
        try std.testing.expect(vote_state.withdrawer.equals(&Pubkey.ZEROES));
        try std.testing.expectEqual(10, vote_state.commission());
        try std.testing.expectEqual(0, vote_state.votes.items.len);
        try std.testing.expectEqual(null, vote_state.root_slot);
        try std.testing.expectEqual(1000, vote_state.inflation_rewards_commission_bps);
        try std.testing.expectEqual(0, vote_state.epoch_credits.items.len);
        try std.testing.expectEqual(0, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(0, vote_state.last_timestamp.timestamp);
    }

    // Current -> V4
    {
        var expected = try VoteStateV3.init(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            10,
            0,
        );
        defer expected.deinit(allocator);

        const vote_state_1_14_1: VoteStateVersions = .{ .v3 = try expected.clone(allocator) };

        var vote_state = try VoteStateVersions.convertToV4(
            vote_state_1_14_1,
            allocator,
            vote_pubkey,
        );
        defer vote_state.deinit(allocator);

        try std.testing.expectEqual(
            expected.voters.count(),
            vote_state.authorized_voters.count(),
        );
        var authorized_voter = vote_state.authorized_voters;
        var expected_authorized_voter = expected.voters;
        try std.testing.expect(
            authorized_voter.getAuthorizedVoter(0).?.equals(
                &expected_authorized_voter.getAuthorizedVoter(0).?,
            ),
        );
        try std.testing.expect(expected.withdrawer.equals(&vote_state.withdrawer));
        try std.testing.expectEqual(expected.commission, vote_state.commission());
        try std.testing.expectEqual(expected.votes.items.len, vote_state.votes.items.len);
        try std.testing.expectEqual(expected.root_slot, vote_state.root_slot);
        try std.testing.expectEqual(
            expected.epoch_credits.items.len,
            vote_state.epoch_credits.items.len,
        );
        try std.testing.expectEqual(expected.last_timestamp.slot, vote_state.last_timestamp.slot);
        try std.testing.expectEqual(
            expected.last_timestamp.timestamp,
            vote_state.last_timestamp.timestamp,
        );
    }
}

test "state.VoteStateV3.setNewAuthorizedVoter: success" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 0;

    var vote_state = try VoteStateV3.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    );
    defer vote_state.deinit(allocator);

    const target_epoch: Epoch = 5;
    _ = try vote_state.setNewAuthorizedVoter(allocator, new_voter, target_epoch);

    const retrived_voter = vote_state.voters.getAuthorizedVoter(target_epoch).?;
    try std.testing.expectEqual(new_voter, retrived_voter);
}

test "state.VoteStateV3.setNewAuthorizedVoter: too soon to reauthorize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 0;

    var vote_state = try VoteStateV3.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    );
    defer vote_state.deinit(allocator);

    // Same as initial epoch
    const target_epoch: Epoch = 0;
    const err = try vote_state.setNewAuthorizedVoter(allocator, new_voter, target_epoch);
    try std.testing.expectEqual(
        VoteError.too_soon_to_reauthorize,
        err.?,
    );
}

test "state.VoteStateV3.setNewAuthorizedVoter: invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const new_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 2; // epoch of current authorized voter

    var vote_state = try VoteStateV3.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    );
    defer vote_state.deinit(allocator);

    const target_epoch: Epoch = 1;
    try std.testing.expectError(
        InstructionError.InvalidAccountData,
        vote_state.setNewAuthorizedVoter(allocator, new_voter, target_epoch),
    );
}

test "state.VoteStateV3.isUninitialized: VoteState0_23_5 invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 2; // epoch of current authorized voter

    var vote_state = VoteStateVersions{ .v0_23_5 = try VoteState0_23_5.init(
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    ) };
    defer vote_state.deinit(allocator);

    try std.testing.expect(!vote_state.isUninitialized());

    const uninitialized_state = VoteStateVersions{
        .v3 = try createTestVoteStateV3(
            allocator,
            node_publey,
            null, // Authorized voters not set
            withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "state.VoteStateV3.isUninitialized: VoteStatev1_14_11 invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 2; // epoch of current authorized voter

    var vote_state = VoteStateVersions{ .v1_14_11 = try VoteState1_14_11.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    ) };
    defer vote_state.deinit(allocator);

    try std.testing.expect(!vote_state.isUninitialized());

    const uninitialized_state = VoteStateVersions{
        .v3 = try createTestVoteStateV3(
            allocator,
            node_publey,
            null, // Authorized voters not set
            withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "state.VoteStateV3.isUninitialized: current invalid account data" {
    // Test attempt to set a voter with an invalid target epoch
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const node_publey = Pubkey.initRandom(prng.random());
    const authorized_voter = Pubkey.initRandom(prng.random());
    const withdrawer = Pubkey.initRandom(prng.random());
    const commission: u8 = 10;
    const epoch = 2; // epoch of current authorized voter

    var vote_state = VoteStateVersions{ .v3 = try VoteStateV3.init(
        allocator,
        node_publey,
        authorized_voter,
        withdrawer,
        commission,
        epoch,
    ) };
    defer vote_state.deinit(allocator);

    try std.testing.expect(!vote_state.isUninitialized());

    const uninitialized_state = VoteStateVersions{
        .v3 = try createTestVoteStateV3(
            allocator,
            node_publey,
            null, // Authorized voters not set
            withdrawer,
            commission,
        ),
    };

    try std.testing.expect(uninitialized_state.isUninitialized());
}

test "state.AuthorizedVoters.init" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const voter_pubkey = Pubkey.initRandom(prng.random());

    var authorized_voters = try AuthorizedVoters.init(allocator, 10, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    try std.testing.expectEqual(authorized_voters.count(), 1);
}

test "state.AuthorizedVoters.getAuthorizedVoter" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    const new_pubkey = Pubkey.initRandom(prng.random());

    var authorized_voters = try AuthorizedVoters.init(allocator, 10, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    const epoch: Epoch = 15;
    try authorized_voters.insert(allocator, epoch, new_pubkey);
    try std.testing.expectEqual(new_pubkey, authorized_voters.getAuthorizedVoter(epoch).?);
}

test "state.AuthorizedVoters.purgeAuthorizedVoters" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    try authorized_voters.insert(allocator, 10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(allocator, 15, Pubkey.initRandom(prng.random()));

    try std.testing.expectEqual(authorized_voters.count(), 3);
    _ = try authorized_voters.purgeAuthorizedVoters(allocator, 12);
    // Only epoch 15 should remain
    try std.testing.expectEqual(authorized_voters.count(), 1);
}

test "state.AuthorizedVoters.first" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    try authorized_voters.insert(allocator, 10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(allocator, 15, Pubkey.initRandom(prng.random()));

    const epoch, const pubkey = authorized_voters.first().?;
    try std.testing.expectEqual(5, epoch);
    try std.testing.expectEqual(voter_pubkey, pubkey);
}

test "state.AuthorizedVoters.last" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());
    var authorized_voters = try AuthorizedVoters.init(
        allocator,
        5,
        Pubkey.initRandom(prng.random()),
    );
    defer authorized_voters.deinit(allocator);

    try authorized_voters.insert(allocator, 10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(allocator, 15, voter_pubkey);

    const epoch, const pubkey = authorized_voters.last().?;
    try std.testing.expectEqual(15, epoch);
    try std.testing.expectEqual(voter_pubkey, pubkey);
}

test "state.AuthorizedVoters.isEmpty" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var authorized_voters = try AuthorizedVoters.init(
        allocator,
        5,
        Pubkey.initRandom(prng.random()),
    );
    defer authorized_voters.deinit(allocator);

    try std.testing.expect(!authorized_voters.isEmpty());
}

test "state.AuthorizedVoters.len" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());

    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    try std.testing.expectEqual(authorized_voters.count(), 1);

    try authorized_voters.insert(allocator, 10, Pubkey.initRandom(prng.random()));
    try authorized_voters.insert(allocator, 15, Pubkey.initRandom(prng.random()));

    try std.testing.expectEqual(authorized_voters.count(), 3);
}

test "state.AuthorizedVoters.contains" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const voter_pubkey = Pubkey.initRandom(prng.random());

    var authorized_voters = try AuthorizedVoters.init(allocator, 5, voter_pubkey);
    defer authorized_voters.deinit(allocator);

    try std.testing.expect(authorized_voters.contains(5));
    try std.testing.expect(!authorized_voters.contains(15));
}

test "state.VoteStateV3.lastLockout" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const epoch = 2; // epoch of current authorized voter

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        epoch,
    );
    defer vote_state.deinit(allocator);

    try std.testing.expectEqual(null, vote_state.lastLockout());

    {
        try vote_state.votes.append(allocator, .{
            .latency = 0,
            .lockout = .{
                .slot = 1,
                .confirmation_count = 1,
            },
        });

        const actual = vote_state.lastLockout().?;
        try std.testing.expectEqualDeep(
            Lockout{ .slot = 1, .confirmation_count = 1 },
            actual,
        );
    }

    {
        try vote_state.votes.append(allocator, .{
            .latency = 1,
            .lockout = Lockout{
                .slot = 2,
                .confirmation_count = 2,
            },
        });

        const actual = vote_state.lastLockout().?;
        try std.testing.expectEqualDeep(
            Lockout{ .slot = 2, .confirmation_count = 2 },
            actual,
        );
    }
}

test "state.VoteStateV3.lastVotedSlot" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const epoch = 2; // epoch of current authorized voter

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        epoch,
    );
    defer vote_state.deinit(allocator);

    try std.testing.expectEqual(null, vote_state.lastVotedSlot());

    {
        try vote_state.votes.append(allocator, .{
            .latency = 0,
            .lockout = .{
                .slot = 1,
                .confirmation_count = 1,
            },
        });

        try std.testing.expectEqual(1, vote_state.lastVotedSlot().?);
    }

    {
        try vote_state.votes.append(allocator, .{
            .latency = 1,
            .lockout = .{
                .slot = 2,
                .confirmation_count = 2,
            },
        });

        try std.testing.expectEqual(2, vote_state.lastVotedSlot().?);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1275
test "state.VoteStateV3.lastLockout extended" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const epoch = 2; // epoch of current authorized voter

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        epoch,
    );
    defer vote_state.deinit(allocator);

    for (0..(MAX_LOCKOUT_HISTORY + 1)) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state, (INITIAL_LOCKOUT * i));
    }

    // The last vote should have been popped b/c it reached a depth of MAX_LOCKOUT_HISTORY
    try std.testing.expectEqual(vote_state.votes.items.len, MAX_LOCKOUT_HISTORY);
    try std.testing.expectEqual(vote_state.root_slot, 0);
    try checkLockouts(&vote_state);

    // One more vote that confirms the entire stack,
    // the root_slot should change to the
    // second vote
    const top_vote = vote_state.votes.items[0].lockout.slot;
    const slot = vote_state.lastLockout().?.lastLockedOutSlot();

    try processSlotVoteUnchecked(allocator, &vote_state, slot);
    try std.testing.expectEqual(top_vote, vote_state.root_slot);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1499
test "state.VoteStateV3.lockout double lockout after expiration" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        0,
    );
    defer vote_state.deinit(allocator);

    for (0..3) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state, (INITIAL_LOCKOUT * i));
    }
    try checkLockouts(&vote_state);

    // Expire the third vote (which was a vote for slot 2). The height of the
    // vote stack is unchanged, so none of the previous votes should have
    // doubled in lockout
    try processSlotVoteUnchecked(allocator, &vote_state, (2 + INITIAL_LOCKOUT + 1));
    try checkLockouts(&vote_state);

    // Vote again, this time the vote stack depth increases, so the votes should
    // double for everybody
    try processSlotVoteUnchecked(allocator, &vote_state, (2 + INITIAL_LOCKOUT + 2));
    try checkLockouts(&vote_state);

    // Vote again, this time the vote stack depth increases, so the votes should
    // double for everybody
    try processSlotVoteUnchecked(allocator, &vote_state, (2 + INITIAL_LOCKOUT + 3));
    try checkLockouts(&vote_state);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1527
test "state.VoteStateV3.lockout expire multiple votes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        0,
    );
    defer vote_state.deinit(allocator);

    for (0..3) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state, (INITIAL_LOCKOUT * i));
    }

    try std.testing.expectEqual(3, vote_state.votes.items[0].lockout.confirmation_count);

    // Expire the second and third votes
    const expire_slot =
        vote_state.votes.items[1].lockout.slot +
        (vote_state.votes.items[1].lockout.lockout()) +
        1;
    try processSlotVoteUnchecked(allocator, &vote_state, expire_slot);
    try std.testing.expectEqual(2, vote_state.votes.items.len);

    // Check that the old votes expired
    try std.testing.expectEqual(0, vote_state.votes.items[0].lockout.slot);
    try std.testing.expectEqual(expire_slot, vote_state.votes.items[1].lockout.slot);

    // Process one more vote
    try processSlotVoteUnchecked(allocator, &vote_state, expire_slot + 1);

    // Confirmation count for the older first vote should remain unchanged
    try std.testing.expectEqual(3, vote_state.votes.items[0].lockout.confirmation_count);

    // The later votes should still have increasing confirmation counts
    try std.testing.expectEqual(2, vote_state.votes.items[1].lockout.confirmation_count);
    try std.testing.expectEqual(1, vote_state.votes.items[2].lockout.confirmation_count);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1558
test "state.VoteStateV3.getCredits" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        0,
    );
    defer vote_state.deinit(allocator);

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state, i);
    }

    try std.testing.expectEqual(0, vote_state.getCredits());

    try processSlotVoteUnchecked(allocator, &vote_state, (MAX_LOCKOUT_HISTORY + 1));
    try std.testing.expectEqual(1, vote_state.getCredits());
    try processSlotVoteUnchecked(allocator, &vote_state, (MAX_LOCKOUT_HISTORY + 2));
    try std.testing.expectEqual(2, vote_state.getCredits());
    try processSlotVoteUnchecked(allocator, &vote_state, (MAX_LOCKOUT_HISTORY + 3));
    try std.testing.expectEqual(3, vote_state.getCredits());
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1577
test "state.VoteStateV3 duplicate vote" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        0,
    );
    defer vote_state.deinit(allocator);

    try processSlotVoteUnchecked(allocator, &vote_state, 0);
    try processSlotVoteUnchecked(allocator, &vote_state, 1);
    try processSlotVoteUnchecked(allocator, &vote_state, 0);

    try std.testing.expectEqual(1, nthRecentLockout(&vote_state, 0).?.slot);
    try std.testing.expectEqual(0, nthRecentLockout(&vote_state, 1).?.slot);
    try std.testing.expectEqual(null, nthRecentLockout(&vote_state, 2));
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1589
test "state.VoteStateV3 nth recent lockout" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var vote_state = try VoteStateV3.init(
        allocator,
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        Pubkey.initRandom(prng.random()),
        0,
        0,
    );
    defer vote_state.deinit(allocator);

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state, i);
    }

    for (0..(MAX_LOCKOUT_HISTORY - 1)) |i| {
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY - i - 1,
            nthRecentLockout(&vote_state, i).?.slot,
        );
    }
    try std.testing.expectEqual(
        null,
        nthRecentLockout(&vote_state, MAX_LOCKOUT_HISTORY),
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L1632
test "state.VoteStateV3.processVote process missed votes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const account_a = Pubkey.initRandom(prng.random());
    var vote_state_a = try createTestVoteStateV3(
        allocator,
        Pubkey.initRandom(prng.random()),
        account_a,
        account_a,
        0,
    );
    defer vote_state_a.deinit(allocator);

    const account_b = Pubkey.initRandom(prng.random());
    var vote_state_b = try createTestVoteStateV3(
        allocator,
        Pubkey.initRandom(prng.random()),
        account_b,
        account_b,
        0,
    );
    defer vote_state_b.deinit(allocator);

    // process some votes on account a
    for (0..5) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state_a, i);
    }

    {
        const recent_a = try recentVotes(allocator, &vote_state_a);
        defer allocator.free(recent_a);
        const recent_b = try recentVotes(allocator, &vote_state_b);
        defer allocator.free(recent_b);

        try std.testing.expect(!std.meta.eql(
            recent_a,
            recent_b,
        ));
    }

    // as long as b has missed less than "NUM_RECENT" votes both accounts should be in sync
    var slots: [MAX_RECENT_VOTES]Slot = undefined;
    for (&slots, 0..) |_, i| {
        slots[i] = i;
    }

    const vote = Vote{ .slots = &slots, .hash = Hash.ZEROES, .timestamp = null };

    var slot_hashes: SlotHashes = .INIT;

    var iter = std.mem.reverseIterator(vote.slots);
    while (iter.next()) |vote_slot| {
        slot_hashes.entries.appendAssumeCapacity(.{
            .slot = vote_slot,
            .hash = vote.hash,
        });
    }

    {
        const maybe_error = vote_state_a.processVote(
            allocator,
            &vote,
            slot_hashes,
            0,
            0,
        );
        try std.testing.expectEqual(null, maybe_error);
    }

    {
        const maybe_error = vote_state_b.processVote(
            allocator,
            &vote,
            slot_hashes,
            0,
            0,
        );
        try std.testing.expectEqual(null, maybe_error);
    }

    {
        const recent_a = try recentVotes(allocator, &vote_state_a);
        defer allocator.free(recent_a);
        const recent_b = try recentVotes(allocator, &vote_state_b);
        defer allocator.free(recent_b);
        try std.testing.expectEqualSlices(Vote, recent_a, recent_b);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1659
test "state.VoteStateV3.processVote skips old vote" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(
        &.{.{ .slot = 0, .hash = vote.hash }},
    );

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);
    const result = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L2856
test "state.VoteStateV3 filter old votes" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const allocator = std.testing.allocator;
    const old_vote_slot = 1;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{old_vote_slot};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    // Vote with all slots that are all older than the SlotHashe
    // error with `VotesTooOldAllFiltered`
    const slot_hashes = SlotHashes.initWithEntries(&.{
        .{ .slot = 3, .hash = Hash.initRandom(random) },
        .{ .slot = 2, .hash = Hash.initRandom(random) },
    });

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(VoteError.votes_too_old_all_filtered, maybe_error);

    // Vote with only some slots older than the SlotHashes history should
    // filter out those older slots
    const vote_slot = 2;
    const vote_slot_hash = for (slot_hashes.entries.constSlice()) |entry| {
        if (entry.slot == vote_slot) {
            break entry.hash;
        }
    } else unreachable;

    var second_votes = [_]u64{vote_slot};

    const second_vote = Vote{
        .slots = &second_votes,
        .hash = vote_slot_hash,
        .timestamp = null,
    };
    _ = try vote_state.processVote(allocator, &second_vote, slot_hashes, 0, 0);

    try std.testing.expectEqualDeep(
        Lockout{ .slot = vote_slot, .confirmation_count = 1 },
        vote_state.votes.items[0].lockout,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1677
test "state.VoteStateV3.processVote empty slot hashes" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &.INIT);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1688
test "state.VoteStateV3.checkSlotsAreValid new vote" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{
        .{ .slot = vote.slots[vote.slots.len - 1], .hash = vote.hash },
    });

    try std.testing.expectEqual(
        null,
        try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes),
    );
}

test "state.VoteStateV3.checkSlotsAreValid bad timestamp" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{
        .{ .slot = vote.slots[vote.slots.len - 1], .hash = vote.hash },
    });

    try std.testing.expectEqual(
        null,
        try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes),
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1700
test "state.VoteStateV3.checkSlotsAreValid bad hash" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{
        .slot = vote.slots[vote.slots.len - 1],
        .hash = Hash.init(&vote.hash.data),
    }});

    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.slot_hash_mismatch, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1712
test "state.VoteStateV3.checkSlotsAreValid bad slot" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{1};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{ .slot = 0, .hash = vote.hash }});
    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.slots_mismatch, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1724
test "state.VoteStateV3.checkSlotsAreValid duplicate vote" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{ .slot = 0, .hash = vote.hash }});

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);
    const result = try vote_state.checkSlotsAreValid(&vote, vote.slots, &slot_hashes);
    try std.testing.expectEqual(VoteError.vote_too_old, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1740
test "state.VoteStateV3.checkSlotsAreValid next vote" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{ .slot = 0, .hash = vote.hash }});

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);

    var next_votes = [_]u64{ 0, 1 };

    const next_vote = Vote{
        .slots = &next_votes,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const next_slot_hashes = SlotHashes.initWithEntries(&.{
        .{ .slot = 1, .hash = vote.hash },
        .{ .slot = 0, .hash = vote.hash },
    });

    const result = try vote_state.checkSlotsAreValid(
        &next_vote,
        next_vote.slots,
        &next_slot_hashes,
    );
    try std.testing.expectEqual(null, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1759
test "state.VoteStateV3.checkSlotsAreValid next vote only" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var slots = [_]u64{0};

    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{ .slot = 0, .hash = vote.hash }});

    const maybe_error = try vote_state.processVote(allocator, &vote, slot_hashes, 0, 0);
    try std.testing.expectEqual(null, maybe_error);

    var next_votes = [_]u64{1};

    const next_vote = Vote{
        .slots = &next_votes,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const next_slot_hashes = SlotHashes.initWithEntries(&.{
        .{ .slot = 1, .hash = vote.hash },
        .{ .slot = 0, .hash = vote.hash },
    });

    const result = try vote_state.checkSlotsAreValid(
        &next_vote,
        next_vote.slots,
        &next_slot_hashes,
    );
    try std.testing.expectEqual(null, result);
}

// [agave] https://github.com/anza-xyz/agave/blob/6679ac4f38640496c64d234fffa61729f1572ce1/programs/vote/src/vote_state/mod.rs#L1777
test "state.VoteStateV3.processVote empty slots" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    const vote = Vote{
        .slots = &[_]u64{},
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    const maybe_error = try vote_state.processVote(
        allocator,
        &vote,
        .INIT,
        0,
        0,
    );
    try std.testing.expectEqual(VoteError.empty_slots, maybe_error);
}

test "state.VoteStateV3.computeVoteLatency" {
    try std.testing.expectEqual(0, VoteStateV3.computeVoteLatency(10, 10));
    try std.testing.expectEqual(0, VoteStateV3.computeVoteLatency(10, 5));
    try std.testing.expectEqual(5, VoteStateV3.computeVoteLatency(5, 10));
    try std.testing.expectEqual(
        std.math.maxInt(u8),
        VoteStateV3.computeVoteLatency(0, std.math.maxInt(u16)),
    );
}

test "state.VoteStateV3.contains_slot" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    try vote_state.votes.append(allocator, .{
        .latency = 1,
        .lockout = Lockout{ .slot = 1, .confirmation_count = 1 },
    });
    try vote_state.votes.append(allocator, .{
        .latency = 1,
        .lockout = Lockout{ .slot = 2, .confirmation_count = 2 },
    });

    try std.testing.expect(vote_state.containsSlot(1));
    try std.testing.expect(vote_state.containsSlot(2));
    try std.testing.expect(!vote_state.containsSlot(3));
    try std.testing.expect(!vote_state.containsSlot(0));
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2223
test "state.VoteStateV3 process new vote too many votes" {
    const allocator = std.testing.allocator;

    var vote_state: VoteStateV3 = .DEFAULT;
    defer vote_state.deinit(allocator);

    var bad_votes = std.array_list.Managed(Lockout).init(allocator);
    defer bad_votes.deinit();

    var slot: usize = 0;
    while (slot <= MAX_LOCKOUT_HISTORY) : (slot += 1) {
        try bad_votes.append(Lockout{
            .slot = slot,
            .confirmation_count = @intCast((MAX_LOCKOUT_HISTORY - slot + 1)),
        });
    }

    const current_epoch = currentEpoch(&vote_state);
    const maybe_error = try processNewVoteStateFromLockouts(
        allocator,
        &vote_state,
        bad_votes.items,
        null,
        null,
        current_epoch,
    );
    try std.testing.expectEqual(VoteError.too_many_votes, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2249
test "state.VoteStateV3 process new vote state root rollback" {
    const allocator = std.testing.allocator;

    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    for (0..MAX_LOCKOUT_HISTORY + 2) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state1, @as(Slot, i));
    }

    try std.testing.expectEqual(1, vote_state1.root_slot);
    // Update vote_state2 with a higher slot so that `process_new_vote_state`
    // doesn't panic.
    var vote_state2 = try vote_state1.clone(allocator);
    defer vote_state2.deinit(allocator);
    try processSlotVoteUnchecked(allocator, &vote_state2, @intCast((MAX_LOCKOUT_HISTORY + 3)));

    // Trying to set a lesser root should error
    const lesser_root: ?Slot = 0;

    const current_epoch = currentEpoch(&vote_state2);
    const maybe_error = try vote_state1.processNewVoteState(
        allocator,
        vote_state2.votes.items,
        lesser_root,
        null,
        current_epoch,
        0,
    );

    try std.testing.expectEqual(VoteError.root_roll_back, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2295
test "state.VoteStateV3 process new vote state zero confirmations" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    const current_epoch = currentEpoch(&vote_state1);

    var bad_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 0 },
        Lockout{ .slot = 1, .confirmation_count = 1 },
    };

    const maybe_error = try processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.zero_confirmations, maybe_error);

    var anoter_bad_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 2 },
        Lockout{ .slot = 1, .confirmation_count = 0 },
    };

    const another_maybe_error = try processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &anoter_bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.zero_confirmations, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2337
test "state.VoteStateV3 process new vote state confirmations too large" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);
    const current_epoch = currentEpoch(&vote_state1);

    var good_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = @as(u32, MAX_LOCKOUT_HISTORY) },
    };

    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &good_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(null, maybe_error);

    var another_vote_state1: VoteStateV3 = .DEFAULT;
    var bad_votes = [_]Lockout{
        Lockout{
            .slot = 0,
            .confirmation_count = @as(u32, MAX_LOCKOUT_HISTORY + 1),
        },
    };

    const another_maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &another_vote_state1,
        &bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.confirmation_too_large, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2379
test "state.VoteStateV3 process new vote state slot smaller than root" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    const current_epoch = currentEpoch(&vote_state1);

    const root_slot: u64 = 5;

    var bad_votes = [_]Lockout{
        Lockout{ .slot = root_slot, .confirmation_count = 2 },
        Lockout{ .slot = root_slot + 1, .confirmation_count = 1 },
    };

    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &bad_votes,
        root_slot,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.slot_smaller_than_root, maybe_error);

    var another_bad_votes = [_]Lockout{
        Lockout{ .slot = root_slot - 1, .confirmation_count = 2 },
        Lockout{ .slot = root_slot + 1, .confirmation_count = 1 },
    };

    const another_maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &another_bad_votes,
        root_slot,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.slot_smaller_than_root, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2422
test "state.VoteStateV3 process new vote state slots not ordered" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    const current_epoch = currentEpoch(&vote_state1);

    var bad_votes = [_]Lockout{
        Lockout{ .slot = 1, .confirmation_count = 2 },
        Lockout{ .slot = 0, .confirmation_count = 1 },
    };

    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.slots_not_ordered, maybe_error);

    var another_bad_votes = [_]Lockout{
        Lockout{ .slot = 1, .confirmation_count = 2 },
        Lockout{ .slot = 1, .confirmation_count = 1 },
    };

    const another_maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &another_bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(VoteError.slots_not_ordered, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2464
test "state.VoteStateV3 process new vote state confirmations not ordered" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    const current_epoch = currentEpoch(&vote_state1);

    var bad_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 1 },
        Lockout{ .slot = 1, .confirmation_count = 2 },
    };

    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(
        VoteError.confirmations_not_ordered,
        maybe_error,
    );

    var another_bad_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 1 },
        Lockout{ .slot = 1, .confirmation_count = 1 },
    };

    const another_maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &another_bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(
        VoteError.confirmations_not_ordered,
        another_maybe_error,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2506
test "state.VoteStateV3 process new vote state lockout mismatch" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    const current_epoch = currentEpoch(&vote_state1);

    var bad_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 2 },
        Lockout{ .slot = 7, .confirmation_count = 1 },
    };

    // Slot 7 should have expired slot 0
    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &bad_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(
        VoteError.new_vote_state_lockout_mismatch,
        maybe_error,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2532
test "state.VoteStateV3 process new vote state confirmation rollback" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);
    const current_epoch = currentEpoch(&vote_state1);

    var votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 4 },
        Lockout{ .slot = 1, .confirmation_count = 3 },
    };

    const maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(null, maybe_error);

    var another_votes = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 4 },
        Lockout{ .slot = 1, .confirmation_count = 2 },
        Lockout{ .slot = 2, .confirmation_count = 1 },
    };
    // Should error because newer vote state should not have lower confirmation the same slot
    // 1
    const another_maybe_error = processNewVoteStateFromLockouts(
        allocator,
        &vote_state1,
        &another_votes,
        null,
        null,
        current_epoch,
    );

    try std.testing.expectEqual(
        VoteError.confirmation_roll_back,
        another_maybe_error,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2575
test "state.VoteStateV3 process new vote state root progress" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try processSlotVoteUnchecked(allocator, &vote_state1, @as(Slot, i));
    }

    try std.testing.expectEqual(null, vote_state1.root_slot);
    var vote_state2 = try vote_state1.clone(allocator);
    defer vote_state2.deinit(allocator);

    // 1) Try to update `vote_state1` with no root,
    // to `vote_state2`, which has a new root, should succeed.
    //
    // 2) Then try to update`vote_state1` with an existing root,
    // to `vote_state2`, which has a newer root, which
    // should succeed.
    for (MAX_LOCKOUT_HISTORY + 1..MAX_LOCKOUT_HISTORY + 3) |new_vote| {
        try processSlotVoteUnchecked(allocator, &vote_state2, new_vote);
        try std.testing.expect(vote_state1.root_slot != vote_state2.root_slot);

        var cloned_votes = try vote_state2.votes.clone(allocator);
        defer cloned_votes.deinit(allocator);

        const maybe_error = try vote_state1.processNewVoteState(
            allocator,
            cloned_votes.items,
            vote_state2.root_slot,
            null,
            currentEpoch(&vote_state2),
            0,
        );

        try std.testing.expectEqual(null, maybe_error);
        try std.testing.expectEqualDeep(vote_state1, vote_state2);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2610
test "state.VoteStateV3 process new vote state same slot but not common ancestor" {
    // It might be possible that during the switch from old vote instructions
    // to new vote instructions, new_state contains votes for slots LESS
    // than the current state, for instance:
    //
    // Current on-chain state: 1, 5
    // New state: 1, 2 (lockout: 4), 3, 5, 7
    //
    // Imagine the validator made two of these votes:
    // 1) The first vote {1, 2, 3} didn't land in the old state, but didn't
    // land on chain
    // 2) A second vote {1, 2, 5} was then submitted, which landed
    //
    //
    // 2 is not popped off in the local tower because 3 doubled the lockout.
    // However, 3 did not land in the on-chain state, so the vote {1, 2, 6}
    // will immediately pop off 2.

    // Construct on-chain vote state
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);
    var slots = [_]Slot{ 1, 2, 5 };
    try processSlotVotesUnchecked(allocator, &vote_state1, slots[0..]);

    const expected_slots = [_]u64{ 1, 5 };
    var actual_slots: [2]u64 = undefined;
    for (vote_state1.votes.items[0..2], 0..) |vote, i| {
        actual_slots[i] = vote.lockout.slot;
    }
    try std.testing.expect(std.mem.eql(u64, &expected_slots, &actual_slots));

    // Construct local tower state
    var vote_state2: VoteStateV3 = .DEFAULT;
    defer vote_state2.deinit(allocator);

    var another_slots = [_]Slot{ 1, 2, 3, 5, 7 };
    try processSlotVotesUnchecked(allocator, &vote_state2, another_slots[0..]);

    const another_expected_slots = [_]u64{ 1, 2, 3, 5, 7 };
    var another_actual_slots: [5]u64 = undefined;
    for (vote_state2.votes.items[0..5], 0..) |vote, i| {
        another_actual_slots[i] = vote.lockout.slot;
    }
    try std.testing.expect(std.mem.eql(u64, &another_expected_slots, &another_actual_slots));

    // See that on-chain vote state can update properly
    var cloned_votes = try vote_state2.votes.clone(allocator);
    defer cloned_votes.deinit(allocator);

    const maybe_error = try vote_state1.processNewVoteState(
        allocator,
        cloned_votes.items,
        vote_state2.root_slot,
        null,
        currentEpoch(&vote_state2),
        0,
    );

    try std.testing.expectEqual(null, maybe_error);
    try std.testing.expectEqualDeep(vote_state1, vote_state2);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2668
test "state.VoteStateV3 process new vote state lockout violation" {
    // Construct on-chain vote state
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    {
        var slots = [_]Slot{ 1, 2, 4, 5 };
        try processSlotVotesUnchecked(allocator, &vote_state1, slots[0..]);

        var actual_slots: [4]u64 = undefined;
        for (vote_state1.votes.items[0..4], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        try std.testing.expect(std.mem.eql(u64, &slots, &actual_slots));
    }

    // Construct conflicting tower state. Vote 4 is missing,
    // but 5 should not have popped off vote 4.
    var vote_state2: VoteStateV3 = .DEFAULT;
    defer vote_state2.deinit(allocator);
    {
        var slots = [_]Slot{ 1, 2, 3, 5, 7 };
        try processSlotVotesUnchecked(allocator, &vote_state2, slots[0..]);

        var actual_slots: [5]u64 = undefined;
        for (vote_state2.votes.items[0..5], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        try std.testing.expect(std.mem.eql(u64, &slots, &actual_slots));
    }

    var cloned_votes = try vote_state2.votes.clone(allocator);
    defer cloned_votes.deinit(allocator);

    const maybe_error = try vote_state1.processNewVoteState(
        allocator,
        cloned_votes.items,
        vote_state2.root_slot,
        null,
        currentEpoch(&vote_state2),
        0,
    );

    try std.testing.expectEqual(VoteError.lockout_conflict, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2710
test "state.VoteStateV3 process new vote state lockout violation2" {
    // Construct on-chain vote state
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    {
        var slots = [_]Slot{ 1, 2, 5, 6, 7 };
        try processSlotVotesUnchecked(allocator, &vote_state1, slots[0..]);

        var actual_slots: [4]u64 = undefined;
        for (vote_state1.votes.items[0..4], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        var expected_slots = [_]Slot{ 1, 5, 6, 7 };
        try std.testing.expect(std.mem.eql(u64, &expected_slots, &actual_slots));
    }

    // Construct a new vote state. Violates on-chain state because 8
    // should not have popped off 7
    var vote_state2: VoteStateV3 = .DEFAULT;
    defer vote_state2.deinit(allocator);
    {
        var slots = [_]Slot{ 1, 2, 3, 5, 6, 8 };
        try processSlotVotesUnchecked(allocator, &vote_state2, slots[0..]);

        var actual_slots: [6]u64 = undefined;
        for (vote_state2.votes.items[0..6], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        try std.testing.expect(std.mem.eql(u64, &slots, &actual_slots));
    }

    // Both vote states contain `5`, but `5` is not part of the common prefix
    // of both vote states. However, the violation should still be detected.
    const cloned_votes = try allocator.dupe(LandedVote, vote_state2.votes.items);
    defer allocator.free(cloned_votes);

    const maybe_error = try vote_state1.processNewVoteState(
        allocator,
        cloned_votes,
        vote_state2.root_slot,
        null,
        currentEpoch(&vote_state2),
        0,
    );

    try std.testing.expectEqual(VoteError.lockout_conflict, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2753
test "state.VoteStateV3 process new vote state expired ancestor not removed" {
    // Construct on-chain vote state
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    {
        var slots = [_]Slot{ 1, 2, 3, 9 };
        try processSlotVotesUnchecked(allocator, &vote_state1, slots[0..]);

        var actual_slots: [2]u64 = undefined;
        for (vote_state1.votes.items[0..2], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        var expected_slots = [_]Slot{ 1, 9 };
        try std.testing.expect(std.mem.eql(u64, &expected_slots, &actual_slots));
    }

    // Example: {1: lockout 8, 9: lockout 2}, vote on 10 will not pop off 1
    // because 9 is not popped off yet
    var vote_state2 = try vote_state1.clone(allocator);
    defer vote_state2.deinit(allocator);

    try processSlotVoteUnchecked(allocator, &vote_state2, 10);

    // Slot 1 has been expired by 10, but is kept alive by its descendant
    // 9 which has not been expired yet.
    try std.testing.expectEqual(1, vote_state2.votes.items[0].lockout.slot);
    try std.testing.expectEqual(9, vote_state2.votes.items[0].lockout.lastLockedOutSlot());
    {
        var expected_slots = [_]Slot{ 1, 9, 10 };
        var actual_slots: [3]u64 = undefined;
        for (vote_state2.votes.items[0..3], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        try std.testing.expect(std.mem.eql(u64, &expected_slots, &actual_slots));
    }

    // Should be able to update vote_state1
    var cloned_votes = try vote_state2.votes.clone(allocator);
    defer cloned_votes.deinit(allocator);

    const maybe_error = try vote_state1.processNewVoteState(
        allocator,
        cloned_votes.items,
        vote_state2.root_slot,
        null,
        currentEpoch(&vote_state2),
        0,
    );
    try std.testing.expectEqual(null, maybe_error);
    // TODO Revisit why std.testing.expectEqualDeep(vote_state1, vote_state2) fails.
    try std.testing.expectEqualDeep(vote_state1.votes.items, vote_state2.votes.items);
    try std.testing.expectEqualDeep(vote_state1.root_slot, vote_state2.root_slot);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2799
test "state.VoteStateV3 process new vote current state contains bigger slots" {
    const allocator = std.testing.allocator;
    var vote_state1: VoteStateV3 = .DEFAULT;
    defer vote_state1.deinit(allocator);

    {
        var slots = [_]Slot{ 6, 7, 8 };
        try processSlotVotesUnchecked(allocator, &vote_state1, slots[0..]);

        var actual_slots: [3]u64 = undefined;
        for (vote_state1.votes.items[0..3], 0..) |vote, i| {
            actual_slots[i] = vote.lockout.slot;
        }
        try std.testing.expect(std.mem.eql(u64, &slots, &actual_slots));
    }
    const root: ?Slot = 1;
    {
        // Try to process something with lockout violations
        var bad_votes = [_]Lockout{
            Lockout{ .slot = 2, .confirmation_count = 5 },
            // Slot 14 could not have popped off slot 6 yet
            Lockout{ .slot = 14, .confirmation_count = 1 },
        };

        const current_epoch = currentEpoch(&vote_state1);

        const maybe_error = processNewVoteStateFromLockouts(
            allocator,
            &vote_state1,
            &bad_votes,
            root,
            null,
            current_epoch,
        );

        try std.testing.expectEqual(VoteError.lockout_conflict, maybe_error);
    }

    {
        var good_votes = [_]LandedVote{
            .{
                .latency = 0,
                .lockout = Lockout{ .slot = 2, .confirmation_count = 5 },
            },
            .{
                .latency = 0,
                .lockout = Lockout{ .slot = 15, .confirmation_count = 1 },
            },
        };

        const another_current_epoch = currentEpoch(&vote_state1);

        const maybe_error = try vote_state1.processNewVoteState(
            allocator,
            &good_votes,
            root,
            null,
            another_current_epoch,
            0,
        );

        try std.testing.expectEqual(null, maybe_error);
        try std.testing.expectEqualDeep(
            vote_state1.votes.items,
            &good_votes,
        );
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2916
test "state.VoteStateV3.checkAndFilterProposedVoteState empty" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const empty_slot_hashes = try buildSlotHashes(random, &[_]Slot{});

    var empty_vote_state = try buildVoteState(
        allocator,
        &[_]Slot{},
        empty_slot_hashes,
    );

    // Test with empty TowerSync, should return EmptySlots error
    {
        var tower_sync = try testTowerSync(
            allocator,
            &[_]Lockout{},
        );
        defer tower_sync.lockouts.deinit(allocator);

        const maybe_error = try empty_vote_state.checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            &empty_slot_hashes,
        );
        try std.testing.expectEqual(VoteError.empty_slots, maybe_error);
    }

    // Test with non-empty TowerSync, should return SlotsMismatch since nothing exists in SlotHashes
    {
        var tower_sync = try testTowerSync(
            allocator,
            &[_]Lockout{
                Lockout{ .slot = 0, .confirmation_count = 1 },
            },
        );
        defer tower_sync.lockouts.deinit(allocator);

        const maybe_error = try empty_vote_state
            .checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            &empty_slot_hashes,
        );
        try std.testing.expectEqual(VoteError.slots_mismatch, maybe_error);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L2948
test "state.VoteStateV3.checkAndFilterProposedVoteState too old" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const latest_vote = 4;
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 1, 2, 3, 4 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 1, 2, 3, latest_vote },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    {
        // Test with a vote for a slot less than the latest vote in the vote_state,
        // should return error `VoteTooOld`
        var tower_sync = try testTowerSync(
            allocator,
            &[_]Lockout{
                Lockout{ .slot = latest_vote, .confirmation_count = 1 },
            },
        );
        defer tower_sync.lockouts.deinit(allocator);

        const maybe_error = try vote_state
            .checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            &slot_hashes,
        );
        try std.testing.expectEqual(VoteError.vote_too_old, maybe_error);
    }

    // Test with a vote state update where the latest slot `X` in the update is
    // 1) Less than the earliest slot in slot_hashes history, AND
    // 2) `X` > latest_vote
    const earliest_slot_in_history = latest_vote + 2;
    const another_slot_hashes = try buildSlotHashes(
        random,
        &[_]Slot{earliest_slot_in_history},
    );

    var another_tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            Lockout{ .slot = earliest_slot_in_history - 1, .confirmation_count = 1 },
        },
    );
    defer another_tower_sync.lockouts.deinit(allocator);

    const maybe_error = try vote_state
        .checkAndFilterProposedVoteState(
        &another_tower_sync.lockouts,
        &another_tower_sync.root,
        another_tower_sync.hash,
        &another_slot_hashes,
    );

    try std.testing.expectEqual(VoteError.vote_too_old, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3063
test "state.VoteStateV3.checkAndFilterProposedVoteState older than history root" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    // Test when `proposed_root` is in `current_vote_state_slots` but it's not the latest
    // slot
    {
        const earliest_slot_in_history: Slot = 5;
        const current_vote_state_slots = [_]Slot{ 1, 2, 3, 4 };
        const current_vote_state_root: ?Slot = null;
        const proposed_slots_and_lockouts = [_]Lockout{
            .{ .slot = 5, .confirmation_count = 1 },
        };
        const proposed_root: Slot = 4;
        const expected_root: ?Slot = 4;
        const expected_vote_state = [_]Lockout{
            Lockout{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }

    // Test when `proposed_root` is in `current_vote_state_slots` but it's not the latest
    // slot and the `current_vote_state_root.is_some()`.
    {
        const earliest_slot_in_history: Slot = 5;
        const current_vote_state_slots = [_]Slot{ 1, 2, 3, 4 };
        const current_vote_state_root: ?Slot = 0;
        const proposed_slots_and_lockouts = [_]Lockout{.{ .slot = 5, .confirmation_count = 1 }};
        const proposed_root: Slot = 4;
        const expected_root: ?Slot = 4;
        const expected_vote_state = [_]Lockout{
            Lockout{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }

    // Test when `proposed_root` is in `current_vote_state_slots` but it's not the latest
    // slot
    {
        const earliest_slot_in_history: Slot = 5;
        const current_vote_state_slots = [_]Slot{ 1, 2, 3, 4 };
        const current_vote_state_root: ?Slot = 0;
        const proposed_slots_and_lockouts = [_]Lockout{
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };
        const proposed_root: Slot = 3;
        const expected_root: ?Slot = 3;
        const expected_vote_state = [_]Lockout{
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }

    // Test when `proposed_root` is not in `current_vote_state_slots`
    {
        const earliest_slot_in_history: Slot = 5;
        const current_vote_state_slots = [_]Slot{ 1, 2, 4 };
        const current_vote_state_root: ?Slot = 0;
        const proposed_slots_and_lockouts = [_]Lockout{
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };
        const proposed_root: Slot = 3;
        const expected_root: ?Slot = 2;
        const expected_vote_state = [_]Lockout{
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }

    // Test when the `proposed_root` is smaller than all the slots in
    // `current_vote_state_slots`, no roots should be set.
    {
        const earliest_slot_in_history: Slot = 4;
        const current_vote_state_slots = [_]Slot{ 3, 4 };
        const current_vote_state_root: ?Slot = null;
        const proposed_slots_and_lockouts = [_]Lockout{
            .{ .slot = 3, .confirmation_count = 3 },
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };
        const proposed_root: Slot = 2;
        const expected_root: ?Slot = null;
        const expected_vote_state = [_]Lockout{
            .{ .slot = 3, .confirmation_count = 3 },
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }

    // Test when `current_vote_state_slots` is empty, no roots should be set
    {
        const earliest_slot_in_history: Slot = 4;
        const current_vote_state_slots = [_]Slot{};
        const current_vote_state_root: ?Slot = null;
        const proposed_slots_and_lockouts = [_]Lockout{
            .{ .slot = 5, .confirmation_count = 1 },
        };
        const proposed_root: Slot = 2;
        const expected_root: ?Slot = null;
        const expected_vote_state = [_]Lockout{
            .{ .slot = 5, .confirmation_count = 1 },
        };

        try runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
            allocator,
            random,
            earliest_slot_in_history,
            &current_vote_state_slots,
            current_vote_state_root,
            &proposed_slots_and_lockouts,
            proposed_root,
            expected_root,
            &expected_vote_state,
        );
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3188
test "state.VoteStateV3.checkAndFilterProposedVoteState slots not ordered" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 1, 2, 3, 4 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{1},
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    const vote_slot = 3;
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };

    // Test with a `TowerSync` where the slots are out of order with empty TowerSync, should return EmptySlots error
    {
        var tower_sync = try testTowerSync(
            allocator,
            &[_]Lockout{
                .{ .slot = 2, .confirmation_count = 2 },
                .{ .slot = 1, .confirmation_count = 3 },
                .{ .slot = vote_slot, .confirmation_count = 1 },
            },
        );
        defer tower_sync.lockouts.deinit(allocator);
        tower_sync.hash = vote_slot_hash;
        const maybe_error = try vote_state.checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            &slot_hashes,
        );
        try std.testing.expectEqual(VoteError.slots_not_ordered, maybe_error);
    }

    // Test with a `TowerSync` where there are multiples of the same slot
    {
        var tower_sync = try testTowerSync(
            allocator,
            &[_]Lockout{
                .{ .slot = 2, .confirmation_count = 2 },
                .{ .slot = 2, .confirmation_count = 2 },
                .{ .slot = vote_slot, .confirmation_count = 1 },
            },
        );
        defer tower_sync.lockouts.deinit(allocator);

        tower_sync.hash = vote_slot_hash;

        const maybe_error = try vote_state
            .checkAndFilterProposedVoteState(
            &tower_sync.lockouts,
            &tower_sync.root,
            tower_sync.hash,
            &slot_hashes,
        );
        try std.testing.expectEqual(VoteError.slots_not_ordered, maybe_error);
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3228
test "state.VoteStateV3.checkAndFilterProposedVoteState older than history slots filtered" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const init_slot_hashes = try buildSlotHashes(random, &[_]Slot{ 1, 2, 3, 4 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 1, 2, 3, 4 },
        init_slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where there:
    // 1) Exists a slot less than `earliest_slot_in_history`
    // 2) This slot does not exist in the vote state already
    // This slot should be filtered out
    const earliest_slot_in_history = 11;
    const slot_hashes = try buildSlotHashes(
        random,
        &[_]Slot{ earliest_slot_in_history, 12, 13, 14 },
    );

    const vote_slot = 12;
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };
    const missing_older_than_history_slot = earliest_slot_in_history - 1;

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 1, .confirmation_count = 4 },
            .{ .slot = missing_older_than_history_slot, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 3 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);

    // Check the earlier slot was filtered out
    const expected_lockouts = [_]Lockout{
        .{ .slot = 1, .confirmation_count = 4 },
        .{ .slot = vote_slot, .confirmation_count = 3 },
    };
    var actual_lockouts: [2]Lockout = undefined;
    for (tower_sync.lockouts.items[0..2], 0..) |lockout, i| {
        actual_lockouts[i] = lockout;
    }

    try std.testing.expectEqualDeep(&expected_lockouts, &actual_lockouts);

    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(null, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3284
test "state.VoteStateV3.checkAndFilterProposedVoteState older than history slots not filtered" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const init_slot_hashes = try buildSlotHashes(random, &[_]Slot{4});

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{4},
        init_slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where there:
    // 1) Exists a slot less than `earliest_slot_in_history`
    // 2) This slot exists in the vote state already
    // This slot should *NOT* be filtered out
    const earliest_slot_in_history = 11;
    const slot_hashes = try buildSlotHashes(
        random,
        &[_]Slot{ earliest_slot_in_history, 12, 13, 14 },
    );

    const vote_slot = 12;
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };
    const existing_older_than_history_slot = 4;

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = existing_older_than_history_slot, .confirmation_count = 3 },
            .{ .slot = vote_slot, .confirmation_count = 2 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);

    // Check the earlier slot was *NOT* filtered out
    try std.testing.expectEqual(tower_sync.lockouts.items.len, 2);

    const expected_lockouts = [_]Lockout{
        .{ .slot = existing_older_than_history_slot, .confirmation_count = 3 },
        .{ .slot = vote_slot, .confirmation_count = 2 },
    };
    var actual_lockouts: [2]Lockout = undefined;
    for (tower_sync.lockouts.items[0..2], 0..) |lockout, i| {
        actual_lockouts[i] = lockout;
    }

    try std.testing.expectEqualDeep(&expected_lockouts, &actual_lockouts);

    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(null, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3337
test "state.VoteStateV3.checkAndFilterProposedVoteState older history slots filtered/not filtered" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const init_slot_hashes = try buildSlotHashes(random, &[_]Slot{6});

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{6},
        init_slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where there exists both a slot:
    // 1) Less than `earliest_slot_in_history`
    // 2) This slot exists in the vote state already
    // which should not be filtered
    //
    // AND a slot that
    //
    // 1) Less than `earliest_slot_in_history`
    // 2) This slot does not exist in the vote state already
    // which should be filtered
    const earliest_slot_in_history = 11;
    const slot_hashes = try buildSlotHashes(
        random,
        &[_]Slot{ earliest_slot_in_history, 12, 13, 14 },
    );

    const vote_slot = 14;
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };
    const missing_older_than_history_slot = 4;
    const existing_older_than_history_slot = 6;

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = missing_older_than_history_slot, .confirmation_count = 4 },
            .{ .slot = existing_older_than_history_slot, .confirmation_count = 3 },
            .{ .slot = 12, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);

    try std.testing.expectEqual(tower_sync.lockouts.items.len, 3);

    const expected_lockouts = [_]Lockout{
        .{ .slot = existing_older_than_history_slot, .confirmation_count = 3 },
        .{ .slot = 12, .confirmation_count = 2 },
        .{ .slot = vote_slot, .confirmation_count = 1 },
    };
    var actual_lockouts: [3]Lockout = undefined;
    for (tower_sync.lockouts.items[0..3], 0..) |lockout, i| {
        actual_lockouts[i] = lockout;
    }
    try std.testing.expectEqualDeep(&expected_lockouts, &actual_lockouts);

    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(null, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3404
test "state.VoteStateV3.checkAndFilterProposedVoteState slot not on fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 2, 4, 6 },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where there:
    // 1) Exists a slot not in the slot hashes history
    // 2) The slot is greater than the earliest slot in the history
    // Thus this slot is not part of the fork and the update should be rejected
    // with error `SlotsMismatch`
    const missing_vote_slot = 3;

    // Have to vote for a slot greater than the last vote in the vote state to avoid VoteTooOld
    // errors
    const vote_slot = vote_state.votes.getLast().lockout.slot + 2;
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = missing_vote_slot, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 3 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(VoteError.slots_mismatch, maybe_error);

    // Test where some earlier vote slots exist in the history, but others don't

    const another_missing_vote_slot = 7;
    var another_tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 2, .confirmation_count = 5 },
            .{ .slot = 4, .confirmation_count = 4 },
            .{ .slot = 6, .confirmation_count = 3 },
            .{ .slot = another_missing_vote_slot, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer another_tower_sync.lockouts.deinit(allocator);
    another_tower_sync.hash = vote_slot_hash;

    const another_maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &another_tower_sync.lockouts,
        &another_tower_sync.root,
        another_tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(VoteError.slots_mismatch, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3459
test "state.VoteStateV3.checkAndFilterProposedVoteState root on different fork" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 2, 4, 6 },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where:
    // 1) The root is not present in slot hashes history
    // 2) The slot is greater than the earliest slot in the history
    // Thus this slot is not part of the fork and the update should be rejected
    // with error `RootOnDifferentFork`
    const new_root: ?Slot = 3;

    // Have to vote for a slot greater than the last vote in the vote state to avoid VoteTooOld
    // errors, but also this slot must be present in SlotHashes
    const vote_slot = 8;
    try std.testing.expectEqual(slot_hashes.entries.buffer[0].slot, vote_slot);
    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;
    tower_sync.root = new_root;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(VoteError.root_on_different_fork, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3495
test "state.VoteStateV3.checkAndFilterProposedVoteState slot newer than slot history" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8, 10 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 2, 4, 6 },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where there:
    // 1) The last slot in the update is a slot not in the slot hashes history
    // 2) The slot is greater than the newest slot in the slot history
    // Thus this slot is not part of the fork and the update should be rejected
    // with error `SlotsMismatch`
    const missing_vote_slot = slot_hashes.entries.buffer[0].slot + 1;

    const vote_slot_hash = Hash.initRandom(random);

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 8, .confirmation_count = 2 },
            .{ .slot = missing_vote_slot, .confirmation_count = 3 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(VoteError.slots_mismatch, maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3521
test "state.VoteStateV3.checkAndFilterProposedVoteState slot all slot hases in update ok" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 2, 4, 6 },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where every slot in the history is
    // in the update

    // Have to vote for a slot greater than the last vote in the vote state to avoid VoteTooOld
    // errors
    const vote_slot = vote_state.votes.getLast().lockout.slot + 2;

    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 2, .confirmation_count = 4 },
            .{ .slot = 4, .confirmation_count = 3 },
            .{ .slot = 6, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);

    // Nothing in the update should have been filtered out
    const expected_lockouts = [_]Lockout{
        .{ .slot = 2, .confirmation_count = 4 },
        .{ .slot = 4, .confirmation_count = 3 },
        .{ .slot = 6, .confirmation_count = 2 },
        .{ .slot = vote_slot, .confirmation_count = 1 },
    };
    var actual_lockouts: [4]Lockout = undefined;
    for (tower_sync.lockouts.items[0..4], 0..) |lockout, i| {
        actual_lockouts[i] = lockout;
    }
    try std.testing.expectEqualDeep(&expected_lockouts, &actual_lockouts);

    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(null, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3574
test "state.VoteStateV3.checkAndFilterProposedVoteState some slot hashes in update ok" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8, 10 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{6},
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where only some slots in the history are
    // in the update, and others slots in the history are missing.

    // Have to vote for a slot greater than the last vote in the vote state to avoid VoteTooOld
    // errors
    const vote_slot = vote_state.votes.getLast().lockout.slot + 2;

    const vote_slot_hash = blk: {
        for (slot_hashes.entries.constSlice()) |item| {
            if (item.slot == vote_slot) {
                break :blk item.hash;
            }
        }
        @panic("Missing vote slot hash");
    };

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 4, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);

    // Nothing in the update should have been filtered out
    const expected_lockouts = [_]Lockout{
        .{ .slot = 4, .confirmation_count = 2 },
        .{ .slot = vote_slot, .confirmation_count = 1 },
    };
    var actual_lockouts: [2]Lockout = undefined;
    for (tower_sync.lockouts.items[0..2], 0..) |lockout, i| {
        actual_lockouts[i] = lockout;
    }
    try std.testing.expectEqualDeep(&expected_lockouts, &actual_lockouts);

    // Because 6 from the original VoteStateV3
    // should not have been popped off in the proposed state,
    // we should get a lockout conflict
    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(VoteError.lockout_conflict, another_maybe_error);
}

// [agave] https://github.com/anza-xyz/agave/blob/bdba5c5f93eeb6b981d41ea3c14173eb36879d3c/programs/vote/src/vote_state/mod.rs#L3630
test "state.VoteStateV3.checkAndFilterProposedVoteState slot hashes mismatch" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const slot_hashes = try buildSlotHashes(random, &[_]Slot{ 2, 4, 6, 8 });

    var vote_state = try buildVoteState(
        allocator,
        &[_]Slot{ 2, 4, 6 },
        slot_hashes,
    );
    defer vote_state.deinit(allocator);

    // Test with a `TowerSync` where the hash is mismatched

    // Have to vote for a slot greater than the last vote in the vote state to avoid VoteTooOld
    // errors
    const vote_slot = vote_state.votes.getLast().lockout.slot + 2;

    const vote_slot_hash = Hash.initRandom(random);

    var tower_sync = try testTowerSync(
        allocator,
        &[_]Lockout{
            .{ .slot = 2, .confirmation_count = 4 },
            .{ .slot = 4, .confirmation_count = 3 },
            .{ .slot = 6, .confirmation_count = 2 },
            .{ .slot = vote_slot, .confirmation_count = 1 },
        },
    );
    defer tower_sync.lockouts.deinit(allocator);
    tower_sync.hash = vote_slot_hash;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(VoteError.slot_hash_mismatch, maybe_error);
}

pub fn processSlotVoteUnchecked(
    allocator: Allocator,
    vote_state: *VoteStateV3,
    slot: Slot,
) !void {
    if (!builtin.is_test) @compileError("processSlotVoteUnchecked only intended for tests");

    var slots: [1]u64 = .{slot};

    const vote: Vote = .{
        .slots = &slots,
        .hash = .ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{
        .slot = vote.slots[vote.slots.len - 1],
        .hash = vote.hash,
    }});

    const epoch = if (vote_state.epoch_credits.items.len == 0)
        0
    else
        vote_state.epoch_credits.getLast().epoch;

    _ = try vote_state.processVoteUnfiltered(
        allocator,
        vote.slots,
        &vote,
        &slot_hashes,
        epoch,
        0,
    );
}

pub fn processSlotVoteUncheckedV4(
    allocator: Allocator,
    vote_state: *VoteStateV4,
    slot: Slot,
) !void {
    if (!builtin.is_test) @compileError("processSlotVoteUncheckedV4 only intended for tests");

    var slots: [1]u64 = .{slot};

    const vote: Vote = .{
        .slots = &slots,
        .hash = .ZEROES,
        .timestamp = null,
    };

    const slot_hashes = SlotHashes.initWithEntries(&.{.{
        .slot = vote.slots[vote.slots.len - 1],
        .hash = vote.hash,
    }});

    const epoch = if (vote_state.epoch_credits.items.len == 0)
        0
    else
        vote_state.epoch_credits.getLast().epoch;

    _ = try vote_state.processVoteUnfiltered(
        allocator,
        vote.slots,
        &vote,
        &slot_hashes,
        epoch,
        0,
    );
}

fn processSlotVotesUnchecked(
    allocator: Allocator,
    vote_state: *VoteStateV3,
    slots: []Slot,
) !void {
    if (!builtin.is_test) @compileError("processSlotsVoteUnchecked only intended for tests");

    for (slots) |slot| {
        try processSlotVoteUnchecked(
            allocator,
            vote_state,
            slot,
        );
    }
}

fn processNewVoteStateFromLockouts(
    allocator: Allocator,
    vote_state: *VoteStateV3,
    new_state: []const Lockout,
    new_root: ?Slot,
    timestamp: ?i64,
    epoch: Epoch,
) !?VoteError {
    if (!builtin.is_test) @compileError("only used for tests");

    const landed_votes = try VoteStateVersions.landedVotesFromLockouts(allocator, new_state);
    defer allocator.free(landed_votes);

    return try vote_state.processNewVoteState(
        allocator,
        landed_votes,
        new_root,
        timestamp,
        epoch,
        0,
    );
}

fn checkLockouts(vote_state: *const VoteStateV3) !void {
    if (!builtin.is_test) @compileError("checkLockouts should only be called in test mode");

    for (vote_state.votes.items, 0..) |*vote, i| {
        const num_votes = vote_state.votes.items.len - i;
        try std.testing.expect(
            vote.lockout.lockout() == try std.math.powi(u64, INITIAL_LOCKOUT, num_votes),
        );
    }
}

fn nthRecentLockout(vote_state: *const VoteStateV3, position: usize) ?Lockout {
    if (!builtin.is_test) {
        @panic("nthRecentLockout should only be called in test mode");
    }
    if (position < vote_state.votes.items.len) {
        const pos = std.math.sub(usize, vote_state.votes.items.len, (position + 1)) catch
            return null;
        return if (pos < vote_state.votes.items.len) vote_state.votes.items[pos].lockout else null;
    }
    return null;
}

fn currentEpoch(self: *const VoteStateV3) u64 {
    if (!builtin.is_test) {
        @panic("currentEpoch should only be called in test mode");
    }
    return if (self.epoch_credits.items.len == 0)
        0
    else
        self.epoch_credits.getLast().epoch;
}

fn buildSlotHashes(random: std.Random, slots: []const Slot) !SlotHashes {
    if (!builtin.is_test) @compileError("buildSlotHashes should only be called in test mode");

    var result: SlotHashes = .INIT;
    var iter = std.mem.reverseIterator(slots);
    while (iter.next()) |slot| {
        result.entries.appendAssumeCapacity(.{
            .slot = slot,
            .hash = Hash.initRandom(random),
        });
    }
    return result;
}

fn buildVoteState(
    allocator: Allocator,
    vote_slots: []const Slot,
    slot_hashes: SlotHashes,
) !VoteStateV3 {
    if (!builtin.is_test) @compileError("buildVoteState should only be called in test mode");

    var vote_state: VoteStateV3 = .DEFAULT;

    if (vote_slots.len > 0) {
        const last_vote_slot = vote_slots[vote_slots.len - 1];
        var vote_hash: Hash = undefined;

        for (slot_hashes.entries.constSlice()) |slot_hash| {
            if (slot_hash.slot == last_vote_slot) {
                vote_hash = slot_hash.hash;
                break;
            }
        }

        const vote = Vote{
            .slots = vote_slots,
            .hash = vote_hash,
            .timestamp = null,
        };

        _ = try vote_state.processVoteUnfiltered(
            allocator,
            vote.slots,
            &vote,
            &slot_hashes,
            0,
            0,
        );
    }

    return vote_state;
}

fn testTowerSync(allocator: Allocator, lockouts_slice: []const Lockout) !TowerSync {
    if (!builtin.is_test) {
        @panic("testTowerSync should only be called in test mode");
    }

    var lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(
        allocator,
        lockouts_slice.len,
    );
    errdefer lockouts.deinit(allocator);

    for (lockouts_slice) |item| {
        try lockouts.append(
            allocator,
            Lockout{
                .slot = item.slot,
                .confirmation_count = item.confirmation_count,
            },
        );
    }

    return TowerSync{
        .lockouts = lockouts,
        .root = null,
        .hash = Hash.ZEROES,
        .timestamp = null,
        .block_id = Hash.ZEROES,
    };
}

fn runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot(
    allocator: Allocator,
    random: std.Random,
    earliest_slot_in_history: Slot,
    current_vote_state_slots: []const Slot,
    current_vote_state_root: ?Slot,
    proposed_slots_and_lockouts: []const Lockout,
    proposed_root: Slot,
    expected_root: ?Slot,
    expected_vote_state: []const Lockout,
) !void {
    if (!builtin.is_test) {
        @panic("runTestCheckAndFilterProposedVoteStateOlderThanHistoryRoot should only in test");
    }
    try std.testing.expect(proposed_root < earliest_slot_in_history);

    var found_expected_root: ?Slot = null;
    var i = current_vote_state_slots.len;
    while (i > 0) {
        i -= 1;
        const slot = current_vote_state_slots[i];
        if (slot <= proposed_root) {
            found_expected_root = slot;
            break;
        }
    }
    try std.testing.expectEqual(expected_root, found_expected_root);

    const last_proposed = proposed_slots_and_lockouts[proposed_slots_and_lockouts.len - 1];
    const latest_slot_in_history = @max(last_proposed.slot, earliest_slot_in_history);

    var slots = std.array_list.Managed(Slot).init(allocator);
    defer slots.deinit();

    const first = if (current_vote_state_slots.len > 0)
        current_vote_state_slots[0]
    else
        0;

    for (first..(latest_slot_in_history + @as(u64, 1))) |slot| {
        try slots.append(slot);
    }

    var slot_hashes = try buildSlotHashes(random, slots.items);

    var vote_state = try buildVoteState(allocator, current_vote_state_slots, slot_hashes);
    defer vote_state.deinit(allocator);

    vote_state.root_slot = current_vote_state_root;

    var j: usize = 0;
    while (j < slot_hashes.entries.len) {
        if (slot_hashes.entries.buffer[j].slot < earliest_slot_in_history) {
            _ = slot_hashes.entries.orderedRemove(j);
        } else {
            j += 1;
        }
    }
    try std.testing.expect(proposed_slots_and_lockouts.len > 0);

    const last_proposed_slot = proposed_slots_and_lockouts[
        proposed_slots_and_lockouts.len - 1
    ].slot;
    var proposed_hash: ?Hash = null;
    for (slot_hashes.entries.constSlice()) |slot_hash| {
        if (slot_hash.slot == last_proposed_slot) {
            proposed_hash = slot_hash.hash;
            break;
        }
    }

    // Test with a `TowerSync` where the root is less than `earliest_slot_in_history`.
    // Root slot in the `TowerSync` should be updated to match the root slot in the
    // current vote state
    var tower_sync = try testTowerSync(allocator, proposed_slots_and_lockouts);
    defer tower_sync.lockouts.deinit(allocator);

    tower_sync.hash = proposed_hash.?;
    tower_sync.root = proposed_root;

    const maybe_error = try vote_state.checkAndFilterProposedVoteState(
        &tower_sync.lockouts,
        &tower_sync.root,
        tower_sync.hash,
        &slot_hashes,
    );
    try std.testing.expectEqual(null, maybe_error);
    try std.testing.expectEqual(expected_root, tower_sync.root);

    // The proposed root slot should become the biggest slot in the current vote state less than
    // `earliest_slot_in_history`.

    const another_maybe_error = try vote_state.processTowerSync(
        allocator,
        &slot_hashes,
        0,
        0,
        &tower_sync,
    );
    try std.testing.expectEqual(null, another_maybe_error);
    try std.testing.expectEqual(expected_root, vote_state.root_slot);

    var actual_lockouts = try std.array_list.Managed(Lockout).initCapacity(
        allocator,
        vote_state.votes.items.len,
    );
    defer actual_lockouts.deinit();

    for (vote_state.votes.items) |vote| {
        try actual_lockouts.append(vote.lockout);
    }

    try std.testing.expectEqualSlices(Lockout, expected_vote_state, actual_lockouts.items);
}

const MAX_RECENT_VOTES: usize = 16;
fn recentVotes(
    allocator: Allocator,
    vote_state: *const VoteStateV3,
) ![]const Vote {
    if (!builtin.is_test) {
        @panic("recentVotes should only in test");
    }
    const start = vote_state.votes.items.len -| MAX_RECENT_VOTES;

    var votes = try std.array_list.Managed(Vote).initCapacity(
        allocator,
        vote_state.votes.items.len - start,
    );

    for (start..vote_state.votes.items.len) |i| {
        const vote = Vote{
            .slots = &[_]Slot{vote_state.votes.items[i].lockout.slot},
            .hash = Hash.ZEROES,
            .timestamp = null,
        };
        try votes.append(vote);
    }

    return votes.toOwnedSlice();
}

// ── VoteState union tests ──────────────────────────────────────────────

test "state.VoteState.initV3 and field accessors" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const node_pk = Pubkey.initRandom(random);
    const voter_pk = Pubkey.initRandom(random);
    const withdrawer_pk = Pubkey.initRandom(random);
    const commission_val: u8 = 50;
    const epoch: Epoch = 7;

    var vs = try VoteState.initV3(
        allocator,
        node_pk,
        voter_pk,
        withdrawer_pk,
        commission_val,
        epoch,
    );
    defer vs.deinit(allocator);

    // Version queries
    try std.testing.expect(vs.isV3());
    try std.testing.expect(!vs.isV4());

    // Field accessors
    try std.testing.expect(vs.nodePubkey().equals(&node_pk));
    try std.testing.expect(vs.withdrawerKey().equals(&withdrawer_pk));
    try std.testing.expectEqual(commission_val, vs.commission());

    // Root slot
    try std.testing.expectEqual(null, vs.rootSlot());
    vs.rootSlotMut().* = 42;
    try std.testing.expectEqual(42, vs.rootSlot());

    // Last timestamp
    try std.testing.expectEqual(0, vs.lastTimestamp().slot);

    // isUninitialized
    try std.testing.expect(!vs.isUninitialized());

    // Votes
    try std.testing.expectEqual(0, vs.votes().items.len);

    // Epoch credits
    try std.testing.expectEqual(0, vs.epochCreditsList().items.len);

    // V4-specific accessors should return null for v3
    try std.testing.expectEqual(null, vs.inflationRewardsCommissionBps());
    try std.testing.expectEqual(null, vs.blockRevenueCollector());
    try std.testing.expectEqual(null, vs.blockRevenueCollectorMut());
    try std.testing.expectEqual(null, vs.inflationRewardsCollector());

    // setInflationRewardsCommissionBps is a no-op on v3
    vs.setInflationRewardsCommissionBps(5000);
    try std.testing.expectEqual(null, vs.inflationRewardsCommissionBps());

    // Mutable accessors
    vs.nodePubkeyMut().* = Pubkey.ZEROES;
    try std.testing.expect(vs.nodePubkey().equals(&Pubkey.ZEROES));

    vs.withdrawerMut().* = Pubkey.ZEROES;
    try std.testing.expect(vs.withdrawerKey().equals(&Pubkey.ZEROES));

    // setCommission on v3
    vs.setCommission(75);
    try std.testing.expectEqual(75, vs.commission());

    // asV3 / asV4
    try std.testing.expect(vs.asV3() != null);
    try std.testing.expectEqual(null, vs.asV4());
    try std.testing.expect(vs.asV3Const() != null);
    try std.testing.expectEqual(null, vs.asV4Const());
}

test "state.VoteState.initV4 and field accessors" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const node_pk = Pubkey.initRandom(random);
    const voter_pk = Pubkey.initRandom(random);
    const withdrawer_pk = Pubkey.initRandom(random);
    const vote_pk = Pubkey.initRandom(random);
    const commission_pct: u8 = 50;
    const epoch: Epoch = 7;

    var vs = try VoteState.initV4(
        allocator,
        node_pk,
        voter_pk,
        withdrawer_pk,
        commission_pct,
        epoch,
        vote_pk,
    );
    defer vs.deinit(allocator);

    // Version queries
    try std.testing.expect(vs.isV4());
    try std.testing.expect(!vs.isV3());

    // Field accessors
    try std.testing.expect(vs.nodePubkey().equals(&node_pk));
    try std.testing.expect(vs.withdrawerKey().equals(&withdrawer_pk));
    try std.testing.expectEqual(commission_pct, vs.commission());

    // Root slot
    try std.testing.expectEqual(null, vs.rootSlot());
    vs.rootSlotMut().* = 99;
    try std.testing.expectEqual(99, vs.rootSlot());

    // Last timestamp
    try std.testing.expectEqual(0, vs.lastTimestamp().slot);

    // isUninitialized: v4 is always initialized
    try std.testing.expect(!vs.isUninitialized());

    // Votes
    try std.testing.expectEqual(0, vs.votes().items.len);

    // Epoch credits
    try std.testing.expectEqual(0, vs.epochCreditsList().items.len);

    // V4-specific accessors
    // commission_pct=50 => inflation_rewards_commission_bps=5000
    try std.testing.expectEqual(5000, vs.inflationRewardsCommissionBps());
    try std.testing.expect(vs.blockRevenueCollector() != null);
    try std.testing.expect(vs.blockRevenueCollectorMut() != null);
    try std.testing.expect(vs.inflationRewardsCollector() != null);
    try std.testing.expect(vs.inflationRewardsCollector().?.equals(&vote_pk));

    // setInflationRewardsCommissionBps on v4
    vs.setInflationRewardsCommissionBps(1234);
    try std.testing.expectEqual(1234, vs.inflationRewardsCommissionBps());
    // commission() returns bps / 100 = 12
    try std.testing.expectEqual(12, vs.commission());

    // setCommission on v4: sets bps = pct * 100
    vs.setCommission(25);
    try std.testing.expectEqual(2500, vs.inflationRewardsCommissionBps());
    try std.testing.expectEqual(25, vs.commission());

    // Mutable accessors
    vs.nodePubkeyMut().* = Pubkey.ZEROES;
    try std.testing.expect(vs.nodePubkey().equals(&Pubkey.ZEROES));

    vs.withdrawerMut().* = Pubkey.ZEROES;
    try std.testing.expect(vs.withdrawerKey().equals(&Pubkey.ZEROES));

    // blockRevenueCollectorMut
    vs.blockRevenueCollectorMut().?.* = Pubkey.ZEROES;
    try std.testing.expect(vs.blockRevenueCollector().?.equals(&Pubkey.ZEROES));

    // asV3 / asV4
    try std.testing.expectEqual(null, vs.asV3());
    try std.testing.expect(vs.asV4() != null);
    try std.testing.expectEqual(null, vs.asV3Const());
    try std.testing.expect(vs.asV4Const() != null);
}

test "state.VoteState.clone and equals" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const node_pk = Pubkey.initRandom(random);
    const voter_pk = Pubkey.initRandom(random);
    const withdrawer_pk = Pubkey.initRandom(random);
    const vote_pk = Pubkey.initRandom(random);

    // Test clone and equals for V3
    {
        var vs3 = try VoteState.initV3(allocator, node_pk, voter_pk, withdrawer_pk, 10, 0);
        defer vs3.deinit(allocator);

        var clone3 = try vs3.clone(allocator);
        defer clone3.deinit(allocator);

        try std.testing.expect(vs3.equals(&clone3));
        try std.testing.expect(clone3.equals(&vs3));
    }

    // Test clone and equals for V4
    {
        var vs4 = try VoteState.initV4(allocator, node_pk, voter_pk, withdrawer_pk, 10, 0, vote_pk);
        defer vs4.deinit(allocator);

        var clone4 = try vs4.clone(allocator);
        defer clone4.deinit(allocator);

        try std.testing.expect(vs4.equals(&clone4));
        try std.testing.expect(clone4.equals(&vs4));
    }

    // Test cross-version equals returns false
    {
        var vs3 = try VoteState.initV3(allocator, node_pk, voter_pk, withdrawer_pk, 10, 0);
        defer vs3.deinit(allocator);

        var vs4 = try VoteState.initV4(allocator, node_pk, voter_pk, withdrawer_pk, 10, 0, vote_pk);
        defer vs4.deinit(allocator);

        try std.testing.expect(!vs3.equals(&vs4));
        try std.testing.expect(!vs4.equals(&vs3));
    }
}

test "state.VoteState.authorizedVoters v3 vs v4" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const voter_pk = Pubkey.initRandom(random);

    // V3: authorized_voters stored as `voters`
    {
        var vs3 = try VoteState.initV3(allocator, Pubkey.ZEROES, voter_pk, Pubkey.ZEROES, 0, 5);
        defer vs3.deinit(allocator);

        var av = vs3.authorizedVotersMut();
        try std.testing.expectEqual(1, av.count());
        try std.testing.expect(av.getAuthorizedVoter(5).?.equals(&voter_pk));
    }

    // V4: authorized_voters stored as `authorized_voters`
    {
        var vs4 = try VoteState.initV4(
            allocator,
            Pubkey.ZEROES,
            voter_pk,
            Pubkey.ZEROES,
            0,
            5,
            Pubkey.ZEROES,
        );
        defer vs4.deinit(allocator);

        var av = vs4.authorizedVotersMut();
        try std.testing.expectEqual(1, av.count());
        try std.testing.expect(av.getAuthorizedVoter(5).?.equals(&voter_pk));
    }
}

test "state.VoteState.votesMut and epochCreditsListMut" {
    const allocator = std.testing.allocator;

    // V3
    {
        var vs3 = try VoteState.initV3(allocator, Pubkey.ZEROES, Pubkey.ZEROES, Pubkey.ZEROES, 0, 0);
        defer vs3.deinit(allocator);

        try vs3.votesMut().append(allocator, .{
            .latency = 0,
            .lockout = .{ .slot = 42, .confirmation_count = 1 },
        });
        try std.testing.expectEqual(1, vs3.votes().items.len);
        try std.testing.expectEqual(42, vs3.votes().items[0].lockout.slot);

        try vs3.epochCreditsListMut().append(allocator, .{
            .epoch = 1,
            .credits = 100,
            .prev_credits = 0,
        });
        try std.testing.expectEqual(1, vs3.epochCreditsList().items.len);
    }

    // V4
    {
        var vs4 = try VoteState.initV4(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            0,
            0,
            Pubkey.ZEROES,
        );
        defer vs4.deinit(allocator);

        try vs4.votesMut().append(allocator, .{
            .latency = 0,
            .lockout = .{ .slot = 99, .confirmation_count = 1 },
        });
        try std.testing.expectEqual(1, vs4.votes().items.len);
        try std.testing.expectEqual(99, vs4.votes().items[0].lockout.slot);

        try vs4.epochCreditsListMut().append(allocator, .{
            .epoch = 2,
            .credits = 200,
            .prev_credits = 0,
        });
        try std.testing.expectEqual(1, vs4.epochCreditsList().items.len);
    }
}

test "state.VoteState.delegating methods" {
    const allocator = std.testing.allocator;

    // V3
    {
        var vs3 = try VoteState.initV3(allocator, Pubkey.ZEROES, Pubkey.ZEROES, Pubkey.ZEROES, 0, 0);
        defer vs3.deinit(allocator);

        // Empty state
        try std.testing.expectEqual(null, vs3.lastVotedSlot());
        try std.testing.expectEqual(null, vs3.lastLockout());
        try std.testing.expect(!vs3.containsSlot(0));
        try std.testing.expectEqual(0, vs3.epochCredits());
        try std.testing.expectEqual(0, vs3.getCredits());

        // Add a vote
        try vs3.votesMut().append(allocator, .{
            .latency = 0,
            .lockout = .{ .slot = 10, .confirmation_count = 1 },
        });
        try std.testing.expectEqual(10, vs3.lastVotedSlot());
        try std.testing.expectEqual(10, vs3.lastLockout().?.slot);
        try std.testing.expect(vs3.containsSlot(10));
        try std.testing.expect(!vs3.containsSlot(11));

        // creditsForVoteAtIndex: latency=0 means legacy vote, returns 1 credit
        try std.testing.expectEqual(1, vs3.creditsForVoteAtIndex(0));

        // incrementCredits
        try vs3.incrementCredits(allocator, 1, 5);
        try std.testing.expectEqual(5, vs3.getCredits());
    }

    // V4
    {
        var vs4 = try VoteState.initV4(
            allocator,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            Pubkey.ZEROES,
            0,
            0,
            Pubkey.ZEROES,
        );
        defer vs4.deinit(allocator);

        try std.testing.expectEqual(null, vs4.lastVotedSlot());
        try std.testing.expectEqual(null, vs4.lastLockout());
        try std.testing.expect(!vs4.containsSlot(0));
        try std.testing.expectEqual(0, vs4.getCredits());

        try vs4.votesMut().append(allocator, .{
            .latency = 0,
            .lockout = .{ .slot = 20, .confirmation_count = 1 },
        });
        try std.testing.expectEqual(20, vs4.lastVotedSlot());
        try std.testing.expectEqual(20, vs4.lastLockout().?.slot);
        try std.testing.expect(vs4.containsSlot(20));

        try vs4.incrementCredits(allocator, 1, 10);
        try std.testing.expectEqual(10, vs4.getCredits());
    }
}

test "state.VoteStateVersions.convertToVoteState: v0_23_5 to v3" {
    const allocator = std.testing.allocator;
    const node_pk = Pubkey.ZEROES;
    const voter_pk = Pubkey.ZEROES;
    const withdrawer_pk = Pubkey.ZEROES;

    var versions: VoteStateVersions = .{ .v0_23_5 = try VoteState0_23_5.init(
        node_pk,
        voter_pk,
        withdrawer_pk,
        10,
        0,
    ) };
    const vs = try versions.convertToVoteState(allocator, null, false);
    defer vs.deinit(allocator);

    try std.testing.expect(vs.isV3());
    try std.testing.expect(!vs.isV4());
    try std.testing.expect(vs.nodePubkey().equals(&node_pk));
    try std.testing.expect(vs.withdrawerKey().equals(&withdrawer_pk));
    try std.testing.expectEqual(10, vs.commission());
    try std.testing.expectEqual(null, vs.rootSlot());
    try std.testing.expectEqual(0, vs.votes().items.len);
    try std.testing.expectEqual(0, vs.epochCreditsList().items.len);
    // v0_23_5 with ZEROES voter → authorized_voters count is 0
    try std.testing.expectEqual(0, vs.authorizedVoters().count());
}

test "state.VoteStateVersions.convertToVoteState: v1_14_11 to v3" {
    const allocator = std.testing.allocator;
    const node_pk = Pubkey.ZEROES;
    const voter_pk = Pubkey.ZEROES;
    const withdrawer_pk = Pubkey.ZEROES;

    var versions: VoteStateVersions = .{ .v1_14_11 = try VoteState1_14_11.init(
        allocator,
        node_pk,
        voter_pk,
        withdrawer_pk,
        20,
        5,
    ) };
    const vs = try versions.convertToVoteState(allocator, null, false);
    defer vs.deinit(allocator);

    try std.testing.expect(vs.isV3());
    try std.testing.expect(!vs.isV4());
    try std.testing.expect(vs.nodePubkey().equals(&node_pk));
    try std.testing.expect(vs.withdrawerKey().equals(&withdrawer_pk));
    try std.testing.expectEqual(20, vs.commission());
    try std.testing.expectEqual(null, vs.rootSlot());
    try std.testing.expectEqual(0, vs.votes().items.len);
    try std.testing.expectEqual(0, vs.epochCreditsList().items.len);
    try std.testing.expectEqual(1, vs.authorizedVoters().count());
}

test "state.VoteStateVersions.convertToVoteState: v3 stays v3" {
    const allocator = std.testing.allocator;

    var versions: VoteStateVersions = .{ .v3 = try VoteStateV3.init(
        allocator,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        30,
        0,
    ) };
    const vs = try versions.convertToVoteState(allocator, null, false);
    defer vs.deinit(allocator);

    try std.testing.expect(vs.isV3());
    try std.testing.expectEqual(30, vs.commission());
}

test "state.VoteStateVersions.convertToVoteState: v4 stays v4 even with target_v4=false" {
    const allocator = std.testing.allocator;
    const vote_pk = Pubkey.ZEROES;

    var versions: VoteStateVersions = .{ .v4 = try VoteStateV4.init(
        allocator,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        40,
        0,
        vote_pk,
    ) };
    const vs = try versions.convertToVoteState(allocator, vote_pk, false);
    defer vs.deinit(allocator);

    // v4 input stays v4 regardless of target_v4 flag
    try std.testing.expect(vs.isV4());
    try std.testing.expectEqual(40, vs.commission());
}

test "state.VoteStateVersions.convertToVoteState: target_v4=true converts to v4" {
    const allocator = std.testing.allocator;
    const vote_pk = Pubkey.ZEROES;

    // v3 -> v4 via target_v4=true
    var versions: VoteStateVersions = .{ .v3 = try VoteStateV3.init(
        allocator,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        50,
        0,
    ) };
    const vs = try versions.convertToVoteState(allocator, vote_pk, true);
    defer vs.deinit(allocator);

    try std.testing.expect(vs.isV4());
    try std.testing.expectEqual(50, vs.commission());
}
