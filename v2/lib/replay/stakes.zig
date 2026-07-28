//! Replay-owned stakes state, scoped to what replay itself reads while
//! executing transactions within a single epoch:
//!   - `EpochVoters` — the frozen per-epoch set of admitted voters
//!     (vote-pubkey, stake, commission) plus a derived side index
//!     for O(1) sol_get_epoch_stake lookup.
//!   - `LiveVoter` / `LiveVoters` — dense per-block live vote-account
//!     state (last-vote slot + timestamp), indexed in lockstep with
//!     `EpochVoters.entries` so per-slot sysvar updates scan them
//!     as parallel arrays.
//!   - `ReplayStakes` — the owner struct: one `EpochVoters` plus one
//!     `LiveVoters` per `BlockPool` slot.

const std = @import("std");

const replay = @import("../replay.zig");
const solana = @import("../solana.zig");
const collections = @import("../collections.zig");

const Pubkey = solana.Pubkey;
const Slot = solana.Slot;
const Epoch = solana.Epoch;

/// SIMD-0357 caps the admitted vote-account set at 2000 post-Alpenglow.
/// Pre-Alpenglow, the effective count on mainnet is around ~1400, so
/// this is a comfortable bound in both regimes.
pub const MAX_ALPENGLOW_VOTE_ACCOUNTS: u16 = 2000;

/// `FixedPubkeyMap` requires a power-of-two capacity and callers size to
/// >= 2x expected occupancy. ceil2(2 * 2000) = 4096.
pub const EPOCH_VOTERS_INDEX_CAP: usize = 4096;

const EpochVotersIndex = collections.FixedPubkeyMap(u16, EPOCH_VOTERS_INDEX_CAP);

/// Frozen per-epoch snapshot of admitted voters.
///
/// `entries` is the source of truth. `by_vote_pk` and `total_stake`
/// are derived from `entries` and refreshed atomically with it — only
/// at snapshot boot today; at each epoch-boundary crossing once
/// boundary derivation is wired in.
///
/// Layout is `extern` so the struct can be persisted or shared as-is;
/// downstream consumers may map it directly.
pub const EpochVoters = extern struct {
    len: u16,
    _pad0: [6]u8 = @splat(0),
    entries: [MAX_ALPENGLOW_VOTE_ACCOUNTS]Entry,
    by_vote_pk: EpochVotersIndex,
    total_stake: u64,

    /// One admitted voter. Positional row — the index of an entry in
    /// `entries[]` is the identity used by all sibling arrays (e.g.
    /// `LiveVoters.entries`). Sorted by `stake` desc at build time.
    pub const Entry = extern struct {
        vote_pk: Pubkey, //           32
        stake: u64, //                 8
        commission_bps: u16, //        2
        _pad: [6]u8 = @splat(0), //    6
    }; //                             48 B

    comptime {
        std.debug.assert(@sizeOf(Entry) == 48);
    }

    /// Zero the struct and reset the map to empty. Call before
    /// building.
    pub fn init(self: *EpochVoters) void {
        self.len = 0;
        self._pad0 = @splat(0);
        // `entries` intentionally left undefined; only slots
        // 0..len are read.
        self.by_vote_pk.init();
        self.total_stake = 0;
    }

    /// O(1) lookup of a voter's stake by vote pubkey. Miss returns 0
    /// (agave / firedancer parity with sol_get_epoch_stake).
    pub fn stakeOf(self: *const EpochVoters, vote_pk: Pubkey) u64 {
        const idx_ptr = self.by_vote_pk.getPtrConst(vote_pk) orelse return 0;
        return self.entries[idx_ptr.*].stake;
    }
};

/// Per-block live vote-account state row. One per position in
/// `EpochVoters.entries`. `.unpopulated` means "no vote landed on
/// this fork yet"; `.update` carries the latest vote slot +
/// timestamp; `.invalidate` marks the voter as retired on this fork
/// (vote account closed).
pub const LiveVoter = extern struct {
    last_vote_slot: Slot, //          8
    last_vote_timestamp: i64, //      8
    kind: Kind, //                    1
    _pad: [7]u8 = @splat(0), //       7

    pub const Kind = enum(u8) {
        unpopulated = 0,
        update = 1,
        invalidate = 2,
    };

    pub const UNPOPULATED: LiveVoter = .{
        .last_vote_slot = 0,
        .last_vote_timestamp = 0,
        .kind = .unpopulated,
    };

    comptime {
        std.debug.assert(@sizeOf(LiveVoter) == 24);
    }
};

/// Dense per-block array indexed by position in `EpochVoters.entries`.
/// Not tagged with a length: `EpochVoters.len` bounds the readable
/// prefix; rows at higher indices are `.unpopulated` and inert.
pub const LiveVoters = extern struct {
    entries: [MAX_ALPENGLOW_VOTE_ACCOUNTS]LiveVoter,

    /// Zero out every row to `.unpopulated`. Used for the root block
    /// at snapshot boot, and as a defensive scrub before a
    /// `BlockPool` slot is re-issued.
    pub fn reset(self: *LiveVoters) void {
        @memset(&self.entries, LiveVoter.UNPOPULATED);
    }
};

comptime {
    // Sanity: keeps memory budgeting honest.
    std.debug.assert(@sizeOf(LiveVoters) == MAX_ALPENGLOW_VOTE_ACCOUNTS * 24);
}

/// Provisional owner struct for replay's stakes state.
///
/// **Temporary shape.** The rest of v2 exposes shared state as one
/// top-level region per collection (`BlockPool`, `TransactionPool`,
/// `ExecReqResponse`), each with its own mmap and passed around as
/// its own pointer. `ReplayStakes` bundles two such regions
/// (`epoch_voters`, `live_voters`) for now; the expected end state
/// is to split them into standalone top-level regions matching
/// that convention. `epoch_voters` and `live_voters` themselves are
/// durable — only the wrapping is provisional.
///
/// Not `extern` — a container of already-`extern` pieces; no
/// cross-process consumer maps `ReplayStakes` itself.
pub const ReplayStakes = struct {
    epoch_voters: EpochVoters,
    /// Indexed by `BlockRef` position within the `BlockPool`. Cloned
    /// from a parent block's slot at `onBlockCreate`. The root
    /// block's slot is filled by `reset()` at boot.
    live_voters: [replay.BlockPool.capacity]LiveVoters,
    /// **Provisional.** Hangs the epoch-boundary hard-stop off a
    /// single field. Once boundary derivation lands and replay
    /// tracks `current` / `t_minus_1` / `t_minus_2` rotation slots,
    /// the epoch of any given slot is derivable from the rotation
    /// state and this field is deleted.
    boot_epoch: Epoch,

    /// Zero-init the struct to a well-defined empty state. Actual
    /// data is populated by the snapshot boot loader and by the
    /// root-block setup path.
    pub fn init(self: *ReplayStakes) void {
        self.epoch_voters.init();
        for (&self.live_voters) |*lv| lv.reset();
        self.boot_epoch = 0;
    }
};

test "EpochVoters init empties the map and clears len" {
    var ev: EpochVoters = undefined;
    ev.init();
    try std.testing.expectEqual(@as(u16, 0), ev.len);
    try std.testing.expectEqual(@as(u64, 0), ev.total_stake);

    var pk: Pubkey = .{ .data = .{0} ** 32 };
    pk.data[0] = 7;
    try std.testing.expectEqual(@as(?*const u16, null), ev.by_vote_pk.getPtrConst(pk));
}

test "EpochVoters.stakeOf returns 0 on miss, entry.stake on hit" {
    var ev: EpochVoters = undefined;
    ev.init();

    var pk_hit: Pubkey = .{ .data = .{0} ** 32 };
    pk_hit.data[0] = 1;
    var pk_miss: Pubkey = .{ .data = .{0} ** 32 };
    pk_miss.data[0] = 2;

    ev.entries[0] = .{ .vote_pk = pk_hit, .stake = 12345, .commission_bps = 700 };
    ev.len = 1;
    try ev.by_vote_pk.insert(pk_hit, 0);

    try std.testing.expectEqual(@as(u64, 12345), ev.stakeOf(pk_hit));
    try std.testing.expectEqual(@as(u64, 0), ev.stakeOf(pk_miss));
}

test "LiveVoters.reset yields all .unpopulated" {
    // 48 KB — fine on the test allocator's heap.
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);

    lv.reset();
    for (lv.entries) |row| {
        try std.testing.expectEqual(LiveVoter.Kind.unpopulated, row.kind);
    }
}
