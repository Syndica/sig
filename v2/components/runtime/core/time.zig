/// The unit of time a given leader schedule is honored.
///
/// It lasts for some number of [`Slot`]s.
pub const Epoch = u64;

/// The unit of time given to a leader for encoding a block.
///
/// It is some some number of _ticks_ long.
pub const Slot = u64;

/// The default tick rate that the cluster attempts to achieve (160 per second).
///
/// Note that the actual tick rate at any given time should be expected to drift.
pub const DEFAULT_TICKS_PER_SECOND: u64 = 160;

// At 160 ticks/s, 64 ticks per slot implies that leader rotation and voting will happen
// every 400 ms. A fast voting cadence ensures faster finality and convergence
pub const DEFAULT_TICKS_PER_SLOT: u64 = 64;

pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

pub const TICKS_PER_DAY: u64 = DEFAULT_TICKS_PER_SECOND * SECONDS_PER_DAY;

/// The number of slots per epoch after initial network warmup.
/// 1 Epoch ~= 2 days.
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 2 * TICKS_PER_DAY / DEFAULT_TICKS_PER_SLOT;
