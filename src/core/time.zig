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
