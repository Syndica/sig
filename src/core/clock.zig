/// The unit of time a given leader schedule is honored.
///
/// It lasts for some number of [`Slot`]s.
pub const Epoch = u64;

/// The unit of time given to a leader for encoding a block.
///
/// It is some some number of _ticks_ long.
pub const Slot = u64;
