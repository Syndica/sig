pub const Epoch = u64;
pub const Slot = u64;
pub const UnixTimestamp = i64;

pub const DEFAULT_TICKS_PER_SECOND: u64 = 160;
pub const DEFAULT_TICKS_PER_SLOT: u64 = 64;
pub const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
pub const TICKS_PER_DAY: u64 = DEFAULT_TICKS_PER_SECOND * SECONDS_PER_DAY;
pub const DEFAULT_SLOTS_PER_EPOCH: u64 = 2 * TICKS_PER_DAY / DEFAULT_TICKS_PER_SLOT;
