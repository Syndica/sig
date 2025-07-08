const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;
const Stakes = sig.core.Stakes;

const StakeHistory = sig.runtime.sysvar.StakeHistory;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const cloneMapAndValues = sig.utils.collections.cloneMapAndValues;

pub const EpochStakesMap = std.AutoArrayHashMapUnmanaged(Epoch, EpochStakes);

pub const EpochStakes = sig.core.epoch_stakes.EpochStakes(.delegation);
