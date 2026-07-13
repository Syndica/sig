const std = @import("std");

/// We use DefaultRwLock to avoid UB in pthread's RwLock, which relies on some
/// assumptions that Sig does not conform to:
/// - it must be pinned to a memory location
/// - it does not support recursive lockShared calls from the same thread
pub const RwLock = std.Thread.RwLock.DefaultRwLock;
