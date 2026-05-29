const std = @import("std");

pub const channel = @import("channel.zig");
pub const mux = @import("mux.zig");
pub const once_cell = @import("once_cell.zig");
pub const reference_counter = @import("reference_counter.zig");
pub const shared_memory = @import("shared_memory.zig");
pub const thread_pool = @import("thread_pool.zig");
pub const exit = @import("exit.zig");

pub const Channel = channel.Channel;
pub const Mux = mux.Mux;
pub const RwMux = mux.RwMux;

/// We use DefaultRwLock to avoid UB in pthread's RwLock, which relies on some
/// assumptions that Sig does not conform to:
/// - it must be pinned to a memory location
/// - it does not support recursive lockShared calls from the same thread
pub const RwLock = std.Thread.RwLock.DefaultRwLock;

pub const OnceCell = once_cell.OnceCell;
pub const ReferenceCounter = reference_counter.ReferenceCounter;
pub const Rc = reference_counter.Rc;
pub const RcSlice = reference_counter.RcSlice;
pub const SharedPointerWindow = shared_memory.SharedPointerWindow;
pub const ThreadPool = thread_pool.ThreadPool;

pub const ExitCondition = exit.ExitCondition;

pub const normalizeDeinitFunction = shared_memory.normalizeDeinitFunction;
