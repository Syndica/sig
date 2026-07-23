//! TODO(1748): migrate replay internals out of `services/replay.zig`.
//!
//! The replay service still owns the block tree / merkle forest, deshred
//! deserialisation state, account-fetching cache, and exec scheduling loop.
//! Those implementation details should eventually live in this component,
//! leaving the service file as orchestration around shared-memory regions.
