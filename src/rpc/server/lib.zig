//! RPC Server API.
//!
//! The server can be run by calling `serveSpawn`, or `serve`; in
//! order to do this, the caller must first initialize a `Context`
//! to provide the basic state and dependencies required to operate
//! the server, and must also provide a `WorkPool`, initialized to
//! a given backend.

const server = @import("server.zig");

comptime {
    _ = server;
}

pub const MIN_READ_BUFFER_SIZE = server.MIN_READ_BUFFER_SIZE;

pub const serveSpawn = server.serveSpawn;
pub const serve = server.serve;

pub const Context = server.Context;
pub const WorkPool = server.WorkPool;

// backends
pub const basic = server.basic;
pub const LinuxIoUring = server.LinuxIoUring;
