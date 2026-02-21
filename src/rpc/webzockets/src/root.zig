const std = @import("std");

pub const types = @import("types.zig");
pub const mask = @import("mask.zig");
pub const http = @import("http.zig");
pub const frame = @import("frame.zig");
pub const reader = @import("reader.zig");
pub const server = @import("server/server.zig");
// Client modules
pub const client = @import("client/client.zig");
pub const client_handshake = @import("client/handshake.zig");
pub const client_connection = @import("client/connection.zig");

pub const Opcode = types.Opcode;
pub const Message = types.Message;
pub const ConnectionState = types.ConnectionState;
pub const CloseCode = types.CloseCode;
pub const FrameHeader = frame.FrameHeader;
pub const FrameError = frame.FrameError;
pub const HandshakeError = types.HandshakeError;
pub const HandshakeState = types.HandshakeState;
pub const ConnectionError = types.ConnectionError;
pub const Role = types.Role;
pub const Server = server.Server;
pub const ClientHandshake = client_handshake.ClientHandshake;
pub const ClientConnection = client_connection.ClientConnection;
pub const Client = client.Client;
pub const ClientMaskPRNG = types.ClientMaskPRNG;

test {
    // Uncomment to see logs during tests
    // std.testing.log_level = .debug;
    _ = @import("types.zig");
    _ = @import("mask.zig");
    _ = @import("http.zig");
    _ = @import("frame.zig");
    _ = @import("reader.zig");
    _ = @import("control_queue.zig");
    _ = @import("server/server.zig");
    _ = @import("server/connection.zig");
    _ = @import("server/handshake.zig");
    _ = @import("server/slot_pool.zig");
    _ = @import("client/client.zig");
    _ = @import("client/handshake.zig");
    _ = @import("client/connection.zig");
}
