const std = @import("std");

pub const types = @import("types.zig");
pub const mask = @import("mask.zig");
pub const http = @import("http.zig");
pub const frame = @import("frame.zig");
pub const reader = @import("reader.zig");
pub const server = @import("server/server.zig");
pub const buffer = @import("buffer.zig");

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
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("control_queue.zig"));
}
