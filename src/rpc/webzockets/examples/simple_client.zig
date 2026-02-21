const std = @import("std");
const xev = @import("xev");
const ws = @import("webzockets_lib");

/// Simple client that sends a message, waits for a response, and disconnects.
///
/// Note: We allocate copies for messages for simplicity. Received message data
/// points into internal read buffers with transient lifetimes, so copies are
/// needed to safely hold onto the data beyond the callback.
const ClientHandler = struct {
    allocator: std.mem.Allocator,
    payload: []const u8,
    received: ?[]const u8 = null,
    sent_copy: ?[]const u8 = null,

    pub fn onOpen(self: *ClientHandler, conn: *SimpleClient.Conn) void {
        const copy = self.allocator.dupe(u8, self.payload) catch return;
        // Print before sending — sendText masks the buffer in-place.
        std.debug.print("Sent ({d} bytes): {s}\n", .{ copy.len, copy });
        conn.sendText(copy) catch {
            self.allocator.free(copy);
            return;
        };
        self.sent_copy = copy;
    }

    pub fn onMessage(self: *ClientHandler, conn: *SimpleClient.Conn, message: ws.Message) void {
        std.debug.print("Received {s} ({d} bytes): {s}\n", .{
            @tagName(message.type),
            message.data.len,
            message.data,
        });
        self.received = self.allocator.dupe(u8, message.data) catch null;
        conn.close(.normal, "");
    }

    pub fn onWriteComplete(self: *ClientHandler, _: *SimpleClient.Conn) void {
        if (self.sent_copy) |buf| {
            std.debug.print("Write complete ({d} masked bytes): 0x{}\n", .{
                buf.len,
                std.fmt.fmtSliceHexLower(buf),
            });
            self.allocator.free(buf);
            self.sent_copy = null;
        }
    }

    pub fn onClose(self: *ClientHandler, _: *SimpleClient.Conn) void {
        if (self.sent_copy) |buf| {
            self.allocator.free(buf);
            self.sent_copy = null;
        }
    }
};

const SimpleClient = ws.Client(ClientHandler, 4096);

fn usage(exe_name: []const u8) void {
    std.debug.print(
        \\Usage: {s} [ip] [port] [message]
        \\Defaults: ip=127.0.0.1 port=8080 message=hello
        \\
    , .{exe_name});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const exe_name = if (args.len > 0) args[0] else "echo-client";
    if (args.len > 1 and (std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help"))) {
        usage(exe_name);
        return;
    }

    const ip_str = if (args.len > 1) args[1] else "127.0.0.1";
    const port: u16 = if (args.len > 2) std.fmt.parseInt(u16, args[2], 10) catch {
        usage(exe_name);
        return error.InvalidPort;
    } else 8080;
    const address = std.net.Address.parseIp4(ip_str, port) catch {
        std.debug.print("Invalid IPv4 address: {s}\n", .{ip_str});
        usage(exe_name);
        return error.InvalidAddress;
    };
    const msg = if (args.len > 3) args[3] else "hello";

    var handler: ClientHandler = .{ .allocator = allocator, .payload = msg };

    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
    defer loop.deinit();

    var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
    std.crypto.random.bytes(&seed);
    var csprng = ws.ClientMaskPRNG.init(seed);

    var conn: SimpleClient.Conn = undefined;
    var client = SimpleClient.init(allocator, &loop, &handler, &conn, &csprng, .{
        .address = address,
        .path = "/",
        .max_message_size = 16 * 1024 * 1024,
    });

    try client.connect();
    defer conn.deinit();
    try loop.run(.until_done);

    if (handler.received) |data| {
        defer allocator.free(data);
        std.debug.print("Response: {s}\n", .{data});
    } else {
        std.debug.print("No response received\n", .{});
    }
}
