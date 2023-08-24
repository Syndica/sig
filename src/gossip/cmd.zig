const std = @import("std");
const GossipService = @import("gossip_service.zig").GossipService;
const Keypair = std.crypto.sign.Ed25519.KeyPair;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const AtomicBool = std.atomic.Atomic(bool);
const SocketAddr = @import("net.zig").SocketAddr;
const ArrayList = std.ArrayList;
const LegacyContactInfo = @import("crds.zig").LegacyContactInfo;
const Logger = @import("../trace/log.zig").Logger;
const UdpSocket = @import("zig-network").Socket;
const Pubkey = @import("../core/pubkey.zig").Pubkey;

const IDENTITY_KEYPAIR_DIR = "/.sig";
const IDENTITY_KEYPAIR_PATH = "/identity.key";

pub fn getOrInitIdentity(allocator: std.mem.Allocator, logger: *Logger) !Keypair {
    const home_dir = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home_dir);
    var path = try std.mem.concat(allocator, u8, &[_][]const u8{ home_dir, IDENTITY_KEYPAIR_DIR, IDENTITY_KEYPAIR_PATH });

    if (std.fs.openFileAbsolute(path, .{})) |file| {
        try file.seekTo(0);

        var buf: [SecretKey.encoded_length]u8 = undefined;
        _ = try file.readAll(&buf);

        var sk = try SecretKey.fromBytes(buf);

        return try Keypair.fromSecretKey(sk);
    } else |err| {
        switch (err) {
            error.FileNotFound => {
                // create ~/.sig dir
                var dir = try std.mem.concat(allocator, u8, &[_][]const u8{ home_dir, IDENTITY_KEYPAIR_DIR });
                std.fs.makeDirAbsolute(dir) catch {
                    logger.debugf("sig directory already exists...", .{});
                };

                // create new keypair
                const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
                defer file.close();

                const kp = try Keypair.create(null);
                try file.writeAll(&kp.secret_key.toBytes());

                return kp;
            },
            else => {
                return err;
            },
        }
    }
}

pub fn runGossipService(
    allocator: std.mem.Allocator,
    my_keypair: *Keypair,
    gossip_port: u16,
    entrypoints: ArrayList(LegacyContactInfo),
    logger: *Logger,
) !void {
    var exit = AtomicBool.init(false);

    // bind the gossip socket
    var gossip_socket_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, gossip_port);
    var gossip_socket = try UdpSocket.create(.ipv4, .udp);
    try gossip_socket.bind(gossip_socket_addr.toEndpoint());

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = LegacyContactInfo.default(my_pubkey);
    contact_info.shred_version = 0;
    contact_info.gossip = gossip_socket_addr;

    _ = entrypoints; // TODO

    // start gossip
    var gossip_service = try GossipService.init(
        allocator,
        contact_info,
        my_keypair.*,
        gossip_socket,
        exit,
    );

    var handle = try std.Thread.spawn(.{}, GossipService.run, .{
        &gossip_service,
        logger,
    });

    handle.join();
}
