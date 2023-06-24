const std = @import("std");
const GossipService = @import("gossip_service.zig").GossipService;
const ClusterInfo = @import("cluster_info.zig").ClusterInfo;
const network = @import("zig-network");
const Keypair = std.crypto.sign.Ed25519.KeyPair;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const AtomicBool = std.atomic.Atomic(bool);
const SocketAddr = @import("net.zig").SocketAddr;
const ArrayList = std.ArrayList;
const LegacyContactInfo = @import("crds.zig").LegacyContactInfo;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var gpa_allocator = gpa.allocator();

const IDENTITY_KEYPAIR_PATH = "/.sig/identity.key";

pub fn getOrInitIdentity(allocator: std.mem.Allocator) !Keypair {
    const home_dir = std.os.getenv("HOME") orelse return error.UnableDetectHomeDir;
    var path = try std.mem.concat(allocator, u8, &[_][]const u8{ home_dir, IDENTITY_KEYPAIR_PATH });
    if (std.fs.openFileAbsolute(path, .{})) |file| {
        try file.seekTo(0);

        var buf: [SecretKey.encoded_length]u8 = undefined;
        _ = try file.readAll(&buf);

        var sk = try SecretKey.fromBytes(buf);

        return try Keypair.fromSecretKey(sk);
    } else |err| {
        switch (err) {
            error.FileNotFound => {
                const file = try std.fs.createFileAbsolute(path, .{ .truncate = true });
                defer file.close();

                const kp = try Keypair.create(null);
                try file.writeAll(kp.secret_key.toBytes()[0..]);

                return kp;
            },
            else => {
                return err;
            },
        }
    }
}

pub fn runGossipService(gossip_port: u16, entrypoints: ArrayList(LegacyContactInfo)) !void {
    var exit = AtomicBool.init(false);
    var gossip_socket_addr = SocketAddr.init_ipv4(.{ 0, 0, 0, 0 }, gossip_port);

    var spy = try ClusterInfo.initSpy(gpa_allocator, gossip_socket_addr, entrypoints);

    var gossip_service = GossipService.init(gpa_allocator, &spy.cluster_info, spy.gossip_socket, exit);

    var handle = try std.Thread.spawn(.{}, GossipService.run, .{&gossip_service});

    handle.join();
}
