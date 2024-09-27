const std = @import("std");

const Logger = @import("../trace/log.zig").Logger;

const Keypair = std.crypto.sign.Ed25519.KeyPair;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const AtomicBool = std.atomic.Value(bool);

const IDENTITY_KEYPAIR_DIR = "/.sig";
const IDENTITY_KEYPAIR_PATH = "/identity.key";

pub fn getOrInitIdentity(allocator: std.mem.Allocator, logger: Logger) !Keypair {
    const home_dir = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home_dir);
    const path = try std.mem.concat(allocator, u8, &[_][]const u8{ home_dir, IDENTITY_KEYPAIR_DIR, IDENTITY_KEYPAIR_PATH });

    if (std.fs.openFileAbsolute(path, .{})) |file| {
        try file.seekTo(0);

        var buf: [SecretKey.encoded_length]u8 = undefined;
        _ = try file.readAll(&buf);

        const sk = try SecretKey.fromBytes(buf);

        return try Keypair.fromSecretKey(sk);
    } else |err| {
        switch (err) {
            error.FileNotFound => {
                // create ~/.sig dir
                const dir = try std.mem.concat(allocator, u8, &[_][]const u8{ home_dir, IDENTITY_KEYPAIR_DIR });
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
