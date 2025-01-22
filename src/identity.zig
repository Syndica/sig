const std = @import("std");
const sig = @import("sig.zig");

const Logger = sig.trace.Logger;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;

pub const IDENTITY_KEYPAIR_PATH = "identity.key";

/// Re-export of stdlib's Ed25519 KeyPair.
pub const KeyPair = std.crypto.sign.Ed25519.KeyPair;

/// Returns the keypair from {app data directory}/{IDENTITY_KEYPAIR_PATH} or creates a new one
/// if the file does not exist. If the file is invalid, an error is returned.
pub fn getOrInit(
    allocator: std.mem.Allocator,
    logger: Logger,
) !KeyPair {
    const app_data_dir_path = try std.fs.getAppDataDir(allocator, "sig");
    defer allocator.free(app_data_dir_path);

    if (!std.fs.path.isAbsolute(app_data_dir_path)) {
        return error.DataDirPathIsNotAbsolute;
    }

    var app_data_dir = try std.fs.cwd().makeOpenPath(app_data_dir_path, .{});
    defer app_data_dir.close();

    if (app_data_dir.openFile(IDENTITY_KEYPAIR_PATH, .{
        // NOTE: the file will never be modified
        .mode = .read_only,
    })) |file| {
        defer file.close();

        var buf: [SecretKey.encoded_length]u8 = undefined;

        const end_pos = try file.getEndPos();
        if (end_pos != buf.len) {
            logger.err().logf(
                "Overlong identity file, expected {} bytes, found {}",
                .{ buf.len, end_pos },
            );
            return error.InvalidIdentityFile;
        }

        const file_len = try file.readAll(&buf);
        if (file_len != buf.len) {
            logger.err().logf(
                "Truncated identity file, expected {} bytes, found {}",
                .{ buf.len, file_len },
            );
            return error.InvalidIdentityFile;
        }

        // NOTE: this should never fail so we can ignore the error
        const secret_key = SecretKey.fromBytes(buf) catch |err| switch (err) {};
        const keypair = try KeyPair.fromSecretKey(secret_key);

        return keypair;
    } else |err| switch (err) {
        else => |e| return e,
        error.FileNotFound => {
            // create the file with a new keypair
            const file = try app_data_dir.createFile(IDENTITY_KEYPAIR_PATH, .{
                .truncate = true,
            });
            defer file.close();

            const keypair = try KeyPair.create(null);
            try file.writeAll(&keypair.secret_key.toBytes());

            return keypair;
        },
    }
}
