const std = @import("std");
const sig = @import("sig.zig");

const Logger = sig.trace.Logger("identity");
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
pub const KeyPair = std.crypto.sign.Ed25519.KeyPair;

pub const IDENTITY_KEYPAIR_PATH = "identity.key";

pub const ValidatorIdentity = struct {
    /// Public key identifying this validator
    validator: sig.core.Pubkey,
    /// Public key of the vote account
    vote_account: ?sig.core.Pubkey,
};

pub const SigningKeys = struct {
    /// Keypair for the node identity used for signing vote transactions
    node: ?KeyPair,
    /// Authorized voter keypairs allowed to sign vote transactions
    authorized_voters: []const KeyPair,
};

/// Returns the keypair from $APP_DATA/IDENTITY_KEYPAIR_PATH or creates a new one
/// if the file does not exist. If the file is invalid, an error is returned.
pub fn getOrInit(allocator: std.mem.Allocator, logger: Logger) !KeyPair {
    const data_directory_path = try std.fs.getAppDataDir(allocator, "sig");
    defer allocator.free(data_directory_path);

    logger.info().logf(
        "searching for identity key at {s}/{s}",
        .{ data_directory_path, IDENTITY_KEYPAIR_PATH },
    );

    var data_directory = try std.fs.cwd().makeOpenPath(data_directory_path, .{});
    defer data_directory.close();

    const file = try data_directory.createFile(
        IDENTITY_KEYPAIR_PATH,
        .{
            .read = true,
            .truncate = false,
            .lock = .exclusive, // no way to check size twice atomically without a lock
        },
    );
    defer file.close();

    const size = (try file.stat()).size;
    if (size == 0) {
        const new_kp: KeyPair = .generate();
        try file.writeAll(&new_kp.secret_key.toBytes());
        return new_kp;
    } else if (size == SecretKey.encoded_length) {
        var buffer: [SecretKey.encoded_length]u8 = undefined;
        const length = try file.readAll(&buffer);
        std.debug.assert(buffer.len == length);

        const secret_key: SecretKey = .{ .bytes = buffer };
        return try KeyPair.fromSecretKey(secret_key);
    } else {
        logger.err().logf(
            "identity file found was the wrong size, expected 64 byte secret key, found {d}",
            .{size},
        );
        return error.InvalidIdentityFile;
    }
}

/// Reads a binary keypair file and returns its public key as `Pubkey`.
pub fn readBinaryKeypairPubkey(path: []const u8) !sig.core.Pubkey {
    var file = try std.fs.cwd().openFile(
        path,
        .{ .lock = .exclusive }, // need exclusive lock in order to check size
    );
    defer file.close();

    const size = (try file.stat()).size;
    if (size != SecretKey.encoded_length) return error.InvalidKeypairFile;

    var buffer: [SecretKey.encoded_length]u8 = undefined;
    const length = try file.readAll(&buffer);
    std.debug.assert(length == buffer.len);

    const secret_key: SecretKey = .{ .bytes = buffer };
    const keypair = try KeyPair.fromSecretKey(secret_key);
    return sig.core.Pubkey.fromPublicKey(&keypair.public_key);
}
