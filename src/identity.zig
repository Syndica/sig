const std = @import("std");
const sig = @import("sig.zig");

const SecretKey = std.crypto.sign.Ed25519.SecretKey;

const Logger = sig.trace.Logger("identity");
const Pubkey = sig.core.Pubkey;

pub const IDENTITY_KEYPAIR_PATH = "identity.json";

/// Re-export of stdlib's Ed25519 KeyPair.
pub const KeyPair = std.crypto.sign.Ed25519.KeyPair;

pub const ValidatorIdentity = struct {
    /// Public key identifying this validator
    validator: Pubkey,
    /// Public key of the vote account
    vote_account: ?Pubkey,
};

pub const SigningKeys = struct {
    /// Keypair for the node identity used for signing vote transactions
    node: ?KeyPair,
    /// Authorized voter keypairs allowed to sign vote transactions
    authorized_voters: []const KeyPair,
};

/// Returns the keypair from {app data directory}/{IDENTITY_KEYPAIR_PATH} or creates a new one
/// if the file does not exist. If the file is invalid, an error is returned.
pub fn getOrInit(allocator: std.mem.Allocator, logger: Logger) !KeyPair {
    const app_data_dir_path = try std.fs.getAppDataDir(allocator, "sig");
    defer allocator.free(app_data_dir_path);

    if (!std.fs.path.isAbsolute(app_data_dir_path)) {
        return error.DataDirPathIsNotAbsolute;
    }

    var app_data_dir = try std.fs.cwd().makeOpenPath(app_data_dir_path, .{});
    defer app_data_dir.close();

    if (app_data_dir.openFile(IDENTITY_KEYPAIR_PATH, .{ .mode = .read_only })) |file| {
        defer file.close();
        return parseKeypairJson(file.reader()) catch |e| {
            logger.err().logf("Invalid identity.json: {}", .{e});
            return error.InvalidIdentityFile;
        };
    } else |err| switch (err) {
        else => |e| return e,
        error.FileNotFound => {
            // create the file with a new keypair
            const file = try app_data_dir.createFile(IDENTITY_KEYPAIR_PATH, .{
                .truncate = true,
            });
            defer file.close();

            const keypair = KeyPair.generate();
            try std.json.stringify(&keypair.secret_key.toBytes(), .{}, file.writer());

            return keypair;
        },
    }
}

/// Reads a pubkey either as a base58 string or from a json keypair file
pub fn readPubkeyFlexible(
    logger: Logger,
    base58_or_kp_path: []const u8,
) error{InvalidPubkeySource}!Pubkey {
    const pk_err = if (Pubkey.parseRuntime(base58_or_kp_path)) |p| return p else |e| e;

    const kp_err = err: {
        const file = std.fs.cwd().openFile(base58_or_kp_path, .{}) catch |e| break :err e;
        defer file.close();

        const keypair = parseKeypairJson(file.reader()) catch |e| break :err e;

        return Pubkey.fromPublicKey(&keypair.public_key);
    };

    logger.err().logf(
        "Could not interpret '{s}' as a base58 pubkey due to {} or a json keypair file due to {}",
        .{ base58_or_kp_path, pk_err, kp_err },
    );
    return error.InvalidPubkeySource;
}

fn parseKeypairJson(reader: anytype) !KeyPair {
    var fba_buf: [SecretKey.encoded_length * 10]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    var json_buf: [SecretKey.encoded_length * 10]u8 = undefined;
    const string_len = try reader.readAll(&json_buf);

    const buf = try std.json.parseFromSliceLeaky(
        [SecretKey.encoded_length]u8,
        fba.allocator(),
        json_buf[0..string_len],
        .{},
    );

    const secret_key = try SecretKey.fromBytes(buf);
    return try KeyPair.fromSecretKey(secret_key);
}

test "readPubkeyFlexible for pubkey string" {
    const parsed_pk = try readPubkeyFlexible(.FOR_TESTS, test_pubkey);
    try std.testing.expectEqual(Pubkey.parse(test_pubkey), parsed_pk);
}

test "readPubkeyFlexible for keypair filename" {
    var dir = std.testing.tmpDir(.{});
    defer dir.cleanup();
    {
        const file = try dir.dir.createFile("keypair.json", .{});
        defer file.close();
        try file.writeAll(test_json);
    }
    var buf: [256]u8 = undefined;
    const path = try dir.dir.realpath("keypair.json", &buf);

    const parsed_pk = try readPubkeyFlexible(.FOR_TESTS, path);

    try std.testing.expectEqual(Pubkey.parse(test_pubkey), parsed_pk);
}

test "readPubkeyFlexible for nonsense string" {
    try std.testing.expectError(error.InvalidPubkeySource, readPubkeyFlexible(.noop, "nonsense"));
}

const test_pubkey = "4gE1hGfMN781mVSpoRJwHdsbWLqZDWLNqTtrtimfhuWR";
const test_json = "[96,2,20,47,167,83,64,68,207,145,30,186,117,222,119,39,159,95,60,168,48,53,8," ++
    "129,248,248,156,77,86,181,231,139,54,159,108,205,206,110,182,234,135,178,145,110,60,88," ++
    "140,170,68,154,85,26,181,166,209,244,173,161,100,35,124,28,126,218]";
