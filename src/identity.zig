const std = @import("std");
const sig = @import("sig.zig");

const SecretKey = std.crypto.sign.Ed25519.SecretKey;
pub const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Logger = sig.trace.Logger("identity");
const Pubkey = sig.core.Pubkey;

pub const IDENTITY_KEYPAIR_PATH = "identity.json";

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
        var file_writer = file.writer(&.{});
        try std.json.fmt(&new_kp.secret_key.toBytes(), .{}).format(&file_writer.interface);
        return new_kp;
    }

    return try parseFromFile(file);
}

pub fn readPubkey(logger: Logger, source: []const u8) error{InvalidPubkeySource}!Pubkey {
    // Try to read the source as a base58 encoded public key.
    const base58_err = if (Pubkey.parseRuntime(source)) |p| return p else |e| e;
    // Try to open a path, read the secret from it, and parse the public key from it.
    const file_err = err: {
        const file = std.fs.cwd().openFile(source, .{ .lock = .exclusive }) catch |e| break :err e;
        defer file.close();
        const kp = parseFromFile(file) catch |e| break :err e;
        return .fromPublicKey(&kp.public_key);
    };

    logger.err().logf(
        "Could not interpret '{s}' as a base58 pubkey due to {} or a json keypair file due to {}",
        .{ source, base58_err, file_err },
    );
    return error.InvalidPubkeySource;
}

fn parseFromFile(file: std.fs.File) !KeyPair {
    // The json parsing only needs a bit of memory to perform state management.
    var fba_buffer: [0x100]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buffer);

    var json_buffer: [SecretKey.encoded_length * 10]u8 = undefined;
    const json_length = try file.readAll(&json_buffer);
    const parsed = try std.json.parseFromSliceLeaky(
        [SecretKey.encoded_length]u8,
        fba.allocator(),
        json_buffer[0..json_length],
        .{},
    );
    const secret_key = try SecretKey.fromBytes(parsed);
    return try .fromSecretKey(secret_key);
}

test "readPubkey for pubkey string" {
    const parsed_pk = try readPubkey(.FOR_TESTS, test_pubkey);
    try std.testing.expectEqual(Pubkey.parse(test_pubkey), parsed_pk);
}

test "readPubkey for keypair filename" {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    {
        const file = try tmp_dir.dir.createFile("keypair.json", .{});
        defer file.close();
        try file.writeAll(test_json);
    }
    var buf: [256]u8 = undefined;
    const path = try tmp_dir.dir.realpath("keypair.json", &buf);

    const parsed_pk = try readPubkey(.FOR_TESTS, path);

    try std.testing.expectEqual(Pubkey.parse(test_pubkey), parsed_pk);
}

test "readPubkey for nonsense string" {
    try std.testing.expectError(error.InvalidPubkeySource, readPubkey(.noop, "nonsense"));
}

const test_pubkey = "4gE1hGfMN781mVSpoRJwHdsbWLqZDWLNqTtrtimfhuWR";
const test_json = "[96,2,20,47,167,83,64,68,207,145,30,186,117,222,119,39,159,95,60,168,48,53,8," ++
    "129,248,248,156,77,86,181,231,139,54,159,108,205,206,110,182,234,135,178,145,110,60,88," ++
    "140,170,68,154,85,26,181,166,209,244,173,161,100,35,124,28,126,218]";
